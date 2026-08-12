//! What sits behind each import, and what to do when nothing does.

pub mod btrieve;
pub mod credits;
pub mod fsd;
pub mod gsbl;
pub mod memory;
pub mod msg;
pub mod runtime;
pub mod screen;
pub mod stream;
pub mod system;
pub mod text;
pub mod user;

use mbbs16::{Machine, Ret};

use crate::Host;
use crate::abi::{Call, Cursor, Wg16};
use crate::exports::{DOSCALLS, GALGSBL, MAJORBBS};
use crate::globals::GLOBALS;

/// A cursor over the outstanding call's argument frame, decoded for [`Wg16`].
///
/// One helper rather than `Cursor::new(machine.arg_frame())` written out at
/// every shim's first line, because every converted shim needs the identical
/// two calls and the crate has only one 16-bit `Abi` to name.
///
/// Takes `&Machine`, not `&mut Machine`: argument reads are immutable
/// (`Machine::arg_u16`/`arg_far` always were), and the returned `Cursor`
/// borrows `machine` for as long as it lives. The plan's own hoisting rule --
/// read every argument at the top of the function, before any other use of
/// `machine` -- is what ends that borrow before a shim goes on to call
/// `&mut Machine` methods; see `crates/mbbs/src/abi.rs`'s module doc for why
/// that is enough for Task 4, and the implementation plan's Task 5 note for
/// why it stops being enough once `Call` holds `mem: &mut A::Mem` alongside
/// a `Cursor` for a whole shim body.
pub(crate) fn args(machine: &Machine) -> Cursor<'_, Wg16> {
    Cursor::new(machine.arg_frame())
}

/// A [`Call<Wg16>`] over the outstanding call's argument frame.
///
/// The `Wg16` half of bridging a shim written against the generic
/// `fn<A: Abi>(&mut Call<A>, &mut Host<A>) -> Result<abi::Ret<A>, ShimError>`
/// shape into the (still concrete) [`Shim`] the dispatch table wants -- see
/// `shims::user`'s `uacoff_wg16` and its four siblings for the other half
/// (converting the `abi::Ret<Wg16>` a generic shim hands back into
/// `mbbs16::Ret`, which `Into::into` already does via `crate::abi`'s
/// `impl From<abi::Ret<Wg16>> for mbbs16::Ret`).
///
/// `Shim` itself stays `Wg16`-concrete rather than going generic
/// (`Shim<A>`), because a bare `fn` pointer is one exact signature and not
/// every entry in `ROUTINES` has been converted -- see
/// `docs/plans/2026-08-11-abi-abstraction-implementation.md`'s Task 5 for the
/// two options weighed and why this one was chosen: the alternative is a
/// change to every one of the table's other entries, which is the work the
/// remaining ten files still owe.
///
/// Computes the frame before taking `machine` mutably -- the same ordering
/// [`Call::new`]'s own doc comment describes, and why this takes
/// `&mut Machine` rather than composing with [`args`] above, which only
/// borrows `machine` immutably.
pub(crate) fn call(machine: &mut Machine) -> Call<'_, Wg16> {
    let frame = machine.arg_frame().to_vec();
    Call::new(machine, &frame)
}

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
    // Strings, numbers and the print buffer. `_wg16`: all thirty of these are
    // generic now (see `shims::text`'s own doc comment).
    (MAJORBBS, "spr", text::spr_wg16, Cleans::Caller),
    (MAJORBBS, "sprintf", text::sprintf_wg16, Cleans::Caller),
    (MAJORBBS, "vsprintf", text::vsprintf_wg16, Cleans::Caller),
    (MAJORBBS, "prf", text::prf_wg16, Cleans::Caller),
    (MAJORBBS, "clrprf", text::clrprf_wg16, Cleans::Caller),
    (MAJORBBS, "stzcpy", text::stzcpy_wg16, Cleans::Caller),
    (MAJORBBS, "strcpy", text::strcpy_wg16, Cleans::Caller),
    (MAJORBBS, "strlen", text::strlen_wg16, Cleans::Caller),
    (MAJORBBS, "rmvwht", text::rmvwht_wg16, Cleans::Caller),
    (MAJORBBS, "skpwht", text::skpwht_wg16, Cleans::Caller),
    (MAJORBBS, "skpwrd", text::skpwrd_wg16, Cleans::Caller),
    (MAJORBBS, "depad", text::depad_wg16, Cleans::Caller),
    (MAJORBBS, "rstrin", text::rstrin_wg16, Cleans::Caller),
    (MAJORBBS, "parsin", text::parsin_wg16, Cleans::Caller),
    (MAJORBBS, "atol", text::atol_wg16, Cleans::Caller),
    (MAJORBBS, "l2as", text::l2as_wg16, Cleans::Caller),
    (MAJORBBS, "toupper", text::toupper_wg16, Cleans::Caller),
    (MAJORBBS, "tolower", text::tolower_wg16, Cleans::Caller),
    (MAJORBBS, "sameas", text::sameas_wg16, Cleans::Caller),
    (MAJORBBS, "sameto", text::sameto_wg16, Cleans::Caller),
    (MAJORBBS, "samein", text::samein_wg16, Cleans::Caller),
    (MAJORBBS, "strcmp", text::strcmp_wg16, Cleans::Caller),
    (MAJORBBS, "strcat", text::strcat_wg16, Cleans::Caller),
    (MAJORBBS, "strncat", text::strncat_wg16, Cleans::Caller),
    (MAJORBBS, "strncpy", text::strncpy_wg16, Cleans::Caller),
    (MAJORBBS, "strchr", text::strchr_wg16, Cleans::Caller),
    (MAJORBBS, "strstr", text::strstr_wg16, Cleans::Caller),
    (MAJORBBS, "strtok", text::strtok_wg16, Cleans::Caller),
    (MAJORBBS, "lastwd", text::lastwd_wg16, Cleans::Caller),
    (MAJORBBS, "sortstgs", text::sortstgs_wg16, Cleans::Caller),
    // Message files, and the options in them. `_wg16`: all ten are generic
    // now (see `shims::msg`'s own doc comment) -- `stgopt` and `prfmsg` were
    // the last two, unblocked once `shims::text::write_cstr`/`append`
    // converted.
    (MAJORBBS, "opnmsg", msg::opnmsg_wg16, Cleans::Caller),
    (MAJORBBS, "clsmsg", msg::clsmsg_wg16, Cleans::Caller),
    (MAJORBBS, "setmbk", msg::setmbk_wg16, Cleans::Caller),
    (MAJORBBS, "rstmbk", msg::rstmbk_wg16, Cleans::Caller),
    (MAJORBBS, "stgopt", msg::stgopt_wg16, Cleans::Caller),
    (MAJORBBS, "numopt", msg::numopt_wg16, Cleans::Caller),
    (MAJORBBS, "ynopt", msg::ynopt_wg16, Cleans::Caller),
    (MAJORBBS, "chropt", msg::chropt_wg16, Cleans::Caller),
    (MAJORBBS, "tokopt", msg::tokopt_wg16, Cleans::Caller),
    (MAJORBBS, "prfmsg", msg::prfmsg_wg16, Cleans::Caller),
    // Memory the module owns, and the leaves that move bytes about.
    (MAJORBBS, "alcmem", memory::alcmem_wg16, Cleans::Caller),
    (MAJORBBS, "alczer", memory::alczer_wg16, Cleans::Caller),
    (MAJORBBS, "galfree", memory::galfree_wg16, Cleans::Caller),
    (
        MAJORBBS,
        "farcoreleft",
        memory::farcoreleft_wg16,
        Cleans::Caller,
    ),
    // `alctile`/`ptrtile` stay `Wg16`-concrete: segment tiling has no
    // flat-memory counterpart (see `shims::memory`'s own doc comment on
    // `alctile`).
    (MAJORBBS, "alctile", memory::alctile, Cleans::Caller),
    (MAJORBBS, "ptrtile", memory::ptrtile, Cleans::Caller),
    (MAJORBBS, "setmem", memory::setmem_wg16, Cleans::Caller),
    (MAJORBBS, "movmem", memory::movmem_wg16, Cleans::Caller),
    (MAJORBBS, "memcpy", memory::memcpy_wg16, Cleans::Caller),
    (MAJORBBS, "memcmp", memory::memcmp_wg16, Cleans::Caller),
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
    // Btrieve: the write family. `dinsbtv` and `dupdbtv` write; `invbtv` and
    // `delbtv` reproduce what `PLBTVSTF.C` did with no file current, and
    // refuse when there is one; `clsbtv` flushes the index and gives four
    // allocations back.
    (MAJORBBS, "dinsbtv", btrieve::dinsbtv, Cleans::Caller),
    (MAJORBBS, "dupdbtv", btrieve::dupdbtv, Cleans::Caller),
    (MAJORBBS, "invbtv", btrieve::invbtv, Cleans::Caller),
    (MAJORBBS, "delbtv", btrieve::delbtv, Cleans::Caller),
    (MAJORBBS, "clsbtv", btrieve::clsbtv, Cleans::Caller),
    // Streams: the module's own files, read and written. All nine are
    // generic now -- `fprintf` converted once `crate::fmt::format_call`
    // existed for it to route through (see `shims::stream::fprintf`'s own
    // doc comment).
    (MAJORBBS, "fopen", stream::fopen_wg16, Cleans::Caller),
    (MAJORBBS, "fclose", stream::fclose_wg16, Cleans::Caller),
    (MAJORBBS, "fgets", stream::fgets_wg16, Cleans::Caller),
    (MAJORBBS, "fread", stream::fread_wg16, Cleans::Caller),
    (MAJORBBS, "fprintf", stream::fprintf_wg16, Cleans::Caller),
    (MAJORBBS, "fflush", stream::fflush_wg16, Cleans::Caller),
    (MAJORBBS, "unlink", stream::unlink_wg16, Cleans::Caller),
    (MAJORBBS, "getdtd", stream::getdtd_wg16, Cleans::Caller),
    (MAJORBBS, "cntdir", stream::cntdir_wg16, Cleans::Caller),
    // The clock, the audit trail, and coming online. `_wg16`: sixteen of
    // these nineteen are generic now (see `shims::system`'s own doc
    // comment); `register_module`, `register_agent` and `rtkick` stay
    // concrete, all three blocked on `Registration`/`Agent`/`Kick` being
    // plain `FarPtr`-typed structs `Host<A>`'s own fields hold regardless of
    // `A` -- see `shims::system`'s doc comment for why that boundary is
    // deliberate, not a gap this task happened to find.
    (MAJORBBS, "access", system::access_wg16, Cleans::Caller),
    (MAJORBBS, "now", system::now_wg16, Cleans::Caller),
    (MAJORBBS, "nctime", system::nctime_wg16, Cleans::Caller),
    (MAJORBBS, "ncdate", system::ncdate_wg16, Cleans::Caller),
    (MAJORBBS, "cofdat", system::cofdat_wg16, Cleans::Caller),
    (MAJORBBS, "ncedat", system::ncedat_wg16, Cleans::Caller),
    (MAJORBBS, "today", system::today_wg16, Cleans::Caller),
    (MAJORBBS, "time", system::time_wg16, Cleans::Caller),
    (MAJORBBS, "srand", system::srand_wg16, Cleans::Caller),
    (MAJORBBS, "genrdn", system::genrdn_wg16, Cleans::Caller),
    // Caller-cleaned, read off the host rather than assumed from its
    // neighbours: lngrnd ends in a bare `retf` (segment 13, offset 0x167) with
    // no immediate, so the module pops its own eight bytes of arguments.
    (MAJORBBS, "lngrnd", system::lngrnd_wg16, Cleans::Caller),
    (MAJORBBS, "gmdnam", system::gmdnam_wg16, Cleans::Caller),
    (MAJORBBS, "shocst", system::shocst_wg16, Cleans::Caller),
    (MAJORBBS, "rtkick", system::rtkick, Cleans::Caller),
    // `_wg16`: these five are converted to the generic `Call<A>`/`Host<A>`
    // shape (see `shims::user`'s own doc comment); the table entry is the
    // monomorphised bridge, not the shim itself. `getin` is the sixth,
    // unblocked once `shims::text::parsin`/`Host::get_input` went generic.
    (MAJORBBS, "begin_polling", user::begin_polling_wg16, Cleans::Caller),
    (MAJORBBS, "stop_polling", user::stop_polling_wg16, Cleans::Caller),
    // `_wg16`: seven of these nine are generic now (see `shims::fsd`'s own
    // doc comment); `fsdego` and `vfyadn` stay concrete, both blocked on
    // `crate::fsd::Scb<Wg16>`-only entry-engine routines (`fsdlin`/`fsdent`/
    // `vfyadn`) in a different, unconverted file.
    (MAJORBBS, "fsdroom", fsd::fsdroom_wg16, Cleans::Caller),
    (MAJORBBS, "fsdapr", fsd::fsdapr_wg16, Cleans::Caller),
    (MAJORBBS, "fsdnan", fsd::fsdnan_wg16, Cleans::Caller),
    (MAJORBBS, "fsdord", fsd::fsdord_wg16, Cleans::Caller),
    (MAJORBBS, "fsdxan", fsd::fsdxan_wg16, Cleans::Caller),
    (MAJORBBS, "fsdrft", fsd::fsdrft_wg16, Cleans::Caller),
    (MAJORBBS, "fsdbkg", fsd::fsdbkg_wg16, Cleans::Caller),
    (MAJORBBS, "fsdego", fsd::fsdego, Cleans::Caller),
    (MAJORBBS, "vfyadn", fsd::vfyadn, Cleans::Caller),
    (MAJORBBS, "dclvda", system::dclvda_wg16, Cleans::Caller),
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
        system::register_textvar_wg16,
        Cleans::Caller,
    ),
    (MAJORBBS, "catastro", system::catastro_wg16, Cleans::Caller),
    // "Restore screen-length to usracc setting" -- `MAJORBBS.C:3776` (wg1),
    // one import, one call site. See `shims::screen`'s own doc comment for
    // what it does, what it does not, and where its one caller actually
    // leads.
    (MAJORBBS, "rstrxf", screen::rstrxf_wg16, Cleans::Caller),
    // The current user: the two routines that turn a channel number into the
    // slot it names.
    (MAJORBBS, "curusr", user::curusr_wg16, Cleans::Caller),
    (MAJORBBS, "uacoff", user::uacoff_wg16, Cleans::Caller),
    (MAJORBBS, "getin", user::getin_wg16, Cleans::Caller),
    (MAJORBBS, "haskey", user::haskey_wg16, Cleans::Caller),
    // Billing, which this host does not do. Both answer yes; `shims::credits`
    // is where that decision is written down. `Cleans::Caller` is measured --
    // `re/ne_arity.py` reads `add sp,8` after all three `otstcrd` sites and
    // `add sp,0Ah` after all three `odedcrd` sites, matching `USRACC.H`'s
    // `(int, long, int)` and `(int, long, int, int)` exactly.
    (MAJORBBS, "otstcrd", credits::otstcrd_wg16, Cleans::Caller),
    (MAJORBBS, "odedcrd", credits::odedcrd_wg16, Cleans::Caller),
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
    // The rest of that runtime, and it does not share one convention. These
    // three take their operands in registers and put nothing on the stack, so
    // there is nothing for either side to clean.
    (MAJORBBS, "f_lxmul@", runtime::f_lxmul, Cleans::Caller),
    (MAJORBBS, "f_lxlsh@", runtime::f_lxlsh, Cleans::Caller),
    (MAJORBBS, "f_lxursh@", runtime::f_lxursh, Cleans::Caller),
    // And this one is a struct copy: two far pointers on the stack, which it
    // pops, and the length in `CX`.
    (
        MAJORBBS,
        "f_scopy@",
        runtime::f_scopy,
        Cleans::Callee(runtime::POINTERS),
    ),
    // The GSBL terminal layer. Fourteen routines, seventy-seven call sites,
    // none of them reached by initialisation. `_wg16`: all seventeen (the
    // fourteen imports plus the three below) are generic now -- see
    // `shims::gsbl`'s own doc comment.
    (GALGSBL, "btutsw", gsbl::btutsw_wg16, Cleans::Caller),
    (GALGSBL, "btuxct", gsbl::btuxct_wg16, Cleans::Caller),
    (GALGSBL, "btuxnf", gsbl::btuxnf_wg16, Cleans::Caller),
    (GALGSBL, "btuxmt", gsbl::btuxmt_wg16, Cleans::Caller),
    (GALGSBL, "btuoes", gsbl::btuoes_wg16, Cleans::Caller),
    (GALGSBL, "btuclo", gsbl::btuclo_wg16, Cleans::Caller),
    (GALGSBL, "btulok", gsbl::btulok_wg16, Cleans::Caller),
    (GALGSBL, "btucli", gsbl::btucli_wg16, Cleans::Caller),
    (GALGSBL, "btuinj", gsbl::btuinj_wg16, Cleans::Caller),
    (GALGSBL, "btutrg", gsbl::btutrg_wg16, Cleans::Caller),
    (GALGSBL, "btuech", gsbl::btuech_wg16, Cleans::Caller),
    (GALGSBL, "btumil", gsbl::btumil_wg16, Cleans::Caller),
    (GALGSBL, "btuibw", gsbl::btuibw_wg16, Cleans::Caller),
    (GALGSBL, "btuica", gsbl::btuica_wg16, Cleans::Caller),
    // Three more GALGSBL routines, registered even though `WCCMMUD.DLL`
    // imports none of them (`re/exports/imports.txt` has no site for any --
    // see `shims::gsbl`'s own doc comment). `rstrxf`, above, is their one
    // caller in this host, and calls each directly rather than through this
    // table -- there is no module far call to dispatch. They are registered
    // anyway because they are ordinary importable GSBL routines and this is
    // where every other one lives, in case a future module asks.
    (GALGSBL, "btuhpk", gsbl::btuhpk_wg16, Cleans::Caller),
    (GALGSBL, "btupbc", gsbl::btupbc_wg16, Cleans::Caller),
    (GALGSBL, "btucpc", gsbl::btucpc_wg16, Cleans::Caller),
];

/// Every constant the host exports.
///
/// Only one so far. `DOSCALLS.135` is the huge shift: how far to shift a count
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
///
/// It was keyed as `#135` while nothing in the recovered sources named it.
/// Phar Lap's own `DOSCALLS.DLL` does -- `DOSHUGESHIFT` -- and `PHAPI.LIB`
/// imports the same ordinal under Borland's spelling `__AHSHIFT`, which is the
/// name the huge-pointer arithmetic above is written in. Both agree with what
/// the sites do, so the key is the symbol now rather than the number.
const ABSOLUTES: &[(&str, &str, u16)] = &[(
    DOSCALLS,
    "doshugeshift",
    mbbs16::SELECTOR_STEP.ilog2() as u16,
)];

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

/// Whether [`crate::Host::run`]'s survey mode (see `crate::survey`) may
/// safely fabricate a return and resume the module past a call to an
/// unimplemented `symbol`, and if so, which convention to clean the call up
/// with.
///
/// An unimplemented symbol has no [`Cleans`] on record -- nothing registered
/// it, so nothing said who pops its arguments -- and guessing wrong does not
/// crash anything: it leaves the module's stack quietly wrong, and every
/// symbol survey mode records afterwards is then downstream of a machine
/// whose stack pointer no longer means what the module thinks it means. That
/// would make the survey's own output look authoritative while being
/// fiction, which is worse than the stop this function exists to let a
/// caller sometimes avoid.
///
/// The rule: default to [`Cleans::Caller`] -- cdecl, "what every MajorBBS
/// routine does" (see [`Cleans::Caller`]'s own doc) -- and refuse outright
/// for anything shaped like this crate's one known exception, Borland's own
/// runtime helpers, all of them named with a trailing `@`
/// (`f_ldiv@`, `f_lmod@`, `f_ludiv@`, `f_lumod@`, `f_scopy@`).
///
/// **`@` alone is not even a reliable *signal* for `Callee`, let alone a way
/// to know the byte count.** Three more `@`-suffixed routines are already
/// registered above (`f_lxmul@`, `f_lxlsh@`, `f_lxursh@`) and every one of
/// them is [`Cleans::Caller`] -- they take their operands in registers and
/// put nothing on the stack, so there is nothing for either side to clean.
/// So this cannot distinguish `Caller` from `Callee` among the eight
/// `@`-suffixed symbols this host has already measured the answer for, and
/// has no basis at all for guessing a byte count for a ninth this host has
/// not. Refusing is always safe -- the caller falls back to the ordinary
/// stop. Guessing a byte count is not, so this never does.
///
/// Measured against the whole of `ROUTINES` above: 136 [`Cleans::Caller`]
/// against 10 [`Cleans::Callee`], and every `Callee` entry is one of the five
/// `@`-suffixed helpers this function refuses to continue past.
pub(crate) fn survey_continue_convention(symbol: &str) -> Option<Cleans> {
    if symbol.contains('@') {
        None
    } else {
        Some(Cleans::Caller)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::GALGSBL;
    use crate::testing::Fixture;

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
    fn fsdbkg_is_wired() {
        // It used to be `Entry::Unimplemented`, on the grounds that clearing
        // an ANSI screen and running a display engine needed a screen this
        // host did not have. Stage 5's Task 6 built one: `fsd::fsddsp` draws
        // the form and `fsdbkg` sends it, with the wrap width zeroed first so
        // the escapes survive `Channel::transmit`.
        assert!(matches!(entry(MAJORBBS, "fsdbkg"), Entry::Routine { .. }));
    }

    #[test]
    fn fsdego_is_wired_to_ordinal_241() {
        // `fsdego` puts a channel into an entry session (Task 5,
        // docs/plans/2026-08-09-fsd-stage4-line-mode.md) -- no longer the
        // routine `shims::fsd`'s own module documentation once named
        // alongside `fsdbkg` as needing a re-entrant call this host cannot
        // make. It refuses on its own terms now (amode==1, no session
        // prepared), rather than unconditionally.
        assert!(matches!(
            entry(MAJORBBS, "fsdego"),
            Entry::Routine(_, Cleans::Caller)
        ));
    }

    /// Every test in `shims::screen` and `shims::gsbl` calls `rstrxf`,
    /// `btuhpk`, `btupbc` and `btucpc` by their Rust name --
    /// `f.invoke(btupbc, ...)`, `f.invoke(rstrxf, ...)` -- which is not how
    /// a module (or, for `rstrxf`, this crate's own MAJORBBS import
    /// dispatch) reaches any routine. That path is `entry`, keyed by the DLL
    /// and the *string* `ROUTINES` was given -- and every one of those tests
    /// would keep passing even if this table wired `"btupbc"` to
    /// `gsbl::btucpc`'s behaviour, or `"rstrxf"` to a routine that does
    /// nothing at all, because none of them go through it. This does.
    #[test]
    fn rstrxf_and_its_gsbl_routines_are_wired_to_the_right_behaviour_by_name() {
        let mut f = Fixture::new();
        let console = f.console();

        let Entry::Routine(btuhpk, _) = entry(GALGSBL, "btuhpk") else {
            panic!("btuhpk must be a routine");
        };
        let Entry::Routine(btupbc, _) = entry(GALGSBL, "btupbc") else {
            panic!("btupbc must be a routine");
        };
        let Entry::Routine(btucpc, _) = entry(GALGSBL, "btucpc") else {
            panic!("btucpc must be a routine");
        };
        let Entry::Routine(rstrxf, _) = entry(MAJORBBS, "rstrxf") else {
            panic!("rstrxf must be a routine");
        };

        f.invoke(btuhpk, &[0, 0, 0]).expect("ok");
        assert!(f.host.gsbl().channel(console).pause_handler_installed);

        f.invoke(btupbc, &[0, 20]).expect("ok");
        assert_eq!(
            f.host.gsbl().channel(console).pause_char,
            20,
            "the table's \"btupbc\" must set pause_char, not clear_pause_char"
        );
        assert_eq!(
            f.host.gsbl().channel(console).clear_pause_char,
            0,
            "and must not have touched clear_pause_char while doing it"
        );

        f.invoke(btucpc, &[0, 19]).expect("ok");
        assert_eq!(
            f.host.gsbl().channel(console).clear_pause_char,
            19,
            "the table's \"btucpc\" must set clear_pause_char, not pause_char"
        );

        // `page_lines` specifically: nothing above this line touches it, so a
        // mutant that resolves `"rstrxf"` to some *other* real routine (one
        // that returns `Ok` without erroring, so `.expect` below would not
        // catch it either) cannot pass by coasting on a value one of the
        // three calls above already left correct.
        f.host
            .point_curusr(&mut f.machine, console)
            .expect("channel 0 is current");
        let account = f.host.users().account(console);
        let at = mbbs16::FarPtr {
            offset: account.offset + crate::users::usracc::SCNBRK as u16,
            selector: account.selector,
        };
        f.machine.write(at, &[24]).expect("account memory");
        f.invoke(rstrxf, &[]).expect("rstrxf does not stop the machine");
        assert_eq!(
            f.host.gsbl().channel(console).page_lines,
            22,
            "the table's \"rstrxf\" must be the real routine: scnbrk(24) - CTNUOS(2)"
        );
    }

    #[test]
    fn an_unknown_symbol_is_unimplemented() {
        assert!(matches!(entry(MAJORBBS, "nonesuch"), Entry::Unimplemented));
    }

    /// `l2as`'s own module tests (`shims::text`) all call it by its Rust
    /// name, which is not how a module reaches it. This goes through `entry`,
    /// keyed by the DLL and the string the `ROUTINES` table was given, the
    /// way `WCCMMUD.DLL`'s own import fixups do.
    #[test]
    fn l2as_is_wired_to_the_right_behaviour_by_name() {
        let mut f = Fixture::new();
        let Entry::Routine(l2as, cleans) = entry(MAJORBBS, "l2as") else {
            panic!("l2as must be a routine");
        };
        assert_eq!(cleans, Cleans::Caller, "14/14 measured sites clean 2 words");

        let value = i32::MIN as u32;
        let args = [value as u16, (value >> 16) as u16];
        let Ret::Far(at) = f.invoke(l2as, &args).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"-2147483648");
    }

    #[test]
    fn the_gsbl_routines_are_reached_under_galgsbl_and_not_under_majorbbs() {
        // Ordinals collide across DLLs -- GALGSBL.72 is `bturno` and
        // MAJORBBS.72 is something else entirely -- so a routine registered
        // under the wrong module name would be dispatched for the wrong import.
        assert!(matches!(entry(GALGSBL, "btuxmt"), Entry::Routine(..)));
        assert!(matches!(entry(MAJORBBS, "btuxmt"), Entry::Unimplemented));
    }

    #[test]
    fn the_huge_shift_steps_one_ldt_entry() {
        let Entry::Absolute(shift) = entry(DOSCALLS, "doshugeshift") else {
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
    fn only_the_stack_helpers_pop_their_own_arguments() {
        // The MajorBBS API is cdecl throughout: the module pushes, the module
        // pops. Only the compiler's own runtime helpers differ, and only the
        // ones that take arguments on the stack at all -- `f_lxmul@` and the two
        // shifts pass everything in registers, so there is nothing to clean and
        // `Cleans::Caller` is the honest answer for them.
        //
        // How much each pops is asserted here too, because the two amounts are
        // the same number for different reasons: two `long`s for the division
        // family, two far pointers for the struct copy.
        let callee: Vec<(&str, Cleans)> = ROUTINES
            .iter()
            .filter(|(_, _, _, cleans)| !matches!(cleans, Cleans::Caller))
            .map(|(_, name, _, cleans)| (*name, *cleans))
            .collect();
        assert_eq!(
            callee,
            [
                ("f_ldiv@", Cleans::Callee(runtime::OPERANDS)),
                ("f_lmod@", Cleans::Callee(runtime::OPERANDS)),
                ("f_ludiv@", Cleans::Callee(runtime::OPERANDS)),
                ("f_lumod@", Cleans::Callee(runtime::OPERANDS)),
                ("f_scopy@", Cleans::Callee(runtime::POINTERS)),
            ]
        );
    }

    #[test]
    fn survey_continue_convention_defaults_ordinary_symbols_to_caller() {
        for name in ["gmdnam", "rtihdlr", "register_agent", "l2as", "prf"] {
            assert_eq!(
                survey_continue_convention(name),
                Some(Cleans::Caller),
                "{name} does not look like a Borland runtime helper"
            );
        }
    }

    #[test]
    fn survey_continue_convention_refuses_every_at_suffixed_symbol_measured_above() {
        // Every symbol `only_the_stack_helpers_pop_their_own_arguments` just
        // pinned as genuinely `Cleans::Callee` must be refused here -- this is
        // the one case a wrong guess corrupts the module's own stack.
        for name in ["f_ldiv@", "f_lmod@", "f_ludiv@", "f_lumod@", "f_scopy@"] {
            assert_eq!(
                survey_continue_convention(name),
                None,
                "{name} is Cleans::Callee and must never be guessed at"
            );
        }
    }

    #[test]
    fn survey_continue_convention_also_refuses_the_at_suffixed_symbols_that_are_actually_caller() {
        // `f_lxmul@`, `f_lxlsh@` and `f_lxursh@` are measured `Cleans::Caller`
        // (they take their operands in registers, nothing is pushed) -- but
        // `survey_continue_convention` cannot tell that from an unimplemented
        // symbol's *name* alone, and refusing a symbol it could safely have
        // continued past is not a correctness bug, only lost coverage. Pinned
        // so a future "smarter" `@` heuristic has to notice it is narrowing
        // this on purpose, not by accident.
        for name in ["f_lxmul@", "f_lxlsh@", "f_lxursh@"] {
            assert_eq!(survey_continue_convention(name), None);
        }
    }
}
