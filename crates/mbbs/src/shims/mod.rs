//! What sits behind each import, and what to do when nothing does.

pub mod borland;
pub mod btrieve;
pub mod cnc;
pub mod credit;
pub mod credits;
pub mod dfa;
pub mod crt;
pub mod dosenv;
pub mod echo;
pub mod evidence;
pub mod fsd;
pub mod ftf;
pub mod ftol;
pub mod gcsp;
pub mod gsbl;
pub mod memory;
pub mod misc;
pub mod mlt;
pub mod msg;
pub mod mudmisc;
pub mod mudtext;
pub mod output;
pub mod runtime;
pub mod screen;
pub mod stream;
pub mod system;
pub mod task;
pub mod vda;
pub mod text;
pub mod tfscan;
pub mod user;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::exports::{DOSCALLS, GALGSBL, GALME, GALMSG, MAJORBBS, PHAPI};
use crate::globals::GLOBALS;
use evidence::Evidence;

/// `KERNEL32.dll`'s own import-directory spelling -- measured byte-for-byte
/// from `LUNATIX.DLL` (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`):
/// mixed case, with the `.dll` suffix, unlike `MAJORBBS`/`GALGSBL`'s bare
/// segment-name spelling those two carry over from the 16-bit world.
///
/// **Not aliased through [`canonical_dll`].** KERNEL32 is not the game-host
/// API under another name -- it is genuinely a different library -- so the
/// routine table below has to key on this exact string for `entry`'s
/// `dll == dll` comparison (case-sensitive; `canonical_dll` only normalises
/// case for the two DLLs it actually does alias) to find it. Local to this
/// file rather than in `crate::exports` alongside `MAJORBBS`/`GALGSBL`/
/// `DOSCALLS`: there is no export table keyed on it, only this one constant
/// string.
const KERNEL32: &str = "KERNEL32.dll";

// `args(machine) -> Cursor<'_, Wg16>` used to live here: a bare `Cursor` over
// the argument frame, with no `Call` and so no way to reach memory. It was
// Task 4's shape, when a shim still took `&mut Machine` and read its
// arguments separately from touching the module's memory.
//
// Its last two callers were `shims::memory`'s `alctile` and `ptrtile`, and
// they went when those two became `Shim<Wg16>` like everything else. `Call`
// subsumes it -- `Call::ptr`/`int`/`long` walk the same frame in the same
// order, and `Call::mem` is the part a bare `Cursor` could never provide.

/// A [`Call<A>`] over the outstanding call's argument frame, for any `Abi`.
///
/// One production caller: `lib.rs`'s dispatch loop (`Host::run`, still
/// concrete on `Wg16` until Task 10), which holds a `&mut A::Cpu` and needs
/// the `Call<A>` that [`Shim<A>`](Shim) wants. No `Wg16`-shaped bridge was
/// needed to keep that caller compiling -- `Wg16::Cpu` already *is*
/// `mbbs_machine::m16::Machine`, so `call::<Wg16>(machine)` binds directly
/// against the concrete `&mut Machine` `Host::run` still holds; the plan's
/// sanctioned fallback (a thin one-task-span `Wg16` wrapper) was not needed.
///
/// It used to have 126 more callers. Every converted routine carried a
/// `_wg16` bridge built from this function -- `foo(&mut super::call(machine), host)
/// .map(Into::into)` -- for one reason: `crate::testing::Fixture::invoke`
/// took a bare `fn(&mut Machine, &mut Host)` and so could not be handed a
/// shim directly. That made every addition to the API surface cost two
/// functions instead of one. `Fixture::invoke` builds its own `Call` now and
/// the bridges are deleted.
///
/// Computes the frame before taking `cpu` mutably -- the same ordering
/// [`Call::new`]'s own doc comment describes, and the reason this copies the
/// frame out rather than borrowing it: `Call` needs `cpu` mutably for
/// [`Call::mem`], so a `Cursor` still borrowing it immutably would be a
/// second live borrow of the same object.
pub(crate) fn call<A: Abi>(cpu: &mut A::Cpu) -> Call<'_, A> {
    let frame = A::arg_frame(cpu).to_vec();
    Call::new(cpu, &frame)
}

/// -1, as a 16-bit `int`.
///
/// What a routine returns when absence or failure is the truth and the module is
/// entitled to be told: `access` on a file that is not there, `unlink` on one it
/// cannot remove. Everywhere else in this crate a host that cannot answer stops
/// the module instead -- these are the routines whose *purpose* includes
/// reporting that something is not there, and for them -1 is an answer.
pub(crate) const NO: u16 = -1i16 as u16;

/// One host routine, generic over the ABI it serves.
///
/// `call` is how it reads the module's arguments and reaches its memory
/// (`Call::mem`); the return value goes back in `AX`/`DX:AX` for `Wg16`, in
/// `EAX` for `Wg32` -- each `Abi`'s own `Ret<A>` conversion decides the
/// placement, not this type.
///
/// This is the shape `pub type Shim = fn(&mut Machine, &mut Host) -> ...`
/// used to name before Task 5's shim-body conversion reached every file with
/// a generic core: see `docs/plans/2026-08-11-abi-abstraction-implementation.md`'s
/// "`Shim<A>` as specified is unreachable, and the table needs a second
/// door" for why flipping it earlier -- while ten routines still had no
/// generic core to point at -- would not have compiled, and why those ten
/// (plus the seventeen Btrieve routines the concrete engine behind them ties
/// to `Wg16`) now live behind [`Abi::native`] instead of in [`routines`].
pub type Shim<A> = fn(&mut Call<A>, &mut Host<A>) -> Result<abi::Ret<A>, ShimError>;

// `Wg16Shim` -- a bare `fn(&mut Machine, &mut Host) -> Result<mbbs_machine::m16::Ret,
// ShimError>`, Wg16-concrete with no `Call` at all -- used to live here, and
// is deleted.
//
// It survived this long on a distinction that does not hold up: that a
// routine with no meaning under any other `Abi` therefore has no use for the
// `Abi` types. Being 16-bit-only means a routine cannot be `Shim<A>` for an
// arbitrary `A`, because `routines<A>()` must yield an entry for every `A`
// and there is no `alctile` for a flat address space. It does not mean the
// routine should take a raw `&mut Machine`. `Shim<Wg16>` is the trait at its
// 16-bit instantiation, and that is what every routine in this crate is now,
// including `shims::memory`'s tiling pair and `shims::runtime`'s eight
// Borland helpers. They stay in [`WG16_ROUTINES`] -- that part was always
// real -- but they no longer need ten adapter closures to get there.

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
    BadPointer(mbbs_machine::m16::FarPtrError),

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

impl From<mbbs_machine::m16::FarPtrError> for ShimError {
    fn from(e: mbbs_machine::m16::FarPtrError) -> Self {
        Self::BadPointer(e)
    }
}

/// What an imported symbol is, for this `Abi`.
pub enum Entry<A: Abi> {
    /// A host routine, reached by far call, and who cleans up after it.
    Routine(Shim<A>, Cleans),

    /// A host global the module addresses directly. Reached by no call at all,
    /// so there is nothing to dispatch -- the address goes into the fixup at
    /// load time and the host never hears about it again.
    Datum,

    /// A constant with no address, written into an instruction's immediate.
    Absolute(u16),

    /// Named, and not implemented. Calling it stops the module and says so.
    Unimplemented,
}

// Manual, not `#[derive(..)]`, for the same reason `abi::Ret<A>`'s own
// comment gives: the derive macro's generated bound is `A: Trait`, which
// `Shim<A>` (a bare `fn` pointer) never needs -- a `fn(&mut Call<A>, ...)`
// is `Copy` regardless of what `A` is, so requiring `A: Copy` to get there
// would be a bound this type does not actually have.
impl<A: Abi> Clone for Entry<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for Entry<A> {}

/// Every routine the host implements that serves *any* `Abi`, by the DLL and
/// the C name that exports it.
///
/// Keyed by name rather than by ordinal so that the export tables stay the one
/// place ordinals are written down. A different host version re-keys the whole
/// table by itself; a table of ordinals would have to be rewritten and would
/// look right while being wrong.
///
/// A function, not a `const`, because its element type names `A`: a `const`
/// item cannot borrow a generic parameter from the function that contains it
/// (there is no such function here, but the same rule would bite a top-level
/// `const ROUTINES<A: Abi>`, and `type_alias`-style workarounds do not exist
/// for `const`s on stable Rust). A fresh `Vec` is built and searched once per
/// [`entry`] call -- import resolution, at module load, never per instruction
/// -- so the cost is not one this crate needs to avoid paying.
///
/// Three hundred and fifteen entries: every routine with a generic
/// `fn<A: Abi>(&mut Call<A>, &mut Host<A>) -> Result<abi::Ret<A>, ShimError>`
/// core -- the Borland runtime's `GetModuleHandleA`/`GetProcAddress` pair
/// among them now (`borland::get_module_handle`/`get_proc_address`), the two
/// KERNEL32 symbols that needed `Wg32::resume` to learn `Cleans::Callee`
/// before they could be registered at all. The twenty-seven that do not have
/// a generic core -- `shims::btrieve`'s seventeen, `shims::runtime`'s eight,
/// `shims::memory`'s `alctile`/`ptrtile` -- are not here; see [`Abi::native`]
/// and [`wg16_native`] for where they live instead, and why.
///
/// Re-derive by counting the `Evidence::Unclassified)` rows inside this
/// function's own `vec![...]` (every row ends with one); cross-check against
/// `crates/mbbs/tests/evidence_manifest.rs`'s `UNCLASSIFIED_CEILING`, which
/// `tools/cargo-serial.sh test -p mbbs --test evidence_manifest` fails loudly
/// if this table's count ever rises above. This number went stale once
/// already, by exactly two hundred and two.
fn routines<A: Abi>() -> Vec<(&'static str, &'static str, Shim<A>, Cleans, Evidence)> {
    vec![
        // Strings, numbers and the print buffer.
        (MAJORBBS, "spr", text::spr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sprintf", text::sprintf, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "vsprintf", text::vsprintf, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "prf", text::prf, Cleans::Caller, Evidence::Unclassified),

        // --- Symbols surveyed as missing across the module corpus and
        // --- implemented 2026-08-14. Each cites its vendor source at its own
        // --- definition; see docs/2026-08-12-module-import-gaps.md for the
        // --- census that ranked them.
        (MAJORBBS, "outmlt", output::outmlt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "clrmlt", output::clrmlt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "prat", output::prat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "locate", output::locate, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "curcurx", output::curcurx, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "curcury", output::curcury, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "prfmlt", mlt::prfmlt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "pmlt", mlt::pmlt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "getmsg", mlt::getmsg, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tfsopn", tfscan::tfsopn, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tfsrdl", tfscan::tfsrdl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tfspfx", tfscan::tfspfx, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tfsabt", tfscan::tfsabt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "injacr", echo::injacr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "hdlinp", echo::hdlinp, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fwrite", crt::fwrite, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "itoa", crt::itoa, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "samend", crt::samend, Cleans::Caller, Evidence::Unclassified),
        // `__LOCALECONVENTION` keeps ONE leading underscore: `exports::c_name`
        // strips exactly one, and stripping greedily would merge `_OLDSEND`
        // with `__OLDSEND`, which are two different symbols.
        (MAJORBBS, "_localeconvention", crt::localeconvention, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfsthn", misc::dfsthn, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "hrtval", misc::hrtval, Cleans::Caller, Evidence::Unclassified),
        // Both MajorMUD NT builds and Rose 3.0NT import hrtval from GALGSBL,
        // not MAJORBBS -- see `hrtval_resolves_from_galgsbl_as_well_as_majorbbs`.
        // Same body, genuinely two libraries' export tables, not a
        // `canonical_dll` alias: only this one symbol is exported from both.
        (GALGSBL, "hrtval", misc::hrtval, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "msgscan", misc::msgscan, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "byenow", misc::byenow, Cleans::Caller, Evidence::Unclassified),
        // GALME ordinal 30, not a MAJORBBS symbol -- see `exports.rs`'s own
        // `galme_ordinal_30_is_the_messaging_engines_6x_compatibility_entry`.
        // `GALMSG` ordinal 30 is `_OLDSEND` -- ONE underscore, where GALME's
        // ordinal 30 is `__OLDSEND` with two. `exports::c_name` strips exactly
        // one, so they normalise to DIFFERENT host names (`oldsend` and
        // `_oldsend`) and need separate rows. They are two symbols in two
        // libraries, not one symbol seen twice; The Rose 2.0 imports the
        // GALMSG one. Both refuse for the same reason -- neither the Messaging
        // Engine nor its 6.x compatibility entry exists here.
        (GALMSG, "oldsend", misc::oldsend, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "initask", task::initask, Cleans::Caller, Evidence::Unclassified),

        // The `dfa*` facade -- the 32-bit Btrieve API. Registered under
        // MAJORBBS because `canonical_dll` already aliases `WGSERVER.EXE` to
        // it (see this file's own doc comment): Worldgroup NT's PE modules
        // import the identical symbols from a differently-NAMED container, and
        // one alias covers the whole surface.
        //
        // The host name is lowercased by `exports::c_name`, so `_dfaSetBlk`
        // arrives here as `dfasetblk`.
        (MAJORBBS, "dfaopen", dfa::dfaOpen, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaclose", dfa::dfaClose, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfasetblk", dfa::dfaSetBlk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfarstblk", dfa::dfaRstBlk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaquery", dfa::dfaQuery, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaquerynp", dfa::dfaQueryNP, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfagetlock", dfa::dfaGetLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaacqlock", dfa::dfaAcqLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaacqnplock", dfa::dfaAcqNPLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaabs", dfa::dfaAbs, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaacqabslock", dfa::dfaAcqAbsLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfagetabslock", dfa::dfaGetAbsLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfasteplock", dfa::dfaStepLock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfainsertv", dfa::dfaInsertV, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfainsert", dfa::dfaInsert, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfainsertdup", dfa::dfaInsertDup, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaupdatev", dfa::dfaUpdateV, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaupdate", dfa::dfaUpdate, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaupdatedup", dfa::dfaUpdateDup, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfadelete", dfa::dfaDelete, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfamode", dfa::dfaMode, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfabegtrans", dfa::dfaBegTrans, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaendtrans", dfa::dfaEndTrans, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaabttrans", dfa::dfaAbtTrans, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfacountrec", dfa::dfaCountRec, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfareclen", dfa::dfaRecLen, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfastat", dfa::dfaStat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfaunlock", dfa::dfaUnlock, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfawaslocked", dfa::dfaWasLocked, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfalastlen", dfa::dfaLastLen, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfavirgin", dfa::dfaVirgin, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfacreate", dfa::dfaCreate, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dfacreatespec", dfa::dfaCreateSpec, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "bgncnc", cnc::bgncnc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "endcnc", cnc::endcnc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cncchr", cnc::cncchr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cncall", cnc::cncall, Cleans::Caller, Evidence::Unclassified),
        // `dftinj` is `injoth`'s fallback, and its body was already inline
        // there. Registering it exposes the entry point; `injoth` now calls
        // the same core, so there is one implementation.
        (MAJORBBS, "dftinj", cnc::dftinj, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        // The rest of `CNCUTL.C`'s family, Phase 2 Task 2.2. Six the corpus
        // imports, and three -- `cnclon`, `cncsig`, `isuidc` -- that it does
        // not: they are called by the six, and a symbol is implemented here
        // because it exists in the API, not because something asked.
        //
        // `Cleans::Caller` throughout, and not by copying the neighbours:
        // every one is a plain cdecl C routine in Galacticomm's own source
        // with no `pascal` qualifier, and eight of the nine take no arguments
        // at all, so there is nothing on the frame for either party to pop.
        (MAJORBBS, "cncint", cnc::cncint, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cnclon", cnc::cnclon, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cncuid", cnc::cncuid, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cncsig", cnc::cncsig, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cncyesno", cnc::cncyesno, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cncwrd", cnc::cncwrd, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "cncnum", cnc::cncnum, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        (MAJORBBS, "morcnc", cnc::morcnc, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/CNCUTL.C")),
        // `isuidc` is GCOMM.LIB's, not the server's -- its own file, and the
        // `SRC/` generation rather than the `VCPROJ/` one the manifest also
        // carries a row for.
        (MAJORBBS, "isuidc", cnc::isuidc, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/ISUIDC.C")),
        (MAJORBBS, "onsys", cnc::onsys, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strupr", cnc::strupr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "injoth", cnc::injoth, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "vdaoff", vda::vdaoff, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuoba", vda::btuoba, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuinp", vda::btuinp, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btupmt", vda::btupmt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "mkdir", ftf::mkdir, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stpans", ftf::stpans, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "farmalloc", ftf::farmalloc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dcdate", ftf::dcdate, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ftgnew", ftf::ftgnew, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ftgsbm", ftf::ftgsbm, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dedcrd", credit::dedcrd, Cleans::Caller, Evidence::Unclassified),
        // `ACCOUNT.C`'s current-user deduction, Phase 2 Task 2.4. `rdedcrd`
        // is `dedcrd` with `real` set; both answer yes, because this host
        // keeps no balance for either to move -- see `shims::credit::YES`.
        (MAJORBBS, "rdedcrd", credit::rdedcrd, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/ACCOUNT.C")),
        (MAJORBBS, "tstcrd", credit::tstcrd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "condex", credit::condex, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sscanf", credit::sscanf, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "memset", credit::memset, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "intdos", credit::intdos, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "getbtv", btrieve::getbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "obtbtv", btrieve::obtbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "anpbtv", btrieve::anpbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "gabbtv", btrieve::gabbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stpbtv", btrieve::stpbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "updbtv", btrieve::updbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "upvbtv", btrieve::upvbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "insbtv", btrieve::insbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stdmchk", gcsp::stdmchk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rejectreq", gcsp::rejectreq, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rsp2read", gcsp::rsp2read, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rsp2write", gcsp::rsp2write, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "senddpk", gcsp::senddpk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cnvs2d", gcsp::cnvs2d, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stp4cs", gcsp::stp4cs, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "clrprf", text::clrprf, Cleans::Caller, Evidence::Unclassified),
        // `MAJORBBS.C`'s input/text pair, Phase 2 Task 2.6.
        (MAJORBBS, "clrinp", text::clrinp, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        // `stansi` syncs GSBL's own ANSI toggle from usracc.ansifl. This
        // host has no second toggle -- `channel_ansi_mem` reads the account
        // live on every output -- so the body is empty and complete.
        (MAJORBBS, "stansi", text::stansi, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "xltctls", text::xltctls, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "stzcpy", text::stzcpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stlcpy", text::stlcpy, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/STLCPY.C")),
        (MAJORBBS, "stzcat", text::stzcat, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/STZCPY.C")),
        (MAJORBBS, "strcpy", text::strcpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strlen", text::strlen, Cleans::Caller, Evidence::Unclassified),
        // Borland's own, re-exported by MAJORBBS like every other C-runtime
        // routine in this table. Evidence::Standard: ISO C settles the
        // semantics and the crate already has each one's sibling to follow --
        // strupr for strlwr, strcmp/stricmp for the two strn*cmp, atol for
        // strtol.
        (MAJORBBS, "strlwr", text::strlwr, Cleans::Caller, Evidence::Standard),
        (MAJORBBS, "strncmp", text::strncmp, Cleans::Caller, Evidence::Standard),
        (MAJORBBS, "strnicmp", text::strnicmp, Cleans::Caller, Evidence::Standard),
        (MAJORBBS, "strtol", text::strtol, Cleans::Caller, Evidence::Standard),
        (MAJORBBS, "rmvwht", text::rmvwht, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "skpwht", text::skpwht, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "skpwrd", text::skpwrd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "depad", text::depad, Cleans::Caller, Evidence::Unclassified),
        // `SIGNUP.C`'s handle-making helpers, Phase 2 Task 2.3. Four the
        // corpus imports, and `isuplo`, which it does not -- `zonkhl` calls
        // it, `MAJORBBS.H:985` declares it and every oracle build exports it,
        // so it is implemented on the same terms as `cnclon` and `cncsig`.
        //
        // Here rather than in a file of their own because all five are what
        // this module already is: transformations of a `CHAR *` the caller
        // owns, beside `depad`, which `stripb` is built out of.
        (MAJORBBS, "stripb", text::stripb, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SIGNUP.C")),
        (MAJORBBS, "makhdl", text::makhdl, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SIGNUP.C")),
        (MAJORBBS, "zonkhl", text::zonkhl, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SIGNUP.C")),
        (MAJORBBS, "isuplo", text::isuplo, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SIGNUP.C")),
        (MAJORBBS, "issupc", text::issupc, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SIGNUP.C")),
        (MAJORBBS, "rstrin", text::rstrin, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "parsin", text::parsin, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "atol", text::atol, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "l2as", text::l2as, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ul2as", text::ul2as, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/L2AS.C")),
        (MAJORBBS, "toupper", text::toupper, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tolower", text::tolower, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sameas", text::sameas, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sameto", text::sameto, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "samein", text::samein, Cleans::Caller, Evidence::Unclassified),
        // Implemented in `shims::user` rather than beside its three
        // siblings above: this session's file ownership was `shims::user`/
        // `shims::mod`, not `shims::text`, and `samend` needs nothing
        // `shims::text` has that `crate::strings::sameas` does not already
        // give it directly.
        (MAJORBBS, "strcmp", text::strcmp, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strcat", text::strcat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strncat", text::strncat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strncpy", text::strncpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strchr", text::strchr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strstr", text::strstr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "strtok", text::strtok, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "lastwd", text::lastwd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sortstgs", text::sortstgs, Cleans::Caller, Evidence::Unclassified),
        // Message files, and the options in them.
        (MAJORBBS, "opnmsg", msg::opnmsg, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "clsmsg", msg::clsmsg, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "setmbk", msg::setmbk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rstmbk", msg::rstmbk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stgopt", msg::stgopt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "numopt", msg::numopt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "lngopt", msg::lngopt, Cleans::Caller, Evidence::Unclassified),
        // numopt's base-16 sibling. It reaches the message text through the
        // same read/value pair, not through a rawmsg this task had to add
        // first -- rawmsg is already registered above.
        (MAJORBBS, "hexopt", msg::hexopt, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/MCVAPI.C")),
        (MAJORBBS, "inimsg", msg::inimsg, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/MCVAPI.C")),
        (MAJORBBS, "setcnf", msg::setcnf, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/SETCNF.C")),
        (MAJORBBS, "applyem", msg::applyem, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/SETCNF.C")),
        (MAJORBBS, "dspmsg", msg::dspmsg, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/BBSUTILS.C")),
        // mdfodmd is folded into scnmdf rather than registered beside it:
        // no oracle build exports it, so it is scnmdf's helper here as it is
        // in MDFUTL.C.
        (MAJORBBS, "scnmdf", msg::scnmdf, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/MDFUTL.C")),
        (MAJORBBS, "ynopt", msg::ynopt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "chropt", msg::chropt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "tokopt", msg::tokopt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "prfmsg", msg::prfmsg, Cleans::Caller, Evidence::Unclassified),
        // Memory the module owns, and the leaves that move bytes about.
        // `alctile`/`ptrtile` are not here -- segment tiling has no
        // flat-memory counterpart, see `Abi::native`.
        (MAJORBBS, "alcmem", memory::alcmem, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "alcdup", memory::alcdup, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/ALCDUP.C")),
        // Six files carry a pltile; the galme one is the module-side library
        // the NE corpus links against, and the other five are standalone
        // utilities.
        (MAJORBBS, "pltile", memory::pltile, Cleans::Caller,
         Evidence::VendorBody("SRC/api/galme/galfoman/PROTSTUF.C")),
        (MAJORBBS, "alczer", memory::alczer, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "galfree", memory::galfree, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "farcoreleft", memory::farcoreleft, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "setmem", memory::setmem, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "movmem", memory::movmem, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "memcpy", memory::memcpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "memmove", memory::memmove, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "memcmp", memory::memcmp, Cleans::Caller, Evidence::Unclassified),
        // Streams: the module's own files, read and written.
        (MAJORBBS, "fopen", stream::fopen, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fclose", stream::fclose, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fgets", stream::fgets, Cleans::Caller, Evidence::Unclassified),
        // `GCOMM.H`'s own `fgets` sibling -- implemented in `shims::user`
        // for the same file-ownership reason `samend` is, above.
        (MAJORBBS, "mdfgets", user::mdfgets, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fgetc", stream::fgetc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fputc", stream::fputc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fread", stream::fread, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fprintf", stream::fprintf, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fflush", stream::fflush, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "flushall", stream::flushall, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "unlink", stream::unlink, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "getdtd", stream::getdtd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cntdir", stream::cntdir, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fnd1st", stream::fnd1st, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fndnxt", stream::fndnxt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fseek", stream::fseek, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ftell", stream::ftell, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rewind", stream::rewind, Cleans::Caller, Evidence::Unclassified),
        // The clock, the audit trail, and coming online.
        (MAJORBBS, "access", system::access, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "now", system::now, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "nctime", system::nctime, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ncdate", system::ncdate, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cofdat", system::cofdat, Cleans::Caller, Evidence::Unclassified),
        // `cofdat`'s inverse, and the two other `DNTAPI.C` routines the
        // corpus asks for. The three transitive helpers they use --
        // `addDaysToDate`, `timeDecode`, `validTime` -- are deliberately not
        // here: no oracle build exports any of them, so they are file-local
        // to the vendor and are private Rust helpers here too.
        // The console block. Three different vendor paths, and the manifest
        // checks the (symbol, path) pair rather than the path alone --
        // setwin/rstwin are the NT VIDAPI.C and scblank is the DOS one.
        (MAJORBBS, "setwin", system::setwin, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/wnt/VIDAPI.C")),
        (MAJORBBS, "rstwin", system::rstwin, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/wnt/VIDAPI.C")),
        (MAJORBBS, "scblank", system::scblank, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/dos/VIDAPI.C")),
        (MAJORBBS, "shochl", system::shochl, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/SUMMARY.C")),
        (MAJORBBS, "baudat", system::baudat, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/OPRLOW.C")),
        // No vendor body anywhere -- only call sites -- so this is the
        // measured one. tests/oracle_gate.rs calls the genuine binaries and
        // records what they do; INC/GCOMM.H:140's macro is the wrong
        // generation and is deliberately not cited.
        (MAJORBBS, "sstatr", system::sstatr, Cleans::Caller, Evidence::Oracle),
        // The vendor's own empty bodies on any hosted build: IRPS.C wraps the
        // single statement in each in #if !defined(UNIX) && !defined(GCWINNT).
        (MAJORBBS, "dsairp", system::dsairp, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/IRPS.C")),
        (MAJORBBS, "enairp", system::enairp, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/IRPS.C")),
        // CATASTRO.C rather than CATASTVB.C/CATAWIN.C: those are the Visual
        // Basic and Windows builds of the same routine, and the NE corpus is
        // neither.
        (MAJORBBS, "memcata", system::memcata, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/CATASTRO.C")),
        (MAJORBBS, "datofc", system::datofc, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/DNTAPI.C")),
        (MAJORBBS, "daytoday", system::daytoday, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/DNTAPI.C")),
        (MAJORBBS, "dctime", system::dctime, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/DNTAPI.C")),
        (MAJORBBS, "ncedat", system::ncedat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "today", system::today, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "time", system::time, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "srand", system::srand, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rand", system::rand, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "genrdn", system::genrdn, Cleans::Caller, Evidence::Unclassified),
        // Caller-cleaned, read off the host rather than assumed from its
        // neighbours: lngrnd ends in a bare `retf` (segment 13, offset
        // 0x167) with no immediate, so the module pops its own eight bytes
        // of arguments.
        (MAJORBBS, "lngrnd", system::lngrnd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "gmdnam", system::gmdnam, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "shocst", system::shocst, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rtkick", system::rtkick, Cleans::Caller, Evidence::Unclassified),
        // Task 2.7's real-time pair. `rtihdlr` stores its handler the way
        // `rtkick` above stores its callback, and nothing runs either;
        // `oldbgnedt` forwards to the `bgnedt` editor pointer and refuses.
        (MAJORBBS, "rtihdlr", system::rtihdlr, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "oldbgnedt", system::oldbgnedt, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "begin_polling", user::begin_polling, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stop_polling", user::stop_polling, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdroom", fsd::fsdroom, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdapr", fsd::fsdapr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdnan", fsd::fsdnan, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdord", fsd::fsdord, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdouc", fsd::fsdouc, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/FSDBBS.C")),
        (MAJORBBS, "fsdxan", fsd::fsdxan, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdrft", fsd::fsdrft, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdbkg", fsd::fsdbkg, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdego", fsd::fsdego, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "vfyadn", fsd::vfyadn, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "outprf", fsd::outprf, Cleans::Caller, Evidence::Unclassified),
        // MajorMUD's text and field-conversion helpers. See `shims::mudtext`.
        (MAJORBBS, "profan", mudtext::profan, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "c2bcpy", mudtext::c2bcpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "b2ccpy", mudtext::b2ccpy, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "findtvar", mudtext::findtvar, Cleans::Caller, Evidence::Unclassified),
        // Beside `findtvar` rather than in `text.rs`, because the table it
        // walks is the one `findtvar` walks. `grbtxv` is not registered: it
        // is `xlttxv`'s own helper here, and no oracle build exports it.
        (MAJORBBS, "xlttxv", mudtext::xlttxv, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MENUING.C")),
        // MajorMUD's remaining gameplay and screen helpers. `curcury` and
        // `listing`'s `whndun` half refuse rather than fabricate: this host
        // tracks no cursor row, and a `Shim<A>` is never handed the
        // `&A::Module` every callback-into-module mechanism needs. See
        // `shims::mudmisc`.
        (MAJORBBS, "listing", mudmisc::listing, Cleans::Caller, Evidence::Unclassified),
        // Galacticomm's text-file scanner. Reachable and MajorMUD-exclusive
        // (zero sites in Lunatix/Tele-Arena/The Rose), which is the opposite
        // signature from `dfsthn`'s shared boilerplate. `tfsopn`/`tfsrdl`
        // refuse loudly pending cross-call scan state on `Host`; see
        // `docs/2026-08-14-tfscan-reachability.md`.
        // The DOS/Phar Lap/GALME environment imports. `dossetvec` and
        // `doscreatedsalias` are documented no-ops inside an unreachable
        // crt0 trampoline; `oldsend` refuses, because answering TRUE would
        // claim mail was sent that this host silently discarded. See
        // `docs/2026-08-14-dos-imports-reachability.md`.
        (DOSCALLS, "dossetvec", dosenv::dossetvec, Cleans::Callee(10), Evidence::Unclassified),
        (PHAPI, "doscreatedsalias", dosenv::doscreatedsalias, Cleans::Callee(6), Evidence::Unclassified),
        (GALME, "_oldsend", dosenv::oldsend, Cleans::Caller, Evidence::Unclassified),
        // `shims::gcsp`'s seven GCSPSRV routines. All twelve of their real
        // call sites are provably unreachable on a telnet host
        // (`docs/2026-08-14-gcsp-reachability.md`: the module's `struct
        // agent` read/write vectors, which nothing here ever dispatches to,
        // and `_TELL_USER`'s `ISGCSU`-gated branch, which nothing here ever
        // sets), so every one of the seven answers with a loud, named
        // refusal rather than a body -- the same shape `dfsthn`/`onsysn`
        // already have for the same reason (see those routines' own doc
        // comments). `re/importgaps.py` now reports these seven as served,
        // which is the honest reading of that word: it means this host has
        // a named answer for the symbol, not that the answer is a faithful
        // implementation -- see that script's own module comment.
        //
        // `rsp2read`/`rsp2write`/`senddpk` were the reason these seven
        // stayed unregistered until now: `GCSPSRV.H:153-171` declares all
        // three twice, behind `#ifdef GCV2`, with differing arity (3/3/6
        // arguments under `GCV2`, 4/4/7 under `#else`), and `re/widthscan.py`
        // used to have no opinion on which branch was real -- registering
        // any of the three would have moved it from "unregistered" straight
        // to "ambiguous: disagreeing declarations", a section
        // `crates/mbbs/tests/argument_widths.rs` asserts is always empty.
        // It has an opinion now: `Wg16` is a measured `GCV2` ABI
        // (`crate::abi::Wg16::GCV2`, corroborated by `struct user`'s
        // measured 41-byte stride -- see `crates/mbbs/src/users.rs`), and
        // `re/widthscan.py`'s `strip_dead_code`/`resolve_via_gcv2` now use
        // that fact to pick the `GCV2` branch when (and only when) a name is
        // otherwise genuinely ambiguous. `WCCMMUD.DLL`'s own call sites
        // confirm the pick independently: `re/ne_arity.py`'s measured
        // caller-cleanup for every one of the three -- 5, 4 and 9 words --
        // matches the `GCV2` branch's 3/3/6-argument prototypes exactly
        // (2+1+2, 1+1+2, 1+2+1+2+1+2 words) and does not match the
        // non-`GCV2` branch's 4/4/7 at all.
        (MAJORBBS, "dclvda", system::dclvda, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "register_module", system::register_module, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "globalcmd", system::globalcmd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "register_agent", system::register_agent, Cleans::Caller, Evidence::Unclassified),
        (
            MAJORBBS,
            "register_textvar",
            system::register_textvar,
            Cleans::Caller,
            Evidence::Unclassified,
        ),
        (MAJORBBS, "catastro", system::catastro, Cleans::Caller, Evidence::Unclassified),
        // "Restore screen-length to usracc setting" -- `MAJORBBS.C:3776`
        // (wg1), one import, one call site. See `shims::screen`'s own doc
        // comment for what it does, what it does not, and where its one
        // caller actually leads.
        (MAJORBBS, "rstrxf", screen::rstrxf, Cleans::Caller, Evidence::Unclassified),
        // The current user: the two routines that turn a channel number into
        // the slot it names.
        (MAJORBBS, "curusr", user::curusr, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "uacoff", user::uacoff, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "usroff", user::usroff, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "mnuoff", user::mnuoff, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MENUING.C")),
        // The user-ID cross-reference half of Task 2.6. `clrxrf` is the
        // vendor's own `numxrf == 0` branch and does nothing; `hdluid`
        // presupposes the subsystem and refuses. See their doc comments.
        (MAJORBBS, "clrxrf", user::clrxrf, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        // `paccit` already had a body, registered in `WG32_ROUTINES` alone
        // because only MajorMUD NT was known to import it. HVSTW imports it
        // off the NE side too, so the same shim is registered here rather
        // than a second one written -- see its own doc comment.
        (MAJORBBS, "paccit", user::paccit, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        // Task 2.7's channel/user pair. `usridx` inverts the `channel`
        // table; `rstchn` is a modem reset this host has no hardware for.
        (MAJORBBS, "usridx", user::usridx, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "rstchn", user::rstchn, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "hdluid", user::hdluid, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/MAJORBBS.C")),
        (MAJORBBS, "getin", user::getin, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "haskey", user::haskey, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "hasmkey", user::hasmkey, Cleans::Caller, Evidence::Unclassified),
        // The echo family. "Turn echo on" (`echon`) is `echonu(usrnum)`
        // against the current channel; "turn echo on utility" (`echonu`)
        // also ends any `echsec` secret-echo session still in progress. See
        // `user::echonu`'s own doc comment for why `echtyp[grpnum[usrnum]]`
        // is a constant on this host, where `wid` really lives for a GCV2
        // ABI, and what `btuchi(usrnum,NULL)` collapses to; `user::echsec`'s
        // own doc comment for the other half -- installing the session --
        // and what installing a real `secchi` handler would have added that
        // this host cannot.
        (MAJORBBS, "echon", user::echon, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "echonu", user::echonu, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "echsec", user::echsec, Cleans::Caller, Evidence::Unclassified),
        // The other-user family: scan every channel for a user-id, in a
        // given module state (`instat`) or online at all (`onsysn`), leaving
        // `othusn`/`othusp`/`othuap` pointed at the result -- and `othkey`,
        // which asks that channel's own keys the way `haskey` asks the
        // current one's.
        (MAJORBBS, "instat", user::instat, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "onsysn", user::onsysn, Cleans::Caller, Evidence::Unclassified),
        // `nliniu` counts channels whose `usrcls` is not VACANT. Beside
        // `onsysn` because it shares that field and that gap: this host
        // never advances `usrcls`, so both answer as though nobody is on.
        (MAJORBBS, "nliniu", user::nliniu, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/ACCOUNT.C")),
        (MAJORBBS, "othkey", user::othkey, Cleans::Caller, Evidence::Unclassified),
        // `LOCKNKEY.C`'s remainder, Phase 2 Task 2.5. `gen_haskey` is the
        // general form `haskey`/`othkey` have been calling all along --
        // registering it exposes an entry point rather than adding a second
        // evaluator. `istxvc` is transitive: `keynam` validates with it, no
        // corpus module imports it, and `GCOMM.H:339` declares it.
        //
        // `nkyrec` and `uidkey` refuse. Both are reads or writes of Btrieve
        // files this host does not keep -- see their doc comments; `uidkey`
        // still answers the empty lock, which the vendor resolves before
        // touching a disk.
        (MAJORBBS, "gen_haskey", user::gen_haskey_shim, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/LOCKNKEY.C")),
        (MAJORBBS, "uhskey", user::uhskey, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/LOCKNKEY.C")),
        (MAJORBBS, "uidkey", user::uidkey, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/LOCKNKEY.C")),
        (MAJORBBS, "nkyrec", user::nkyrec, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/LOCKNKEY.C")),
        (MAJORBBS, "keynam", user::keynam, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/LOCKNKEY.C")),
        (MAJORBBS, "istxvc", user::istxvc, Cleans::Caller,
         Evidence::VendorBody("SRC/api/gcommlib/ISTXVC.C")),
        // The default `stsrou` a module gets if it registers none of its
        // own. See `user::dfsthn`'s own doc comment for why its one real
        // branch is unreachable on this host, measured rather than assumed.
        // The multi-user broadcast family's one member LunatiX actually
        // imports -- see `user::clrmlt`'s own doc comment for why the other
        // three (`prfmlt`/`pmlt`/`outmlt`) stay unimplemented.
        // Billing, which this host does not do. Both answer yes;
        // `shims::credits` is where that decision is written down.
        // `Cleans::Caller` is measured -- `re/ne_arity.py` reads
        // `add sp,8` after all three `otstcrd` sites and `add sp,0Ah` after
        // all three `odedcrd` sites, matching `USRACC.H`'s `(int, long,
        // int)` and `(int, long, int, int)` exactly.
        (MAJORBBS, "otstcrd", credits::otstcrd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "odedcrd", credits::odedcrd, Cleans::Caller, Evidence::Unclassified),
        // The rest of `ACCOUNT.C`'s Phase 2 block. `addcrd`/`crdusr` post
        // nothing and answer the online-ness this host can measure;
        // `howbuy` is the vendor's own `pester`-off branch. See each
        // routine's doc comment -- none of the three is a stub, and none
        // refuses.
        (MAJORBBS, "addcrd", credits::addcrd, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/ACCOUNT.C")),
        (MAJORBBS, "crdusr", credits::crdusr, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/ACCOUNT.C")),
        (MAJORBBS, "howbuy", credits::howbuy, Cleans::Caller,
         Evidence::VendorBody("SRC/server/wgserver/ACCOUNT.C")),
        // Borland's own C++ runtime plumbing LunatiX links against from
        // `cw3220mt.DLL`, aliased onto `MAJORBBS` same as everything above --
        // and the one KERNEL32 call that can be served alongside it. See
        // `borland`'s own module doc for what each of these does, why nine
        // of the ten are no-ops, why `abort` is not, and why
        // `GetModuleHandleA`/`GetProcAddress` are deliberately *not* here.
        (MAJORBBS, "_startup", borland::startup, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "_startupd", borland::startupd, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "@_catchcleanup$qv", borland::catch_cleanup, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "_exceptionhandler", borland::exception_handler, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "_errormessage", borland::error_message, Cleans::Caller, Evidence::Unclassified),
        (
            MAJORBBS,
            "@__lockdebuggerdata$qv",
            borland::lock_debugger_data,
            Cleans::Caller,
            Evidence::Unclassified,
        ),
        (
            MAJORBBS,
            "@__unlockdebuggerdata$qv",
            borland::unlock_debugger_data,
            Cleans::Caller,
            Evidence::Unclassified,
        ),
        (
            MAJORBBS,
            "__debuggerdisableterminatecallback",
            borland::debugger_disable_terminate_callback,
            Cleans::Caller,
            Evidence::Unclassified,
        ),
        (MAJORBBS, "_free_heaps", borland::free_heaps, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "abort", borland::abort, Cleans::Caller, Evidence::Unclassified),
        (KERNEL32, "getversion", borland::getversion, Cleans::Caller, Evidence::Unclassified),
        // stdcall, not cdecl -- measured at LunatiX's own call sites
        // (0x41d61d, 0x41d62c: 4 and 8 bytes pushed, neither followed by an
        // `add esp`). `Wg32::resume` services `Cleans::Callee` for exactly
        // this reason; see `borland`'s own module doc comment for why both
        // answer NULL rather than a fabricated handle or address.
        (
            KERNEL32,
            "getmodulehandlea",
            borland::get_module_handle,
            Cleans::Callee(4),
            Evidence::Unclassified,
        ),
        (
            KERNEL32,
            "getprocaddress",
            borland::get_proc_address,
            Cleans::Callee(8),
            Evidence::Unclassified,
        ),
        // Btrieve. Seventeen routines, and the last block to reach this table
        // -- they sat in `WG16_ROUTINES` from the day it was created until
        // the engine behind them became `Btrieve<A>` and `Host<A>`'s own
        // `btrieve` field stopped eliding its parameter. Neither the shims
        // nor the engine were ever 16-bit in substance; a defaulted type
        // parameter on one struct field was holding all seventeen here.
        (MAJORBBS, "omdbtv", btrieve::omdbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "opnbtv", btrieve::opnbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "setbtv", btrieve::setbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rstbtv", btrieve::rstbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "cntrbtv", btrieve::cntrbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "qrybtv", btrieve::qrybtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "qnpbtv", btrieve::qnpbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "obtbtvl", btrieve::obtbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stpbtvl", btrieve::stpbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "absbtv", btrieve::absbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "aabbtv", btrieve::aabbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "gabbtvl", btrieve::gabbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dinsbtv", btrieve::dinsbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "dupdbtv", btrieve::dupdbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "invbtv", btrieve::invbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "delbtv", btrieve::delbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "clsbtv", btrieve::clsbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "clsbb", btrieve::clsbb, Cleans::Caller, Evidence::Unclassified),
        // --- Track B, 2026-08-15: the rest of BTVSTF.H's declared surface ---
        // Twelve wrappers, taking this layer from 26 of 36 to all 36. Their
        // only surviving implementation is `PLBTVSTF.C`, the Phar Lap BTVSTF
        // layer -- NOT MajorBBS 5.11's `BTVSTF.C`, which predates all twelve,
        // and not `re/wg33src`, which carries no BTVSTF layer at all.
        //
        // Eight of the twelve are absent from the MajorBBS 6.25 copy and come
        // from Worldgroup 1.0: the transaction pair, every locking variant,
        // and `wslbtv`. Locking and explicit transactions are post-6.25
        // additions to this layer, which is worth knowing before citing "the
        // v6-era body" for any of them.
        //
        // `sttbtv` has no body in any of the three generations -- declared at
        // `BTVSTF.H:169` and implemented nowhere recovered. It stores its
        // argument and is wired to nothing, because no consumer exists in
        // `archive/` or `re/` to wire it to. That uncertainty is recorded in
        // its own doc comment rather than papered over.
        (MAJORBBS, "bxabtv", btrieve::bxabtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "exabtv", btrieve::exabtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "getbtvl", btrieve::getbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "anpbtvl", btrieve::anpbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "anpbtvlk", btrieve::anpbtvlk, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "aabbtvl", btrieve::aabbtvl, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "unlbtv", btrieve::unlbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sttbtv", btrieve::sttbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rlenbtv", btrieve::rlenbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "wslbtv", btrieve::wslbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "llnbtv", btrieve::llnbtv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "crtbtv", btrieve::crtbtv, Cleans::Caller, Evidence::Unclassified),
        // The GSBL terminal layer. Fourteen routines, seventy-seven call
        // sites, none of them reached by initialisation, plus three more
        // (`btuhpk`/`btupbc`/`btucpc`) registered even though `WCCMMUD.DLL`
        // imports none of them -- `rstrxf`, above, is their one caller in
        // this host, and calls each directly rather than through this
        // table. They are registered anyway because they are ordinary
        // importable GSBL routines and this is where every other one
        // lives, in case a future module asks.
        (GALGSBL, "btutsw", gsbl::btutsw, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuxct", gsbl::btuxct, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuxnf", gsbl::btuxnf, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuxmt", gsbl::btuxmt, Cleans::Caller, Evidence::Unclassified),
        // Not one of the fourteen above -- `WCCMMUD.DLL` never imports it.
        // `LUNATIX.DLL` does, seven times, and is why `GALGSBL.dll!_btuxmn`
        // was the seventh name Task 5's alias could not serve. See
        // `gsbl::btuxmn`'s own doc comment for the prototype, the call-site
        // arity check, and the one property it does not yet reproduce.
        (GALGSBL, "btuxmn", gsbl::btuxmn, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuoes", gsbl::btuoes, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuclo", gsbl::btuclo, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btulok", gsbl::btulok, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btucli", gsbl::btucli, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuinj", gsbl::btuinj, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btutrg", gsbl::btutrg, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuech", gsbl::btuech, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btumil", gsbl::btumil, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuibw", gsbl::btuibw, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuica", gsbl::btuica, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuhpk", gsbl::btuhpk, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btupbc", gsbl::btupbc, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btucpc", gsbl::btucpc, Cleans::Caller, Evidence::Unclassified),
        // --- Track A, 2026-08-15: closing the ten-build import survey ---
        // The GALGSBL character-interrupt family. Ordinals confirmed against
        // the vendor's own `re/wg33src/LIB/GALGSBL.DEF` (3, 4, 5, 8, 52, 64)
        // rather than a reconstructed map. `btuchi` refuses: its callback
        // replaces the character-translation stage of every later character,
        // and this host's input path has no equivalent of the `tasks`/
        // `Host::prctask` sweep that lets `initask` defer invocation.
        (GALGSBL, "btuche", gsbl::btuche, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuchi", gsbl::btuchi, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btuclc", gsbl::btuclc, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btucls", gsbl::btucls, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "btutru", gsbl::btutru, Cleans::Caller, Evidence::Unclassified),
        (GALGSBL, "chiout", gsbl::chiout, Cleans::Caller, Evidence::Unclassified),
        // Allocation. `alcblok`/`ptrblok`/`freblok` are NOT here -- the two
        // vendor branches have structurally different headers, so they are
        // ABI-concrete in both native tables below.
        (MAJORBBS, "galmalloc", memory::galmalloc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "sizmem", memory::sizmem, Cleans::Caller, Evidence::Unclassified),
        // Borland's runtime, re-exported through MAJORBBS. `_fgetc` points at
        // `stream::fgetc` deliberately: Borland's `_fgetc` is
        // `{ ++fp->level; return fgetc(fp); }`, observably the same routine,
        // and `crt` carried a dead duplicate body that has been deleted. It is
        // a *different symbol* from the already-registered `fgetc` because this
        // host strips exactly one leading underscore -- stripping greedily
        // would merge `_OLDSEND` and `__OLDSEND`, which are two real symbols.
        (MAJORBBS, "_fgetc", stream::fgetc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "stricmp", crt::stricmp, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ultoa", crt::ultoa, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "ungetc", crt::ungetc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rename", crt::rename, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "getenv", crt::getenv, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "gettime", crt::gettime, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "_doserror", crt::doserror, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "__errno", crt::errno, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "_lrand", crt::lrand, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "searchpath", crt::searchpath, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "setmode", crt::setmode, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "read", crt::read, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "write", crt::write, Cleans::Caller, Evidence::Unclassified),
        // `mfytask` completes the pair `initask` opened: a module could
        // register a task and then fail modifying it.
        (MAJORBBS, "mfytask", task::mfytask, Cleans::Caller, Evidence::Unclassified),
        // `.MSG` access. Both of these were previously "absent on purpose"
        // because `WCCMMUD.DLL` does not import them -- the reasoning the
        // scope rule suspends. The Rose imports `getasc` at six sites.
        (MAJORBBS, "getasc", msg::getasc, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "rawmsg", msg::rawmsg, Cleans::Caller, Evidence::Unclassified),
        // FSD. `fsdfxt` deliberately does NOT refuse an out-of-range field:
        // it is the vendor's own guarded wrapper around the unguarded
        // `fsdnan`, and `buffer[0]='\0'` is its documented answer.
        (MAJORBBS, "fsdfxt", fsd::fsdfxt, Cleans::Caller, Evidence::Unclassified),
        (MAJORBBS, "fsdrhd", fsd::fsdrhd, Cleans::Caller, Evidence::Unclassified),
        // Five fixed arguments, measured: the wg1 and WG3.3 headers and
        // `ACCOUNT.C` all agree, and Rose's own call site cleans 7 words.
        (MAJORBBS, "swtcls", user::swtcls, Cleans::Caller, Evidence::Unclassified),
        // Runtime name resolution: one shared resolver, two ABI-native faces.
        // Both answer library presence truthfully and report "not found" for a
        // symbol address, which is the real API's own contract -- thunk indices
        // are minted only at module load.
        (DOSCALLS, "dosgetmodhandle", dosenv::dosgetmodhandle, Cleans::Callee(8), Evidence::Unclassified),
        (DOSCALLS, "dosgetprocaddr", dosenv::dosgetprocaddr, Cleans::Callee(10), Evidence::Unclassified),
        (KERNEL32, "loadlibrarya", borland::loadlibrarya, Cleans::Callee(4), Evidence::Unclassified),
        (KERNEL32, "freelibrary", borland::freelibrary, Cleans::Callee(4), Evidence::Unclassified),
        // The last unresolved import across all ten surveyed builds. Answers
        // GMEERR because that is what the vendor's own body answers when the
        // messaging engine is not running, which for this host is always --
        // see `dosenv::simpsnd`, and note it is NOT zero, which would mean
        // "still processing" and spin the caller.
        (GALME, "simpsnd", dosenv::simpsnd, Cleans::Caller, Evidence::Unclassified),
    ]
}

/// The second door: routines that answer only for `Wg16`. See
/// [`Abi::native`]'s own doc comment for why these twenty-seven are here and
/// not in [`routines`].
///
/// A `const`, unlike [`routines`], because nothing here is generic over `A`
/// -- every entry is already `Shim<Wg16>`, so there is no per-instantiation
/// table to build.
const WG16_ROUTINES: &[(&str, &str, Shim<Wg16>, Cleans, Evidence)] = &[
    // Segment tiling: no flat-memory counterpart. Never given a `Call`-taking
    // body (see `shims::memory`'s own doc comment on `alctile`), so these are
    // non-capturing closures adapting `Wg16Shim` into `Shim<Wg16>` -- a
    // reborrow of `call.cpu` (`Call<Wg16>::cpu` is `&mut mbbs_machine::m16::Machine`,
    // since `Wg16::Cpu = mbbs_machine::m16::Machine`) and the reverse `Ret` conversion
    // `impl From<mbbs_machine::m16::Ret> for abi::Ret<Wg16>` supplies.
    (MAJORBBS, "alctile", memory::alctile, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "ptrtile", memory::ptrtile, Cleans::Caller, Evidence::Unclassified),
    // The compiler's own runtime, which this host exports because the real
    // one did. Same adapter shape as the tiling pair above. These four pop
    // their own arguments -- see `runtime`.
    (MAJORBBS, "f_ldiv@", runtime::f_ldiv, Cleans::Callee(runtime::OPERANDS), Evidence::Unclassified),
    (MAJORBBS, "f_lmod@", runtime::f_lmod, Cleans::Callee(runtime::OPERANDS), Evidence::Unclassified),
    (MAJORBBS, "f_ludiv@", runtime::f_ludiv, Cleans::Callee(runtime::OPERANDS), Evidence::Unclassified),
    (MAJORBBS, "f_lumod@", runtime::f_lumod, Cleans::Callee(runtime::OPERANDS), Evidence::Unclassified),
    // The rest of that runtime, and it does not share one convention. These
    // three take their operands in registers and put nothing on the stack,
    // so there is nothing for either side to clean.
    (MAJORBBS, "f_lxmul@", runtime::f_lxmul, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "f_lxlsh@", runtime::f_lxlsh, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "f_lxursh@", runtime::f_lxursh, Cleans::Caller, Evidence::Unclassified),
    // And this one is a struct copy: two far pointers on the stack, which it
    // pops, and the length in `CX`.
    (MAJORBBS, "f_scopy@", runtime::f_scopy, Cleans::Callee(runtime::POINTERS), Evidence::Unclassified),
    // `f_spush@` looks like `f_scopy@`'s sibling and is NOT callee-cleaned.
    // Measured, not assumed: all six of The Rose's call sites disassemble to
    // `lea ax,[bp+disp]; mov dx,ss; mov cx,<len>; call far F_SPUSH@` -- nothing
    // pushed, no `add sp` after. That is the register-only shape of
    // `f_lxmul@`/`f_lxlsh@`/`f_lxursh@` above, not the stack-argument shape of
    // the four division helpers. Getting this wrong does not crash; it leaves
    // arguments on the module's own stack and shifts every later frame.
    (MAJORBBS, "f_spush@", runtime::f_spush, Cleans::Caller, Evidence::Unclassified),
    // The block allocator, `Wg16` half. ABI-concrete rather than generic
    // because the vendor's two branches are structurally different, not just
    // reordered: GCDOS chains globs through a `segarray` of pointers, the flat
    // branch stores data inline. Both headers here are byte-identical to
    // `ALCBLOK.C`'s own.
    (MAJORBBS, "alcblok", memory::alcblok, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "ptrblok", memory::ptrblok, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "freblok", memory::freblok, Cleans::Caller, Evidence::Unclassified),
    // Screen and per-user state that only the 16-bit builds import. `extoff`
    // additionally *needs* `Wg16`: it reaches the GCV2-only `extusr` table.
    (MAJORBBS, "explode", screen::explode, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "iniscn", screen::iniscn, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "extoff", user::extoff, Cleans::Caller, Evidence::Unclassified),
];

/// [`Abi::native`]'s `Wg16` half: a lookup into [`WG16_ROUTINES`], the table
/// itself living here (alongside [`routines`], `ABSOLUTES` and `GLOBALS`)
/// rather than in `crates/mbbs/src/abi.rs`, so that file states only that
/// the door exists and not what is behind it.
pub(crate) fn wg16_native(dll: &str, symbol: &str) -> Option<(Shim<Wg16>, Cleans)> {
    WG16_ROUTINES
        .iter()
        .find(|(d, n, _, _, _)| *d == dll && *n == symbol)
        .map(|(_, _, shim, cleans, _)| (*shim, *cleans))
}

/// The `Wg32` half of the same idea: routines that cannot be generic over
/// `A` because their answer comes from somewhere only the 32-bit machine
/// has.
///
/// One entry so far, and it is the same reason [`WG16_ROUTINES`] exists at
/// all. `__ftol` takes its argument in the x87 register stack rather than in
/// the call frame, so its shim reads
/// [`take_st0`](mbbs_machine::m32::Machine::take_st0) -- a method on the flat
/// 32-bit machine, with no counterpart on the segmented one and no accessor
/// on [`Abi`]. Making it generic would mean inventing an `Abi` method that
/// exactly one ABI could ever answer.
///
/// The key is `_ftol`, with **one** leading underscore, not `ftol`.
/// [`crate::exports::c_name`] strips exactly one, so the module's
/// `__ftol` arrives here as `_ftol` -- `borland.rs`'s own test asserts that
/// mapping rather than leaving it to be rediscovered.
///
/// `Cleans::Caller` because no call site pushes a stack argument at all: the
/// operand is on the FPU stack, and all thirteen of LunatiX's call sites are
/// preceded by `fld`/`fild`/`fmul` with nothing pushed.
const WG32_ROUTINES: &[(&str, &str, Shim<crate::abi::Wg32>, Cleans, Evidence)] = &[
    (MAJORBBS, "_ftol", ftol::ftol, Cleans::Caller, Evidence::Unclassified),
    // The block allocator, `Wg32` half. Same C export names as the `Wg16`
    // entries in `WG16_ROUTINES` -- this is deliberate, not the duplicate
    // registration `6d8af77` cleaned up. One symbol, two ABI-concrete bodies,
    // reached through `Abi::native`, exactly as `wg16_native`/`wg32_native`
    // already dispatch. The vendor's flat branch is a single inline
    // allocation with `size` at offset 0 and element 0 at +8; this matches it
    // byte for byte and adds the `qty` the vendor omits, in the six header
    // bytes `alczer` already zeroes, so the bounds check the flat branch
    // structurally cannot have costs no compatibility.
    (MAJORBBS, "alcblok", memory::alcblok32, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "ptrblok", memory::ptrblok32, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "freblok", memory::freblok32, Cleans::Caller, Evidence::Unclassified),
    // WGNT host services. Only the PE32 builds import these -- MajorMUD NT
    // for the first five, Rose 3.0NT for the rest.
    (MAJORBBS, "getfiletm", system::getfiletm, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "paccit", user::paccit, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "samepatu", user::samepatu, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "vtmsend", system::vtmsend, Cleans::Caller, Evidence::Unclassified),
    (MAJORBBS, "vtmsndok", system::vtmsndok, Cleans::Caller, Evidence::Unclassified),
];

/// [`Abi::native`]'s `Wg32` half. See [`wg16_native`], which this mirrors.
pub(crate) fn wg32_native(dll: &str, symbol: &str) -> Option<(Shim<crate::abi::Wg32>, Cleans)> {
    WG32_ROUTINES
        .iter()
        .find(|(d, n, _, _, _)| *d == dll && *n == symbol)
        .map(|(_, _, shim, cleans, _)| (*shim, *cleans))
}

/// Every registration's `(dll, name, evidence)`, across all three tables.
///
/// For `crates/mbbs/tests/evidence_manifest.rs`. Built against `Wg16` because
/// the `Evidence` of a registration does not vary by ABI -- the generic table
/// is the same rows either way, and the two ABI-concrete tables are unioned
/// in so nothing is invisible to the audit.
pub fn evidence_census() -> Vec<(&'static str, &'static str, evidence::Evidence)> {
    let mut out: Vec<_> =
        routines::<Wg16>().into_iter().map(|(dll, name, _, _, ev)| (dll, name, ev)).collect();
    out.extend(WG16_ROUTINES.iter().map(|(dll, name, _, _, ev)| (*dll, *name, *ev)));
    out.extend(WG32_ROUTINES.iter().map(|(dll, name, _, _, ev)| (*dll, *name, *ev)));
    out
}

/// Every constant the host exports.
///
/// Only one so far. `DOSCALLS.135` is the huge shift: how far to shift a count
/// of 64 KiB chunks to get the matching selector increment. Thirteen of
/// `WCCMMUD.DLL`'s fixups resolve it straight into the immediate of a
/// `mov $x, %cx` that is followed by a `shl`, which is Borland's huge-pointer
/// normalisation and is what identifies it.
///
/// [`SELECTOR_STEP`](mbbs_machine::m16::SELECTOR_STEP) is the answer, expressed as the
/// shift the module wants: consecutive LDT entries are eight apart, so a count
/// of chunks becomes a selector delta by shifting left three.
///
/// **This is only true once a huge object's chunks occupy consecutive LDT
/// entries**, which was an open question when the constant went in and is no
/// longer: [`alloc_tiled`](mbbs_machine::m16::Machine::alloc_tiled) reserves a region's
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
    mbbs_machine::m16::SELECTOR_STEP.ilog2() as u16,
)];

/// The library name a 32-bit PE import table names the game-host API by,
/// mapped onto the name every table in this file already keys it as.
///
/// Measured (`docs/plans/2026-08-12-abi-border-implementation.md`, Task 15's
/// unstated dependency, and confirmed here by the round-trip test this
/// function exists for): 16-bit MajorBBS modules import the game API from a
/// DLL/segment named `MAJORBBS` (`crate::exports::MAJORBBS`, and every entry
/// in [`routines`]/[`WG16_ROUTINES`]), but Worldgroup NT's PE modules import
/// the *identical* symbols from `WGSERVER.EXE` -- confirmed against the real
/// DLL with `objdump -p` (`WGSERVER.EXE!_l2as`). The API renamed at the file
/// level when Worldgroup moved off segmented DOS binaries; the dispatch
/// table underneath did not, so one alias -- not a per-symbol rename -- is
/// the whole gap. `_l2as`'s leading underscore is unrelated and already
/// handled: `exports::c_name` strips it before a symbol name ever reaches
/// this function, uniformly for both container formats.
///
/// # The second alias: `cw3220mt.DLL`
///
/// Real data asked, and this is what it said. `LUNATIX.DLL` imports 37
/// symbols from `cw3220mt.DLL` -- Borland C++ 5.x's 32-bit runtime -- and
/// seventeen of them are C library routines this table already serves:
/// `strcpy`, `fopen`, `sprintf`, `toupper` and the rest. They are in the
/// `MAJORBBS` table for a historical reason, not an arbitrary one: 16-bit
/// modules got their C library *from* `MAJORBBS.DLL`, which re-exported
/// Borland's 16-bit runtime. Worldgroup NT links the same routines from
/// Borland's own DLL instead. Same functions, same prototypes, different
/// file -- which is exactly the shape `WGSERVER.EXE` already had.
///
/// The twenty that are not served stay unserved: aliasing maps a library
/// name, it does not invent entries, so `cw3220mt.DLL!_ftol` is
/// [`Entry::Unimplemented`] before and after. `crates/mbbs/tests/lunatix.rs`
/// pins exactly which, and this alias shrank that list by seventeen.
///
/// **The widths behind it had to be fixed first.** Every one of those
/// seventeen was written and tested only against `Wg16`, and six of them
/// read a C `int` through `as u16`/`as i16` -- `Wg16`'s width hard-coded.
/// Aliasing before fixing them would have routed a 32-bit module into
/// `toupper` that cannot return `EOF` and `fread` that silently short-reads.
/// See those routines' own doc comments.
///
/// # The third alias: `GALGSBL.dll`
///
/// This paragraph used to say the opposite, and the wrong version was
/// load-bearing: it is why the alias was not added, which is why this stage's
/// terminal I/O looked bigger than it was. What it said was that
/// `GALGSBL.dll`'s seven `btu*` imports "are genuinely unserved rather than
/// served under another name, and an alias would only move where they fail."
///
/// Six of the seven were already served. `btuclo`, `btuinj`, `btumil`,
/// `btuoes` and `btuxnf` are entries in [`routines`] keyed `GALGSBL`, and
/// `bturno` is a host global in `crate::globals`. The only thing between a PE
/// module and all six was that `crate::exports::GALGSBL` is the bare
/// `"GALGSBL"` a 16-bit NE segment is named, while a PE import directory
/// spells the same library `"GALGSBL.dll"`. Exactly the `WGSERVER.EXE`
/// situation, one generation later and one library over.
///
/// The seventh, `btuxmn`, was genuinely absent when this paragraph was
/// written -- aliasing maps a library name, it does not invent entries, and
/// there was no entry to map onto. It is implemented now
/// ([`gsbl::btuxmn`], Task 7), so as of this alias all seven `btu*` imports
/// are served. Kept as a footnote rather than deleted: it is the reason this
/// alias shipped one commit ahead of full coverage instead of waiting for it.

/// Still a list of named aliases, not a general suffix-stripping rule.
/// Case-insensitive because PE import directory names are conventionally
/// upper-cased but nothing in the format requires it.
fn canonical_dll(dll: &str) -> &str {
    const ALIASES: &[(&str, &str)] = &[
        ("WGSERVER.EXE", MAJORBBS),
        ("cw3220mt.DLL", MAJORBBS),
        ("GALGSBL.dll", GALGSBL),
        // Same situation as `GALGSBL.dll` directly above, one library over,
        // found 2026-08-15. Both 32-bit builds import `GALME.dll!_simpsnd`
        // while this host registers GALME's routines under the bare
        // `"GALME"` an NE segment is named -- so without this alias the
        // lookup misses a routine that exists, exactly as it did for
        // `hrtval` under GALGSBL. Nothing else is currently imported from
        // GALME by a PE build, but `_oldsend` would have the same problem
        // the moment one did.
        ("GALME.dll", GALME),
    ];
    ALIASES
        .iter()
        .find(|(from, _)| dll.eq_ignore_ascii_case(from))
        .map_or(dll, |(_, to)| to)
}

/// A C `int` argument, sign-extended from `A`'s own width to `i32`.
///
/// [`Call::int`](crate::abi::Call::int) already reads exactly
/// [`Abi::INT_WIDTH`] bytes and hands back an `A::Int`, so widening it to
/// `u32` is lossless -- but it is *zero*-extended, and a C `int` is signed.
/// Under `Wg16` a `-1` arrives as `0x0000FFFF`; under `Wg32` as
/// `0xFFFFFFFF`. Neither is `-1` as an `i32` until the sign is put back at
/// the right width, which is what this does.
///
/// # Why a helper and not `as i16`
///
/// `as i16` was the idiom throughout this module, and it is `Wg16`'s answer
/// hard-coded. It gets the sign right for a 2-byte `int` and silently
/// mangles a 4-byte one: `fgets(buf, 40000, f)` under `Wg32` became a
/// *negative* length and was refused, and `70000` became `4464`. There is no
/// unsigned counterpart here because none is needed -- an `unsigned`
/// argument is already correct as `Into::<u32>::into(call.int())`, since
/// zero-extension from `A`'s width is exactly what that does.
pub(crate) fn sign_extend<A: Abi>(raw: u32) -> i32 {
    // `INT_WIDTH` is 2 or 4, so `bits` is 16 or 0 -- both in range for a
    // shift, and the 0 case is the identity it should be.
    let bits = 32 - A::INT_WIDTH as u32 * 8;
    ((raw << bits) as i32) >> bits
}

/// What the host knows about a symbol, for `A`.
///
/// `symbol` is the C name when the export tables have one and `#<ordinal>` when
/// they do not, which is how a DLL with no table of its own is still addressed
/// by something stable.
///
/// Checks, in order: the shared table (every routine with a generic core),
/// the constants, the globals, and finally [`Abi::native`] -- `A`'s own door,
/// for the routines that answer only for it. A symbol nothing above answers
/// is [`Entry::Unimplemented`], exactly as it always has been; an `Abi` whose
/// `native` returns `None` for everything (`Wg32`, today) walks the same
/// already-tested path a genuinely unimplemented symbol always has.
///
/// `dll` is canonicalised once, here, through [`canonical_dll`] -- the one
/// choke point both of this crate's callers (`Resolver::resolve` at load
/// time, `Host::run`'s dispatch loop at call time) already go through, so
/// neither needs its own copy of the alias.
pub fn entry<A: Abi>(dll: &str, symbol: &str) -> Entry<A> {
    let dll = canonical_dll(dll);
    if let Some((_, _, shim, cleans, _)) = routines::<A>()
        .into_iter()
        .find(|(d, n, _, _, _)| *d == dll && *n == symbol)
    {
        return Entry::Routine(shim, cleans);
    }
    if let Some((_, _, value)) = ABSOLUTES.iter().find(|(d, n, _)| *d == dll && *n == symbol) {
        return Entry::Absolute(*value);
    }
    if GLOBALS.iter().any(|g| g.dll == dll && g.name == symbol) {
        return Entry::Datum;
    }
    if let Some((shim, cleans)) = A::native(dll, symbol) {
        return Entry::Routine(shim, cleans);
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
/// Measured against the whole of what [`entry`] can answer -- [`routines`]
/// plus [`WG16_ROUTINES`] (not [`WG32_ROUTINES`]: `Wg32::native` answers
/// `None` for everything today, so nothing there is reachable through
/// `entry`), 332 in all: 319 [`Cleans::Caller`] against 13
/// [`Cleans::Callee`]. Five of the thirteen are the `@`-suffixed helpers this
/// function refuses to continue past; the other eight,
/// `borland::get_module_handle`/`get_proc_address` (`KERNEL32.dll`'s
/// `GetModuleHandleA`/`GetProcAddress`) and `dosenv::dossetvec`/
/// `doscreatedsalias`/`dosgetmodhandle`/`dosgetprocaddr` plus
/// `borland::loadlibrarya`/`freelibrary`, are **not** -- but that does not
/// weaken the claim above, because this function is only ever consulted for
/// a symbol [`entry`] answers [`Entry::Unimplemented`], and all eight of
/// those are [`Entry::Routine`]. Survey mode never has to guess their
/// convention; it runs the real, correctly-registered shim instead. (An
/// earlier count here said 136 against 10, wrong even before this file split
/// `ROUTINES` in two; a later one said 138 against 5, correct before the
/// KERNEL32 pair above was registered; a later one still said 140 against 7,
/// correct before the DOSCALLS/PHAPI loader routines and the KERNEL32
/// `LoadLibraryA`/`FreeLibrary` pair joined them -- each count has one
/// accounting for its own moment, not several at once.)
///
/// Re-derive by counting `Cleans::Caller`/`Cleans::Callee` occurrences
/// within [`routines`]'s and [`WG16_ROUTINES`]'s own spans (not a whole-file
/// `grep`, which also matches non-registration sites); this split went stale
/// three times before, which is why the history above is kept rather than
/// overwritten.
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

    /// The whole point of [`sign_extend`]: a C `int` is signed at `A`'s own
    /// width, and the old `as i16` was `Wg16`'s answer hard-coded.
    ///
    /// The `Wg32` column is what the 16-bit-shaped idiom got wrong. `-1`
    /// arrives as `0xFFFFFFFF` and must stay `-1`; `40000` is a positive
    /// `int` under a 4-byte `int` and became *negative* under `as i16`, which
    /// is what made `fgets(buf, 40000, f)` a refusal instead of a read.
    #[test]
    fn a_c_int_is_signed_at_the_abis_own_width() {
        // (raw bits on the frame, what Wg16 means, what Wg32 means)
        let cases: &[(u32, i32, i32)] = &[
            (0x0000_0000, 0, 0),
            (0x0000_0001, 1, 1),
            (0x0000_FFFF, -1, 65535),
            (0xFFFF_FFFF, -1, -1),
            (0x0000_9C40, -25536, 40000),
            (0x0001_1170, 4464, 70000),
        ];
        for &(raw, w16, w32) in cases {
            assert_eq!(sign_extend::<Wg16>(raw), w16, "Wg16 of {raw:#010x}");
            assert_eq!(sign_extend::<crate::abi::Wg32>(raw), w32, "Wg32 of {raw:#010x}");
        }
    }

    #[test]
    fn a_global_is_a_datum() {
        assert!(matches!(entry::<Wg16>(MAJORBBS, "usrnum"), Entry::Datum));
        assert!(matches!(entry::<Wg16>(MAJORBBS, "margv"), Entry::Datum));
        assert!(matches!(entry::<Wg16>(GALGSBL, "bturno"), Entry::Datum));
    }

    #[test]
    fn a_global_belongs_to_the_dll_that_exports_it() {
        // `bturno` is GSBL's, not MAJORBBS's. Asking the wrong DLL for it must
        // not find it, or a name shared between two DLLs would bind one to the
        // other's memory.
        assert!(matches!(entry::<Wg16>(MAJORBBS, "bturno"), Entry::Unimplemented));
        assert!(matches!(entry::<Wg16>(GALGSBL, "usrnum"), Entry::Unimplemented));
    }

    #[test]
    fn hrtval_resolves_from_galgsbl_as_well_as_majorbbs() {
        // Both MajorMUD NT builds and Rose 3.0NT import hrtval from GALGSBL,
        // not MAJORBBS. canonical_dll folds "GALGSBL.dll" to GALGSBL, so a
        // MAJORBBS-only registration is unreachable for them.
        assert!(
            matches!(entry::<Wg16>(GALGSBL, "hrtval"), Entry::Routine(..)),
            "hrtval must resolve under GALGSBL"
        );
        assert!(
            matches!(entry::<Wg16>(MAJORBBS, "hrtval"), Entry::Routine(..)),
            "and must still resolve under MAJORBBS"
        );
    }

    /// Task 15's unstated dependency, settled: the real PE spells the
    /// game-host library `WGSERVER.EXE` (confirmed by `objdump -p` against
    /// the reference DLL) where every entry in [`routines`] keys it
    /// `MAJORBBS`. Without [`canonical_dll`], `entry::<Wg32>("WGSERVER.EXE",
    /// "l2as")` finds nothing at all -- not because `l2as` has no generic
    /// core (it does, and `Wg16` already reaches it under its own DLL
    /// name), but because the DLL name never matches. This is the
    /// mutation-worthy assertion: delete `canonical_dll`'s call in `entry`
    /// and this goes from `Routine` to `Unimplemented`.
    #[test]
    fn wgserver_exe_aliases_onto_majorbbs_for_wg32() {
        assert!(matches!(
            entry::<crate::abi::Wg32>("WGSERVER.EXE", "l2as"),
            Entry::Routine(..)
        ));
        // Case-insensitively: PE import directory names are conventionally
        // upper-cased, but nothing in the format requires it, and this
        // crate's own resolver must not depend on a case the real DLL
        // happens to use today.
        assert!(matches!(
            entry::<crate::abi::Wg32>("wgserver.exe", "l2as"),
            Entry::Routine(..)
        ));
        // The alias is exactly one name -- it must not swallow an unrelated
        // DLL that merely shares a suffix or a prefix.
        assert!(matches!(
            entry::<crate::abi::Wg32>("GALGSBL.DLL", "l2as"),
            Entry::Unimplemented
        ));
    }

    /// A PE module's `GALGSBL.dll` reaches the same table a 16-bit module's
    /// `GALGSBL` does.
    ///
    /// The library renamed when Worldgroup moved off segmented binaries, the
    /// same way `MAJORBBS` became `WGSERVER.EXE`. `crate::exports::GALGSBL` is
    /// the bare `"GALGSBL"` a 16-bit NE names; the PE import directory spells
    /// it `"GALGSBL.dll"`. One alias, not six per-symbol renames.
    #[test]
    fn galgsbl_dll_is_the_same_library_as_galgsbl() {
        for name in ["btuclo", "btuinj", "btumil", "btuoes", "btuxnf"] {
            assert!(
                matches!(
                    entry::<crate::abi::Wg32>("GALGSBL.dll", name),
                    Entry::Routine(..)
                ),
                "{name} is implemented and a PE module must reach it"
            );
        }
        assert!(
            matches!(entry::<crate::abi::Wg32>("GALGSBL.dll", "bturno"), Entry::Datum),
            "bturno is a host global, not a routine -- the alias has to carry \
             data lookups too, or the module gets a null IAT slot"
        );
        // `btuxmn` was the one genuinely absent entry when this test was
        // written for Task 5; Task 7 implemented it in the same session, so
        // the alias now reaches all seven `btu*` imports, not six.
        assert!(
            matches!(
                entry::<crate::abi::Wg32>("GALGSBL.dll", "btuxmn"),
                Entry::Routine(..)
            ),
            "btuxmn is implemented (Task 7) and a PE module must reach it too"
        );

        // Case-insensitively, because nothing in the PE format requires the
        // conventional upper-casing.
        assert!(matches!(
            entry::<crate::abi::Wg32>("galgsbl.DLL", "btuclo"),
            Entry::Routine(..)
        ));

        // And the alias must not have moved GSBL's symbols into MAJORBBS.
        // Ordinals collide across DLLs and `bturno` is GALGSBL's, not
        // MAJORBBS's -- see `a_global_belongs_to_the_dll_that_exports_it`.
        assert!(matches!(
            entry::<crate::abi::Wg32>(MAJORBBS, "bturno"),
            Entry::Unimplemented
        ));
    }

    #[test]
    fn fsdbkg_is_wired() {
        // It used to be `Entry::Unimplemented`, on the grounds that clearing
        // an ANSI screen and running a display engine needed a screen this
        // host did not have. Stage 5's Task 6 built one: `fsd::fsddsp` draws
        // the form and `fsdbkg` sends it, with the wrap width zeroed first so
        // the escapes survive `Channel::transmit`.
        assert!(matches!(entry::<Wg16>(MAJORBBS, "fsdbkg"), Entry::Routine { .. }));
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
            entry::<Wg16>(MAJORBBS, "fsdego"),
            Entry::Routine(_, Cleans::Caller)
        ));
    }

    /// Every test in `shims::screen` and `shims::gsbl` calls `rstrxf`,
    /// `btuhpk`, `btupbc` and `btucpc` by their Rust name --
    /// `f.invoke(btupbc, ...)`, `f.invoke(rstrxf, ...)` -- which is
    /// not how a module (or, for `rstrxf`, this crate's own MAJORBBS import
    /// dispatch) reaches any routine. That path is `entry`, keyed by the DLL
    /// and the *string* [`routines`] was given -- and every one of those
    /// tests would keep passing even if this table wired `"btupbc"` to
    /// `gsbl::btucpc`'s behaviour, or `"rstrxf"` to a routine that does
    /// nothing at all, because none of them go through it. This does.
    ///
    /// `Fixture::invoke_call`, not `invoke`: `entry` now hands back a
    /// `Shim<Wg16>` (`Call`-shaped), the same thing [`routines`] and
    /// [`WG16_ROUTINES`] themselves hold, rather than a `_wg16` bridge --
    /// see [`Shim`]'s own doc comment.
    #[test]
    fn rstrxf_and_its_gsbl_routines_are_wired_to_the_right_behaviour_by_name() {
        let mut f = Fixture::new();
        let console = f.console();

        let Entry::Routine(btuhpk, _) = entry::<Wg16>(GALGSBL, "btuhpk") else {
            panic!("btuhpk must be a routine");
        };
        let Entry::Routine(btupbc, _) = entry::<Wg16>(GALGSBL, "btupbc") else {
            panic!("btupbc must be a routine");
        };
        let Entry::Routine(btucpc, _) = entry::<Wg16>(GALGSBL, "btucpc") else {
            panic!("btucpc must be a routine");
        };
        let Entry::Routine(rstrxf, _) = entry::<Wg16>(MAJORBBS, "rstrxf") else {
            panic!("rstrxf must be a routine");
        };

        f.invoke_call(btuhpk, &[0, 0, 0]).expect("ok");
        assert!(f.host.gsbl().channel(console).pause_handler_installed);

        f.invoke_call(btupbc, &[0, 20]).expect("ok");
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

        f.invoke_call(btucpc, &[0, 19]).expect("ok");
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
        let at = mbbs_machine::m16::FarPtr {
            offset: account.offset + f.host.users().account_layout().scnbrk,
            selector: account.selector,
        };
        f.machine.write(at, &[24]).expect("account memory");
        f.invoke_call(rstrxf, &[])
            .expect("rstrxf does not stop the machine");
        assert_eq!(
            f.host.gsbl().channel(console).page_lines,
            22,
            "the table's \"rstrxf\" must be the real routine: scnbrk(24) - CTNUOS(2)"
        );
    }

    #[test]
    fn an_unknown_symbol_is_unimplemented() {
        assert!(matches!(entry::<Wg16>(MAJORBBS, "nonesuch"), Entry::Unimplemented));
    }

    /// `l2as`'s own module tests (`shims::text`) all call it by its Rust
    /// name, which is not how a module reaches it. This goes through `entry`,
    /// keyed by the DLL and the string [`routines`] was given, the way
    /// `WCCMMUD.DLL`'s own import fixups do.
    #[test]
    fn l2as_is_wired_to_the_right_behaviour_by_name() {
        let mut f = Fixture::new();
        let Entry::Routine(l2as, cleans) = entry::<Wg16>(MAJORBBS, "l2as") else {
            panic!("l2as must be a routine");
        };
        assert_eq!(cleans, Cleans::Caller, "14/14 measured sites clean 2 words");

        let value = i32::MIN as u32;
        let args = [value as u16, (value >> 16) as u16];
        let abi::Ret::Ptr(at) = f.invoke_call(l2as, &args).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"-2147483648");
    }

    #[test]
    fn the_gsbl_routines_are_reached_under_galgsbl_and_not_under_majorbbs() {
        // Ordinals collide across DLLs -- GALGSBL.72 is `bturno` and
        // MAJORBBS.72 is something else entirely -- so a routine registered
        // under the wrong module name would be dispatched for the wrong import.
        assert!(matches!(entry::<Wg16>(GALGSBL, "btuxmt"), Entry::Routine(..)));
        assert!(matches!(entry::<Wg16>(MAJORBBS, "btuxmt"), Entry::Unimplemented));
    }

    #[test]
    fn the_huge_shift_steps_one_ldt_entry() {
        let Entry::Absolute(shift) = entry::<Wg16>(DOSCALLS, "doshugeshift") else {
            panic!("DOSCALLS.135 is a constant");
        };
        assert_eq!(
            1u16 << shift,
            mbbs_machine::m16::SELECTOR_STEP,
            "shifting by this must land on the next selector"
        );
    }

    #[test]
    fn nothing_is_in_two_tables_at_once() {
        // They answer the same question, and a symbol in two would resolve to
        // whichever is consulted first -- a far call into globals memory, or a
        // variable at a code address, or the second door. Neither fails loudly.
        let generic = routines::<Wg16>();
        for (dll, name, _, _, _) in &generic {
            assert!(
                !GLOBALS.iter().any(|g| g.dll == *dll && g.name == *name),
                "{dll}.{name} is both a routine and a global"
            );
            assert!(
                !ABSOLUTES.iter().any(|(d, n, _)| d == dll && n == name),
                "{dll}.{name} is both a routine and a constant"
            );
            assert!(
                !WG16_ROUTINES.iter().any(|(d, n, _, _, _)| d == dll && n == name),
                "{dll}.{name} is both a generic routine and behind Wg16's door"
            );
        }
        for (dll, name, _) in ABSOLUTES {
            assert!(
                !GLOBALS.iter().any(|g| g.dll == *dll && g.name == *name),
                "{dll}.{name} is both a constant and a global"
            );
        }
        for (dll, name, _, _, _) in WG16_ROUTINES {
            assert!(
                !GLOBALS.iter().any(|g| g.dll == *dll && g.name == *name),
                "{dll}.{name} is both a routine and a global"
            );
            assert!(
                !ABSOLUTES.iter().any(|(d, n, _)| d == dll && n == name),
                "{dll}.{name} is both a routine and a constant"
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
        // How much each pops is asserted here too, because the amounts repeat
        // for different reasons: two `long`s for the division family, two far
        // pointers for the struct copy, and (unrelated to any of that) one
        // and two 32-bit Win32 arguments for the KERNEL32 pair below.
        //
        // Checked against both tables, not just `WG16_ROUTINES` -- the
        // invariant this pins is about the whole of what `entry` can answer,
        // and a future routine landing in the generic table with the wrong
        // `Cleans` should fail this test too, not be invisible to it. That
        // is no longer a hypothetical for the generic table specifically:
        // `borland::get_module_handle`/`get_proc_address` are the first two
        // `Cleans::Callee` rows [`routines`] itself carries (KERNEL32's
        // stdcall pair -- see `shims::borland`'s own module doc comment), so
        // this list is no longer five entries pulled entirely from
        // `WG16_ROUTINES`.
        let generic = routines::<Wg16>();
        let callee: Vec<(&str, Cleans)> = generic
            .iter()
            .map(|(dll, name, _, cleans, _)| (*dll, *name, *cleans))
            .chain(WG16_ROUTINES.iter().map(|(dll, name, _, cleans, _)| (*dll, *name, *cleans)))
            .filter(|(_, _, cleans)| !matches!(cleans, Cleans::Caller))
            .map(|(_, name, cleans)| (name, cleans))
            .collect();
        assert_eq!(
            callee,
            [
                // Far pascal, not cdecl -- the OS/2-derived DOS and Phar Lap
                // extender APIs a Borland huge-model crt0 links against
                // declare `APIENTRY`, and the callee pops. `dossetvec` takes
                // `USHORT` + two far pointers (2+4+4); `doscreatedsalias`
                // takes `SEL` + `PSEL` (2+4). Both live inside an
                // unreachable crt0 trampoline, so these byte counts are
                // measured from the declarations rather than from a call
                // this host will ever make -- see `shims::dosenv`.
                ("dossetvec", Cleans::Callee(10)),
                ("doscreatedsalias", Cleans::Callee(6)),
                ("getmodulehandlea", Cleans::Callee(4)),
                ("getprocaddress", Cleans::Callee(8)),
                // Runtime name resolution, added 2026-08-15 -- the same two
                // conventions as the four rows above, one library over each.
                // Phar Lap's pair is far pascal like `dossetvec`:
                // `DosGetModHandle` takes two far pointers (4+4);
                // `DosGetProcAddr` takes a handle and two far pointers
                // (2+4+4). KERNEL32's pair is stdcall like
                // `getmodulehandlea`/`getprocaddress`: one 32-bit argument
                // each, an `LPCSTR` and an `HMODULE` respectively.
                ("dosgetmodhandle", Cleans::Callee(8)),
                ("dosgetprocaddr", Cleans::Callee(10)),
                ("loadlibrarya", Cleans::Callee(4)),
                ("freelibrary", Cleans::Callee(4)),
                // `f_spush@` is deliberately NOT in this list. It looks like
                // `f_scopy@`'s sibling and is not: all six of The Rose's call
                // sites disassemble to a register-only sequence with nothing
                // pushed and no `add sp` after, so `Cleans::Caller` is the
                // measured answer. See its row in `WG16_ROUTINES`.
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

/// Every symbol the 2026-08-15 ten-build survey found missing is now served.
///
/// Guards against a future refactor silently unregistering one. The module
/// binaries live in `archive/` and outside this repo, so this asserts the
/// **registration table**, not the DLLs -- it must run without the archive
/// present. Re-derive the list with `re/importgaps.py <module> --abi wg16|wg32`
/// against the ten builds named in
/// `docs/plans/2026-08-15-host-api-surface-design.md` § 1.
///
/// # Why a table assertion and not a survey
///
/// The survey script is the thing that was wrong twice during this work. It
/// could not see `GALMSG` at all (`634017b`), so it reported an already-served
/// symbol as unnameable for three days; and before that it could not parse PE
/// modules, so the entire 32-bit half of the surface went unmeasured
/// (`c943fe4`). A test that shelled out to it would inherit both classes of
/// blindness. Asserting [`entry`] directly is the one check a measurement bug
/// cannot fool, because [`entry`] is what the loader itself calls.
///
/// Lives here rather than in `crates/mbbs/tests/` because `crate::shims` is a
/// private module: an integration test cannot reach [`entry`], and making the
/// module public to accommodate a test would widen the crate's API for no
/// other reason.
#[cfg(test)]
mod import_surface {
    use super::*;
    use crate::abi::Wg32;

    /// `(library, symbol)` for every gap the ten-build survey found.
    const CLOSED_BY_TRACK_A: &[(&str, &str)] = &[
        // GALGSBL: the character-interrupt family, plus the alias that left an
        // already-implemented routine unreachable for three 32-bit builds.
        (GALGSBL, "btuche"),
        (GALGSBL, "btuchi"),
        (GALGSBL, "btuclc"),
        (GALGSBL, "btucls"),
        (GALGSBL, "btutru"),
        (GALGSBL, "chiout"),
        (GALGSBL, "hrtval"),
        // Allocation.
        (MAJORBBS, "alcblok"),
        (MAJORBBS, "ptrblok"),
        (MAJORBBS, "freblok"),
        (MAJORBBS, "galmalloc"),
        (MAJORBBS, "sizmem"),
        // Borland's runtime, re-exported through MAJORBBS.
        (MAJORBBS, "_fgetc"),
        (MAJORBBS, "stricmp"),
        (MAJORBBS, "ultoa"),
        (MAJORBBS, "ungetc"),
        (MAJORBBS, "rename"),
        (MAJORBBS, "getenv"),
        (MAJORBBS, "gettime"),
        (MAJORBBS, "_doserror"),
        (MAJORBBS, "__errno"),
        (MAJORBBS, "_lrand"),
        (MAJORBBS, "searchpath"),
        (MAJORBBS, "setmode"),
        (MAJORBBS, "read"),
        (MAJORBBS, "write"),
        (MAJORBBS, "f_spush@"),
        // Tasking, messages, FSD, screen, accounts.
        (MAJORBBS, "mfytask"),
        (MAJORBBS, "getasc"),
        (MAJORBBS, "rawmsg"),
        (MAJORBBS, "fsdfxt"),
        (MAJORBBS, "fsdrhd"),
        (MAJORBBS, "explode"),
        (MAJORBBS, "iniscn"),
        (MAJORBBS, "swtcls"),
        (MAJORBBS, "extoff"),
        // WGNT host services -- 32-bit builds only.
        (MAJORBBS, "getfiletm"),
        (MAJORBBS, "paccit"),
        (MAJORBBS, "samepatu"),
        (MAJORBBS, "vtmsend"),
        (MAJORBBS, "vtmsndok"),
        // Runtime name resolution, Phar Lap half.
        (DOSCALLS, "dosgetmodhandle"),
        (DOSCALLS, "dosgetprocaddr"),
    ];

    /// The datums, separate because the failure mode differs in kind: a module
    /// *addresses* these rather than calling them, so a routine registration
    /// puts a dispatch thunk's address into the fixup and the module reads a
    /// function where it wanted state -- every routine implemented, nothing
    /// happening.
    const DATUMS: &[(&str, &str)] = &[
        (MAJORBBS, "fsdusr"),
        (MAJORBBS, "emlsdrou"),
        (MAJORBBS, "errcod"),
        (MAJORBBS, "othexp"),
        (MAJORBBS, "kilipg"),
        (MAJORBBS, "kilsrc"),
    ];

    fn served16(dll: &str, name: &str) -> bool {
        !matches!(entry::<Wg16>(dll, name), Entry::Unimplemented)
    }

    fn served32(dll: &str, name: &str) -> bool {
        !matches!(entry::<Wg32>(dll, name), Entry::Unimplemented)
    }

    #[test]
    fn every_symbol_the_survey_found_missing_is_now_served() {
        let unserved: Vec<_> = CLOSED_BY_TRACK_A
            .iter()
            .filter(|(dll, name)| !served16(dll, name) && !served32(dll, name))
            .collect();
        assert!(unserved.is_empty(), "unserved under BOTH ABIs: {unserved:?}");
    }

    #[test]
    fn the_kernel32_resolution_pair_serves_wg32() {
        // Spelled with the `.dll` suffix a PE import directory carries, which
        // is the literal value `KERNEL32` holds; `canonical_dll` leaves it be.
        for name in ["loadlibrarya", "freelibrary"] {
            assert!(served32(KERNEL32, name), "KERNEL32!{name} must serve Wg32");
        }
    }

    #[test]
    fn the_datums_are_addressable_and_not_callable() {
        for (dll, name) in DATUMS {
            assert!(
                matches!(entry::<Wg16>(dll, name), Entry::Datum),
                "{dll}!{name} must be a Datum, not a Routine"
            );
        }
    }

    #[test]
    fn the_block_allocator_serves_both_abis_from_two_bodies() {
        // Same C export in both native tables, deliberately: the vendor's two
        // `ALCBLOK.C` branches have structurally different headers, so no one
        // generic body can be byte-compatible with both. This is not the
        // duplicate registration `6d8af77` removed -- these are ABI-concrete
        // and reached through `Abi::native`.
        for name in ["alcblok", "ptrblok", "freblok"] {
            assert!(served16(MAJORBBS, name), "{name} must serve Wg16");
            assert!(served32(MAJORBBS, name), "{name} must serve Wg32");
        }
    }

    /// Every routine `BTVSTF.H` declares is registered — all 36.
    ///
    /// Track B took this from 26. The list is the header's, not a
    /// hand-maintained one: re-derive it with
    ///
    /// ```text
    /// grep -aoE "^(void|int|long|char|unsigned) +\*? *[a-z_0-9]+ *\(" \
    ///   archive/galacticomm/extract/wg1/GALDSRC/SRC/BTVSTF.H
    /// ```
    ///
    /// Note the `-a`: `grep` here is `ugrep -I` and silently skips files it
    /// judges binary, 1990s C headers included.
    #[test]
    fn the_whole_btvstf_declared_surface_is_registered() {
        const BTVSTF: &[&str] = &[
            "aabbtv", "aabbtvl", "absbtv", "anpbtv", "anpbtvl", "anpbtvlk", "bxabtv", "clsbtv",
            "cntrbtv", "crtbtv", "delbtv", "dinsbtv", "dupdbtv", "exabtv", "gabbtv", "gabbtvl",
            "getbtv", "getbtvl", "insbtv", "invbtv", "llnbtv", "obtbtv", "obtbtvl", "omdbtv",
            "qnpbtv", "qrybtv", "rlenbtv", "rstbtv", "setbtv", "stpbtv", "stpbtvl", "sttbtv",
            "unlbtv", "updbtv", "upvbtv", "wslbtv",
        ];
        let missing: Vec<_> = BTVSTF
            .iter()
            .filter(|n| matches!(entry::<Wg16>(MAJORBBS, n), Entry::Unimplemented))
            .collect();
        assert!(missing.is_empty(), "BTVSTF.H declares these and they are unserved: {missing:?}");
        assert_eq!(BTVSTF.len(), 36, "BTVSTF.H declares 36; this list drifted");
    }

    #[test]
    fn simpsnd_resolves_under_the_pe_spelling_of_galme() {
        // The last unresolved import across all ten builds, and it needed two
        // things: the routine, and `canonical_dll` learning that a PE import
        // directory spells the library `GALME.dll` while this host registers
        // under the bare `GALME` an NE segment carries. Both 32-bit builds ask
        // for `GALME.dll!_simpsnd` and nothing else from that library, so the
        // alias had no other symbol to be noticed by.
        assert!(
            matches!(entry::<Wg32>("GALME.dll", "simpsnd"), Entry::Routine(..)),
            "GALME.dll!simpsnd must resolve for a PE module"
        );
        assert!(
            matches!(entry::<Wg16>(GALME, "simpsnd"), Entry::Routine(..)),
            "and under the bare NE spelling too"
        );
        // The alias must not have been achieved by folding GALME into
        // MAJORBBS -- they are genuinely different libraries.
        assert!(
            matches!(entry::<Wg16>(MAJORBBS, "simpsnd"), Entry::Unimplemented),
            "simpsnd is GALME's, not MAJORBBS's"
        );
    }

    #[test]
    fn galmsg_ordinal_thirty_is_served_and_was_never_unnameable() {
        // Carried for three days as a symbol this host "cannot even name". It
        // is `_OLDSEND`, mapped in `crates/mbbs/data/galmsg_wg101.tsv` and
        // registered long before that claim was written -- the survey script
        // simply could not see the library. Pinned so the claim cannot return.
        assert!(
            matches!(entry::<Wg16>(GALMSG, "oldsend"), Entry::Routine(..)),
            "GALMSG ordinal 30 is oldsend, and is served"
        );
    }
}
