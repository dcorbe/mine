//! `dfa*`: the data-file API `WGSERVER.EXE` exports to 32-bit (PE) modules,
//! and the highest-leverage single block in the whole PE import survey --
//! `dfaSetBlk`, `dfaInsertV` and `dfaAcqLock` are each imported by 37 of the
//! 71 modules surveyed (`re/isv_union_pe_symbols.tsv`).
//!
//! # A facade over the same Btrieve engine `shims::btrieve` already built
//!
//! `re/wg33src/SRC/api/gcommlib/DFAAPI.C` -- the vendor source, cited
//! throughout this file. **It exists only in `re/wg33src`**, not in the
//! `wg1`/`wg20` archive trees this crate cites elsewhere; every line number
//! below is `DFAAPI.C`'s own, and there is no `wg1` copy to disagree with it.
//!
//! `DFAAPI.C`'s own `btvu()` (`:908-985`) is a second, independent wrapper
//! around the *identical* underlying Btrieve function codes
//! `crate::btrieve` already implements for `PLBTVSTF.C`'s `btvuptr` --
//! opcode 0 opens, 2 inserts, 3 updates, 4 deletes, 5-13 acquire by key,
//! 22 gets the absolute position, 23 acquires by it, 24/33-35 step, and so
//! on. `dfa*` is not a second database: it is `btv*`'s sibling on top of the
//! same file format, the same B-tree, the same [`crate::btrieve::Block`].
//! So every routine below is expressed in terms of that engine and of
//! `shims::btrieve`'s own already-tested positioning core
//! ([`btv::locate`], [`btv::absolute`]'s reasoning re-derived for the one
//! shape it does not fit, [`btv::deliver`], [`btv::answer_with_key`],
//! [`btv::update_variable`], [`btv::duplicate_key`]) rather than
//! reimplementing any of it -- this file widens several of those items from
//! `fn` to `pub(crate) fn` so it can reuse them, with no behaviour change.
//!
//! # `dfa`/`dfastk` are never `bb`/`bbstk`
//!
//! `BTVSTF.H:36` declares `extern struct btvblk *bb;` -- a real, module-
//! addressable global a fixup can name, which is why [`crate::globals`]
//! places `bb` in memory the module itself can read (see
//! [`btv::positioned`]'s own module -- `crate::globals`'s doc comment --
//! for the mechanism). `DFAAPI.H` declares no such extern for `dfa`: it is a
//! plain file-scope `static` inside `DFAAPI.C`, invisible to anything
//! outside the object file that provides `dfaOpen` and friends. So unlike
//! `bb`, `dfa` and its ten-deep stack are never reachable from a module at
//! all, and this host keeps them as genuine host-side state instead --
//! [`crate::btrieve::Btrieve::dfa_current`]/`dfa_set`/`dfa_restore`/
//! `dfa_set_current`, added to the *same* `Btrieve<A>` a `Host<A>` already
//! carries one of, so a module opening files through both `btv*` and
//! `dfa*` (nothing in the surveyed corpus does; `WCCMMUD.DLL`, the one
//! module this host runs end to end, is 16-bit and imports no `dfa*` symbol
//! at all) would see the two families as genuinely independent, exactly as
//! `DFAAPI.C` and `PLBTVSTF.C` are two independent object files.
//!
//! # The module-memory block image is `btvblk`'s, reused
//!
//! `dfaOpen` still has to hand the module a real pointer it can pass back to
//! `dfaClose`/`dfaSetBlk` later, so this reuses
//! [`crate::btrieve::Btrieve::open`] verbatim -- the *same* allocation
//! `opnbtv` uses, laid out as `crate::btrieve`'s private `field` module
//! describes for `struct btvblk` (`BTVSTF.H:17`). That is not a shortcut
//! taken for convenience: `DFAAPI.H`'s non-Windows `struct dfablk`
//! (`:132-145`) declares `posblk`/`filnam`/`reclen`/`key`/`data`/`lastkn`/
//! `keylns[SEGMAX]` in the same order as `struct btvblk`, and -- unlike
//! `btvblk`'s `int reclen`/`int lastkn`/`int keylns[]`, which are `A`'s own
//! `int` width -- `dfablk` types `reclen`/`lastkn` `USHORT`/`SHORT`
//! explicitly, always two bytes regardless of ABI, and `keylns[]` likewise.
//! So `crate::btrieve`'s `field::` offsets (all fixed-width, never
//! `A::INT_WIDTH`-scaled) are `dfablk`'s true byte layout, not merely close
//! to it -- which is what lets [`btv::key_number`]'s `LASTKN` constant
//! (offset 142) and every other module-memory read below work unchanged.
//!
//! What real `dfablk` has beyond `keylns` is not reproduced: under
//! `GCWINNT` it carries `flddefList[SEGMAX]`/`unpackKeySiz[SEGMAX]`, two
//! arrays that exist only to drive `cvtDataIP`'s field-by-field marshalling
//! between the module's own struct layout and Btrieve's packed one -- a
//! translation layer this host does not implement at all (every record this
//! host reads or writes is raw bytes, never converted). `DFAFILE` is opaque
//! to application code (`DFAAPI.H` names no field offset a module could
//! code against, unlike `bb`'s documented direct-access convention), so
//! nothing here is known to read past `keylns`.
//!
//! `dfaOpen`'s `owner` argument -- a Btrieve access password, `DFAAPI.C:137,
//! 146-152` -- is refused rather than silently accepted when it is not
//! null: this host checks no such password, and opening a protected file as
//! though it had none would be a fabricated success. `dfaOpen`'s own retry
//! loop on Btrieve status 20 ("the engine isn't ready", `:156-159`) and its
//! unconditional wait on status 85 ("locked by another process", `:161-163`)
//! are both dropped with no observable effect: this host is single-process,
//! so nothing else can hold that lock and the loop's only other exit is
//! success.
//!
//! # `ASSERT(dfa != NULL)` is not a guard, and this file says so per routine
//!
//! `PLBTVSTF.C` opens most of its routines with a real, always-compiled
//! `if (bb == NULL) { return ...; }`. `DFAAPI.C` is inconsistent about this
//! in a way worth naming once here rather than eleven times below: several
//! routines guard the same way (`dfaQuery`, `dfaQueryNP`, `dfaGetLock`,
//! `dfaAcqLock`, `dfaAcqNPLock`, `dfaUpdateDup`, `dfaStepLock`), and several
//! others open with only `ASSERT(dfa != NULL)` -- a macro that compiles to
//! nothing outside a debug build -- and then dereference `dfa->` unguarded
//! (`dfaInsert`/`dfaInsertV`/`dfaInsertDup`, `dfaUpdate`/`dfaUpdateV`,
//! `dfaDelete`), or have no check of any kind before calling `btvu()`
//! (`dfaAbs`, `dfaAcqAbsLock`). `btvu()` itself (`:916-984`, every one of its
//! three platform branches) unconditionally dereferences `dfa->posblk` to
//! find where Btrieve's own position block lives, so a release build with
//! `dfa == NULL` and no real guard faults *inside* `btvu()`, not at the call
//! site -- the identical shape [`shims::btrieve::dinsbtv`]/[`dupdbtv`]
//! already describe for `bb->reclen`. This host reproduces the *outcome*
//! (the module is stopped, per "runtime crashes are better than undefined
//! behaviour") rather than the fault site, and each routine's own doc
//! comment says which of the two shapes it is.
//!
//! # Method
//!
//! Every routine takes `(call: &mut Call<A>, host: &mut Host<A>)` and reads
//! its arguments off `call` in the vendor prototype's own order --
//! `DFAAPI.H:216-401` -- through the same [`btv::i16_arg`]/[`btv::u16_arg`]
//! width helpers `shims::btrieve` uses, for the same reason: `A::Int` is
//! `u16` under `Wg16` and `u32` under `Wg32`, and every `dfa*` prototype
//! declares its flag/option arguments plain `int`.
//!
//! # Registration
//!
//! All thirty-three routines below are registered in `shims/mod.rs` under
//! `MAJORBBS`, lowercased -- `_dfaSetBlk` arrives at the table as
//! `dfasetblk`, see `exports::c_name`. Worldgroup NT's PE modules import the
//! identical symbols from a differently-named container, which one alias
//! covers.
//!
//! This paragraph used to say the opposite -- "not registered here" --
//! which was true of the commit that introduced this file and false from
//! the one that registered its routines. A claim about another file's
//! contents cannot be kept honest from here, so check it rather than
//! trust it: the count is a grep for quoted `dfa` names in `shims/mod.rs`.

// The C names throughout `DFAAPI.H`/`DFAAPI.C` are mixed-case
// (`dfaSetBlk`, not `dfa_set_blk`), and every routine below keeps its
// vendor spelling verbatim -- the same convention every other shim file in
// this crate follows for its own (all-lowercase, so never triggering this
// lint) C names.
#![allow(non_snake_case)]

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::btrieve::AbiMem;
use crate::btrieve::{Btrieve, Geometry, Step};
use crate::shims::ShimError;
use crate::shims::btrieve as btv;

/// The owner token this task's cross-channel lock table uses -- the
/// channel/user number currently running, per `usrnum`
/// ([`Host::current_channel_mem`]). `crates/btrieve` is `Mem`-agnostic and
/// knows nothing of [`crate::chan::Chan`], so this is where a `Chan`
/// becomes the raw `u32` [`crate::btrieve::Btrieve::dfa_take_lock`] takes.
///
/// `None` when `usrnum` does not currently name a channel -- `MAJORBBS.C:882`
/// sets it to `-1` before any module's init runs, and a `dfa*` lock taken
/// from outside any channel's own turn (module init loading its own data,
/// for one) is not taken *on behalf of* a channel at all. There is nothing
/// for such a lock to conflict with by definition, so callers skip the
/// cross-channel check entirely on `None` rather than refuse the whole call
/// over a channel that was never current to begin with.
fn current_owner<A: Abi>(call: &mut Call<A>, host: &Host<A>) -> Option<u32> {
    let chan = host.current_channel_mem(call.mem()).ok()?;
    // `Chan::number` is always non-negative -- it is only ever constructed
    // from `Terms::chan`/`Terms::all`, both bounds-checked against a
    // channel count -- so this cast never wraps.
    Some(chan.number() as u32)
}

/// The file `dfa*` routines currently work on, refusing if none is.
///
/// For the routines `DFAAPI.C` never guards at all (see the module doc
/// comment's guard census): `btvu()` would have faulted dereferencing
/// `dfa->posblk`, and this refuses by name instead of reproducing a crash a
/// module could not have caught either.
/// A Btrieve record position, as the module sees it: **high word first**.
///
/// Genuine Btrieve 6.15 hands `Get-Position` (op 22) back, and takes
/// `Get-Direct`/`Step` positions in, as a word-swapped `LONG` -- the same
/// "high word first" convention every pointer inside the file format uses
/// (`crates/btrieve`'s `pages::long`/`to_long`). This crate carries a
/// record's position internally as a plain little-endian `u32`
/// (`layout.position` = `page*pagesize + header + slot*physical`), so the
/// two halves have to be swapped at the module boundary.
///
/// **Measured, not assumed:** every one of the 7,060 records `btrvprobe
/// step` yields from The Rose's `RCI_MOD1.DAT`, and every record of the v6
/// oracle fixture `DUPKEY30.DAT`, reports a position that is exactly this
/// swap of the plain slot position (`page 2, slot 0` -> `1030` -> engine
/// `0x0406_0000`). Without it, `dfaAbs` hands back `0x0002_a4f0` where the
/// engine says `0xa4f0_0002`, and a module that does arithmetic on the
/// value -- The Rose's universe loader steps, `dfaAbs`, `dfaGetAbsLock`s and
/// compares -- never terminates.
///
/// Its own inverse, so the same function encodes an outgoing position and
/// decodes an incoming one. Scoped to `dfa*` deliberately: `WCCMMUD.DLL`
/// reaches absolute positioning through `absbtv`/`gabbtv` (the `btv*`
/// spellings), which round-trip the value opaquely and so are unaffected by
/// which half leads -- swapping there is correct too but wants a live
/// MajorMUD re-verify, so it is a separate step. See `shims::btrieve`'s
/// `absbtv`/`current_position`.
fn position_swap(position: u32) -> u32 {
    (position << 16) | (position >> 16)
}

fn dfa_required<A: Abi>(host: &Host<A>, who: &str) -> Result<A::Ptr, ShimError> {
    let block = host.btrieve.dfa_current();
    if block == Btrieve::<AbiMem<A>>::null() {
        return Err(ShimError::Failed(format!(
            "{who} with no dfa file current -- DFAAPI.C has no dfa == NULL guard here, \
             and btvu()'s own dereference of dfa->posblk is what would have faulted on \
             the real host"
        )));
    }
    host.btrieve.block(block).map_err(|e| ShimError::Failed(format!("{who}: {e}")))?;
    Ok(block)
}

/// The file `dfa*` routines currently work on, or `None` if none is.
///
/// For the routines `DFAAPI.C` *does* guard -- an explicit
/// `if (dfa == NULL) { ASSERT(...); return ...; }` that runs in every build,
/// ASSERT or not -- which answer quietly rather than refusing, the same
/// convention [`btv::positioned`] gives `bb`.
fn dfa_positioned<A: Abi>(host: &Host<A>, who: &str) -> Result<Option<A::Ptr>, ShimError> {
    let block = host.btrieve.dfa_current();
    if block == Btrieve::<AbiMem<A>>::null() {
        return Ok(None);
    }
    host.btrieve.block(block).map_err(|e| ShimError::Failed(format!("{who}: {e}")))?;
    Ok(Some(block))
}

/// Record what a delivering `dfa*` call just wrote into the module's
/// buffer, for [`dfaLastLen`] -- see the engine's own `dfa_last_len` field
/// doc comment for the exact scope of what updates this and what does not.
/// Silently does nothing if `block` is no longer resolvable or not
/// positioned, which cannot happen on any of this file's own call sites
/// (each calls this immediately after a successful deliver) but costs
/// nothing to be defensive about.
fn note_len<A: Abi>(host: &mut Host<A>, block: A::Ptr) {
    let Ok(file) = host.btrieve.block(block) else {
        return;
    };
    let Some(record) = file.current() else {
        return;
    };
    let len = usize::from(file.maxlen()).min(record.bytes.len());
    host.btrieve.dfa_set_last_len(len as u16);
}

/// Case-insensitive `strcmp`, bounded the same way [`btv::strcmp_eq`] is.
///
/// `dfaAcqNPLock`'s own `chkcas == 0` path is `stricmp` (`DFAAPI.C:437`),
/// where `anpbtv`'s btv equivalent always passes `chkcas=1` and so never
/// needed this. ASCII-only lowercasing, for the same reason `strcmp_eq`
/// scans no further than its own operands' length: there is no undefined
/// memory on the other side of either buffer to fall back on C's
/// unbounded `stricmp` scanning into.
fn stricmp_eq(a: &[u8], b: &[u8]) -> bool {
    let lower = |bytes: &[u8]| -> Vec<u8> {
        let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
        bytes[..end].iter().map(|byte| byte.to_ascii_lowercase()).collect()
    };
    lower(a) == lower(b)
}

/// `DFAFILE *dfaOpen(const CHAR *filnam, USHORT maxlen, const CHAR *owner)`
/// -- open a data file.
///
/// `DFAAPI.C:133-177`. Opens through the same
/// [`crate::btrieve::Btrieve::open`] [`btv::opnbtv`] uses -- see this
/// file's own module doc comment for why the module-memory image `open`
/// allocates is `dfablk`'s true layout and not merely a convenient reuse --
/// then makes the new block current with [`crate::btrieve::Btrieve::dfa_set`]
/// rather than [`crate::btrieve::Btrieve::set`]: `:175`'s own
/// `dfaSetBlk(dfa)` runs after `dfa` has already been reassigned to the
/// freshly allocated block (`:142`), so what gets pushed is that new
/// pointer -- see [`dfaSetBlk`]'s own doc comment for why that is not the
/// same operation `opnbtv`'s "pushes itself" is.
///
/// A non-null `owner` is refused -- see the module doc comment. The
/// retry-on-status-20 loop and the wait-on-status-85 loop (`:153-164`) have
/// no counterpart here: both exist for contention this single-process host
/// cannot have.
pub fn dfaOpen<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let maxlen = btv::ushort_arg::<A>(call.int());
    let owner = call.ptr();
    if owner != Btrieve::<AbiMem<A>>::null() {
        return Err(ShimError::Failed(
            "dfaOpen with a non-null owner -- DFAAPI.C:146-152 passes it to Btrieve's own \
             OPEN call as an access password, and this host checks no such password, so \
             opening a protected file here would be a fabricated success rather than an \
             honest refusal"
                .to_owned(),
        ));
    }

    let named = String::from_utf8_lossy(
        filnam.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<A>::dos_name(&named).map_err(ShimError::Failed)?;
    let path = host.btrieve_file(&name).map_err(ShimError::Failed)?;
    let geometry = Geometry::read(&name, &path).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Same two-directions arithmetic `opnbtv`'s own doc comment works
    // through in full; noted rather than re-derived here.
    if maxlen < geometry.reclen {
        host.note(format!(
            "{name} holds {}-byte records and dfaOpen opened it for only {maxlen}, so a \
             read is truncated -- see opnbtv's own doc comment for the full reasoning, \
             which applies identically here",
            geometry.reclen
        ));
    }

    let block = {
        let Host { btrieve, heap, .. } = host;
        btrieve
            .open(call.mem(), heap, &name, &path, geometry, maxlen)
            .map_err(|e| ShimError::Failed(format!("dfaOpen({name}): {e}")))?
    };
    if super::traced() {
        eprintln!("mbbs-trace: DFAOPEN {name} -> {block:?}");
    }

    // Deliberately unreported. The overflow is normal MajorMUD behaviour and
    // the drop is the fidelity: the module nests `dfaSetBlk` deeper than ten
    // and the real host lost the outermost entry too -- see `Btrieve::dfa_set`,
    // where the ten-deep limit and what falls off it are documented. Saying so
    // at runtime told nobody anything after the first time and buried the
    // notes that matter, at `WCCKNMS2.DAT [x1678]` in one session.
    let _ = host.btrieve.dfa_set(block);
    Ok(abi::Ret::Ptr(block))
}

/// `VOID dfaClose(struct dfablk *dfap)` -- close a data file.
///
/// `DFAAPI.C:654-672`, and -- like [`btv::clsbtv`] -- `dfa=dfap` is written
/// **unconditionally**, before anything decides whether there is a file to
/// close: `goodptr(dfa=dfap)` assigns as part of evaluating its own
/// argument, whichever way the guard then goes. Closing makes the argument
/// current on the way out, even when it names nothing this host opened.
///
/// `DFAAPI.C` additionally macro-`ASSERT`s `dfap != NULL` (`:660`) where
/// `clsbtv` has none -- academic in a release build, where `ASSERT`
/// compiles to nothing and `goodptr`'s own null check is what actually
/// runs, so this reproduces `clsbtv`'s exact behaviour for a null `dfap`
/// rather than the debug-build assertion failure nothing here can trigger.
///
/// The ten-deep stack behind `dfa` is not purged, for the identical reason
/// [`btv::clsbtv`]'s own doc comment gives for `bbstk`: a later
/// `dfaRstBlk` that pops down to a since-closed block writes it into `dfa`
/// unexamined, and whichever routine reads `dfa` next gets the same "not an
/// open file" refusal a pointer that was never opened gets.
pub fn dfaClose<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dfap = call.ptr();
    host.btrieve.dfa_set_current(dfap);

    let Host { btrieve, heap, .. } = host;
    btrieve
        .close(call.mem(), heap, dfap)
        .map_err(|e| ShimError::Failed(format!("dfaClose: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaSetBlk(struct dfablk *dfaptr)` -- make `dfaptr` the current dfa
/// file.
///
/// A thin argument-reading wrapper around
/// [`crate::btrieve::Btrieve::dfa_set`] -- see that method's own doc comment
/// for the full account of why it pushes the *new* pointer rather than the
/// one it replaces, which is the one genuine behavioural difference from
/// [`btv::setbtv`].
///
/// # A refusal this host adds, not one `DFAAPI.C` has
///
/// `dfaSetBlk` itself never dereferences `dfaptr` -- it only stores it
/// (`:186-192`), so on the real host a garbage or stale pointer set here
/// caused no fault until some *later* `dfa*` call tried to use it, deep
/// inside `btvu()`. `setbtv` (`btv::setbtv`) already made the opposite
/// choice for the identical shape -- refuse eagerly, naming this call
/// rather than a much later, harder-to-diagnose one -- and this follows it,
/// deliberately extending a convention `DFAAPI.C`'s own text does not
/// state, on the same "runtime crashes are better than undefined
/// behaviour, and a refusal beats a deferred one" reasoning.
pub fn dfaSetBlk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dfaptr = call.ptr();
    if super::traced() {
        eprintln!("mbbs-trace: DFASETBLK {dfaptr:?}");
    }
    if dfaptr != Btrieve::<AbiMem<A>>::null() {
        host.btrieve.block(dfaptr).map_err(|e| ShimError::Failed(format!("dfaSetBlk: {e}")))?;
    }
    // Deliberately unreported. The overflow is normal MajorMUD behaviour and
    // the drop is the fidelity: the module nests `dfaSetBlk` deeper than ten
    // and the real host lost the outermost entry too -- see `Btrieve::dfa_set`,
    // where the ten-deep limit and what falls off it are documented. Saying so
    // at runtime told nobody anything after the first time and buried the
    // notes that matter, at `WCCKNMS2.DAT [x1678]` in one session.
    let _ = host.btrieve.dfa_set(dfaptr);
    Ok(abi::Ret::Void)
}

/// `VOID dfaRstBlk(VOID)` -- restore the dfa file that was current before
/// the last `dfaSetBlk`.
///
/// A thin wrapper around [`crate::btrieve::Btrieve::dfa_restore`], which
/// *is* the same shifting shape [`btv::rstbtv`]/[`Btrieve::restore`] give
/// `bbstk` -- see `dfa_restore`'s own doc comment. An empty stack is not an
/// error, for the identical reason `rstbtv`'s is not.
pub fn dfaRstBlk<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (_restored, empty) = host.btrieve.dfa_restore();
    if empty {
        host.note(
            "dfaRstBlk with nothing to restore, so the current dfa file is now null -- \
             which is what the real host does, and what every dfa* routine that guards \
             at all checks for"
                .to_owned(),
        );
    }
    Ok(abi::Ret::Void)
}

/// `GBOOL dfaQuery(const VOID *key, SHORT keynum, USHORT qryopt)` -- position
/// the file without reading a record.
///
/// `DFAAPI.C:227-275`. `DFAAPI.H:173-181`'s `dfaQuery*` macros use the
/// identical 55-63 numbering `BTVSTF.H`'s `q*btv` macros do (`dfaQueryEQ`
/// is `dfaQuery(k,n,55)`, exactly `qeqbtv`'s own `qrybtv(k,n,55)`), so this
/// is [`btv::locate`] with `into: None`, the same as [`btv::qrybtv`].
///
/// **Explicit guard** (`:235-238`, `if (dfa == NULL) { ASSERT(...);
/// return(FALSE); }`) -- quiet `FALSE` with no file current, the same as
/// `qrybtv`.
pub fn dfaQuery<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaQuery")? else {
        btv::note_no_file(host, "dfaQuery");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let key = call.ptr();
    let keynum = btv::i16_arg::<A>(call.int());
    let qryopt = btv::i16_arg::<A>(call.int());
    let op = btv::Op::of(qryopt - 50).ok_or_else(|| {
        ShimError::Failed(format!(
            "dfaQuery with option {qryopt}, which is none of the nine DFAAPI.H's \
             dfaQuery* macros produce"
        ))
    })?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(btv::locate(
        call,
        host,
        btv::Request {
            who: "dfaQuery",
            block,
            op,
            keynum,
            value: key,
            into: None,
            lock: 0,
        },
    )?))))
}

/// `GBOOL dfaQueryNP(USHORT qryopt)` -- step in key order, and read the
/// record.
///
/// `DFAAPI.C:277-312`, `ASSERT(qryopt >= 55 && qryopt <= 63)`. Unlike
/// [`btv::qnpbtv`]'s citation of `bb->lastkn` being passed directly rather
/// than through a `-1` sentinel, `DFAAPI.C:296` does the identical thing
/// (`btvu(qryopt-50,dfa->data,dfa->key,dfa->lastkn,dfa->reclen)`) -- and it
/// is the same non-difference: [`btv::key_number`] given `-1` *reads*
/// `lastkn` back without rewriting it, which is bit-for-bit what passing
/// `dfa->lastkn` directly already does, so `keynum: -1` is the right
/// translation here too.
///
/// **Explicit guard** (`:283-286`), quiet `FALSE` with no file current.
pub fn dfaQueryNP<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaQueryNP")? else {
        btv::note_no_file(host, "dfaQueryNP");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let qryopt = btv::i16_arg::<A>(call.int());
    let op = btv::Op::of(qryopt - 50).ok_or_else(|| {
        ShimError::Failed(format!("dfaQueryNP with option {qryopt}, which is not a get operation"))
    })?;
    let into = btv::data_buffer(host, block)?;
    let found = btv::locate(
        call,
        host,
        btv::Request {
            who: "dfaQueryNP",
            block,
            op,
            keynum: -1,
            value: Btrieve::<AbiMem<A>>::null(),
            into: Some(into),
            lock: 0,
        },
    )?;
    if found {
        note_len(host, block);
    }
    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `VOID dfaGetLock(VOID *recptr, const VOID *key, SHORT keynum, USHORT
/// getopt, USHORT loktyp)` -- get a record by key, or stop.
///
/// `DFAAPI.C:314-361`. `dfaGetLock` is to [`dfaAcqLock`] exactly what
/// `getbtvl` is to `obtbtvl` -- same five arguments, same opcode range
/// 5-13, same underlying [`btv::locate`] call, and the identical one-place
/// divergence [`btv::getbtv`]'s own doc comment quotes side by side with
/// `obtbtvl`: `:352-353` sends *any* nonzero status straight to
/// `dfaPosError("GET")`, with no status-4/9/`dfaWasLocked` exception --
/// where [`dfaAcqLock`]'s own `:404-411` has exactly that exception. So a
/// module written against `dfaGetLock` is entitled to assume the record is
/// there; one written against `dfaAcqLock` is not.
///
/// **Explicit guard** (`:322-325`), quiet no-op with no file current --
/// `VOID`, so there is nothing to answer either way.
pub fn dfaGetLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaGetLock")? else {
        btv::note_no_file(host, "dfaGetLock");
        return Ok(abi::Ret::Void);
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = btv::i16_arg::<A>(call.int());
    let getopt = btv::i16_arg::<A>(call.int());
    let lock = btv::i16_arg::<A>(call.int());

    let op = btv::Op::of(getopt).ok_or_else(|| {
        ShimError::Failed(format!(
            "dfaGetLock with option {getopt}, which is none of the nine BTVSTF.H-style \
             g-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => btv::data_buffer(host, block)?,
        false => into,
    };
    let found = btv::locate(
        call,
        host,
        btv::Request {
            who: "dfaGetLock",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock,
        },
    )?;
    if !found {
        let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
        return Err(ShimError::Failed(format!(
            "dfaGetLock found no record in {} -- DFAAPI.C:352-353 sends any nonzero \
             status straight to dfaPosError(\"GET\"), unlike dfaAcqLock's status-4/9/\
             dfaWasLocked special case, so this refuses instead of answering false",
            file.name()
        )));
    }
    note_len(host, block);
    Ok(abi::Ret::Void)
}

/// `GBOOL dfaAcqLock(VOID *recptr, const VOID *key, SHORT keynum, USHORT
/// obtopt, USHORT loktyp)` -- acquire a record by key.
///
/// `DFAAPI.C:363-419`, and this is [`btv::obtbtvl`] with a `dfa` prefix:
/// identical five arguments, identical opcode range 5-13, identical
/// status-4/9/`dfaWasLocked` -> quiet `FALSE` convention (`:404-411`), so
/// [`btv::locate`]'s own return -- `false` for not-found -- is already the
/// right answer with nothing extra to check. The highest-imported symbol in
/// the whole `dfa*` family (37 of 71 surveyed modules).
///
/// **Explicit guard** (`:372-376`), quiet `FALSE` with no file current.
///
/// # Cross-channel: a different channel already holding this record
///
/// `btv::locate` already took `lock` in the session-wide, unowned
/// `ops::LockTable` (mode-mixing bookkeeping, shared with `btv*`,
/// unchanged). Once that -- and delivery -- have already succeeded, this
/// also attributes the lock to the channel currently running
/// ([`current_owner`]) through
/// [`crate::btrieve::Btrieve::dfa_take_lock`]. A *different* channel
/// already holding the exact record found is folded into `found = false`
/// here, which is exactly the `dfaWasLocked()` -> quiet `FALSE` case
/// `DFAAPI.C:404-411` already describes for status 84/85 -- so this needs
/// no new branch below, only a `found` that can now also come back `false`
/// for this reason.
pub fn dfaAcqLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaAcqLock")? else {
        btv::note_no_file(host, "dfaAcqLock");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = btv::i16_arg::<A>(call.int());
    let obtopt = btv::i16_arg::<A>(call.int());
    let lock = btv::i16_arg::<A>(call.int());

    let op = btv::Op::of(obtopt).ok_or_else(|| {
        ShimError::Failed(format!(
            "dfaAcqLock with option {obtopt}, which is none of the nine BTVSTF.H-style \
             a-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => btv::data_buffer(host, block)?,
        false => into,
    };
    let found = btv::locate(
        call,
        host,
        btv::Request {
            who: "dfaAcqLock",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock,
        },
    )?;
    let found = match (found && lock != 0, current_owner(call, host)) {
        (true, Some(owner)) => host
            .btrieve
            .dfa_take_lock(block, lock, owner)
            .map_err(ShimError::Failed)?,
        (true, None) | (false, _) => found,
    };
    if found {
        note_len(host, block);
    }
    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `GBOOL dfaAcqNPLock(VOID *recptr, GBOOL chkcas, USHORT anpopt, USHORT
/// loktyp)` -- step to the next/previous record and say whether it is
/// still in the same key group.
///
/// `DFAAPI.C:421-440`, structurally identical to `PLBTVSTF.C`'s
/// `anpbtvlk` (which [`btv::anpbtv`]'s own doc comment quotes in full) with
/// two arguments `anpbtv` fixes at 1/0 taken as real ones here: `chkcas`
/// selects `strcmp` (case-sensitive, [`btv::strcmp_eq`]) versus `stricmp`
/// ([`stricmp_eq`], this file's own), and `loktyp` is threaded through to
/// [`dfaAcqLock`]'s own `locate` call instead of fixed at 0.
///
/// The saved-key-then-step-then-compare shape, including the "if `recptr`
/// is null the comparison is not what it looks like" caveat, is exactly
/// `anpbtv`'s own -- see that routine's doc comment rather than repeating
/// it here.
///
/// **Explicit guard** (`:428-431`), quiet `FALSE` with no file current.
pub fn dfaAcqNPLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let chkcas = btv::i16_arg::<A>(call.int());
    let anpopt = btv::i16_arg::<A>(call.int());
    let loktyp = btv::i16_arg::<A>(call.int());

    let Some(block) = dfa_positioned(host, "dfaAcqNPLock")? else {
        btv::note_no_file(host, "dfaAcqNPLock");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    // `btv::acquire_next_prev`, not a body of its own: `DFAAPI.C:432-436` and
    // `PLBTVSTF.C:409-412` are the same four steps, and this file used to
    // transcribe them a second time. See that core's doc comment for the one
    // divergence the two copies had already grown.
    let stepped = btv::acquire_next_prev(
        call, host, "dfaAcqNPLock", block, recptr, chkcas != 0, anpopt, loktyp,
    )?;
    // `DFAAPI.C:433` records the length once the step succeeded, BEFORE the
    // key comparison at `:434-436` decides the answer -- so a record found
    // whose key moved still updates `dfa->lastlen`.
    let Some(equal) = stepped else {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    note_len(host, block);
    Ok(abi::Ret::Int(A::Int::from(u16::from(equal))))
}

/// `LONG dfaAbs(VOID)` -- the absolute position of the current record.
///
/// `DFAAPI.C:448-457`, opcode 22 -- the identical Btrieve call
/// [`btv::absbtv`] makes. **No guard of any kind**, not even `ASSERT`:
/// `btvu(22,&abspos,NULL,0,sizeof(LONG))` runs straight into `dfa->posblk`.
/// `absbtv` had a real zero to reproduce (`PLBTVSTF.C:426`'s own guard);
/// this has none, so a missing file is a refusal rather than an invented
/// `0` -- `0` is also a real file offset a module could mistake for "no
/// file current" here, the same reasoning `absbtv`'s own doc comment gives
/// for why it does not answer `0` when merely unpositioned either.
pub fn dfaAbs<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = dfa_required(host, "dfaAbs")?;
    let position = btv::current_position(host, "dfaAbs", block)?;
    if super::btrieve_traced() {
        let name = host
            .btrieve
            .block(block)
            .map(|file| file.name().to_owned())
            .unwrap_or_default();
        eprintln!("mbbs-btv: dfaAbs {name} -> {position} (module sees {:#010x})", position_swap(position));
    }
    Ok(abi::Ret::Long(position_swap(position)))
}

/// `dfaAcqAbsLock`/`dfaGetAbsLock`'s shared middle, which is now
/// [`btv::absolute`] with this side's own two answers filled in.
///
/// `GALPORT.C` names `aabbtvl`/`dfaAcqAbsLock` and `gabbtvl`/`dfaGetAbsLock`
/// one routine each, and this used to be a second transcription of
/// `btv::absolute` -- the same find-position, place-cursor, take-lock,
/// answer-key, deliver sequence written out again. Only two things ever
/// differed, and both are parameters now: where the file comes from
/// (`dfa_required` here against `positioned` there) and what a negative key
/// number means (`DFAAPI.C` ASSERTs `keynum >= 0`; `PLBTVSTF.C:483` stores it
/// unchecked).
///
/// `note_len` stays here rather than moving into the core: `dfa->lastlen` is
/// this side's bookkeeping and the `btv*` spellings have no such field.
///
/// # Cross-channel: a different channel already holding this record
///
/// Same rule [`dfaAcqLock`]'s own doc comment states, folded into `found`
/// here for the identical reason: `dfaAcqAbsLock` already treats any
/// nonzero status as `false` (`DFAAPI.C:496-503`, `return(status == 0)`),
/// and `dfaGetAbsLock` already refuses whenever this returns `false`
/// (`:467-469`) -- so making a cross-channel conflict just another way to
/// come back `false` gets both callers' already-divergent handling right
/// with no extra code in either.
///
/// # Errors
///
/// A negative key number, no `dfa` file current, or whatever
/// [`btv::absolute`] refuses.
fn dfa_acq_abs<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &'static str,
    recptr: A::Ptr,
    abspos: u32,
    keynum: i16,
    loktyp: i16,
) -> Result<bool, ShimError> {
    let block = dfa_required(host, who)?;
    let found = btv::absolute(
        call,
        host,
        btv::Position {
            who,
            block,
            negative_keynum: btv::NegativeKey::Refuse,
            // `dfaGetAbsLock` reports its own failure (`DFAAPI.C:467-469`
            // sends it to `dfaPosError("GET-ABSOLUTE")`), so the core must
            // answer `false` and let the caller do it.
            fatal: false,
            lock: loktyp,
            into: recptr,
            position: abspos,
            keynum,
        },
    )?;
    let found = match (found && loktyp != 0, current_owner(call, host)) {
        (true, Some(owner)) => host
            .btrieve
            .dfa_take_lock(block, loktyp, owner)
            .map_err(ShimError::Failed)?,
        (true, None) | (false, _) => found,
    };
    if super::btrieve_traced() {
        let name = host
            .btrieve
            .block(block)
            .map(|file| file.name().to_owned())
            .unwrap_or_default();
        eprintln!("mbbs-btv: {who} {name} abspos={abspos} keynum={keynum} -> {found}");
    }
    if found {
        note_len(host, block);
    }
    Ok(found)
}

/// `GBOOL dfaAcqAbsLock(VOID *recptr, LONG abspos, SHORT keynum, USHORT
/// loktyp)` -- acquire the record at a file position.
///
/// See [`dfa_acq_abs`], which is this routine's whole body. The single
/// import measured (`re/isv_union_pe_symbols.tsv`), against
/// [`dfaGetAbsLock`]'s 17 -- consistent with `DFAAPI.C:459-470` treating
/// `dfaGetAbsLock` as the one modules were meant to call and this as its
/// worker.
pub fn dfaAcqAbsLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let abspos = position_swap(call.long());
    let keynum = btv::i16_arg::<A>(call.int());
    let loktyp = btv::i16_arg::<A>(call.int());
    let found = dfa_acq_abs(call, host, "dfaAcqAbsLock", recptr, abspos, keynum, loktyp)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `VOID dfaGetAbsLock(VOID *recptr, LONG abspos, SHORT keynum, USHORT
/// loktyp)` -- get the record at a file position, or stop.
///
/// `DFAAPI.C:459-470`:
///
///
/// A two-line wrapper: [`dfa_acq_abs`] is the whole body, and this refuses
/// when it answers `false` instead of returning it -- the same `gabbtvl`
/// relationship to `aabbtv` has, restated for a family whose worker refuses
/// on no file rather than answering quietly (see [`dfa_acq_abs`]'s own doc
/// comment).
pub fn dfaGetAbsLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let abspos = position_swap(call.long());
    let keynum = btv::i16_arg::<A>(call.int());
    let loktyp = btv::i16_arg::<A>(call.int());
    let found = dfa_acq_abs(call, host, "dfaGetAbsLock", recptr, abspos, keynum, loktyp)?;
    if !found {
        let block = host.btrieve.dfa_current();
        let name = host
            .btrieve
            .block(block)
            .map(|file| file.name().to_owned())
            .unwrap_or_else(|_| "<no dfa file>".to_owned());
        return Err(ShimError::Failed(format!(
            "dfaGetAbsLock found no record in {name} at that position -- DFAAPI.C:467-469 \
             sends a failed dfaAcqAbsLock straight to dfaPosError(\"GET-ABSOLUTE\")"
        )));
    }
    Ok(abi::Ret::Void)
}

/// `GBOOL dfaStepLock(VOID *recptr, USHORT stpopt, USHORT loktyp)` -- walk
/// the file in the order the pages hold it.
///
/// `DFAAPI.C:507-532`. The core -- which physical position `stpopt`
/// (24/33/34/35) moves to from whichever [`Cursor`] the file already holds
/// -- is [`btv::stpbtvl`]'s own body, quoted here verbatim rather than
/// factored into a shared helper: `btv::stpbtv`'s own doc comment already
/// made and explains that same choice for the second copy of this logic,
/// and this file follows the same "append, don't restructure an
/// already-tested routine" precedent for the third.
///
/// **Explicit guard** (`:513-516`), quiet `FALSE` with no file current --
/// the one member of this family where `dfa*` is *more* defensive than its
/// `btv*` counterpart: `stpbtvl` (`PLBTVSTF.C:509`) has no guard at all and
/// dereferences `bb` twice before anything is checked, which is why
/// `btv::stpbtvl`/`btv::stpbtv` both refuse on a missing file rather than
/// answering quietly. `dfaStepLock` genuinely does check first.
///
/// # Cross-channel: a different channel already holding this record
///
/// `DFAAPI.C:521-527` has its own `dfaWasLocked()` -> quiet `FALSE`
/// exception for `dfaStepLock`, same as `dfaAcqLock`'s. Once positioning
/// and delivery have already succeeded, this attributes the lock to the
/// channel currently running ([`current_owner`]); a different channel
/// already holding the landed-on record overrides the `TRUE` this would
/// otherwise return.
pub fn dfaStepLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaStepLock")? else {
        btv::note_no_file(host, "dfaStepLock");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let into = call.ptr();
    let opt = btv::i16_arg::<A>(call.int());
    let lock = btv::i16_arg::<A>(call.int());
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => btv::data_buffer(host, block)?,
        false => into,
    };

    // 33/34/24/35 are Btrieve's Step First/Last/Next/Previous -- see
    // `btv::stpbtvl`'s own doc comment.
    let step = match opt {
        33 => Step::First,
        34 => Step::Last,
        24 => Step::Next,
        35 => Step::Previous,
        _ => {
            return Err(ShimError::Failed(format!(
                "dfaStepLock with option {opt}, which is none of 24, 33, 34 and 35"
            )));
        }
    };

    btv::load(host, block)?;
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();

    // `Block::step_position` (`crates/btrieve::ops`), not `Block::records()`
    // -- see `btv::stpbtvl`'s own doc comment for why. This is the third
    // copy of this exact positioning logic (`btv::stpbtvl`, `btv::stpbtv`,
    // this one), and MajorMUD calls *this* one -- `dfaStepLock` is the
    // `dfa*` name for the same operation `btv*`'s `stpbtvl` answers, and
    // `WCCMMUD.DLL` uses the `dfa*` family throughout -- so the whole-file
    // read this used to make on every step is the one of the three that
    // was actually reachable from a live board.
    let at = file
        .step_position(step)
        .map_err(|e| ShimError::Failed(format!("dfaStepLock({opt}) on {name}: {e}")))?;
    if super::traced() || super::btrieve_traced() {
        eprintln!("mbbs-btv: dfaStepLock {name} {step:?} -> {at:?}");
    }
    if at.is_none() {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    btv::take_lock(host, block, lock)?;
    btv::deliver(call, host, block, into)?;
    if lock != 0
        && let Some(owner) = current_owner(call, host)
        && !host
            .btrieve
            .dfa_take_lock(block, lock, owner)
            .map_err(ShimError::Failed)?
    {
        // A different channel already holds the record this landed on --
        // `DFAAPI.C:521-527`'s own `dfaWasLocked()` case, quiet `FALSE`
        // rather than the `TRUE` a successful step otherwise returns.
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    note_len(host, block);
    Ok(abi::Ret::Int(A::Int::from(1u16)))
}


/// `VOID dfaInsertV(VOID *recptr, USHORT length)` -- insert a new record at
/// a module-supplied length.
///
/// `DFAAPI.C:599-616`. **No `dfa == NULL` guard** -- only `ASSERT` (`:604`)
/// before `dfa->data`/`dfa->key` are read unguarded -- so a missing file is
/// refused, the same shape `btv::dinsbtv`/`upvbtv` already give their own
/// unguarded reads.
pub fn dfaInsertV<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let length = btv::ushort_arg::<A>(call.int());
    let block = dfa_required(host, "dfaInsertV")?;
    btv::insert_record(call, host, "dfaInsertV", block, recptr, length, true)?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaInsert(VOID *recptr)` -- insert a new record at the dfa file's
/// own record length.
///
/// `DFAAPI.C:591-597`: `dfaInsertV(recptr,dfa->reclen)`, nothing else. Same
/// unguarded-fault shape as [`dfaInsertV`] -- `dfa->reclen` is read to build
/// the call before `dfaInsertV`'s own (nonexistent) guard would run.
pub fn dfaInsert<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = dfa_required(host, "dfaInsert")?;
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    btv::insert_record(call, host, "dfaInsert", block, recptr, length, true)?;
    Ok(abi::Ret::Void)
}

/// `GBOOL dfaInsertDup(VOID *recptr)` -- insert a new record, answering
/// `FALSE` rather than stopping on a duplicate-key collision.
///
/// `DFAAPI.C:618-643`, `dfa->reclen` always (never variable, unlike
/// [`dfaInsertV`]). **`ASSERT` only, no runtime guard** (`:624`) -- the
/// same unguarded shape as [`dfaInsert`]/[`dfaInsertV`], despite this
/// routine's own duplicate-key handling being the quiet one.
pub fn dfaInsertDup<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = dfa_required(host, "dfaInsertDup")?;
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    let ok = btv::insert_record(call, host, "dfaInsertDup", block, recptr, length, false)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(ok))))
}


/// `VOID dfaUpdateV(VOID *recptr, USHORT length)` -- update the record the
/// file is positioned on, at a module-supplied length.
///
/// `DFAAPI.C:542-559`, opcode 3 -- the identical Btrieve call
/// [`btv::upvbtv`] makes, with the identical "every nonzero status,
/// duplicate-key included, is an error" convention (`:556-558` has no
/// `case 5`), which is exactly why this reuses [`btv::update_variable`]
/// unchanged rather than writing its own write path.
///
/// **No `dfa == NULL` guard** -- `ASSERT` only (`:547`), `dfa->data`/
/// `dfa->key`/`dfa->lastkn` read unguarded -- so a missing file is refused.
pub fn dfaUpdateV<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let length = btv::ushort_arg::<A>(call.int());
    let block = dfa_required(host, "dfaUpdateV")?;
    btv::update_variable(call, host, "dfaUpdateV", block, recptr, length, false)?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaUpdate(VOID *recptr)` -- update the record the file is
/// positioned on, at the dfa file's own record length.
///
/// `DFAAPI.C:534-540`: `dfaUpdateV(recptr,dfa->reclen)`, nothing else. Same
/// unguarded-fault shape as [`dfaUpdateV`] -- `dfa->reclen` is read before
/// `dfaUpdateV`'s own (nonexistent) guard would run.
pub fn dfaUpdate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = dfa_required(host, "dfaUpdate")?;
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    btv::update_variable(call, host, "dfaUpdate", block, recptr, length, false)?;
    Ok(abi::Ret::Void)
}

/// `GBOOL dfaUpdateDup(VOID *recptr)` -- update the record the file is
/// positioned on, answering `FALSE` rather than stopping on a duplicate-key
/// collision.
///
/// `DFAAPI.C:561-589`, `dfa->reclen` always. **Explicit guard**
/// (`:567-570`, `if (dfa == NULL) { ASSERT(...); return(FALSE); }`) --
/// unlike every other member of the insert/update family, this one really
/// does check first, which is why it answers quietly here rather than
/// refusing.
pub fn dfaUpdateDup<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let Some(block) = dfa_positioned(host, "dfaUpdateDup")? else {
        btv::note_no_file(host, "dfaUpdateDup");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    // `btv::update_variable`, not a helper of its own: `GALPORT.C` names
    // `dupdbtv`/`dfaUpdateDup` one routine, and this file used to carry a
    // second transcription of it.
    let ok = btv::update_variable(call, host, "dfaUpdateDup", block, recptr, length, true)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(ok))))
}

/// `VOID dfaDelete(VOID)` -- delete the record the file is positioned on.
///
/// `DFAAPI.C:645-652`:
///
///
/// No arguments -- the record is whichever one the dfa file is positioned
/// on, exactly [`btv::delbtv`]'s own shape, except this host actually
/// writes: [`crate::btrieve::Block::delete`] exists in the engine already
/// (built for the fixed-length case, refusing on a variable-length file)
/// but had no shim calling it before this file -- `btv::delbtv` and
/// `btv::invbtv` both still refuse outright, per their own doc comments'
/// "nothing in this crate writes to a Btrieve file". `dfaDelete` is the
/// first caller.
///
/// `dfa->lastkn` (the key number `btvu`'s call passes) plays no part in
/// which record is deleted or which keys' indexes are updated -- deletion
/// removes the record from every key's order at once
/// (`Records::delete`) -- the identical non-role `btv::dupdbtv`'s own doc
/// comment describes for the same argument in the update call.
///
/// **`ASSERT` only, no runtime guard** (`:648`), `dfa->lastkn`/
/// `dfa->reclen` read unguarded as arguments to the underlying call -- a
/// missing file is refused.
pub fn dfaDelete<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = dfa_required(host, "dfaDelete")?;
    // `btv::delete_record`, not a body of its own: `GALPORT.C` names
    // `delbtv`/`dfaDelete` one routine, and the cursor invalidation this used
    // to omit (`ce64fbbe`) is exactly what a second transcription loses.
    btv::delete_record(host, "dfaDelete", block)?;
    Ok(abi::Ret::Void)
}

// ---------------------------------------------------------------------------
// Everything below was added after this file's first pass, once
// `re/wg33src/LIB/WGSERVER.DEF` -- the vendor's own export definition file,
// not merely a corpus survey of what surveyed modules happen to import --
// turned out to name thirteen more `dfa*` ordinals (433-465 plus 1517) than
// the nineteen/twenty this file started with. `_dfalgrec` (ordinal 20, far
// from the 433-465 block and spelled nothing like `DFAAPI.H`'s own
// camelCase convention) and `_audfAddEntry`/`_audfAddLowLevel` (a different
// prefix entirely) are excluded as unrelated symbols that merely share a
// substring, not omissions.
//
// `dfaStatus` (`DFAAPI.H:390-394`) is deliberately not implemented: it is
// declared in the header but `WGSERVER.DEF` exports no `_dfaStatus` symbol
// at all, so it is not part of the surface a PE module can actually import.

/// `VOID dfaMode(SHORT mode)` -- set the mode the next `dfaOpen` uses.
///
/// `DFAAPI.C:179-184`: `dfaomode=mode;`, unconditional -- no validation at
/// all, unlike [`btv::omdbtv`]'s own refusal of a value outside the five
/// `PRIMBV`/`ACCLBV`/`RONLBV`/`VERFBV`/`EXCLBV` constants. Reproduced rather
/// than tightened: `dfaMode` genuinely stores whatever it is given.
///
/// A mode is now read -- but on the *other* side of the family, and not
/// this one. Task 8 made `Btrieve::open` consume `Btrieve::mode()`, the
/// mode `omdbtv` sets and `opnbtv` opens under, so a file `opnbtv` opens
/// `RONLBV`/`VERFBV`/`EXCLBV`/`ACCLBV` is now enforced accordingly.
/// `dfaOpen` calls that same `Btrieve::open`, but still passes it no mode
/// of its own, so `dfa_mode` (what this function sets) is stored and
/// reported (`Btrieve::dfa_mode`) but still not consumed by anything.
///
/// **This is a real, live gap, not a dormant one.** The 32-bit PE
/// `WCCMMUD.DLL` imports this very symbol (`_dfaMode`, one of 17 `dfa*`
/// imports from `WGSERVER.EXE`) and calls it with `0` at boot on the live
/// board -- see `Btrieve::dfa_current`'s own doc comment for the measured
/// import list. A module on that path calling `dfaMode(RONLBV)` today
/// gets no enforcement at all: see `Btrieve::dfa_mode`'s own doc comment
/// for the named follow-up this is filed under.
pub fn dfaMode<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mode = btv::i16_arg::<A>(call.int());
    host.btrieve.dfa_set_mode(mode);
    Ok(abi::Ret::Void)
}

/// `VOID dfaBegTrans(USHORT loktyp)` -- begin a datafile transaction.
///
/// `DFAAPI.C:201-209`: `btvu(19+loktyp,NULL,NULL,0,0)`, opcode 19 -- the
/// identical Btrieve call [`crate::btrieve::Btrieve::begin`] already
/// implements and measured against genuine Btrieve; that method's own doc
/// comment already cites this exact line for why a transaction has no file
/// argument at all (a property of the whole session, not of any one file).
///
/// `loktyp` is read and discarded -- `begin`'s own doc comment: measured
/// with no observable difference on a host that is single-process by
/// construction, so there is never a second session to wait on or not.
pub fn dfaBegTrans<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _loktyp = btv::i16_arg::<A>(call.int());
    host.btrieve
        .begin()
        .map_err(|e| ShimError::Failed(format!("dfaBegTrans: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaEndTrans(VOID)` -- end the current datafile transaction, keeping
/// every write made since [`dfaBegTrans`].
///
/// `DFAAPI.C:219-225`, opcode 20 -- [`crate::btrieve::Btrieve::end`].
pub fn dfaEndTrans<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    host.btrieve
        .end()
        .map_err(|e| ShimError::Failed(format!("dfaEndTrans: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaAbtTrans(VOID)` -- abort the current datafile transaction,
/// undoing every write made since [`dfaBegTrans`].
///
/// `DFAAPI.C:211-217`, opcode 21 -- [`crate::btrieve::Btrieve::abort`].
pub fn dfaAbtTrans<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    host.btrieve
        .abort()
        .map_err(|e| ShimError::Failed(format!("dfaAbtTrans: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `ULONG dfaCountRec(VOID)` -- how many records the current dfa file holds.
///
/// `DFAAPI.C:778-792`. Reads exactly [`crate::btrieve::Geometry::records`]
/// -- the same field [`btv::cntrbtv`] answers with -- rather than building a
/// full `B_STAT` reply just to pull one field back out of it:
/// `crate::btrieve::stat`'s own module doc comment names `dfaCountRec` and
/// [`dfaRecLen`] specifically as needing none of that machinery, because
/// this host already has both fields on `Geometry` without a wire reply to
/// build one from.
///
/// **No guard of any kind**, not even `ASSERT` -- straight to
/// `btvu(15,...)`, which dereferences `dfa->posblk` unconditionally.
pub fn dfaCountRec<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = dfa_required(host, "dfaCountRec")?;
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Ok(abi::Ret::Long(file.geometry().records))
}

/// `USHORT dfaRecLen(VOID)` -- the file's own record length.
///
/// `DFAAPI.C:794-808`. `statbf.fs.reclen` is the *file's* record length
/// ([`crate::btrieve::Geometry::reclen`]), not the module's own declared one
/// ([`crate::btrieve::Block::maxlen`], what [`dfaOpen`]'s `maxlen` argument
/// set) -- the identical two-numbers-allowed-to-differ distinction
/// [`btv::opnbtv`]'s own doc comment works through for `bb->reclen`.
///
/// **No guard of any kind.**
pub fn dfaRecLen<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = dfa_required(host, "dfaRecLen")?;
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Ok(abi::Ret::Int(A::Int::from(file.geometry().reclen)))
}

/// `VOID dfaStat(USHORT len)` -- Btrieve's own `B_STAT` reply, verbatim,
/// into `dfa->data`.
///
/// `DFAAPI.C:810-818`:
///
///
/// The wire reply this writes is [`crate::btrieve::Block::stat`]'s own
/// [`crate::btrieve::Stat::wire`] -- measured against genuine Pervasive
/// Btrieve 6.15 (`crate::btrieve::stat`'s own module doc comment,
/// `tools/btrieve-oracle/statprobe.c`), the same reply this host already
/// hands back verbatim for whatever routine reaches it first.
///
/// # `len` too short is a refusal, not a truncated delivery
///
/// `:815-817` has no exception for status 22 ("buffer too short") the way
/// [`dfaAcqAbsLock`]'s own `:489-497` does -- *any* nonzero status,
/// truncation included, goes straight to `dfaErrPtr("STAT")`. So a module
/// that offers too small a buffer stops the board on the real host, and
/// this refuses by name rather than delivering
/// [`crate::btrieve::deliver`]'s own truncated prefix, which exists
/// for exactly the read-family calls that *do* have a 22-is-fine exception.
///
/// **`ASSERT` only, no runtime guard** (`:814`) -- a missing file is
/// refused.
pub fn dfaStat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let len = btv::ushort_arg::<A>(call.int());
    let block = dfa_required(host, "dfaStat")?;

    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let stat = file.stat().map_err(|e| ShimError::Failed(e.to_string()))?;
    let version = file.geometry().version;
    let name = file.name().to_owned();
    let data = file.data();
    let full = stat.wire(version, 0);

    let (usable, short) = crate::btrieve::deliver(&full, usize::from(len));
    if short {
        return Err(ShimError::Failed(format!(
            "dfaStat({len}) on {name}: a {}-byte STAT reply does not fit -- DFAAPI.C:815-817 \
             sends any nonzero status (including 22, \"buffer too short\") straight to \
             dfaErrPtr(\"STAT\"), with no exception for it, so this refuses rather than \
             deliver a truncated reply",
            full.len()
        )));
    }
    let bytes = usable.to_vec();
    data.write(call.mem(), &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `VOID dfaUnlock(LONG abspos, SHORT keynum)` -- release a lock.
///
/// `DFAAPI.C:836-850`:
///
///
/// `DFAAPI.H:211-214`'s four macros produce three distinct `keynum`s:
/// `dfaUnlockOne()` (`0`: release the single lock this session holds at the
/// file's *current* position), `dfaUnlockCur()`/`dfaUnlockSel(f)` (`-1`:
/// release the lock at an explicit `abspos`, current position or not), and
/// `dfaUnlockAll()` (`-2`: release every lock this session holds, on every
/// file).
///
/// **Only `keynum == 0` is implemented.** It is exactly what
/// [`crate::btrieve::Btrieve::unlock_current`] already is -- release the
/// lock this session holds at `at`'s own current cursor position, Btrieve op
/// 27 with `keynum = 0`, per that method's own doc comment. The other two
/// are refused by name rather than approximated: `keynum == -1` needs an
/// unlock-at-an-arbitrary-position primitive (`unlock_current` only ever
/// reads the block's *own* current position, never an explicit one), and
/// `keynum == -2` needs a release-every-lock-this-session-holds-across-
/// every-file primitive -- [`crate::btrieve::ops::LockTable::release_all_for`]
/// releases every lock on *one* block, not across the whole session. Neither
/// primitive exists in the engine today.
pub fn dfaUnlock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _abspos = call.long();
    let keynum = btv::i16_arg::<A>(call.int());
    let block = dfa_required(host, "dfaUnlock")?;
    match keynum {
        0 => {
            host.btrieve.unlock_current(block).map_err(ShimError::Failed)?;
            Ok(abi::Ret::Void)
        }
        -1 => Err(ShimError::Failed(
            "dfaUnlock with keynum -1 (dfaUnlockCur/dfaUnlockSel: unlock at an explicit \
             abspos) -- this host's engine has no unlock-at-an-arbitrary-position \
             primitive, only unlock-at-the-block's-own-current-position \
             (crate::btrieve::Btrieve::unlock_current)"
                .to_owned(),
        )),
        -2 => Err(ShimError::Failed(
            "dfaUnlock with keynum -2 (dfaUnlockAll: release every lock this session \
             holds, on every file) -- this host's LockTable only releases every lock on \
             one block at a time (release_all_for), not across the whole session"
                .to_owned(),
        )),
        _ => Err(ShimError::Failed(format!(
            "dfaUnlock with keynum {keynum}, which is none of 0, -1 or -2 -- DFAAPI.H's own \
             four macros produce only those three"
        ))),
    }
}

/// `GBOOL dfaWasLocked(VOID)` -- whether the last dfa* call failed because
/// the record or file was locked by another session.
///
/// `DFAAPI.C:852-856`: `return(status == 84 || status == 85)` -- Btrieve's
/// own "record locked by another user" and "file locked by another process"
/// statuses.
///
/// **Always `FALSE`, but no longer because status 84/85 is unproducible.**
/// Task 9 gave `dfaAcqLock`/`dfaAcqAbsLock`/`dfaGetAbsLock`/`dfaStepLock` a
/// real cross-channel conflict (`crate::btrieve::Btrieve::dfa_take_lock`,
/// status 84 -- one channel already holding a record refuses a different
/// one), so this host genuinely can produce the condition `DFAAPI.C:852-856`
/// names now. What is still missing is a place to remember *which* of the
/// two reasons the last dfa* call answered "not found" for: real Btrieve's
/// own `status` is a single global every `btvu()` call updates and every
/// routine, `dfaWasLocked` included, reads directly; this host has no
/// equivalent slot, and adding one is a bigger change than this task's four
/// named calls -- see the final report's own concerns. `FALSE` here is
/// consequently still every answer, not a chosen one -- register the gap
/// rather than guess at it. Not blocking today's one surveyed caller:
/// `_dfaWasLocked` is absent from `WCCMMUD.DLL`'s own 32-bit import list
/// (`crate::btrieve::Btrieve::dfa_current`'s doc comment).
pub fn dfaWasLocked<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `USHORT dfaLastLen(VOID)` -- length of the last record a `dfa*` call
/// read.
///
/// `DFAAPI.C:442-446`: `return(lastlen)`. See the engine's own
/// `Btrieve::dfa_last_len` field doc comment for exactly which calls in this
/// file update it (every one that delivers a record into the module's
/// buffer) and the one respect in which that is narrower than the real
/// host's own `lastlen` (updated after *every* `btvu()` call, writes
/// included).
pub fn dfaLastLen<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(host.btrieve.dfa_last_len())))
}

/// `GBOOL dfaVirgin(const CHAR *src, const CHAR *dst)` -- copy a virgin
/// database file into place.
///
/// `DFAAPI.C:858-873`, and `dfaCopyFile` (`:987-1017`), which does the
/// actual copy. `src`/`dst` are stems without extension --
/// `stlcat(stlcpy(srcfil,src,...),".vir",...)` and
/// `stlcat(stlcpy(dstfil,(dst==NULL)?src:dst,...),".dat",...)` -- so `dst`
/// null means the same stem as `src`.
///
/// This host already performs the identical atomic copy-then-rename
/// implicitly, in [`Host::btrieve_file`], whenever [`dfaOpen`]/`opnbtv`
/// finds no `.DAT` but a matching `.VIR` beside it. `dfaVirgin` needs its
/// own copy of that shape rather than a call into `btrieve_file` because it
/// allows `dst` to differ from `src`, which `btrieve_file`'s own
/// same-stem-only convention does not.
///
/// # Answers `FALSE`, never refuses
///
/// `dfaCopyFile` (`:987-1017`) never `catastro`s -- every failure path
/// (`fopen` on the source, `fopen` on the destination, a write error)
/// returns `FALSE` and nothing else. So a missing virgin file or a failed
/// copy is a quiet `FALSE` here too, matching this one routine's own
/// graceful-failure convention rather than this crate's usual refusal.
pub fn dfaVirgin<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let src = call.ptr();
    let dst = call.ptr();

    let src_stem = String::from_utf8_lossy(
        src.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let dst_stem = if dst == Btrieve::<AbiMem<A>>::null() {
        src_stem.clone()
    } else {
        String::from_utf8_lossy(
            dst.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
        )
        .into_owned()
    };

    let virgin_name = format!("{src_stem}.VIR");
    let dat_name = format!("{dst_stem}.DAT");
    let Some(from) = host.find(&virgin_name) else {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let to = host.root.join(&dat_name);
    let part = host.root.join(format!("{dat_name}.{}.part", std::process::id()));
    let copied = std::fs::copy(&from, &part).and_then(|_| std::fs::rename(&part, &to));
    match copied {
        Ok(_) => {
            host.note(format!("installed {dat_name} from {} via dfaVirgin", from.display()));
            Ok(abi::Ret::Int(A::Int::from(1u16)))
        }
        Err(_) => {
            let _ = std::fs::remove_file(&part);
            Ok(abi::Ret::Int(A::Int::from(0u16)))
        }
    }
}

/// `VOID dfaCreate(const CHAR *filnam, VOID *databuf, SHORT keyno, USHORT
/// lendbuf)` -- create a new datafile from a raw create-request buffer.
///
/// `DFAAPI.C:757-776`. `filnam` -- despite doubling as the underlying
/// Btrieve call's *key* argument (`:767`, `crtdfa->key=(CHAR *)filnam`) --
/// really is the filename: every file-identifying opcode in this API passes
/// the name through the key slot ([`dfaOpen`]'s own `:155` does the
/// identical thing). `databuf`/`lendbuf` are one `struct dfaStatFileSpec`
/// (`DFAAPI.H:147-155`, 16 bytes, fixed width -- `USHORT`/`UCHAR` fields
/// throughout, nothing ABI-dependent) followed by one `struct
/// dfaStatKeySpec` (`:157-165`, 16 bytes) per key *segment* -- the exact
/// shape [`dfaCreateSpec`] builds and the exact shape
/// `crate::btrieve::stat` measured a STAT *reply* as (one entry per
/// segment, not per key -- see that module's own doc comment).
///
/// # `keyno` is an overwrite flag, not a key count
///
/// `DFAAPI.H`'s own prototype comment calls it "number of keys", and that
/// does not match the one call site that exists: `dfaCreateSpec`'s own
/// `:753` passes `overwrite ? 0 : -1`, and the number of keys travels
/// inside the buffer instead (`fs.nKeys`). Real Btrieve's `B_CREATE`
/// `keynum` argument selects overwrite behaviour (`0` = replace an existing
/// file, `-1` = refuse if one exists), which is what this host honours:
/// [`crate::btrieve::create`] never overwrites regardless of
/// `keyno` (see its own doc comment), so `keyno == 0` on a file that
/// already exists is refused here exactly as `keyno == -1` would be -- an
/// honest refusal in place of an overwrite this engine cannot perform, not
/// a silent one.
///
/// # What this engine cannot represent
///
/// [`crate::btrieve::FileSpec`] has no `flags` field and always
/// pre-allocates exactly one data page -- so a nonzero `fs.flags`
/// (`DFACF_VARIABLE`/`BLANKTRUNC`/`COMPRESS`/`KEYONLY`/`FREESPACE*`) or an
/// `fs.nPreAllocate` other than `0`/`1` is refused before anything is
/// written, rather than silently creating a file with a shape the module
/// did not ask for. A segment's `DFASF_ALTCOLLATE` bit is refused the same
/// way: this host has no alternate collating sequence file to read one
/// from either.
///
/// # Unverified against a live engine
///
/// Every other write path in this crate is measured against genuine
/// Pervasive Btrieve (`tools/btrieve-oracle`); this one and
/// [`dfaCreateSpec`] are derived from `DFAAPI.H`'s struct layouts and
/// `DFAAPI.C`'s own build loop with no oracle run against either, because
/// no PE module in this repository's corpus calls either routine and there
/// is no create-side probe for this wire format yet. Stated as a fact about
/// this implementation's confidence, not smoothed over.
pub fn dfaCreate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let databuf = call.ptr();
    let keyno = btv::i16_arg::<A>(call.int());
    let lendbuf = btv::ushort_arg::<A>(call.int());

    let named = String::from_utf8_lossy(
        filnam.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<A>::dos_name(&named).map_err(ShimError::Failed)?;

    if keyno != 0 && keyno != -1 {
        return Err(ShimError::Failed(format!(
            "dfaCreate({name}) with keyno {keyno}, which is neither 0 (overwrite) nor -1 \
             (refuse if it exists) -- DFAAPI.C:753's own call site produces only those two"
        )));
    }

    let bytes = databuf
        .resolve(call.mem(), usize::from(lendbuf))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let spec = decode_create_buffer(&bytes)?;

    let path = host.root.join(&name);
    crate::btrieve::create(&path, &spec)
        .map_err(|e| ShimError::Failed(format!("dfaCreate({name}): {e}")))?;
    host.note(format!("created {name} via dfaCreate"));
    Ok(abi::Ret::Void)
}

/// Decode one `struct dfaStatFileSpec` + N `struct dfaStatKeySpec` buffer
/// (`DFAAPI.H:147-165`) into a [`crate::btrieve::FileSpec`]. See
/// [`dfaCreate`]'s own doc comment for the byte layout and for what this
/// refuses outright.
fn decode_create_buffer(bytes: &[u8]) -> Result<crate::btrieve::FileSpec, ShimError> {
    use crate::btrieve::{FileSpec, KeySpec, SegmentSpec};

    const FILE_SPEC: usize = 16;
    const KEY_SPEC: usize = 16;
    const DFAKF_DUPLICATE: u16 = 1;
    const DFAKF_MODIFYABLE: u16 = 2;
    const DFAKF_MANUAL: u16 = 8;
    const DFAKF_NULL: u16 = 512;
    const DFASF_SEGMENT: u16 = 16;
    const DFASF_ALTCOLLATE: u16 = 32;
    const DFASF_DESCENDING: u16 = 64;

    if bytes.len() < FILE_SPEC {
        return Err(ShimError::Failed(format!(
            "a create buffer of {} bytes, shorter than one dfaStatFileSpec ({FILE_SPEC})",
            bytes.len()
        )));
    }
    let word = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);

    let record_length = word(0);
    let page_size = word(2);
    let n_keys = word(4);
    let flags = word(10);
    let n_pre_allocate = word(14);

    if flags != 0 {
        return Err(ShimError::Failed(format!(
            "create flags {flags:#06x} -- this engine's FileSpec has no representation for \
             DFACF_VARIABLE/BLANKTRUNC/COMPRESS/KEYONLY/FREESPACE*, so any nonzero flags \
             word is refused rather than silently ignored"
        )));
    }
    if n_pre_allocate > 1 {
        return Err(ShimError::Failed(format!(
            "nPreAllocate {n_pre_allocate} -- this engine always pre-allocates exactly one \
             data page, so anything else cannot be honoured"
        )));
    }

    let mut keys: Vec<KeySpec> = Vec::new();
    let mut segments: Vec<SegmentSpec> = Vec::new();
    let mut duplicates = false;
    let mut modifiable = false;
    let mut at = FILE_SPEC;
    let mut seen_keys = 0u16;

    while seen_keys < n_keys {
        if at + KEY_SPEC > bytes.len() {
            return Err(ShimError::Failed(format!(
                "a create buffer with {n_keys} keys declared, but the key spec at byte {at} \
                 runs past the buffer's own {} bytes",
                bytes.len()
            )));
        }
        let position = word(at);
        let length = word(at + 2);
        let seg_flags = word(at + 4);
        let ext_type = bytes[at + 10];

        if seg_flags & DFASF_ALTCOLLATE != 0 {
            return Err(ShimError::Failed(
                "a key segment with DFASF_ALTCOLLATE set -- this host has no alternate \
                 collating sequence file to read one from"
                    .to_owned(),
            ));
        }
        if seg_flags & (DFAKF_MANUAL | DFAKF_NULL) != 0 {
            return Err(ShimError::Failed(format!(
                "a key with flags {seg_flags:#06x} setting DFAKF_MANUAL and/or DFAKF_NULL -- \
                 unsupported on the read side (see keys::parse's own UNSUPPORTED table), so \
                 refused here rather than written and discovered broken later"
            )));
        }

        duplicates = seg_flags & DFAKF_DUPLICATE != 0;
        modifiable = seg_flags & DFAKF_MODIFYABLE != 0;

        segments.push(SegmentSpec {
            // `position` is 1-based on the wire (`DFAAPI.C:734`'s own
            // `+1`); `SegmentSpec::offset` is 0-based, `create.rs`'s own
            // convention.
            offset: position.checked_sub(1).ok_or_else(|| {
                ShimError::Failed(
                    "a key segment at wire position 0, which is not valid -- positions are \
                     1-based"
                        .to_owned(),
                )
            })?,
            length,
            kind: ext_type,
            descending: seg_flags & DFASF_DESCENDING != 0,
        });

        let more_segments = seg_flags & DFASF_SEGMENT != 0;
        at += KEY_SPEC;
        if !more_segments {
            keys.push(KeySpec {
                segments: std::mem::take(&mut segments),
                duplicates,
                modifiable,
            });
            seen_keys += 1;
        }
    }

    Ok(FileSpec {
        record_length,
        page_size,
        keys,
    })
}

/// `VOID dfaCreateSpec(const CHAR *fileName, GBOOL overwrite, size_t
/// recordLength, size_t pageSize, INT flags, INT nPreAllocate, INT nKeys,
/// struct dfaKeySpec *keys, const CHAR *altFile)` -- create a new datafile
/// from a structured key specification.
///
/// `DFAAPI.C:674-755`. The one PE ordinal in the whole family that lives far
/// from the rest (`WGSERVER.DEF` ordinal 1517, against 433-465 for
/// everything else) -- consistent with it being a later, higher-level
/// addition over [`dfaCreate`].
///
/// # This does not build the wire buffer at all
///
/// The vendor implementation builds exactly the `struct dfaStatFileSpec` +
/// `struct dfaStatKeySpec[]` buffer [`dfaCreate`]'s own doc comment
/// describes, then calls `dfaCreate` (`:753`) to do the actual work. This
/// host skips that intermediate step: it reads `keys`' own module-memory
/// arrays directly into a [`crate::btrieve::FileSpec`] and calls
/// [`crate::btrieve::create`] itself. That is a faithful
/// reimplementation of the *observable* behaviour (a file is created with
/// the record length, page size and keys the module described, or it is
/// not) without re-deriving `dfaCreate`'s own wire format only to decode it
/// straight back out again one call later.
///
/// # Reading `struct dfaKeySpec`/`struct dfaSegSpec` out of module memory
///
/// `DFAAPI.H:60-92`:
///
///
/// Every `size_t`/`INT`/pointer field is read at `A`'s own width
/// ([`Abi::INT_WIDTH`]/[`Abi::PTR_WIDTH`]) -- realistically always `Wg32`,
/// since no `Wg16` module imports any `dfa*` symbol at all (`MAJORBBS.DEF`
/// exports none; only `WGSERVER.DEF` does).
///
/// **Assumed struct layout, not measured.** `dfaSegSpec`'s four `size_t`/
/// `INT` fields plus one `CHAR` sum to `4*INT_WIDTH + 1` bytes, and the
/// ordinary C ABI pads a struct to its widest member's alignment (`INT_WIDTH`
/// itself, here) with nothing in `DFAAPI.H` suggesting `#pragma pack` --
/// so each `segs[]` entry is read at a `round_up(4*INT_WIDTH + 1,
/// INT_WIDTH)` stride (20 bytes under `Wg32`). This is the one place in
/// this file with no compiled binary or measured wire capture behind it: no
/// PE module in this repository's corpus calls `dfaCreateSpec`, so there is
/// nothing to check the stride against. If a module using this turns up and
/// this refuses or misreads its `segs[]` array past the first segment, this
/// assumption is where to look first.
///
/// # What this engine cannot represent
///
/// Identical to [`dfaCreate`]'s own list: any nonzero `flags`, an
/// `nPreAllocate` other than `0`/`1`, and a non-null `altFile`/
/// `DFASF_ALTCOLLATE` segment (an alternate collating sequence this host
/// cannot read). All three refuse before anything is created.
///
/// `overwrite` has the identical caveat [`dfaCreate`]'s own doc comment
/// gives `keyno`: this engine's `create()` never overwrites, so
/// `overwrite != 0` on a file that already exists is refused rather than
/// honoured.
pub fn dfaCreateSpec<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    use crate::btrieve::{FileSpec, KeySpec, SegmentSpec};

    const DFAKF_DUPLICATE: u32 = 1;
    const DFAKF_MODIFYABLE: u32 = 2;
    const DFAKF_MANUAL: u32 = 8;
    const DFAKF_NULL: u32 = 512;
    const DFASF_ALTCOLLATE: u32 = 32;
    const DFASF_DESCENDING: u32 = 64;

    let file_name = call.ptr();
    let _overwrite: u32 = call.int().into();
    let record_length: u32 = call.int().into();
    let page_size: u32 = call.int().into();
    let flags: u32 = call.int().into();
    let n_pre_allocate: u32 = call.int().into();
    let n_keys: u32 = call.int().into();
    let keys_ptr = call.ptr();
    let alt_file = call.ptr();

    let name = {
        let named = String::from_utf8_lossy(
            file_name.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
        )
        .into_owned();
        Host::<A>::dos_name(&named).map_err(ShimError::Failed)?
    };

    if flags != 0 {
        return Err(ShimError::Failed(format!(
            "dfaCreateSpec({name}) with flags {flags:#010x} -- this engine's FileSpec has \
             no representation for DFACF_VARIABLE/BLANKTRUNC/COMPRESS/KEYONLY/FREESPACE*, \
             so any nonzero flags word is refused"
        )));
    }
    if n_pre_allocate > 1 {
        return Err(ShimError::Failed(format!(
            "dfaCreateSpec({name}) with nPreAllocate {n_pre_allocate} -- this engine always \
             pre-allocates exactly one data page"
        )));
    }
    if alt_file != Btrieve::<AbiMem<A>>::null() {
        return Err(ShimError::Failed(format!(
            "dfaCreateSpec({name}) with a non-null altFile -- this host has no alternate \
             collating sequence support to read one into"
        )));
    }

    let record_length = u16::try_from(record_length).map_err(|_| {
        ShimError::Failed(format!(
            "dfaCreateSpec({name}): record length {record_length} does not fit in 16 bits"
        ))
    })?;
    let page_size = u16::try_from(page_size).map_err(|_| {
        ShimError::Failed(format!(
            "dfaCreateSpec({name}): page size {page_size} does not fit in 16 bits"
        ))
    })?;

    // `struct dfaKeySpec { INT flags; INT nSegments; struct dfaSegSpec *segs; }`
    // -- no padding: two same-width `INT`s followed by a pointer of the
    // same width is already aligned.
    let key_stride = 2 * A::INT_WIDTH + A::PTR_WIDTH;
    // `struct dfaSegSpec { size_t position; size_t length; INT type; INT
    // flags; CHAR nullChar; }` -- padded to `INT_WIDTH`, see this routine's
    // own doc comment.
    let seg_stride = (4 * A::INT_WIDTH + 1).next_multiple_of(A::INT_WIDTH);

    let mut file_keys: Vec<KeySpec> = Vec::with_capacity(n_keys as usize);
    for key_index in 0..n_keys {
        let key_at = A::ptr_checked_add(keys_ptr, key_index as usize * key_stride).ok_or_else(|| {
            ShimError::Failed(format!(
                "dfaCreateSpec({name}): key {key_index}'s own dfaKeySpec entry runs past \
                 addressable memory"
            ))
        })?;

        let key_flags: u32 = read_uint::<A>(call, key_at)?;
        let n_segments: u32 =
            read_uint::<A>(call, A::ptr_checked_add(key_at, A::INT_WIDTH).ok_or_else(|| {
                ShimError::Failed(format!("dfaCreateSpec({name}): key {key_index}'s nSegments field is unaddressable"))
            })?)?;
        let segs_at = read_ptr::<A>(
            call,
            A::ptr_checked_add(key_at, 2 * A::INT_WIDTH).ok_or_else(|| {
                ShimError::Failed(format!("dfaCreateSpec({name}): key {key_index}'s segs field is unaddressable"))
            })?,
        )?;

        if key_flags & DFAKF_MANUAL != 0 || key_flags & DFAKF_NULL != 0 {
            return Err(ShimError::Failed(format!(
                "dfaCreateSpec({name}): key {key_index} sets DFAKF_MANUAL and/or DFAKF_NULL \
                 -- unsupported on the read side (see keys::parse's own UNSUPPORTED table)"
            )));
        }
        let duplicates = key_flags & DFAKF_DUPLICATE != 0;
        let modifiable = key_flags & DFAKF_MODIFYABLE != 0;

        let mut segments: Vec<SegmentSpec> = Vec::with_capacity(n_segments as usize);
        for seg_index in 0..n_segments {
            let seg_at = A::ptr_checked_add(segs_at, seg_index as usize * seg_stride).ok_or_else(|| {
                ShimError::Failed(format!(
                    "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s dfaSegSpec \
                     entry runs past addressable memory"
                ))
            })?;
            let position = read_uint::<A>(call, seg_at)?;
            let length = read_uint::<A>(
                call,
                A::ptr_checked_add(seg_at, A::INT_WIDTH).ok_or_else(|| {
                    ShimError::Failed(format!(
                        "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s length \
                         field is unaddressable"
                    ))
                })?,
            )?;
            let kind = read_uint::<A>(
                call,
                A::ptr_checked_add(seg_at, 2 * A::INT_WIDTH).ok_or_else(|| {
                    ShimError::Failed(format!(
                        "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s type \
                         field is unaddressable"
                    ))
                })?,
            )?;
            let seg_flags = read_uint::<A>(
                call,
                A::ptr_checked_add(seg_at, 3 * A::INT_WIDTH).ok_or_else(|| {
                    ShimError::Failed(format!(
                        "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s flags \
                         field is unaddressable"
                    ))
                })?,
            )?;

            if seg_flags & DFASF_ALTCOLLATE != 0 {
                return Err(ShimError::Failed(format!(
                    "dfaCreateSpec({name}): key {key_index} segment {seg_index} sets \
                     DFASF_ALTCOLLATE -- this host has no alternate collating sequence file \
                     to read one from"
                )));
            }

            let kind = u8::try_from(kind).map_err(|_| {
                ShimError::Failed(format!(
                    "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s type \
                     {kind} does not fit in a byte"
                ))
            })?;
            let position = u16::try_from(position).map_err(|_| {
                ShimError::Failed(format!(
                    "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s position \
                     {position} does not fit in 16 bits"
                ))
            })?;
            let length = u16::try_from(length).map_err(|_| {
                ShimError::Failed(format!(
                    "dfaCreateSpec({name}): key {key_index} segment {seg_index}'s length \
                     {length} does not fit in 16 bits"
                ))
            })?;

            segments.push(SegmentSpec {
                // `dfaCreateSpec`'s own segments are already 0-based
                // (`struct dfaSegSpec`'s own doc comment, `DFAAPI.H:61`) --
                // unlike the wire format [`decode_create_buffer`] reads,
                // which is 1-based. No `-1` here.
                offset: position,
                length,
                kind,
                descending: seg_flags & DFASF_DESCENDING != 0,
            });
        }

        file_keys.push(KeySpec {
            segments,
            duplicates,
            modifiable,
        });
    }

    let path = host.root.join(&name);
    let spec = FileSpec {
        record_length,
        page_size,
        keys: file_keys,
    };
    crate::btrieve::create(&path, &spec)
        .map_err(|e| ShimError::Failed(format!("dfaCreateSpec({name}): {e}")))?;
    host.note(format!("created {name} via dfaCreateSpec"));
    Ok(abi::Ret::Void)
}

/// Read one `A::INT_WIDTH`-byte `INT`/`size_t` field out of module memory
/// at an arbitrary address, zero-extended to `u32`. [`Call::int`] cannot do
/// this: it reads the *next* argument off the call frame in order, not an
/// arbitrary address, which is what walking a `struct dfaKeySpec`/`struct
/// dfaSegSpec` array needs.
fn read_uint<A: Abi>(call: &mut Call<A>, at: A::Ptr) -> Result<u32, ShimError> {
    let bytes = at
        .resolve(call.mem(), A::INT_WIDTH)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(A::int_from_bytes(bytes).into())
}

/// Read one pointer-width field out of module memory at an arbitrary
/// address -- the `segs` field of a `struct dfaKeySpec`, specifically. See
/// [`read_uint`]'s own doc comment for why this cannot be [`Call::ptr`].
fn read_ptr<A: Abi>(call: &mut Call<A>, at: A::Ptr) -> Result<A::Ptr, ShimError> {
    let bytes = at
        .resolve(call.mem(), A::PTR_WIDTH)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(A::ptr_from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use crate::testing::Fixture;
    use mbbs_machine::m16::{FarPtr, Ret};

    /// The position the module sees is the plain slot position with its two
    /// 16-bit halves swapped -- the exact bytes genuine Btrieve 6.15 returns.
    ///
    /// Measured with `tools/btrieve-oracle/btrvprobe step`: The Rose's
    /// `RCI_MOD1.DAT` record at page 338, slot 1 (plain `338*512+6+234 =
    /// 173296 = 0x0002_a4f0`) reports position `0xa4f0_0002`; the v6 oracle
    /// fixture `DUPKEY30.DAT`'s first record (page 2, slot 0, plain `1030 =
    /// 0x0000_0406`) reports `0x0406_0000`. The swap is its own inverse, so
    /// one function both encodes an outgoing `dfaAbs` and decodes an incoming
    /// `dfaGetAbsLock`/`dfaAcqAbsLock`.
    #[test]
    fn position_swap_matches_genuine_btrieve_and_round_trips() {
        assert_eq!(position_swap(0x0002_a4f0), 0xa4f0_0002, "RCI_MOD1 page 338 slot 1");
        assert_eq!(position_swap(0x0000_0406), 0x0406_0000, "DUPKEY30 page 2 slot 0");
        // Its own inverse: decode(encode(x)) == x, for every position a
        // `dfaGetAbsLock` might have to un-swap back to what `dfaAbs` gave.
        for p in [0u32, 1, 6, 1030, 173296, 0x0002_a4f0, 0xffff_ffff, 0x1234_5678] {
            assert_eq!(position_swap(position_swap(p)), p, "round-trip {p:#x}");
        }
    }

    /// Open a file through `dfaOpen`, as a module would.
    fn open(f: &mut Fixture, name: &str, maxlen: u16) -> FarPtr {
        let at = f.text(name);
        let Ret::Far(block) = f
            .invoke(dfaOpen, &[at.offset, at.selector, maxlen, 0, 0])
            .expect("dfaOpen")
        else {
            panic!("dfaOpen returns a pointer");
        };
        block
    }

    /// Where a dfa file's own record buffer lives.
    fn buffer(f: &Fixture, block: FarPtr) -> FarPtr {
        f.host.btrieve().block(block).expect("open").data()
    }

    /// The two-byte key of the record a read left in a buffer.
    fn got(f: &Fixture, at: FarPtr) -> u16 {
        let bytes = f.machine.resolve(at, 2).expect("readable");
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    /// `dfaQuery(key, keynum, opt)` with a real key value, or the lowest,
    /// highest, next or previous.
    fn query(f: &mut Fixture, keynum: i16, opt: i16) -> bool {
        f.invoke(dfaQuery, &[0, 0, keynum as u16, opt as u16])
            .expect("dfaQuery")
            == Ret::U16(1)
    }

    /// `dfaAcqLock(NULL, key, keynum, opt, lock)` -- acquire into the file's
    /// own data buffer, taking whatever lock `lock` names (`0` for none).
    fn acquire(f: &mut Fixture, key: Option<u16>, keynum: i16, opt: i16, lock: i16) -> bool {
        let value = match key {
            Some(n) => f.bytes(&n.to_le_bytes(), false),
            None => Btrieve::<AbiMem<Wg16>>::null(),
        };
        f.invoke(
            dfaAcqLock,
            &[0, 0, value.offset, value.selector, keynum as u16, opt as u16, lock as u16],
        )
        .expect("dfaAcqLock")
            == Ret::U16(1)
    }

    /// A 64-byte `SAMPLE.DAT`-shaped record: the key at offset 0, a
    /// NUL-terminated name from offset 2, the rest zero. Identical shape to
    /// `shims::btrieve`'s own `sample_record` -- not shared, because that one
    /// is private to that file's test module.
    fn sample_record(key: i16, name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..2].copy_from_slice(&key.to_le_bytes());
        let name = name.as_bytes();
        bytes[2..2 + name.len()].copy_from_slice(name);
        bytes
    }

    // -----------------------------------------------------------------
    // `dfaSetBlk`/`dfaRstBlk`: the ten-deep, shifting stack, and the one
    // place it is not the same shape as `setbtv`/`rstbtv`.
    // -----------------------------------------------------------------

    #[test]
    fn dfa_current_is_null_before_any_open_and_dfaopen_makes_the_new_file_current() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().dfa_current(), Btrieve::<AbiMem<Wg16>>::null());
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(f.host.btrieve().dfa_current(), block);
    }

    /// **The highest-value test in this file.** `dfaSetBlk` pushes the
    /// pointer it was just handed (`DFAAPI.C:186-192`, `*dfastk=dfa=dfaptr;`
    /// evaluates its right-hand side first); `setbtv` pushes the pointer it
    /// is *replacing* (`*bbstk=bb;` reads `bb` before this call's own
    /// assignment). See `Btrieve::dfa_set`'s own doc comment for the full
    /// derivation, including why an open alone cannot tell the two shapes
    /// apart -- an open's own `dfaSetBlk(dfa)` always fires after `dfa` has
    /// already been reassigned to the same new pointer, so both shapes push
    /// the same value.
    ///
    /// They diverge on a call not immediately paired with a restore: calling
    /// `dfaSetBlk` a second time on the pointer that is *already* current.
    /// Traced by hand against both shapes (this file's own commit message
    /// carries the full trace):
    ///
    /// - the real (`dfa_set`) shape pushes `A` **twice**, so it takes THREE
    ///   `dfaRstBlk` calls to reach null, and the first two both still
    ///   answer `A`;
    /// - a `setbtv`-shape "simplification" reads the true previous current
    ///   (`A`, since the redundant call runs after `A` is already current)
    ///   and pushes it once, so only TWO `dfaRstBlk` calls are needed, and
    ///   the second is already null.
    ///
    /// So the discriminating assertion is that the **second** `dfaRstBlk`
    /// after the redundant set still answers `A`, not null. A "simplified"
    /// implementation makes that specific assertion fail while every other
    /// assertion in this file (and in `shims::btrieve`'s own `setbtv`/
    /// `rstbtv` suite) keeps passing -- which is exactly the kind of
    /// divergence invisible to the type system the task that added this test
    /// was written to catch.
    #[test]
    fn dfasetblk_pushing_the_current_pointer_again_diverges_from_the_setbtv_shape() {
        let mut f = Fixture::new();
        let a = open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(f.host.btrieve().dfa_current(), a, "dfaOpen makes the new file current");

        // The redundant, explicit re-set: the module calling dfaSetBlk again
        // on the file that is already current. Nothing in DFAAPI.C guards
        // against this.
        f.invoke(dfaSetBlk, &[a.offset, a.selector]).expect("re-sets the same pointer");
        assert_eq!(f.host.btrieve().dfa_current(), a);

        f.invoke(dfaRstBlk, &[]).expect("restores");
        assert_eq!(
            f.host.btrieve().dfa_current(),
            a,
            "first restore after the redundant set: still A -- a setbtv-shape \
             implementation would already be null here"
        );

        f.invoke(dfaRstBlk, &[]).expect("restores");
        assert_eq!(
            f.host.btrieve().dfa_current(),
            a,
            "second restore: STILL A. dfaSetBlk pushed the pointer it was handed \
             twice, and popping twice answers it twice -- this is the assertion a \
             setbtv-shape simplification fails"
        );

        f.invoke(dfaRstBlk, &[]).expect("restores");
        assert_eq!(
            f.host.btrieve().dfa_current(),
            Btrieve::<AbiMem<Wg16>>::null(),
            "only the third restore runs the stack out"
        );
    }

    #[test]
    fn the_dfa_stack_is_ten_deep_and_the_eleventh_drops_the_oldest() {
        // `DFSTSZ` is 10 and the shift is `movmem`, not an index -- so an
        // eleventh push neither refuses nor grows the stack: it silently
        // loses the outermost entry.
        //
        // Asserted on the stack itself, not on a host note. The note this
        // used to check was removed: MajorMUD overflows this stack as a
        // matter of course, thousands of times a session, so it reported
        // normal behaviour as if it were a fault. The *drop* is still the
        // fidelity being tested, and it is observable without it.
        let mut f = Fixture::new();
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let other = open(&mut f, "OTHER.DAT", 32);

        // Eleven explicit sets on top of what the two opens already pushed.
        for _ in 0..11 {
            f.invoke(dfaSetBlk, &[other.offset, other.selector]).expect("sets");
        }

        // Thirteen restores, and the number is measured rather than reasoned
        // about. Thirteen pushes happened -- `first` from its open, `other`
        // from its own, then eleven explicit sets -- and with the stack made
        // deep enough to keep them all, `first` comes back on restore 13
        // exactly. Any smaller count is a tautology: at ten, and at twelve,
        // `other` is on top whether the stack dropped anything or not, and a
        // DFSTSZ=32 mutation passes. Verified in both directions.
        for _ in 0..13 {
            f.invoke(dfaRstBlk, &[]).expect("restores");
        }
        assert_ne!(
            f.host.btrieve().dfa_current(),
            first,
            "the outermost entry never comes back -- it fell off the bottom. A \
             stack deep enough to have kept it answers SAMPLE.DAT here, which \
             is what makes this the assertion that catches a wrong DFSTSZ"
        );
        assert_eq!(
            f.host.btrieve().dfa_current(),
            other,
            "OTHER.DAT, and never null: `dfaRstBlk` is \
             `movmem(dfastk+1,dfastk,..)`, whose destination is one entry \
             shorter than the stack, so the bottom slot is never written and \
             repeats forever. This stack does not drain, which is why `first` \
             being unreachable is a claim about the drop rather than about \
             running out of entries"
        );
    }

    // -----------------------------------------------------------------
    // `dfaOpen`/`dfaClose`.
    // -----------------------------------------------------------------

    #[test]
    fn dfaopen_refuses_a_non_null_owner() {
        // A refusal this host ADDS -- DFAAPI.C:146-152 passes a non-null
        // owner straight to Btrieve as an access password; this host checks
        // no such password, so honouring it would be a fabricated success.
        let mut f = Fixture::new();
        let name = f.text("SAMPLE.DAT");
        let owner = f.text("PASSWORD");
        let e = f
            .invoke(dfaOpen, &[name.offset, name.selector, 64, owner.offset, owner.selector])
            .expect_err("this host checks no such password");
        assert!(e.to_string().contains("dfaOpen"), "{e}");
        assert!(e.to_string().contains("owner"), "{e}");
    }

    #[test]
    fn dfaopen_notes_a_maxlen_smaller_than_the_files_own_record_length() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 32);
        let note = f.host.notes().last().expect("noted").clone();
        assert!(note.contains("dfaOpen"), "{note}");
        assert!(note.contains("truncated"), "{note}");
    }

    #[test]
    fn dfaclose_writes_its_argument_into_dfa_unconditionally_even_a_file_that_was_never_opened() {
        // `DFAAPI.C:661`'s `goodptr(dfa=dfap)` assigns as part of evaluating
        // its own argument, whichever way the guard then goes.
        let mut f = Fixture::new();
        let nonsense = FarPtr {
            offset: 0x40,
            selector: f.host.globals().selector(),
        };
        assert_eq!(
            f.invoke(dfaClose, &[nonsense.offset, nonsense.selector]).expect("closes"),
            Ret::Void
        );
        assert_eq!(
            f.host.btrieve().dfa_current(),
            nonsense,
            "dfa now names a pointer this host never opened"
        );
        // And whatever asks next, with no other dfaOpen/dfaSetBlk in between,
        // refuses -- it names nothing this host ever opened.
        assert!(f.invoke(dfaAbs, &[]).is_err());
    }

    #[test]
    fn dfaclose_really_closes_the_named_file_and_leaves_a_different_one_open() {
        let mut f = Fixture::new();
        let a = open(&mut f, "SAMPLE.DAT", 64);
        let b = open(&mut f, "OTHER.DAT", 32);
        assert_eq!(f.host.btrieve().dfa_current(), b);

        f.invoke(dfaClose, &[a.offset, a.selector]).expect("closes A, not the current file");
        assert_eq!(
            f.host.btrieve().dfa_current(),
            a,
            "closing A makes A current, overriding B, which was current a moment ago"
        );
        assert!(f.host.btrieve().block(a).is_err(), "A is really closed");
        assert!(f.host.btrieve().block(b).is_ok(), "B is untouched");
    }

    // -----------------------------------------------------------------
    // The query family, and the position it leaves behind.
    // -----------------------------------------------------------------

    #[test]
    fn dfaquery_positions_and_leaves_the_key_but_does_not_read_a_record() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);
        let key = f.host.btrieve().block(block).expect("open").key();

        assert!(query(&mut f, 0, 63), "highest");
        assert_eq!(got(&f, key), 7, "the key it found");
        assert_eq!(got(&f, into), 0, "but the record buffer is untouched");
    }

    #[test]
    fn dfaquerynp_steps_in_key_order_and_reads() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(query(&mut f, 0, 62), "lowest, positions only");
        assert_eq!(got(&f, into), 0, "a query reads no record");

        assert_eq!(f.invoke(dfaQueryNP, &[56]).expect("next"), Ret::U16(1));
        assert_eq!(got(&f, into), 2, "key order: 1 is lowest, so next is 2");
    }

    #[test]
    fn dfaquery_with_no_dfa_file_current_answers_nothing_found() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().dfa_current(), Btrieve::<AbiMem<Wg16>>::null());
        assert!(!query(&mut f, 0, 62));
    }

    // -----------------------------------------------------------------
    // The lock family: dfaAcqLock, dfaGetAbsLock, dfaAcqAbsLock,
    // dfaStepLock -- and dfaGetLock, whose one divergence from dfaAcqLock
    // is worth pinning by value.
    // -----------------------------------------------------------------

    #[test]
    fn dfaacqlock_finds_a_record_by_key_and_records_its_lock_type() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(5), 0, 5, 100), "equal to 5, locked with type 100");
        assert_eq!(got(&f, into), 5);
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), Some(100));
    }

    #[test]
    fn dfaacqlock_answers_false_on_a_key_that_does_not_exist() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(!acquire(&mut f, Some(99), 0, 5, 0), "there is no key 99");
    }

    /// The one documented behavioural difference between `dfaGetLock` and
    /// `dfaAcqLock`: `DFAAPI.C:352-353` sends *any* nonzero status straight
    /// to `dfaPosError("GET")`, with no status-4/9/`dfaWasLocked` exception
    /// -- unlike `dfaAcqLock`'s own `:404-411`. Same file, same missing key,
    /// opposite outcome.
    #[test]
    fn dfagetlock_refuses_on_the_identical_not_found_case_dfaacqlock_answers_quietly() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(!acquire(&mut f, Some(99), 0, 5, 0), "dfaAcqLock on this case: quiet false");

        let value = f.bytes(&99u16.to_le_bytes(), false);
        let e = f
            .invoke(dfaGetLock, &[0, 0, value.offset, value.selector, 0, 5, 0])
            .expect_err("dfaGetLock refuses instead of answering false");
        assert!(e.to_string().contains("dfaGetLock"), "{e}");
    }

    #[test]
    fn dfaacqabslock_finds_the_record_dfaabs_named() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(6), 0, 5, 0), "equal to 6");
        let Ret::U32(position) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };
        assert!(acquire(&mut f, None, 0, 12, 0), "somewhere else entirely");

        assert_eq!(
            f.invoke(dfaAcqAbsLock, &[0, 0, position as u16, (position >> 16) as u16, 0, 0])
                .expect("acquires"),
            Ret::U16(1)
        );
        assert_eq!(got(&f, into), 6, "back on the record dfaAbs named");
    }

    #[test]
    fn dfaacqabslock_answers_false_at_a_position_no_record_has() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let bogus: u32 = 0xFFFF_FFF0;
        assert_eq!(
            f.invoke(dfaAcqAbsLock, &[0, 0, bogus as u16, (bogus >> 16) as u16, 0, 0])
                .expect("answers"),
            Ret::U16(0)
        );
    }

    /// `DFAAPI.C:459-470`: `dfaGetAbsLock` sends a failed `dfaAcqAbsLock`
    /// straight to `dfaPosError`, with no quiet-false exception. Identical
    /// bogus position, opposite outcome from the test above.
    #[test]
    fn dfagetabslock_refuses_at_the_identical_position_dfaacqabslock_answers_quietly() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let bogus: u32 = 0xFFFF_FFF0;
        let e = f
            .invoke(dfaGetAbsLock, &[0, 0, bogus as u16, (bogus >> 16) as u16, 0, 0])
            .expect_err("dfaGetAbsLock has no quiet-false exception for a bad position");
        assert!(e.to_string().contains("dfaGetAbsLock"), "{e}");
    }

    /// `DFAAPI.C:466,484` `ASSERT(keynum >= 0)` -- unlike `aabbtv`/
    /// `gabbtvl`, which tolerate and store a negative one unchecked
    /// (`btv::absolute`'s own doc comment). A behavioural divergence the
    /// vendor source marks deliberately, not an oversight.
    #[test]
    fn dfaacqabslock_refuses_a_negative_key_number_unlike_aabbtv_and_gabbtvl() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f
            .invoke(dfaAcqAbsLock, &[0, 0, 0, 0, (-1i16) as u16, 0])
            .expect_err("DFAAPI.C ASSERTs keynum >= 0");
        assert!(e.to_string().contains("dfaAcqAbsLock"), "{e}");
        assert!(e.to_string().contains("-1"), "{e}");
    }

    #[test]
    fn dfasteplock_walks_the_file_in_the_order_the_pages_hold_it() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        let mut stepped = vec![];
        assert_eq!(f.invoke(dfaStepLock, &[0, 0, 33, 0]).expect("first"), Ret::U16(1));
        stepped.push(got(&f, into));
        while f.invoke(dfaStepLock, &[0, 0, 24, 0]).expect("next") == Ret::U16(1) {
            stepped.push(got(&f, into));
        }
        assert_eq!(stepped, [4, 1, 7, 2, 6, 3, 5], "the order the pages hold, not key order");
    }

    /// `stpbtvl` has no guard at all and refuses by name with no file
    /// current (`shims::btrieve`'s own `stpbtvl_with_no_file_current_refuses_by_name`);
    /// `DFAAPI.C:513-516` genuinely checks first, so `dfaStepLock` answers a
    /// quiet `FALSE` instead -- the one member of this family where `dfa*`
    /// is *more* defensive than its `btv*` counterpart.
    #[test]
    fn dfasteplock_with_no_dfa_file_current_answers_quietly_unlike_stpbtvl() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().dfa_current(), Btrieve::<AbiMem<Wg16>>::null());
        assert_eq!(f.invoke(dfaStepLock, &[0, 0, 33, 0]).expect("answers"), Ret::U16(0));
    }

    // -----------------------------------------------------------------
    // Task 9: cross-channel lock ownership. Two owners, one file, contending
    // for the same record -- the scenario this task exists for: a lock one
    // channel holds across polls is mutual exclusion between *players*.
    // -----------------------------------------------------------------

    /// A host with two channels to contend with each other, over the same
    /// checked-in `tests/data` -- everything else `Fixture::new` sets up.
    fn two_channel_fixture() -> Fixture {
        Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2))
    }

    /// Point `usrnum` at channel `n`, the way [`crate::Host::point_curusr`]
    /// would -- read back by [`current_owner`] the same way a real dfa*
    /// call reads it.
    fn as_channel(f: &mut Fixture, n: i16) {
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &n.to_le_bytes())
            .expect("usrnum placed");
    }

    #[test]
    fn dfaacqlock_refuses_a_record_a_different_channel_already_holds() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(5), 0, 5, 100), "channel 0 locks key 5");

        as_channel(&mut f, 1);
        assert!(
            !acquire(&mut f, Some(5), 0, 5, 100),
            "channel 1 must be refused -- status 84, channel 0 still holds key 5"
        );
        assert!(
            acquire(&mut f, Some(6), 0, 5, 100),
            "channel 1 can still lock an unrelated record: this is not a blanket refusal"
        );
    }

    #[test]
    fn dfaacqlock_lets_the_same_channel_reacquire_its_own_lock() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(5), 0, 5, 100), "first acquire");
        assert!(
            acquire(&mut f, Some(5), 0, 5, 100),
            "re-locking your own record is a harmless no-op, not a conflict with yourself"
        );
    }

    #[test]
    fn dfaacqlock_grants_a_record_a_different_channel_already_released() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(5), 0, 5, 100), "channel 0 locks key 5");
        // Auto-release: `docs/lock-oracle-answer.md` -- taking a second
        // single-record lock releases the first, now scoped to the owner
        // that took it.
        assert!(acquire(&mut f, Some(6), 0, 5, 100), "channel 0 moves its single lock to key 6");

        as_channel(&mut f, 1);
        assert!(
            acquire(&mut f, Some(5), 0, 5, 100),
            "key 5 is free once channel 0's own auto-release let go of it"
        );
    }

    #[test]
    fn dfaacqabslock_refuses_a_position_a_different_channel_already_holds() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(6), 0, 5, 100), "positioned on key 6");
        let Ret::U32(position) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };
        assert_eq!(
            f.invoke(dfaAcqAbsLock, &[0, 0, position as u16, (position >> 16) as u16, 0, 100])
                .expect("acquires"),
            Ret::U16(1),
            "channel 0 takes an abs lock on the same position"
        );

        as_channel(&mut f, 1);
        assert_eq!(
            f.invoke(dfaAcqAbsLock, &[0, 0, position as u16, (position >> 16) as u16, 0, 100])
                .expect("answers"),
            Ret::U16(0),
            "channel 1 refused -- channel 0 still holds this position"
        );
    }

    /// `dfaGetAbsLock` has no quiet-false convention at all
    /// (`dfagetabslock_refuses_at_the_identical_position_dfaacqabslock_answers_quietly`,
    /// above) -- a cross-channel conflict is exactly the same kind of
    /// refusal `DFAAPI.C:467-469` sends to `dfaPosError`, so this refuses by
    /// name rather than answering `0`.
    #[test]
    fn dfagetabslock_refuses_via_hard_error_on_a_cross_channel_conflict() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(6), 0, 5, 100), "positioned on key 6");
        let Ret::U32(position) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };
        assert_eq!(
            f.invoke(dfaAcqAbsLock, &[0, 0, position as u16, (position >> 16) as u16, 0, 100])
                .expect("acquires"),
            Ret::U16(1)
        );

        as_channel(&mut f, 1);
        let e = f
            .invoke(dfaGetAbsLock, &[0, 0, position as u16, (position >> 16) as u16, 0, 100])
            .expect_err("dfaGetAbsLock has no quiet-false exception, cross-channel included");
        assert!(e.to_string().contains("dfaGetAbsLock"), "{e}");
    }

    #[test]
    fn dfasteplock_refuses_a_position_a_different_channel_already_holds() {
        let mut f = two_channel_fixture();
        open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert_eq!(
            f.invoke(dfaStepLock, &[0, 0, 33, 100]).expect("first"),
            Ret::U16(1),
            "channel 0 steps to the first physical record and locks it"
        );

        as_channel(&mut f, 1);
        assert_eq!(
            f.invoke(dfaStepLock, &[0, 0, 33, 100]).expect("answers"),
            Ret::U16(0),
            "channel 1 lands on the identical first physical record -- refused"
        );
        // Physically the second record, not the first -- unaffected by
        // channel 0's hold on the first.
        assert_eq!(
            f.invoke(dfaStepLock, &[0, 0, 24, 100]).expect("answers"),
            Ret::U16(1),
            "a different physical position is unaffected by the conflict above"
        );
    }

    #[test]
    fn closing_the_dfa_file_releases_a_different_channels_hold_too() {
        let mut f = two_channel_fixture();
        let block = open(&mut f, "SAMPLE.DAT", 64);

        as_channel(&mut f, 0);
        assert!(acquire(&mut f, Some(5), 0, 5, 100), "channel 0 locks key 5");

        assert_eq!(
            f.invoke(dfaClose, &[block.offset, block.selector]).expect("closes"),
            Ret::Void
        );

        // Reopening gives a fresh file (and a fresh `BlockId` underneath
        // it), so a lock channel 1 can now take here proves nothing on its
        // own -- see `closing_a_block_releases_the_dfa_locks_surface_too`
        // (`crates/btrieve/src/lib.rs`) for the same fact checked directly
        // against the table `close` releases. This is the shim-level
        // observable: the module can reopen and use the file normally,
        // which a lock leaked past close would not change either -- kept as
        // an end-to-end smoke test of the wiring, not the release proof
        // itself.
        open(&mut f, "SAMPLE.DAT", 64);
        as_channel(&mut f, 1);
        assert!(
            acquire(&mut f, Some(5), 0, 5, 100),
            "the reopened file's key 5 is free to lock"
        );
    }

    // -----------------------------------------------------------------
    // Insert/update/delete, including the V and Dup variants.
    // -----------------------------------------------------------------

    #[test]
    fn dfainsertv_inserts_a_record_readable_after_reopening_and_establishes_currency() {
        let dir = crate::testing::scratch_with("dfa-insertv", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(99, "Zorro"), false);

        f.invoke(dfaInsertV, &[recptr.offset, recptr.selector, 64]).expect("inserts");
        let Ret::U32(after) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };

        // Re-read from disk with a fresh host -- the check that matters.
        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(99), 0, 5, 0), "the new record is on disk");
        assert_eq!(
            g.read(FarPtr { offset: into.offset + 2, selector: into.selector }),
            "Zorro"
        );
        let Ret::U32(expected) = g.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };
        assert_eq!(after, expected, "dfaInsertV established currency on the record it just inserted");
    }

    #[test]
    fn dfainsertv_refuses_a_record_colliding_on_a_key_without_duplicates() {
        let dir = crate::testing::scratch_with("dfa-insertv-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(5, "Imposter"), false);

        let e = f
            .invoke(dfaInsertV, &[recptr.offset, recptr.selector, 64])
            .expect_err("key 5 already belongs to Troll, and dfaInsertV has no case-5 exception");
        assert!(e.to_string().contains("dfaInsertV"), "{e}");
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(7), "nothing written");
    }

    /// `DFAAPI.C:637-638`'s own `case 5: break;` -- the one insert routine
    /// that answers quietly on the identical collision the test above
    /// refuses on.
    #[test]
    fn dfainsertdup_answers_false_on_the_identical_collision_instead_of_refusing() {
        let dir = crate::testing::scratch_with("dfa-insertdup-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(5, "Imposter"), false);

        assert_eq!(
            f.invoke(dfaInsertDup, &[recptr.offset, recptr.selector]).expect("answers"),
            Ret::U16(0)
        );
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(7), "nothing written");
    }

    #[test]
    fn dfaupdatev_updates_the_positioned_record_in_place_and_it_is_readable_afterwards() {
        let dir = crate::testing::scratch_with("dfa-updatev", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "equal to 5, which is Troll");
        let Ret::U32(before) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };

        let recptr = f.bytes(&sample_record(5, "TROLLX"), false);
        f.invoke(dfaUpdateV, &[recptr.offset, recptr.selector, 64]).expect("updates");
        let Ret::U32(after) = f.invoke(dfaAbs, &[]).expect("position") else {
            panic!("dfaAbs returns a long");
        };
        assert_eq!(before, after, "opcode 3 rewrites the record in place");

        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(5), 0, 5, 0), "still key 5");
        assert_eq!(
            g.read(FarPtr { offset: into.offset + 2, selector: into.selector }),
            "TROLLX"
        );
    }

    #[test]
    fn dfaupdatev_refuses_a_duplicate_key_collision_with_no_case_5_exception() {
        let dir = crate::testing::scratch_with("dfa-updatev-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(6, "Imposter"), false);

        let e = f
            .invoke(dfaUpdateV, &[recptr.offset, recptr.selector, 64])
            .expect_err("key 6 already belongs to Elf, and upvbtv's own :544-546 has no case 5");
        assert!(e.to_string().contains("dfaUpdateV"), "{e}");
    }

    #[test]
    fn dfaupdatedup_answers_false_on_the_identical_collision_instead_of_refusing() {
        let dir = crate::testing::scratch_with("dfa-updatedup-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(6, "Imposter"), false);

        assert_eq!(
            f.invoke(dfaUpdateDup, &[recptr.offset, recptr.selector]).expect("answers"),
            Ret::U16(0)
        );
    }

    /// `DFAAPI.C:567-570` really does check `dfa == NULL` first for
    /// `dfaUpdateDup` -- unlike `dfaUpdate`/`dfaUpdateV`, which read
    /// `dfa->data` unguarded and so refuse. Same missing file, opposite
    /// outcome from the family it otherwise mirrors.
    #[test]
    fn dfaupdatedup_has_its_own_explicit_guard_and_answers_quietly_with_no_dfa_file_current() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().dfa_current(), Btrieve::<AbiMem<Wg16>>::null());
        let recptr = f.bytes(&sample_record(1, "X"), false);
        assert_eq!(
            f.invoke(dfaUpdateDup, &[recptr.offset, recptr.selector]).expect("answers"),
            Ret::U16(0)
        );

        let e = f
            .invoke(dfaUpdateV, &[recptr.offset, recptr.selector, 64])
            .expect_err("dfaUpdateV has no such guard and refuses instead");
        assert!(e.to_string().contains("dfaUpdateV"), "{e}");
    }

    /// `dfaDelete` is the first shim in this crate to call
    /// `Block::delete` -- `btv::delbtv`/`invbtv` both still refuse outright.
    #[test]
    fn dfadelete_removes_the_positioned_record_and_it_is_gone_after_reopening() {
        let dir = crate::testing::scratch_with("dfa-delete", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "equal to 5, which is Troll");
        f.invoke(dfaDelete, &[]).expect("deletes");
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(6));

        let mut g = Fixture::rooted(dir);
        open(&mut g, "SAMPLE.DAT", 64);
        assert!(!acquire(&mut g, Some(5), 0, 5, 0), "gone from disk, not just from memory");
        assert_eq!(g.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(6));
    }

    /// After a delete the file must be positioned [`Cursor::Nowhere`], the
    /// same decision `btv::delbtv` and `btrieve::btrcall`'s own op-4 dispatch
    /// both take -- `crates/btrieve/src/btrcall.rs:576-583` says why in
    /// as many words: "so a deleted record does not stay reachable as
    /// current".
    ///
    /// `dfaDelete` was the one of the three delete paths that did not, so the
    /// block stayed positioned on a record that no longer existed. Asserted
    /// through a second `dfaDelete`, which must refuse for want of a position
    /// rather than act on the stale one.
    #[test]
    fn dfadelete_leaves_the_file_positioned_nowhere() {
        let dir = crate::testing::scratch_with("dfa-delete-cursor", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "equal to 5, which is Troll");
        f.invoke(dfaDelete, &[]).expect("deletes");

        let e = f
            .invoke(dfaDelete, &[])
            .expect_err("the cursor is Nowhere, so there is nothing to delete");
        assert!(
            e.to_string().contains("not positioned on a record"),
            "a delete must not leave the deleted record current: {e}"
        );
    }

    #[test]
    fn dfadelete_with_nothing_positioned_refuses() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(dfaDelete, &[]).expect_err("never positioned");
        assert!(e.to_string().contains("dfaDelete"), "{e}");
    }

    // -----------------------------------------------------------------
    // `dfaUnlock` -- only `keynum == 0` is implemented.
    // -----------------------------------------------------------------

    #[test]
    fn dfaunlock_keynum_zero_releases_the_lock_at_the_current_position() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(6), 0, 5, 100), "equal to 6, locked");
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), Some(100));

        f.invoke(dfaUnlock, &[0, 0, 0]).expect("unlocks");
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), None);
    }

    #[test]
    fn dfaunlock_refuses_every_keynum_this_engine_cannot_honour() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);

        // dfaUnlockCur/dfaUnlockSel: unlock at an explicit abspos. No such
        // primitive exists in this engine.
        let e = f.invoke(dfaUnlock, &[0, 0, (-1i16) as u16]).expect_err("-1 refuses");
        assert!(e.to_string().contains("dfaUnlock"), "{e}");
        assert!(e.to_string().contains("-1"), "{e}");

        // dfaUnlockAll: release every lock this session holds, on every
        // file. No such primitive either.
        let e = f.invoke(dfaUnlock, &[0, 0, (-2i16) as u16]).expect_err("-2 refuses");
        assert!(e.to_string().contains("-2"), "{e}");

        // 7 is none of the three DFAAPI.H's four macros actually produce.
        let e = f.invoke(dfaUnlock, &[0, 0, 7]).expect_err("7 refuses");
        assert!(e.to_string().contains("dfaUnlock"), "{e}");
    }

    // -----------------------------------------------------------------
    // The transaction trio.
    // -----------------------------------------------------------------

    #[test]
    fn dfabegtrans_then_dfaendtrans_keeps_the_insert_on_disk() {
        let dir = crate::testing::scratch_with("dfa-endtrans-keeps", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);

        f.invoke(dfaBegTrans, &[0]).expect("begin");
        let recptr = f.bytes(&sample_record(99, "Zorro"), false);
        f.invoke(dfaInsertV, &[recptr.offset, recptr.selector, 64]).expect("inserts");
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(8));
        f.invoke(dfaEndTrans, &[]).expect("end");

        let mut g = Fixture::rooted(dir);
        open(&mut g, "SAMPLE.DAT", 64);
        assert_eq!(g.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(8), "kept on disk");
        assert!(acquire(&mut g, Some(99), 0, 5, 0), "and findable by its key");
    }

    #[test]
    fn dfabegtrans_then_dfaabttrans_undoes_the_insert_on_disk() {
        let dir = crate::testing::scratch_with("dfa-abttrans-undoes", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);

        f.invoke(dfaBegTrans, &[0]).expect("begin");
        let recptr = f.bytes(&sample_record(99, "Zorro"), false);
        f.invoke(dfaInsertV, &[recptr.offset, recptr.selector, 64]).expect("inserts");
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(8), "visible before abort");
        f.invoke(dfaAbtTrans, &[]).expect("abort");
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(7), "undone in memory");

        let mut g = Fixture::rooted(dir);
        open(&mut g, "SAMPLE.DAT", 64);
        assert_eq!(g.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(7), "and on disk");
        assert!(!acquire(&mut g, Some(99), 0, 5, 0), "never really there");
    }

    #[test]
    fn dfabegtrans_twice_without_ending_is_refused() {
        let mut f = Fixture::new();
        f.invoke(dfaBegTrans, &[0]).expect("the first begin opens one");
        let e = f.invoke(dfaBegTrans, &[0]).expect_err("nested begin is refused, not stacked");
        assert!(e.to_string().contains("already"), "{e}");
    }

    // -----------------------------------------------------------------
    // dfaWasLocked, and the rest of the surface: dfaLastLen, dfaMode,
    // dfaCountRec/dfaRecLen, dfaVirgin, dfaCreate/dfaCreateSpec.
    // -----------------------------------------------------------------

    /// Status 84 ("locked by another user") is a real, producible outcome
    /// as of Task 9 (`dfaacqlock_refuses_a_record_a_different_channel_
    /// already_holds`, above) -- but `dfaWasLocked` still has nowhere to
    /// read that reason back from (see its own doc comment), so it still
    /// answers `FALSE` unconditionally, including right after the one case
    /// a module would plausibly go looking for a lock conflict.
    #[test]
    fn dfawaslocked_always_answers_false() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(f.invoke(dfaWasLocked, &[]).expect("answers"), Ret::U16(0));

        assert!(!acquire(&mut f, Some(99), 0, 5, 0), "a failed acquire");
        assert_eq!(f.invoke(dfaWasLocked, &[]).expect("answers"), Ret::U16(0));
    }

    /// `dfaAcqNPLock` steps and answers 0 when the key it lands on differs
    /// from the one it saved.
    ///
    /// There was no `dfaAcqNPLock` test at all before this, which is how
    /// extracting `btv::acquire_next_prev` nearly folded two conditions
    /// together unnoticed.
    ///
    /// # What this does NOT pin, and why
    ///
    /// `DFAAPI.C:433` records `dfa->lastlen` when the step FINDS a record;
    /// `:434-436` then compares the keys, and that comparison is only the
    /// *answer*. So a record found whose key moved should still update
    /// `lastlen`. The code follows that ordering on the vendor's authority and
    /// **no test here discriminates it**: `note_len` stores
    /// `min(maxlen, record.len())`, every record in `SAMPLE.DAT` is the same
    /// fixed length, so `lastlen` reads identically whether the ordering is
    /// right or wrong. A mutation moving `note_len` behind the comparison
    /// passes the whole suite.
    ///
    /// Pinning it needs a variable-length fixture -- records of differing
    /// length -- which this tree's `tests/data` does not have. Stated rather
    /// than papered over with an assertion that looks like it covers the
    /// ordering when it cannot.
    #[test]
    fn dfaacqnplock_steps_and_answers_zero_when_the_key_moved() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5, 0), "positioned on Troll");
        assert_ne!(f.invoke(dfaLastLen, &[]).expect("answers"), Ret::U16(0));

        // A real `recptr`, not the module's null. With null, `:433`'s step
        // delivers into `dfa->data` -- the very buffer `:432` just saved the
        // old key into -- so the comparison at `:434-436` ends up comparing the
        // new record against its own key and answers 1. That is the vendor's
        // own behaviour and presumably why real call sites pass a buffer; it
        // also means a null here would test nothing.
        let into = f.buffer(64);
        let mut args = Fixture::far(into).to_vec();
        args.extend_from_slice(&[1, 6, 0]); // chkcas, acquire-next, no lock
        let answer = f.invoke(dfaAcqNPLock, &args).expect("acquire-next");
        assert_eq!(answer, Ret::U16(0), "a different record has a different key");

        // The step delivered a record, so a length is on record. This says
        // nothing about the ordering above -- see this test's own doc.
        let reclen = f.host.btrieve().block(block).expect("open").geometry().reclen;
        assert_eq!(
            f.invoke(dfaLastLen, &[]).expect("answers"),
            Ret::U16(64u16.min(reclen))
        );
    }

    #[test]
    fn dfalastlen_is_zero_before_any_read_and_the_delivered_length_after_one() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(f.invoke(dfaLastLen, &[]).expect("answers"), Ret::U16(0), "nothing read yet");

        let reclen = f.host.btrieve().block(block).expect("open").geometry().reclen;
        assert!(acquire(&mut f, Some(6), 0, 5, 0));
        let expected = 64u16.min(reclen);
        assert_eq!(f.invoke(dfaLastLen, &[]).expect("answers"), Ret::U16(expected));
    }

    /// `DFAAPI.C:179-184`'s `dfaomode=mode;` has no validation at all --
    /// unlike `omdbtv`, which refuses a value outside the five documented
    /// mode constants (`shims::btrieve`'s own
    /// `omdbtv_keeps_the_mode_and_refuses_one_that_is_not_a_mode`). Same
    /// invalid value, opposite outcome.
    #[test]
    fn dfamode_stores_whatever_it_is_given_with_no_validation_unlike_omdbtv() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().dfa_mode(), 0, "PRIMBV until told otherwise");
        f.invoke(dfaMode, &[7]).expect("stores 7 unchecked");
        assert_eq!(f.host.btrieve().dfa_mode(), 7);
    }

    #[test]
    fn dfacountrec_and_dfareclen_answer_the_files_own_geometry() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let reclen = f.host.btrieve().block(block).expect("open").geometry().reclen;

        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(7));
        assert_eq!(f.invoke(dfaRecLen, &[]).expect("answers"), Ret::U16(reclen));
    }

    /// The one behaviour `dfaVirgin` has that `btrieve_file`'s own implicit
    /// install (whatever `dfaOpen`/`opnbtv` do when a `.DAT` is missing)
    /// does not: `dst` may name a different stem than `src`.
    #[test]
    fn dfavirgin_honours_a_destination_stem_that_differs_from_the_source() {
        let dir = crate::testing::scratch_with("dfa-virgin-rename", &["VIRGIN.VIR"]);
        let mut f = Fixture::rooted(dir);
        assert!(f.host.find("VIRGIN.DAT").is_none());

        let src = f.text("VIRGIN");
        let dst = f.text("RENAMED");
        assert_eq!(
            f.invoke(dfaVirgin, &[src.offset, src.selector, dst.offset, dst.selector])
                .expect("copies"),
            Ret::U16(1)
        );
        assert!(f.host.find("RENAMED.DAT").is_some(), "installed under the DESTINATION stem");
        assert!(
            f.host.find("VIRGIN.DAT").is_none(),
            "never installed under the source stem"
        );
    }

    #[test]
    fn dfavirgin_answers_false_rather_than_refusing_when_there_is_no_virgin_file() {
        // `dfaCopyFile` never `catastro`s -- every failure path returns
        // FALSE, unlike this crate's usual refusal convention.
        let mut f = Fixture::new();
        let src = f.text("NOSUCH");
        assert_eq!(
            f.invoke(dfaVirgin, &[src.offset, src.selector, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    /// Pins the raw wire layout `decode_create_buffer` reads
    /// (`dfaStatFileSpec` + one `dfaStatKeySpec`) by round-tripping it
    /// through a real `dfaOpen`. Like `dfaCreate`/`dfaCreateSpec`
    /// themselves, this is unverified against a live engine -- there is no
    /// PE module in this repository's corpus that calls either routine --
    /// so this pins *current* behaviour, not a measured-correct one.
    #[test]
    fn dfacreate_builds_a_file_from_a_raw_buffer_that_dfaopen_can_then_open() {
        let dir = crate::testing::scratch("dfa-create-raw-buffer");
        let mut f = Fixture::rooted(dir);
        let filnam = f.text("CREATED.DAT");

        let mut buf = vec![0u8; 32];
        buf[0..2].copy_from_slice(&8u16.to_le_bytes()); // record_length
        buf[2..4].copy_from_slice(&512u16.to_le_bytes()); // page_size
        buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // n_keys
        // flags (byte 10) and n_pre_allocate (byte 14) stay zero.
        buf[16..18].copy_from_slice(&1u16.to_le_bytes()); // key position, 1-based
        buf[18..20].copy_from_slice(&2u16.to_le_bytes()); // key length
        buf[26] = 1; // ext_type
        let databuf = f.bytes(&buf, false);

        f.invoke(
            dfaCreate,
            &[filnam.offset, filnam.selector, databuf.offset, databuf.selector, (-1i16) as u16, 32],
        )
        .expect("creates");

        let block = open(&mut f, "CREATED.DAT", 8);
        assert_eq!(f.host.btrieve().block(block).expect("open").geometry().reclen, 8);
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(0));
    }

    #[test]
    fn dfacreate_refuses_nonzero_flags() {
        // This engine's FileSpec has no representation for
        // DFACF_VARIABLE/BLANKTRUNC/COMPRESS/KEYONLY/FREESPACE*.
        let dir = crate::testing::scratch("dfa-create-refuses-flags");
        let mut f = Fixture::rooted(dir);
        let filnam = f.text("BAD.DAT");

        let mut buf = vec![0u8; 32];
        buf[0..2].copy_from_slice(&8u16.to_le_bytes());
        buf[2..4].copy_from_slice(&512u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        buf[10..12].copy_from_slice(&1u16.to_le_bytes()); // nonzero flags
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&2u16.to_le_bytes());
        buf[26] = 1;
        let databuf = f.bytes(&buf, false);

        let e = f
            .invoke(
                dfaCreate,
                &[filnam.offset, filnam.selector, databuf.offset, databuf.selector, (-1i16) as u16, 32],
            )
            .expect_err("nonzero flags refused");
        assert!(e.to_string().contains("flags"), "{e}");
    }

    /// Pins `dfaCreateSpec`'s own module-memory `struct dfaKeySpec`/`struct
    /// dfaSegSpec` stride (`key_stride`/`seg_stride`, this file's own doc
    /// comment on `dfaCreateSpec` marks this as an assumed layout, not a
    /// measured one) by writing one real key with one real segment and
    /// confirming the file `dfaCreateSpec` builds is the one the buffer
    /// described, not garbage read from the wrong offset.
    #[test]
    fn dfacreatespec_reads_its_key_and_segment_arrays_and_creates_the_matching_file() {
        let dir = crate::testing::scratch("dfa-createspec");
        let mut f = Fixture::rooted(dir);

        // `struct dfaSegSpec`: position 0 (already 0-based, DFAAPI.H:61),
        // length 2, type 1, flags 0 -- each field A::INT_WIDTH (2) bytes
        // under Wg16, per this routine's own doc comment.
        let mut seg_bytes = vec![0u8; 10];
        seg_bytes[0..2].copy_from_slice(&0u16.to_le_bytes());
        seg_bytes[2..4].copy_from_slice(&2u16.to_le_bytes());
        seg_bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        seg_bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
        let seg_at = f.bytes(&seg_bytes, false);

        // `struct dfaKeySpec`: flags 0, nSegments 1, segs -> the one above.
        let mut key_bytes = vec![0u8; 8];
        key_bytes[0..2].copy_from_slice(&0u16.to_le_bytes());
        key_bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        key_bytes[4..6].copy_from_slice(&seg_at.offset.to_le_bytes());
        key_bytes[6..8].copy_from_slice(&seg_at.selector.to_le_bytes());
        let key_at = f.bytes(&key_bytes, false);

        let name = f.text("SPECCED.DAT");
        f.invoke(
            dfaCreateSpec,
            &[
                name.offset, name.selector,
                0,   // overwrite
                8,   // recordLength
                512, // pageSize
                0,   // flags
                0,   // nPreAllocate
                1,   // nKeys
                key_at.offset, key_at.selector,
                0, 0, // altFile, null
            ],
        )
        .expect("creates");

        let block = open(&mut f, "SPECCED.DAT", 8);
        assert_eq!(f.host.btrieve().block(block).expect("open").geometry().reclen, 8);
        assert_eq!(f.invoke(dfaCountRec, &[]).expect("counts"), Ret::U32(0));
    }
}
