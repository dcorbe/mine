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
//! Not registered here -- this file is new and `shims/mod.rs` is off limits
//! to it; see this crate's own top-level report for the exact rows and the
//! one open question (`crate::exports::WGSERVER` already exists, unused,
//! and is *not* what these rows should key on -- see that report).

// The C names throughout `DFAAPI.H`/`DFAAPI.C` are mixed-case
// (`dfaSetBlk`, not `dfa_set_blk`), and every routine below keeps its
// vendor spelling verbatim -- the same convention every other shim file in
// this crate follows for its own (all-lowercase, so never triggering this
// lint) C names.
#![allow(non_snake_case)]

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::btrieve::{Btrieve, Cursor, Geometry};
use crate::shims::ShimError;
use crate::shims::btrieve as btv;

/// The file `dfa*` routines currently work on, refusing if none is.
///
/// For the routines `DFAAPI.C` never guards at all (see the module doc
/// comment's guard census): `btvu()` would have faulted dereferencing
/// `dfa->posblk`, and this refuses by name instead of reproducing a crash a
/// module could not have caught either.
fn dfa_required<A: Abi>(host: &Host<A>, who: &str) -> Result<A::Ptr, ShimError> {
    let block = host.btrieve.dfa_current();
    if block == Btrieve::<A>::null() {
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
    if block == Btrieve::<A>::null() {
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
    let maxlen = btv::u16_arg::<A>(call.int(), "dfaOpen")?;
    let owner = call.ptr();
    if owner != Btrieve::<A>::null() {
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

    if let Some(dropped) = host.btrieve.dfa_set(block) {
        host.note(format!(
            "the dfaSetBlk stack is ten deep and overflowed, so {dropped} fell off the \
             bottom -- exactly as it would have on the real host"
        ));
    }
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
    if dfaptr != Btrieve::<A>::null() {
        host.btrieve.block(dfaptr).map_err(|e| ShimError::Failed(format!("dfaSetBlk: {e}")))?;
    }
    if let Some(dropped) = host.btrieve.dfa_set(dfaptr) {
        host.note(format!(
            "the dfaSetBlk stack is ten deep and overflowed, so {dropped} fell off the \
             bottom -- exactly as it would have on the real host"
        ));
    }
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
            value: Btrieve::<A>::null(),
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
    let into = match into == Btrieve::<A>::null() {
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
    let into = match into == Btrieve::<A>::null() {
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

    // `:432` -- `movmem(dfa->key,dfa->data,dfa->keylns[dfa->lastkn])`, read
    // before the step below can overwrite either buffer.
    let key = btv::key_number(call, host, block, -1)?;
    let key_len = btv::key_length(host, block, key)?;
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let old = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let data_buf = btv::data_buffer(host, block)?;
    data_buf
        .write(call.mem(), &old)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // `:433` -- `dfaAcqLock(recptr,NULL,-1,anpopt,loktyp)`.
    let op = btv::Op::of(anpopt).ok_or_else(|| {
        ShimError::Failed(format!("dfaAcqNPLock with option {anpopt}, which is not a get operation"))
    })?;
    let into = match recptr == Btrieve::<A>::null() {
        true => btv::data_buffer(host, block)?,
        false => recptr,
    };
    let found = btv::locate(
        call,
        host,
        btv::Request {
            who: "dfaAcqNPLock",
            block,
            op,
            keynum: -1,
            value: Btrieve::<A>::null(),
            into: Some(into),
            lock: loktyp,
        },
    )?;
    if !found {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    note_len(host, block);

    // `:434-436` -- compare the scratch copy against the key the step just
    // refreshed, `strcmp` or `stricmp` per `chkcas`.
    let data_buf = btv::data_buffer(host, block)?;
    let now = data_buf
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let landed = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let equal = if chkcas != 0 {
        btv::strcmp_eq(&now, &landed)
    } else {
        stricmp_eq(&now, &landed)
    };
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
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file.current().ok_or_else(|| {
        ShimError::Failed(format!("dfaAbs on {}, which is not positioned on a record", file.name()))
    })?;
    Ok(abi::Ret::Long(record.position))
}

/// The core [`dfaAcqAbsLock`] is, and -- via `DFAAPI.C:467`'s own
/// `dfaAcqAbsLock(recptr,abspos,keynum,loktyp)` call -- [`dfaGetAbsLock`]
/// re-derives rather than reproduces by re-entering the dispatch table
/// (this crate's shims call each other's *logic*, never the table itself).
/// Both public routines below read the same four arguments in the same
/// order and hand them here.
///
/// `DFAAPI.C:472-505`. `recptr`/`abspos`/`keynum`/`loktyp` map onto exactly
/// what `btv::absolute`'s own `Position` bundles for `aabbtv`/`gabbtvl`,
/// but this does not call `absolute` unchanged: `absolute` treats "no file
/// current" as a quiet `false` via [`btv::positioned`], which is `aabbtv`'s
/// and `gabbtvl`'s own *real* guard (`PLBTVSTF.C:452,476`). `dfaAcqAbsLock`
/// has no such guard -- only `ASSERT(dfa != NULL)` (`:479`) before an
/// unguarded `dfa->data`/`dfa->lastkn` -- so this refuses instead, through
/// [`dfa_required`], and re-derives the rest of `absolute`'s core (find the
/// physical position, seek, lock, answer the key, deliver the record)
/// directly rather than forcing it through a helper whose no-file case does
/// not fit.
///
/// `keynum < 0` is refused outright: `:466,484` `ASSERT(keynum >= 0)`,
/// where `aabbtv`/`gabbtvl` have no such assertion and store a negative one
/// unchecked (`PLBTVSTF.C:483`, `btv::absolute`'s own "`bb->lastkn=keynum`
/// and nothing else" note) -- a real host would have stored `dfa->lastkn`
/// the same way, but `DFAAPI.C`'s own `ASSERT` marks it as a case the
/// vendor considered a bug rather than a documented limit, so this refuses
/// rather than reproduces it.
///
/// The status-22 truncation `:489-497` performs by hand
/// (`dfa->data[dfa->reclen-1]='\0'; status=0;`) is exactly what
/// [`btv::deliver`] already does for every routine that calls it -- see
/// that function's own doc comment -- so no separate handling is needed
/// here.
fn dfa_acq_abs<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &str,
    recptr: A::Ptr,
    abspos: u32,
    keynum: i16,
    loktyp: i16,
) -> Result<bool, ShimError> {
    if keynum < 0 {
        return Err(ShimError::Failed(format!(
            "{who} with key number {keynum} -- DFAAPI.C ASSERTs keynum >= 0 here (unlike \
             aabbtv/gabbtvl, which tolerate and store a negative one), so a negative key \
             number is a module bug this host refuses rather than reproduces"
        )));
    }

    let block = dfa_required(host, who)?;
    let recptr = match recptr == Btrieve::<A>::null() {
        true => btv::data_buffer(host, block)?,
        false => recptr,
    };
    btv::load(host, block)?;
    let key = btv::key_number(call, host, block, keynum)?;

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let Some(physical) = records.find_physical(abspos) else {
        return Ok(false);
    };
    let cursor = match records.place_in(key, physical) {
        Some(at) => Cursor::Ordered { key, at },
        None => Cursor::Physical { at: physical },
    };
    file.seek_to(cursor);
    btv::take_lock(host, block, loktyp)?;
    btv::answer_with_key(call, host, block, key)?;
    btv::deliver(call, host, block, recptr)?;
    note_len(host, block);
    Ok(true)
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
    let abspos = call.long();
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
    let abspos = call.long();
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
pub fn dfaStepLock<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = dfa_positioned(host, "dfaStepLock")? else {
        btv::note_no_file(host, "dfaStepLock");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let into = call.ptr();
    let opt = btv::i16_arg::<A>(call.int());
    let lock = btv::i16_arg::<A>(call.int());
    let into = match into == Btrieve::<A>::null() {
        true => btv::data_buffer(host, block)?,
        false => into,
    };

    btv::load(host, block)?;
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let count = file.records().map_err(|e| ShimError::Failed(e.to_string()))?.len();

    let at = match (opt, file.cursor()) {
        (33, _) => 0,
        (34, _) if count > 0 => count - 1,
        (34, _) => return Ok(abi::Ret::Int(A::Int::from(0u16))),
        (24, Cursor::Physical { at }) => at + 1,
        (35, Cursor::Physical { at }) if at > 0 => at - 1,
        (35, Cursor::Physical { .. }) => return Ok(abi::Ret::Int(A::Int::from(0u16))),
        (24 | 35, Cursor::Ordered { key, at }) => {
            let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
            let physical = records
                .ordered(key, at)
                .and_then(|record| records.find_physical(record.position))
                .ok_or_else(|| {
                    ShimError::Failed(format!(
                        "dfaStepLock({opt}) on {}: the ordered cursor (key {key}, {at}) \
                         does not resolve to a physical record -- the file changed under it",
                        file.name()
                    ))
                })?;
            match opt {
                24 => physical + 1,
                _ if physical > 0 => physical - 1,
                _ => return Ok(abi::Ret::Int(A::Int::from(0u16))),
            }
        }
        (24 | 35, Cursor::Nowhere) => {
            return Err(ShimError::Failed(format!(
                "dfaStepLock({opt}) on {}, which is positioned Nowhere -- nothing has \
                 positioned it yet, by a key or by a step",
                file.name()
            )));
        }
        _ => {
            return Err(ShimError::Failed(format!(
                "dfaStepLock with option {opt}, which is none of 24, 33, 34 and 35"
            )));
        }
    };

    if at >= count {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    file.seek_to(Cursor::Physical { at });
    btv::take_lock(host, block, lock)?;
    btv::deliver(call, host, block, into)?;
    note_len(host, block);
    Ok(abi::Ret::Int(A::Int::from(1u16)))
}

/// The body [`dfaInsert`]/[`dfaInsertV`]/[`dfaInsertDup`] share -- opcode 2,
/// always key 0 (`DFAAPI.C:613,634`: `btvu(2,recptr,dfa->key,0,length)` in
/// both), which is [`btv::dinsbtv`]'s own body with `length` and the
/// duplicate-key convention taken as parameters instead of fixed.
///
/// `refuse_on_duplicate` is `true` for [`dfaInsert`]/[`dfaInsertV`] (no
/// `case 5` branch at either's underlying call -- `:613`/`:556`-shaped, see
/// [`btv::upvbtv`]'s own doc comment for the identical shape) and `false`
/// for [`dfaInsertDup`] (`:634-642`'s own `case 5: break;`).
fn dfa_insert<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &str,
    block: A::Ptr,
    recptr: A::Ptr,
    length: u16,
    refuse_on_duplicate: bool,
) -> Result<bool, ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let recptr = match recptr == Btrieve::<A>::null() {
        true => file.data(),
        false => recptr,
    };
    let bytes = recptr
        .resolve(call.mem(), usize::from(length))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    if let Some((key, value)) = btv::duplicate_key(host, block, &bytes, None)? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        if refuse_on_duplicate {
            return Err(ShimError::Failed(format!(
                "{who} on {name} collided with an existing record on key {key} \
                 ({value:02x?}), which does not permit duplicates -- unlike \
                 dfaInsertDup's own case-5 branch (DFAAPI.C:637-638), {who}'s underlying \
                 call has no exception for a duplicate, so this refuses instead of \
                 answering false and silently discarding the write"
            )));
        }
        btv::note_duplicate_key(host, who, &name, key, &value);
        return Ok(false);
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let position = file.insert(&bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Currency on the record just inserted, key 0's order -- see
    // `btv::dinsbtv`'s own doc comment for why key 0 specifically.
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let physical = records.find_physical(position).expect("insert just wrote this position");
    let cursor = match records.place_in(0, physical) {
        Some(at) => Cursor::Ordered { key: 0, at },
        None => Cursor::Physical { at: physical },
    };
    file.seek_to(cursor);
    Ok(true)
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
    let length = btv::u16_arg::<A>(call.int(), "dfaInsertV")?;
    let block = dfa_required(host, "dfaInsertV")?;
    dfa_insert(call, host, "dfaInsertV", block, recptr, length, true)?;
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
    dfa_insert(call, host, "dfaInsert", block, recptr, length, true)?;
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
    let ok = dfa_insert(call, host, "dfaInsertDup", block, recptr, length, false)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(ok))))
}

/// The body [`dfaUpdateDup`] alone needs: [`btv::update_variable`]'s own
/// write with the one convention it does not offer -- a duplicate-key
/// collision answers a quiet `false` instead of refusing.
///
/// `DFAAPI.C:561-589`'s own `case 5: break;` (`:583-584`) is the one branch
/// [`dfaUpdate`]/[`dfaUpdateV`]'s underlying call (`:543`) does not have --
/// see [`dfaUpdateV`]'s own doc comment, which is why those two reuse
/// [`btv::update_variable`] unchanged and this does not.
fn dfa_update_dup<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    block: A::Ptr,
    recptr: A::Ptr,
    length: u16,
) -> Result<bool, ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let position = file
        .current()
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "dfaUpdateDup on {}, which is not positioned on a record -- opcode 3 \
                 updates the record the file is positioned on, and nothing has \
                 positioned this one",
                file.name()
            ))
        })?
        .position;
    let recptr = match recptr == Btrieve::<A>::null() {
        true => file.data(),
        false => recptr,
    };
    let bytes = recptr
        .resolve(call.mem(), usize::from(length))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    if let Some((key, value)) = btv::duplicate_key(host, block, &bytes, Some(position))? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        btv::note_duplicate_key(host, "dfaUpdateDup", &name, key, &value);
        return Ok(false);
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    file.update(position, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Same currency re-derivation `btv::dupdbtv`/`update_variable` already
    // give their own writes -- see either's doc comment for why an
    // `Ordered` cursor is recomputed and a `Physical` one needs no
    // correction.
    if let Cursor::Ordered { key, .. } = file.cursor() {
        let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
        let physical = records.find_physical(position).expect("update just wrote this position");
        let cursor = match records.place_in(key, physical) {
            Some(at) => Cursor::Ordered { key, at },
            None => Cursor::Physical { at: physical },
        };
        file.seek_to(cursor);
    }
    Ok(true)
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
    let length = btv::u16_arg::<A>(call.int(), "dfaUpdateV")?;
    let block = dfa_required(host, "dfaUpdateV")?;
    btv::update_variable(call, host, "dfaUpdateV", block, recptr, length)?;
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
    btv::update_variable(call, host, "dfaUpdate", block, recptr, length)?;
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
    let ok = dfa_update_dup(call, host, block, recptr, length)?;
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
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let position = file
        .current()
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "dfaDelete on {}, which is not positioned on a record -- nothing has \
                 positioned it yet",
                file.name()
            ))
        })?
        .position;

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    file.delete(position).map_err(|e| ShimError::Failed(e.to_string()))?;
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
/// than tightened: `dfaMode` genuinely stores whatever it is given, and
/// nothing reads it back until a `dfaOpen` -- which, like `opnbtv`, does not
/// yet do anything with the mode beyond keeping it (see `omdbtv`'s own doc
/// comment for why).
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
    let len = btv::u16_arg::<A>(call.int(), "dfaStat")?;
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
/// **Always `FALSE`.** This host is single-process by construction (see,
/// among several others, [`crate::btrieve::Btrieve::begin`]'s own doc
/// comment), so there is never a second session to hold a conflicting lock
/// -- statuses 84/85 describe a condition this host cannot produce, not one
/// it has chosen not to reproduce. `FALSE` is the honestly-derived answer
/// here, not a placeholder standing in for future work.
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
    let dst_stem = if dst == Btrieve::<A>::null() {
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
    let lendbuf = btv::u16_arg::<A>(call.int(), "dfaCreate")?;

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
    if alt_file != Btrieve::<A>::null() {
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
