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
