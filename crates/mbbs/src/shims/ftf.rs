//! Nine imports that share nothing but an unresolved-symbol report: three
//! data globals, two routines from the File Transfer Framework this host does
//! not have, and four ordinary DOS/Borland-runtime routines this host does.
//!
//! ```text
//! _FTGPTR      7 modules, 210 sites     _MKDIR       8 modules
//! _FTFSCB      6 modules,  70 sites     _STPANS      8 modules
//! _FTGNEW      6 modules                _FARMALLOC   8 modules
//! _FTGSBM      6 modules                _DCDATE      6 modules
//!                                       _TSHMSG      6 modules, 82 sites
//! ```
//!
//! # `_FTGPTR`, `_FTFSCB`, `_TSHMSG` are not routines
//!
//! `FTG.H:97-98` declares `ftgptr` as data:
//!
//!
//! `FTF.C:26-27` (wg1) declares `ftfscb` the same way:
//!
//!
//! (wg1's `FTF.C` never defines `struct ftfscb`'s fields anywhere in this
//! archive -- the type is used only as a pointer, which C allows for an
//! incomplete type. The field layout survives in `re/wg33src`'s later
//! `FTF.H`, cited on [`ftgsbm`]'s own doc comment below.)
//!
//! And `FTG.H:74` declares `tshmsg` as a fixed buffer, not a function --
//! confirmed by seven `strcpy`/`sprintf`/`stlcpy` writes into it at
//! `AAEFU.C:1775-1820` alone, never a call:
//!
//!
//! Every call site across all three is a `->field` dereference or a direct
//! read/write, never `ftgptr(...)`/`ftfscb(...)`/`tshmsg(...)` -- so a shim
//! function is the wrong shape for any of them. **No shim is written for
//! these three.** What each one needs instead is a [`crate::globals`] row:
//!
//! ```text
//! g("ftgptr", PTR),   // FTG.H:97-98 -- struct ftg *ftgptr
//! g("ftfscb", PTR),   // FTF.C:26-27 -- struct ftfscb *ftfscb
//! g("tshmsg", 81),    // FTG.H:74, TSHLEN=80 at FTG.H:66 -- char tshmsg[81]
//! ```
//!
//! (`PTR` is the crate's existing 4-byte far-pointer width constant, already
//! used by every other `struct *` global in that table.) This file does not
//! add them -- the task that wrote it was told not to touch `globals.rs`.
//!
//! # `_FTGNEW`, `_FTGSBM` refuse loudly: the File Transfer Framework itself
//!
//! [`crate::shims::misc::listing`] already found and documented this gap --
//! "This host implements no File Transfer Framework at all: `ftgnew`,
//! `ftgsbm`, `struct ftfpsp`, `ftfscb` and the tagspec-handler protocol they
//! imply have no counterpart anywhere in this crate (checked; zero hits)."
//! [`ftgnew`] and [`ftgsbm`] are that framework's own two entry points, not
//! callers of it -- naming them here rather than deferring to `listing`'s
//! citation because *their* bodies are what make the gap concrete: see each
//! function's own doc comment for exactly which pieces of missing state they
//! read.
//!
//! # `_MKDIR`, `_STPANS`, `_FARMALLOC`, `_DCDATE` are ordinary and implemented
//!
//! None of the four touches the FTF. `mkdir` and `farmalloc` are Borland
//! runtime, re-exported the same way `access`/`unlink`/`time` already are in
//! this crate (no Galacticomm header redeclares them as anything else).
//! `stpans` and `dcdate` are `GCOMM.LIB` utilities with recovered C source.
//! See each function's own doc comment.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::shims::{NO, ShimError};

/// `int ftgnew(void)` -- `FILEXFER.C:651-664` -- issue a new tagspec pointer.
///
///
/// Every line after `setftu()` reads state this host has never had. `setftu`
/// itself (`FILEXFER.C:344-359`) is worse than `ftgnew` alone lets on:
///
///
/// `ftuser` is a per-user `struct ftuser` array (`FILEXFER.H:18-37`,
/// `FILEXFER.H:51`) sized `nterms`, holding the whole file-transfer state
/// machine for every channel; `ptrblok(scbblok, usrnum)` and
/// `ptrblok(ftgblok, usrnum)` resolve into block pools this host never
/// allocates; `maxtags` is a per-board config value nothing here reads. None
/// of `ftuser`, `ftuptr`, `maxtags`, `ftgusr`, `scbblok`, `ftgblok` exists in
/// this crate -- same finding [`crate::shims::misc::listing`] already made
/// for the framework as a whole, reached here from the framework's own
/// allocation routine rather than one of its callers.
///
/// # Errors
///
/// Always. There is no partial `ftgnew` that returns a real tagspec slot
/// without the array it would come from -- a fabricated success here would
/// hand back a pointer [`ftgsbm`] (equally unimplemented) or a module's own
/// `tshxxx()` would then dereference into memory this host never reserved.
pub fn ftgnew<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Err(ShimError::Failed(
        "ftgnew(): this host has no File Transfer Framework -- setftu() alone reads \
         ftuser[usrnum], ptrblok(scbblok,usrnum) and ptrblok(ftgblok,usrnum), none of \
         which this crate allocates (see this function's own doc comment, and \
         crate::shims::misc::listing's, which found the same gap from a caller of \
         ftgnew/ftgsbm rather than the routines themselves)"
            .to_string(),
    ))
}

/// `int ftgsbm(char *prot)` -- `FILEXFER.C:791-887` -- submit the tagspec
/// [`ftgnew`] just issued, for tagging, immediate download, or a download-
/// options prompt.
///
///
/// A strict superset of [`ftgnew`]'s gap, not a milder version of it: this
/// needs everything `ftgnew` needed (`setftu()`'s whole chain), plus
/// `curmbk`/`ftfmb`-scoped `prfmsg` calls against an FTF-specific `.MSG` file
/// this host has never loaded (`FTFDNHDR`, `TAGFULL`, and the rest --
/// `FILEXFER.MSG`, not one of `WCCMMUD.DLL`'s own), `fndprt` (protocol table
/// lookup against `fthead`/`fttail`, a linked list of `struct ftfpsp` this
/// host never builds because it registers no protocols), `usrptr->state`
/// transitioned into `ftfstt` (a *second* state machine layered onto the
/// user record this host's own `state`/`substt` handling has no branch for),
/// `stxfer()` (starts the actual byte-level transfer engine -- Kermit,
/// Zmodem, and the rest, none of which this host implements), and a call
/// back into the module's own `tshndl` callback (`ftgptr->tshndl(TSHVIS)`) --
/// the same "a shim cannot call module code" gap `listing`'s doc comment
/// names for the identical reason.
///
/// # Errors
///
/// Always, for all of the reasons above and the same one [`ftgnew`] refuses
/// for: no fabricated `rc` is honest here, because every branch this routine
/// could take next depends on state this host does not have.
pub fn ftgsbm<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *prot` -- read only so the refusal can name what was asked for;
    // nothing downstream of this needs the value.
    let prot = call.ptr();
    let asked = String::from_utf8_lossy(
        prot.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    Err(ShimError::Failed(format!(
        "ftgsbm({asked:?}): this host has no File Transfer Framework -- setftu()'s whole \
         chain is missing (see ftgnew's doc comment), plus an FTF-specific .MSG file, a \
         protocol table this host registers nothing into, a second state machine on top \
         of state/substt, and a callback into module code no shim can make (see this \
         function's own doc comment)"
    )))
}

/// `int mkdir(const char *path)` -- Borland's; no Galacticomm header
/// redeclares it (`GCOMM.H` has `gmkdir`, a different, unimported routine --
/// see this function's own paragraph below).
///
/// Zero on success, `-1` on any failure -- Borland's own contract, and the
/// one `valpath()` (`GALFIL.C:2143`) leans on directly:
///
///
/// -- `mkdir()` called purely to test a path, its failure read as an
/// ordinary answer and not a fault. That is the contract honoured here:
/// **every** failure this shim's own `std::fs::create_dir` can report --
/// already exists, missing parent, permission denied -- becomes `-1`, the
/// same as the DOS mkdir() a module built around this return code expects,
/// not a host-level [`ShimError::Failed`]. The one exception is
/// [`Host::dos_name`] refusing the path outright (a drive letter, a
/// `..`, anything outside the module's own directory): that is not a
/// filesystem answer DOS could ever have given, so it is treated the same
/// way [`super::stream::fopen`] and [`super::stream::unlink`] already treat
/// it -- a loud refusal, not a quiet `-1`.
///
/// **Non-recursive**, matching Borland's `mkdir()` (and unlike
/// [`super::stream::fopen`]'s own directory-creation, which *is*
/// `create_dir_all` -- that call is the host's own bookkeeping for a
/// module's write, not the module's routine, and failing it silently would
/// be the host, not the module, losing data).
///
/// # `gmkdir`, not this
///
/// `GCOMM.H:511` also declares `void gmkdir(char *dirnam);` -- a different,
/// unimported symbol (checked against the census this task was given: only
/// `_MKDIR` appears, never `_GMKDIR`) that recursively makes every path
/// component. Building that instead of `mkdir()` would silently give modules
/// more than Borland's own runtime ever did.
///
/// # Errors
///
/// If the path escapes the module's own directory ([`Host::dos_name`]'s
/// rule), or if reading `path` out of module memory fails.
pub fn mkdir<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;

    // Already there -- file or directory, `mkdir()` does not distinguish --
    // is exactly DOS's EEXIST: -1, not a host refusal. `-1` at `A`'s own
    // width (`int_from_u32(u32::MAX)`), not `A::Int::from(NO)`, which
    // zero-extends `0xffff` to `65535` under `Wg32` -- see `findtvar`.
    if host.find(&name).is_some() {
        return Ok(abi::Ret::Int(A::int_from_u32(u32::MAX)));
    }

    match std::fs::create_dir(host.root.join(&name)) {
        Ok(()) => Ok(abi::Ret::Int(A::Int::from(0u16))),
        // Missing parent, permission denied, or anything else `mkdir()`'s
        // own two-value contract (0 or -1) was always going to collapse
        // into `-1` regardless of which it was.
        Err(_) => Ok(abi::Ret::Int(A::int_from_u32(u32::MAX))),
    }
}

/// `char *stpans(char *str)` -- `GCOMM.H:364` -- strip ANSI escapes and
/// `ESC[[ansi|ascii]` IF-ANSI constructs from a string, in place, returning
/// the same pointer.
///
/// No C source survives in the wg1 tree (`GCOMM.H:364` is a bare prototype;
/// `STPANS.C` is not among wg1's `GALDSRC/SRC` files). The body below is
/// ported from `re/wg33src/SRC/api/gcommlib/STPANS.C:17-83`, cited per file
/// because wg1 has none to prefer:
///
///
/// `ESC` is 27 (`GCOMM.H:181`, also `KBDAPI.H:54` in wg33).
///
/// # What this always keeps, and always drops
///
/// A plain `ESC[...<letter>` run (any CSI: colour, cursor move, whatever the
/// final byte is) is deleted whole, letter included. An `ESC[[ansi|ascii]`
/// construct keeps only the ASCII half and drops the opener, the ANSI half,
/// the `|`, and the closing `]` -- this is a strip routine, not
/// [`crate::ifansi::process`]'s live *resolve-by-capability* (that function
/// keeps whichever branch a real terminal's ANSI support picked; this one
/// always behaves as if there is none, because "strip" has one answer).
/// **They agree on `ansi: false`** for every wellformed two-branch
/// construct, but not on the malformed ones -- see the next two paragraphs
/// -- so this is its own port rather than a call into that function with a
/// fixed flag.
///
/// A single-branch construct with no `|` -- `ESC[[ansi]`, nothing to fall
/// back to -- is dropped **whole**: with no ASCII text to keep, stripping
/// leaves nothing. `crate::ifansi::process` disagrees here on purpose (its
/// own doc comment: no separator found means the opener alone is dropped and
/// the rest survives as literal text) -- a live-resolve function has to
/// leave *something* on the wire; a strip function does not.
///
/// An `ESC[[ansi|ascii` with no closing `]` before end-of-string, `\n`, or
/// `\r`: if the `|` was never reached either, the whole broken opener-through-
/// wherever-scanning-stopped span is dropped. If the `|` *was* reached (so
/// the ASCII branch is already in place and being copied through), the
/// missing `]` is simply never found and scanning resumes normally from
/// there -- the ASCII text already emitted stays, matching the C's
/// `zapdansi`-true fall-through exactly (no `continue`, so no further
/// deletion happens).
///
/// # Byte buffer, not `String`
///
/// [`ModulePtr::read_cstr`] and `write` move raw bytes. `stpans` never
/// decodes them -- every byte this algorithm inspects (`ESC`, `[`, `]`,
/// `|`, `\n`, `\r`, and `isalpha`'s ASCII range) is below 0x80, so a CP437
/// string with high-bit bytes in it (accented letters, box-drawing) is
/// carried through untouched rather than risking corruption through a UTF-8
/// round trip -- the same reasoning `crate::cp437`'s own module doc gives
/// for keeping that translation out of paths like this one.
///
/// # Errors
///
/// If reading or writing `str` through module memory fails.
pub fn stpans<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let str_ptr = call.ptr();
    let original = str_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let mut stripped = strip_ansi(original);
    stripped.push(0);
    str_ptr
        .write(call.mem(), &stripped)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(str_ptr))
}

/// The state machine `stpans`'s doc comment quotes, translated from
/// in-place `movmem` shifts (the C's `str`/`ansptr`/`ifansptr` pointer
/// arithmetic on one buffer) into `Vec::drain`/`Vec::remove` on an owned
/// buffer with no NUL sentinel -- `i >= buf.len()` stands in for the C's
/// `*str == '\0'` test everywhere that test appears, including inside the
/// `inifansi` branch where it is one of three alternatives rather than a
/// guard at the top.
///
/// Kept free of `A`/`Call`/`Host` entirely so it can be exercised directly
/// by this module's tests without a fixture.
fn strip_ansi(mut buf: Vec<u8>) -> Vec<u8> {
    const ESC: u8 = 27; // GCOMM.H:181

    let mut i = 0usize;
    let mut in_ansi = false;
    let mut in_if_ansi = false;
    let mut zapped = false;
    let mut ansi_start = 0usize;
    let mut if_ansi_start = 0usize;

    loop {
        if in_if_ansi {
            if i < buf.len() && buf[i] == b'|' && !zapped {
                // movmem(str+1,ifansptr,strlen(str+1)+1); str=ifansptr;
                buf.drain(if_ansi_start..=i);
                i = if_ansi_start;
                zapped = true;
                continue;
            } else if i < buf.len() && buf[i] == b']' {
                if zapped {
                    // movmem(str+1,str,strlen(str+1)+1) -- drop just the ']'.
                    buf.remove(i);
                } else {
                    // movmem(str+1,ifansptr,strlen(str+1)+1); str=ifansptr;
                    buf.drain(if_ansi_start..=i);
                    i = if_ansi_start;
                }
                in_if_ansi = false;
                continue;
            } else if i >= buf.len() || buf[i] == b'\n' || buf[i] == b'\r' {
                in_if_ansi = false;
                if !zapped {
                    // movmem(str,ifansptr,strlen(str)+1); str=ifansptr;
                    buf.drain(if_ansi_start..i);
                    i = if_ansi_start;
                    continue;
                }
                // zapped: fall through unchanged, matching the C's lack of
                // a `continue` on this arm.
            }
        }
        if i >= buf.len() {
            break;
        }
        if in_ansi {
            if buf[i].is_ascii_alphabetic() {
                in_ansi = false;
                // movmem(str+1,ansptr,strlen(str+1)+1); str=ansptr;
                buf.drain(ansi_start..=i);
                i = ansi_start;
                continue;
            } else if buf[i] == b'[' {
                in_ansi = false;
            }
        } else if buf[i] == ESC && buf.get(i + 1) == Some(&b'[') {
            if buf.get(i + 2) == Some(&b'[') {
                in_if_ansi = true;
                zapped = false;
                if_ansi_start = i;
            } else {
                in_ansi = true;
                ansi_start = i;
            }
            i += 1;
        }
        i += 1;
    }
    buf
}

/// `char *farmalloc(unsigned long size)` -- `GCOMM.H:124` -- Borland's far
/// heap allocator (`GCOMM.H:122`: `#define getml(ln) farmalloc(ln)`, the
/// name most vendor source actually calls it by).
///
/// Same heap [`super::memory::alcmem`] already reserves from --
/// [`crate::heap::Heap::reserve`] -- not a second one. A module mixing
/// `farmalloc`/`farfree` with `alcmem`/`galfree` (both real DOS conventions
/// existed; nothing stopped a module using either) gets the same arena
/// either way, the same as the real host's single far heap did.
///
/// **`galfree`, not a `farfree` shim.** This host's census gave `_FARMALLOC`
/// with no matching `_FARFREE` -- every one of the eight importing modules
/// frees through `galfree` instead (the same asymmetric pairing
/// `getml`/`galfree` already is in `GCOMM.H` itself: `getml` is a macro over
/// `farmalloc`, but nothing defines a `getml`-shaped free). So the block this
/// returns is freed the ordinary way, through [`super::memory::galfree`],
/// and no `farfree` shim exists here to duplicate what it already does.
///
/// **Loud on the two cases the real host answered with `NULL`**, matching
/// [`super::memory::alcmem`]'s own choice for the identical situations and
/// for the identical reason (see that function's doc comment): a size of
/// zero, or a heap with no room.
///
/// **16-bit block size, same ceiling as `alcmem`.** `size` is `unsigned
/// long` -- wider than `alcmem`'s `UINT` -- but [`crate::heap::Heap::reserve`]
/// takes a `u16`, because nothing in this host's heap has ever modelled a
/// single block larger than one 64K arena (`memory.rs`'s own `SEGMENT`).
/// Real Borland `farmalloc` could ask the OS for more; this host's heap
/// design already could not have honoured that for `alcmem`, and giving
/// `farmalloc` a wider promise it cannot keep would be the fabricated
/// success this crate exists to refuse -- so a `size` over 65,535 is a loud
/// refusal, not a silent truncation.
///
/// # Errors
///
/// If `size` is zero, exceeds 65,535, or the heap has no room and may not
/// grow.
pub fn farmalloc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = call.long();
    let size = u16::try_from(size)
        .map_err(|_| ShimError::Failed(format!("farmalloc: {size} bytes, over this host's 65,535-byte block ceiling")))?;
    let at = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("farmalloc: {e}")))?;
    Ok(abi::Ret::Ptr(at))
}

/// `USHORT dcdate(const char *datstr)` -- `DOSFACE.H:78` (wg1: `int
/// dcdate(char *datstr);`) -- decode a DOS date from `"MM/DD[/YY[YY]]"` into
/// DOS's packed 16-bit form, or `GCINVALIDDOT` (`0xFFFF`,
/// `re/wg33src/INC/DNTAPI.H:136`) if the text is not a valid date.
///
/// No C source survives in wg1 for this one either -- cited to
/// `re/wg33src/SRC/api/gcommlib/DNTAPI.C`, the same file `crate::clock`'s own
/// module doc already cites for `now`/`today`/`time`'s correction. `dcdate`
/// itself (`DNTAPI.C:287-297`):
///
///
/// `dateDecode` (`DNTAPI.C:225-253`):
///
///
/// `validDate` (`DNTAPI.C:636-641`) is `1<=year<=9999 && 1<=month<=12 &&
/// 1<=day<=lastDayOfMonth(month,year)`; `lastDayOfMonth` (`DNTAPI.C:672-686`)
/// is the ordinary 30/31/28-or-29 table with `isLeapYear`
/// (`DNTAPI.H:192`: `((yr)&3)==0 && ((yr)%100!=0 || (yr)%400==0)`); `dddate`
/// (`DNTAPI.H:184`) is `(mon<<5)+day+((year-1980)<<9)` -- the exact packing
/// [`crate::clock::Civil::dos_date`] already implements (and this shim reuses
/// rather than duplicates, see below).
///
/// # Two deliberate simplifications
///
/// **`sscanf`'s exact grammar is not reproduced byte-for-byte.** What is
/// reproduced: leading whitespace skipped before each number, an optional
/// sign, decimal digits, a literal `/` between fields, and the two-attempt
/// `MM/DD/YYYY` then `MM/DD` fallback with `n == AABB` selecting the
/// default-year path exactly as the C does. What is not: `sscanf`'s
/// willingness to keep matching past trailing garbage after the fields it
/// wanted (`"01/02/1990extra"` scans as `AABBCC` in C; this parser requires
/// nothing unparsed after the matched fields other than what the two-attempt
/// structure already tolerates). Every caller in the corpus census passes a
/// board-authored or user-typed date field, not an arbitrary trailing-noise
/// string, and getting the noise case wrong fails safe -- to `GCINVALIDDOT`,
/// this routine's own documented "no" -- rather than silently.
///
/// **The `y up to 9999` branch is narrowed to what DOS can actually pack.**
/// `validDate` accepts any year 1-9999, but `dddate`'s packing shifts
/// `year-1980` into a 7-bit field (`DNTAPI.H:184`) -- a year past 2107
/// silently wraps in the real host's 16-bit arithmetic, which is corruption,
/// not an answer. [`crate::clock::Civil::dos_date`] already refuses instead
/// of wrapping (its own doc comment: "the old inline version clamped, which
/// turned 1970 into 1980 -- a date that is wrong rather than absent"), so
/// this shim calls it and lets that refusal stand in for the vendor's silent
/// wraparound: a year outside `1980..=2107` becomes `GCINVALIDDOT` here,
/// never a wrapped packed value that looks like a different, wrong date.
///
/// # Errors
///
/// If reading `datstr` out of module memory fails. An unparsable or
/// out-of-range date is not an error -- it is `GCINVALIDDOT`, the routine's
/// own documented answer for exactly that.
pub fn dcdate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    const GCINVALIDDOT: u16 = 0xFFFF; // DNTAPI.H:136

    let ptr = call.ptr();
    let text = String::from_utf8_lossy(
        ptr.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let Some((month, day, year)) = decode_date(&text) else {
        return Ok(abi::Ret::Int(A::Int::from(GCINVALIDDOT)));
    };

    // `year` is `None` exactly when only `MM/DD` was given, matching the
    // C's `n == AABB` branch -- and that branch is the only one that reads
    // the clock at all (`y=ddyear(today())`, `DNTAPI.C:236`), so `today()`
    // is asked for here and nowhere else, not unconditionally on every
    // call. The day-of-month bound `decode_date` deferred for this case
    // (see `finish`'s own doc comment) is re-checked now that a year is
    // finally known, exactly where the C checks it too -- `dateDecode`
    // resolves `y` before its own `lastDayOfMonth(m,y) < d` test runs.
    let year = match year {
        Some(y) => y,
        None => {
            let today_year = host
                .clock()
                .civil()
                .map_err(|e| ShimError::Failed(format!("dcdate: {e}")))?
                .year;
            if i64::from(day) > i64::from(last_day_of_month(month, today_year)) {
                return Ok(abi::Ret::Int(A::Int::from(GCINVALIDDOT)));
            }
            today_year
        }
    };

    let civil = crate::clock::Civil {
        year,
        month: u32::from(month),
        day: u32::from(day),
        hour: 0,
        minute: 0,
        second: 0,
    };
    match civil.dos_date() {
        Ok(packed) => Ok(abi::Ret::Int(A::Int::from(packed))),
        // Out of the 1980..=2107 range dddate() can pack -- see this
        // function's own doc comment's second simplification.
        Err(_) => Ok(abi::Ret::Int(A::Int::from(GCINVALIDDOT))),
    }
}

/// `dateDecode` + `validDate` (`DNTAPI.C:225-253`, `:636-641`), minus the
/// year default (left to the caller, which alone has a [`Host`] to ask
/// [`crate::clock::Clock`] through). `None` is `dcdate`'s `GCINVALIDDOT`;
/// `Some((month, day, None))` is a valid `MM/DD` with the year left for the
/// caller to fill in from `today()`; `Some((month, day, Some(year)))` is a
/// fully-specified date, already range-checked including the day-of-month
/// bound for that year.
fn decode_date(src: &str) -> Option<(u8, u8, Option<i32>)> {
    let src = src.trim_start();

    // `sscanf(src,"%d/%d/%d",...)` then, on failure, `sscanf(src,"%d/%d",...)`.
    if let Some((m, d, y)) = scan_three(src) {
        let y = normalise_year(y)?;
        return finish(m, d, Some(y));
    }
    let (m, d) = scan_two(src)?;
    finish(m, d, None)
}

/// The `if (m < 1 || 12 < m) { m=-1; }` / day-bound check shared by both
/// `scan_three` and `scan_two`'s callers in `decode_date`.
fn finish(m: i64, d: i64, y: Option<i32>) -> Option<(u8, u8, Option<i32>)> {
    if !(1..=12).contains(&m) {
        return None;
    }
    let m = m as u8;
    if let Some(y) = y {
        if d < 1 || i64::from(last_day_of_month(m, y)) < d {
            return None;
        }
    } else if d < 1 || d > 31 {
        // No year yet (defaults to `today()`'s, which the caller supplies):
        // reject only what could never be a day in any year, the same
        // widest-possible bound `validDate`'s own `1 <= day` half enforces
        // before `lastDayOfMonth` narrows it once a year is known.
        return None;
    }
    Some((m, d as u8, y))
}

/// `sscanf(src,"%d/%d/%d",&m,&d,&y)` -- three slash-separated integers, with
/// leading whitespace and an optional sign on each, same as `%d` always
/// skips/accepts. See [`dcdate`]'s own doc comment for what is and is not
/// reproduced of `sscanf`'s exact grammar.
fn scan_three(src: &str) -> Option<(i64, i64, i64)> {
    let (m, rest) = scan_int(src)?;
    let rest = rest.strip_prefix('/')?;
    let (d, rest) = scan_int(rest)?;
    let rest = rest.strip_prefix('/')?;
    let (y, _rest) = scan_int(rest)?;
    Some((m, d, y))
}

/// `sscanf(src,"%d/%d",&m,&d)`.
fn scan_two(src: &str) -> Option<(i64, i64)> {
    let (m, rest) = scan_int(src)?;
    let rest = rest.strip_prefix('/')?;
    let (d, _rest) = scan_int(rest)?;
    Some((m, d))
}

/// One `%d`: skip leading whitespace, take an optional sign, then one or
/// more decimal digits. Returns the parsed value and what is left of `src`.
fn scan_int(src: &str) -> Option<(i64, &str)> {
    let src = src.trim_start();
    let mut end = 0;
    let bytes = src.as_bytes();
    if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
        end += 1;
    }
    let digits_start = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == digits_start {
        return None;
    }
    let value: i64 = src[..end].parse().ok()?;
    Some((value, &src[end..]))
}

/// `y+=(y < 80 ? 2000 : 1900);` two-digit rule, plus the `y < 1 || 9999 < y`
/// refusal that comes first in the C. Takes the raw `%d`-scanned value
/// (which can be any width, not just 1-4 digits) because `sscanf("%d")`
/// itself places no digit-count limit either.
fn normalise_year(y: i64) -> Option<i32> {
    if !(1..=9999).contains(&y) {
        return None;
    }
    let y = if y < 100 {
        y + if y < 80 { 2000 } else { 1900 }
    } else {
        y
    };
    i32::try_from(y).ok()
}

/// `lastDayOfMonth` (`DNTAPI.C:672-686`). `month` is already known to be
/// `1..=12` by every caller.
fn last_day_of_month(month: u8, year: i32) -> u8 {
    const DAYS: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut n = DAYS[usize::from(month) - 1];
    if month == 2 && is_leap_year(year) {
        n += 1;
    }
    n
}

/// `#define isLeapYear(yr) (((yr)&3) == 0 && (((yr)%100) != 0 || ((yr)%400) == 0))`
/// (`re/wg33src/INC/DNTAPI.H:192`).
fn is_leap_year(year: i32) -> bool {
    year & 3 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- strip_ansi -------------------------------------------------------

    #[test]
    fn strip_ansi_deletes_a_plain_csi_run_letter_included() {
        assert_eq!(
            strip_ansi(b"\x1b[1;37mHello\x1b[0m".to_vec()),
            b"Hello".to_vec()
        );
    }

    #[test]
    fn strip_ansi_passes_through_plain_text_unchanged() {
        assert_eq!(strip_ansi(b"nothing to strip".to_vec()), b"nothing to strip".to_vec());
    }

    #[test]
    fn strip_ansi_keeps_only_the_ascii_branch_of_ifansi() {
        assert_eq!(strip_ansi(b"\x1b[[ansi|ascii]".to_vec()), b"ascii".to_vec());
    }

    #[test]
    fn strip_ansi_keeps_the_ascii_branch_even_with_nested_colour_in_the_ansi_branch() {
        assert_eq!(
            strip_ansi(b"\x1b[[\x1b[1;33mBOLD\x1b[0m|plain]".to_vec()),
            b"plain".to_vec()
        );
    }

    #[test]
    fn strip_ansi_drops_a_single_branch_ifansi_whole() {
        // No `|`: no ASCII fallback to keep, so stripping leaves nothing --
        // this is where `crate::ifansi::process` disagrees, on purpose (see
        // `stpans`'s own doc comment).
        assert_eq!(strip_ansi(b"before\x1b[[ansi]after".to_vec()), b"beforeafter".to_vec());
    }

    #[test]
    fn strip_ansi_drops_an_unclosed_ifansi_before_the_separator() {
        assert_eq!(strip_ansi(b"before\x1b[[broken and unterminated".to_vec()), b"before".to_vec());
    }

    #[test]
    fn strip_ansi_keeps_the_ascii_branch_even_when_its_closer_is_missing() {
        // `|` was reached (ASCII branch selected and copied in), but the `]`
        // never arrives before the string ends: the ASCII text already
        // emitted stays.
        assert_eq!(strip_ansi(b"\x1b[[ansi|ascii and no closer".to_vec()), b"ascii and no closer".to_vec());
    }

    #[test]
    fn strip_ansi_leaves_an_unterminated_plain_csi_untouched() {
        // No final letter ever arrives, so the C never deletes it -- see
        // `strip_ansi`'s own doc comment on why this is not a bug to fix.
        assert_eq!(strip_ansi(b"plain \x1b[1;3".to_vec()), b"plain \x1b[1;3".to_vec());
    }

    #[test]
    fn strip_ansi_preserves_high_bit_cp437_bytes() {
        let input = vec![b'a', 0xB0, 0xB1, b'b'];
        assert_eq!(strip_ansi(input.clone()), input);
    }

    // ---- decode_date --------------------------------------------------

    #[test]
    fn decode_date_full_date_ok() {
        assert_eq!(decode_date("01/09/1989"), Some((1, 9, Some(1989))));
    }

    #[test]
    fn decode_date_two_digit_year_below_80_is_2000s() {
        assert_eq!(decode_date("01/09/05"), Some((1, 9, Some(2005))));
    }

    #[test]
    fn decode_date_two_digit_year_80_and_above_is_1900s() {
        assert_eq!(decode_date("01/09/89"), Some((1, 9, Some(1989))));
    }

    #[test]
    fn decode_date_no_year_defers_to_caller() {
        assert_eq!(decode_date("01/09"), Some((1, 9, None)));
    }

    #[test]
    fn decode_date_bad_month_is_none() {
        assert_eq!(decode_date("13/09/1989"), None);
    }

    #[test]
    fn decode_date_day_past_month_end_is_none() {
        assert_eq!(decode_date("02/30/1989"), None);
    }

    #[test]
    fn decode_date_feb_29_in_a_leap_year_is_ok() {
        assert_eq!(decode_date("02/29/2000"), Some((2, 29, Some(2000))));
    }

    #[test]
    fn decode_date_feb_29_in_a_non_leap_year_is_none() {
        assert_eq!(decode_date("02/29/1900"), None);
    }

    #[test]
    fn decode_date_garbage_is_none() {
        assert_eq!(decode_date("not a date"), None);
    }
}
