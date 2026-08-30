//! The host's own text variables: `SRC/api/galtxv/TXTVBL.C`, "the default
//! suite of text variables that comes with Worldgroup Baseline Edition",
//! registered before any add-on module's init runs.
//!
//! **Why this exists.** The Rose 3.0NT (`RCIROSE.DLL`, PE32) booted and then
//! faulted five times in sixty seconds, in a real-time kick, at an address
//! ending `0x705` -- RVA `0x4c705`, which is
//!
//! ```text
//! push  "SYSTEM_NAME"
//! call  findtvar
//! lea   eax, [ebx+ebx*4]            ; index * 5
//! mov   edx, [_txtvars]
//! mov   ecx, [edx]                  ; the table
//! mov   eax, [ecx+eax*4+0x10]       ; txtvars[i].varrou     <== fault
//! call  eax
//! ```
//!
//! No `-1` check, because no vendor module ever needed one: `init__galtxv`
//! registers `SYSTEM_NAME` and sixty others before any add-on's init runs.
//! This host registered none, so `txtvars` was NULL, `findtvar` answered
//! `-1`, and the module read `[0 - 4]`.
//!
//! **Mechanism.** Each variable's `varrou` is a host-reserved thunk -- the
//! same door `bgnedt` goes through (`Host::vectors`) -- whose `ImportSite`
//! names the vendor's routine (`tvar_sysnam`), so `shims::entry` resolves it
//! like any import and the module's `call eax` lands in [`tvar_sysnam`].
//! [`register_standard`] runs from `Host::new`, before any module is loaded,
//! in the vendor's order, so every index matches a Worldgroup 3.x board's.
//!
//! **What each answers** is in its own doc comment. Three groups cannot be
//! the vendor's own data, because this host has no such data at all, and
//! each says so where it is answered rather than pretending otherwise:
//! - class-table limits (`usrptr->cltptr`): no class table here, and a class
//!   without limits is what the vendor's own branches print as `UNLIMITED`;
//! - the menu page (`mnuoff(usrnum)`): no menuing system, so the page is
//!   empty and the vendor's own empty-page fallbacks apply;
//! - the `sv`/`sv2` statistics: nothing here counts calls, uploads or
//!   accounts, and zero is the count of what this host has done.
//!
//! A per-user variable with nobody current (`usrnum == -1`, a real-time
//! kick) stops the module rather than reading whatever `usaptr` last held,
//! which is what the vendor's `usaptr->userid` would do. The Rose's kick
//! asks only for `SYSTEM_NAME`, which needs no user.

use mbbs_machine::module::{ImportSite, Symbol};
use mbbs_machine::ptr::ModulePtr;

use crate::abi::{self, Abi, Call};
use crate::exports::MAJORBBS;
use crate::shims::system::{ncdate_text, ncdatel_text, ncedat_text, ncedatl_text, nctime_text};
use crate::shims::text::{SPR_BYTES, write_cstr_mem};
use crate::shims::{Shim, ShimError};
use crate::users::Field;
use crate::Host;

/// Every text variable `init__galtxv` registers (`TXTVBL.C:53-116`), in
/// its order: the name a module passes `findtvar`, the vendor's routine
/// name (which is what the thunk's `ImportSite` carries, and what a stop at
/// one reports), and the shim behind it.
pub(crate) fn standard<A: Abi>() -> Vec<(&'static str, &'static str, Shim<A>)> {
    vec![
        ("USERID", "tvar_userid", tvar_userid),
        ("PORT", "tvar_portno", tvar_portno),
        ("CHANNEL", "tvar_channo", tvar_channo),
        ("NAME", "tvar_usrnam", tvar_usrnam),
        ("COMPANY", "tvar_usrad1", tvar_usrad1),
        ("ADDRESS1", "tvar_usrad2", tvar_usrad2),
        ("ADDRESS2", "tvar_usrad3", tvar_usrad3),
        ("ADDRESS3", "tvar_usrad4", tvar_usrad4),
        ("PHONE", "tvar_usrpho", tvar_usrpho),
        ("SYSTEM_TYPE", "tvar_systyp", tvar_systyp),
        ("ANSI", "tvar_ansifl", tvar_ansifl),
        ("SCREEN_WIDTH", "tvar_scnwid", tvar_scnwid),
        ("SCREEN_LENGTH", "tvar_scnbrk", tvar_scnbrk),
        ("AGE", "tvar_usrage", tvar_usrage),
        ("SEX", "tvar_usrsex", tvar_usrsex),
        ("CREATION_DATE", "tvar_credat", tvar_credat),
        ("CREATION_DATE_L", "tvar_crdatl", tvar_crdatl),
        ("LAST_ON", "tvar_usedat", tvar_usedat),
        ("LAST_ON_L", "tvar_usdatl", tvar_usdatl),
        ("CLASS", "tvar_curcls", tvar_curcls),
        ("CREDITS", "tvar_tckavl", tvar_tckavl),
        ("CREDITS_EVER", "tvar_tcktot", tvar_tcktot),
        ("PAID_EVER", "tvar_tckpai", tvar_tckpai),
        ("TIME_ONLINE", "tvar_timonl", tvar_timonl),
        ("CALL_TIME_LIMIT", "tvar_timcal", tvar_timcal),
        ("DAY_TIME_LIMIT", "tvar_timday", tvar_timday),
        ("TIME_TODAY", "tvar_usdtdy", tvar_usdtdy),
        ("DAYS_LEFT", "tvar_dyslft", tvar_dyslft),
        ("DEBT_LIMIT", "tvar_dbtlmt", tvar_dbtlmt),
        ("BAUD", "tvar_bdrate", tvar_bdrate),
        ("CREDIT_RATE", "tvar_ccrate", tvar_ccrate),
        ("PAGE", "tvar_pagnam", tvar_pagnam),
        ("PARENT", "tvar_parpag", tvar_parpag),
        ("TITLE", "tvar_mnuttl", tvar_mnuttl),
        ("DATE", "tvar_sydate", tvar_sydate),
        ("DATE_L", "tvar_sydatl", tvar_sydatl),
        ("TIME", "tvar_sytime", tvar_sytime),
        ("SYSTEM_NAME", "tvar_sysnam", tvar_sysnam),
        ("SYSTEM_COMPANY", "tvar_syscmp", tvar_syscmp),
        ("SYSTEM_ADDRESS1", "tvar_sysad1", tvar_sysad1),
        ("SYSTEM_ADDRESS2", "tvar_sysad2", tvar_sysad2),
        ("SYSTEM_PHONE", "tvar_syspho", tvar_syspho),
        ("RESTRICTED_PHO", "tvar_sysrst", tvar_sysrst),
        ("CHARGE_PER_HOUR", "tvar_chhour", tvar_chhour),
        ("MINIMUM_CHARGE", "tvar_chgmin", tvar_chgmin),
        ("REG_NUMBER", "tvar_regnum", tvar_regnum),
        ("NUMBER_OF_LINES", "tvar_nmline", tvar_nmline),
        ("OTHERS_ONLINE", "tvar_ninuse", tvar_ninuse),
        ("TOTAL_CALLS", "tvar_ncalls", tvar_ncalls),
        ("DOWNLOADS", "tvar_dwnlds", tvar_dwnlds),
        ("UPLOADS", "tvar_nuplds", tvar_nuplds),
        ("TOTAL_MESSAGES", "tvar_msgtot", tvar_msgtot),
        ("OPEN_FORUM_MSGS", "tvar_sigopn", tvar_sigopn),
        ("OPEN_EMAIL_MSGS", "tvar_emlopn", tvar_emlopn),
        ("TOTAL_ACCOUNTS", "tvar_numact", tvar_numact),
        ("TOTAL_MALE", "tvar_nummal", tvar_nummal),
        ("TOTAL_FEMALE", "tvar_numfem", tvar_numfem),
        ("TOTAL_CORP", "tvar_numcor", tvar_numcor),
        ("TOTAL_ANSI", "tvar_numans", tvar_numans),
        ("BBS_VERSION", "tvar_vrsion", tvar_vrsion),
        ("MIN_ONLINE", "tvar_minonl", tvar_minonl),
    ]
}

/// `init__galtxv()` -- register every entry of [`standard`] behind a
/// host thunk, in order. Called from `Host::new`, so it precedes every
/// module and every other host thunk; the `bgnedt` vector `finish_init`
/// reserves comes after these.
///
/// # Errors
///
/// If the machine is out of thunks, or the heap cannot hold the table.
pub(crate) fn register_standard<A: Abi>(host: &mut Host<A>, machine: &mut A::Cpu) -> std::io::Result<()> {
    for (name, routine, _) in standard::<A>() {
        let (index, thunk) = A::reserve_host_thunk(machine)?;
        host.add_textvar(A::mem(machine), name, thunk)
            .map_err(|e| std::io::Error::other(format!("{name}: {e}")))?;
        host.vectors.push((
            index,
            ImportSite {
                module: MAJORBBS.to_owned(),
                symbol: Symbol::Name(routine.to_owned()),
                resolved: true,
            },
        ));
    }
    Ok(())
}

// `struct usracc` (`USRACC.H:20-56`, `INC/UStructs.h`): 301 bytes, laid out
// identically under both ABIs because every non-`CHAR` field is declared at
// an explicit width (`USHORT`, `SHORT`, `LONG`). Summed from the field sizes
// -- `UIDSIZ 30`, `PSWSIZ 10`, `NADSIZ 30`, `PHOSIZ 16`, `KEYSIZ 16`,
// `AXSSIZ 7` -- and pinned to `users::AccountLayout` by
// `usracc_offsets_agree_with_account_layout` below, where the two overlap.
const UIDSIZ: u16 = 30;
const NADSIZ: u16 = 30;
const PHOSIZ: u16 = 16;
const KEYSIZ: u16 = 16;
const USRACC_USERID: u16 = 0;
const USRACC_USRNAM: u16 = 40;
const USRACC_USRAD1: u16 = 70;
const USRACC_USRAD2: u16 = 100;
const USRACC_USRAD3: u16 = 130;
const USRACC_USRAD4: u16 = 160;
const USRACC_USRPHO: u16 = 190;
const USRACC_SYSTYP: u16 = 206;
const USRACC_ANSIFL: u16 = 208;
const USRACC_SCNWID: u16 = 209;
const USRACC_SCNBRK: u16 = 210;
const USRACC_AGE: u16 = 212;
const USRACC_SEX: u16 = 213;
const USRACC_CREDAT: u16 = 214;
const USRACC_USEDAT: u16 = 216;
const USRACC_CURCLS: u16 = 256;
const USRACC_TIMTDY: u16 = 272;
const USRACC_CREDS: u16 = 280;
const USRACC_TOTCREDS: u16 = 284;
const USRACC_TOTPAID: u16 = 288;

/// `MAJORBBS.H:31` -- the `scnbrk` code that means no page breaks at all.
const CTNUOS: u8 = 2;

/// `SIGNUP.C:80-85` -- what `systyp` codes are called.
const SYSSTG: [&str; 4] = ["OTHER", "IBM-PC", "Macintosh", "Apple/non-Mac"];

/// `SIGNUP.C:87-89` -- what `ansifl` values are called.
const ANSSTG: [&str; 4] = ["non-ANSI", "ANSI", "ANSI OFF", "ANSI ON"];

/// `struct user`'s `minut4` (`MAJORBBS.H:111`). GCV2 packs the struct with
/// 2-byte `int`s -- `usrcls, keys(4), state, substt, lofstt, usetmr` puts it
/// at `0x0e`; the non-GCV2 build leads with `flags, tckrst, tckonl, baud`
/// (16 bytes) and 4-byte `INT`s, so the same six fields put it at `0x28`.
/// Both derivations land `usrcls`/`state`/`substt` exactly where
/// `users::UserLayout` already measured them.
fn user_minut4<A: Abi>() -> Field {
    if A::GCV2 { Field::new(0x0e, 2) } else { Field::new(0x28, 4) }
}

/// `struct user`'s `baud` (`MAJORBBS.H:103` non-GCV2, `:116` GCV2): a
/// `LONG` at `0x0c` after the three `ULONG`s, or a `USHORT` at `0x18`
/// straight after the GCV2 `flags` at `0x14`.
fn user_baud<A: Abi>() -> Field {
    if A::GCV2 { Field::new(0x18, 2) } else { Field::new(0x0c, 4) }
}

/// Hand the module `text` in one of `spr`'s rotating buffers -- what the
/// vendor's `spr("%d", ...)` routines do, and, for its string-literal
/// returns (`"UNLIMITED"`, `"Logon"`), indistinguishable from the literal.
fn answer<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, text: &str) -> Result<abi::Ret<A>, ShimError> {
    let at = host.next_spr_buffer();
    write_cstr_mem::<A>(call.mem(), at, text.as_bytes(), SPR_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// The `varrou` result the vendor hands back as a pointer into a host
/// global -- `bbsttl`, `company`, `bturno` -- is the pointer itself.
fn global_ptr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, name: &str) -> Result<abi::Ret<A>, ShimError> {
    host.globals()
        .pointer_mem(call.mem(), name)
        .map(abi::Ret::Ptr)
        .map_err(|e| ShimError::Failed(format!("{name}: {e}")))
}

/// `usaptr` -- the current user's account record, which is the current
/// channel's. A kick with nobody current is refused by name rather than
/// read through whatever the global last held.
fn account<A: Abi>(call: &mut Call<A>, host: &Host<A>) -> Result<A::Ptr, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    Ok(host.users().account(chan))
}

/// `usrptr` -- the current channel's `struct user`.
fn user<A: Abi>(call: &mut Call<A>, host: &Host<A>) -> Result<A::Ptr, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    Ok(host.users().slot(chan))
}

/// A fixed-width `CHAR` field, read to its terminator or its full width.
fn cstr_field<A: Abi>(mem: &A::Mem, base: A::Ptr, at: u16, size: u16) -> Result<String, ShimError> {
    let bytes = A::ptr_offset(base, at)
        .resolve(mem, usize::from(size))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// A little-endian integer field of `width` bytes, zero-extended.
fn uint_field<A: Abi>(mem: &A::Mem, base: A::Ptr, field: Field) -> Result<u32, ShimError> {
    let bytes = A::ptr_offset(base, field.at)
        .resolve(mem, usize::from(field.width))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let mut wide = [0u8; 4];
    wide[..bytes.len()].copy_from_slice(bytes);
    Ok(u32::from_le_bytes(wide))
}

/// The same field, sign-extended from its own width.
fn int_field<A: Abi>(mem: &A::Mem, base: A::Ptr, field: Field) -> Result<i32, ShimError> {
    let raw = uint_field::<A>(mem, base, field)?;
    Ok(match field.width {
        1 => i32::from(raw as u8 as i8),
        2 => i32::from(raw as u16 as i16),
        _ => raw as i32,
    })
}

/// `usaptr->` a `CHAR[]` field of the current account.
fn account_str<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, at: u16, size: u16) -> Result<abi::Ret<A>, ShimError> {
    let acc = account(call, host)?;
    // The vendor returns the field's own address; the module gets a copy
    // with the same bytes and the same terminator.
    let text = cstr_field::<A>(call.mem(), acc, at, size)?;
    answer(call, host, &text)
}

/// `usaptr->` a numeric field of the current account.
fn account_int<A: Abi>(call: &mut Call<A>, host: &Host<A>, field: Field) -> Result<i32, ShimError> {
    let acc = account(call, host)?;
    int_field::<A>(call.mem(), acc, field)
}

/// `usrptr->` a numeric field of the current `struct user`.
fn user_int<A: Abi>(call: &mut Call<A>, host: &Host<A>, field: Field) -> Result<i32, ShimError> {
    let slot = user(call, host)?;
    int_field::<A>(call.mem(), slot, field)
}

/// `"%d minute%c"` with the vendor's own plural rule: `'s'` unless exactly
/// one, and `'\0'` -- nothing -- when it is.
fn minutes(n: i64) -> String {
    format!("{n} minute{}", if n != 1 { "s" } else { "" })
}

/// A packed DOS date the way `spr`'s callers take one.
fn packed(v: i32) -> u16 {
    v as u16
}

/// `TXTVBL.C:125` -- `usaptr->userid`.
pub fn tvar_userid<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USERID, UIDSIZ)
}

/// `TXTVBL.C:131` -- `spr("%d", usrnum)`.
pub fn tvar_portno<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    answer(call, host, &chan.index().to_string())
}

/// `TXTVBL.C:137` -- `strupr(spr("%x", channel[usrnum]))`. `channel[]` is
/// the word table `Users::channels` placed, two bytes an entry.
pub fn tvar_channo<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    let at = A::ptr_offset(host.users().channels(), chan.index() as u16 * 2);
    let value = int_field::<A>(call.mem(), at, Field::new(0, 2))?;
    answer(call, host, &format!("{value:X}"))
}

/// `TXTVBL.C:143` -- `usaptr->usrnam`.
pub fn tvar_usrnam<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRNAM, NADSIZ)
}

/// `TXTVBL.C:149` -- `usaptr->usrad1`, the company line.
pub fn tvar_usrad1<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRAD1, NADSIZ)
}

/// `TXTVBL.C:155` -- `usaptr->usrad2`.
pub fn tvar_usrad2<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRAD2, NADSIZ)
}

/// `TXTVBL.C:161` -- `usaptr->usrad3`.
pub fn tvar_usrad3<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRAD3, NADSIZ)
}

/// `TXTVBL.C:167` -- `usaptr->usrad4`.
pub fn tvar_usrad4<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRAD4, NADSIZ)
}

/// `TXTVBL.C:173` -- `usaptr->usrpho`.
pub fn tvar_usrpho<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_USRPHO, PHOSIZ)
}

/// `TXTVBL.C:179` -- `sysstg[usaptr->systyp]`. A code past the table is
/// refused rather than read off its end, which is what the vendor's would
/// do with it.
pub fn tvar_systyp<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let code = account_int(call, host, Field::new(USRACC_SYSTYP, 1))?;
    let name = usize::try_from(code)
        .ok()
        .and_then(|i| SYSSTG.get(i))
        .ok_or_else(|| ShimError::Failed(format!("systyp {code} names no system type")))?;
    answer(call, host, name)
}

/// `TXTVBL.C:185` -- `ansstg[usaptr->ansifl]`.
pub fn tvar_ansifl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let code = account_int(call, host, Field::new(USRACC_ANSIFL, 1))?;
    let name = usize::try_from(code)
        .ok()
        .and_then(|i| ANSSTG.get(i))
        .ok_or_else(|| ShimError::Failed(format!("ansifl {code} names no ANSI setting")))?;
    answer(call, host, name)
}

/// `TXTVBL.C:191` -- `spr("%d", usaptr->scnwid)`.
pub fn tvar_scnwid<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let acc = account(call, host)?;
    let width = uint_field::<A>(call.mem(), acc, Field::new(USRACC_SCNWID, 1))?;
    answer(call, host, &width.to_string())
}

/// `TXTVBL.C:197` -- `"(continuous)"` for `CTNUOS`, else the length.
pub fn tvar_scnbrk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let acc = account(call, host)?;
    let length = uint_field::<A>(call.mem(), acc, Field::new(USRACC_SCNBRK, 1))?;
    if length == u32::from(CTNUOS) {
        return answer(call, host, "(continuous)");
    }
    answer(call, host, &length.to_string())
}

/// `TXTVBL.C:204` -- the age if positive, else `"N/A"`.
pub fn tvar_usrage<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let age = account_int(call, host, Field::new(USRACC_AGE, 1))?;
    if age > 0 {
        return answer(call, host, &age.to_string());
    }
    answer(call, host, "N/A")
}

/// `TXTVBL.C:215` -- `'M'`, `'F'`, or `"Unknown"`.
pub fn tvar_usrsex<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let sex = account_int(call, host, Field::new(USRACC_SEX, 1))? as u8;
    answer(call, host, match sex {
        b'M' => "Male",
        b'F' => "Female",
        _ => "Unknown",
    })
}

/// `TXTVBL.C:222` -- `ncdate(usaptr->credat)`: empty for a zero date, the
/// way `ncdate` itself is.
pub fn tvar_credat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = packed(account_int(call, host, Field::new(USRACC_CREDAT, 2))?);
    answer(call, host, &ncdate_text(date).unwrap_or_default())
}

/// `TXTVBL.C:228` -- `ncdatel(usaptr->credat)`, `MM/DD/YYYY`.
pub fn tvar_crdatl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = packed(account_int(call, host, Field::new(USRACC_CREDAT, 2))?);
    answer(call, host, &ncdatel_text(date).unwrap_or_default())
}

/// `TXTVBL.C:234` -- `ncdate(usaptr->usedat)`.
pub fn tvar_usedat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = packed(account_int(call, host, Field::new(USRACC_USEDAT, 2))?);
    answer(call, host, &ncdate_text(date).unwrap_or_default())
}

/// `TXTVBL.C:240` -- `ncdatel(usaptr->usedat)`.
pub fn tvar_usdatl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = packed(account_int(call, host, Field::new(USRACC_USEDAT, 2))?);
    answer(call, host, &ncdatel_text(date).unwrap_or_default())
}

/// `TXTVBL.C:246` -- `usaptr->curcls`.
pub fn tvar_curcls<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    account_str(call, host, USRACC_CURCLS, KEYSIZ)
}

/// `TXTVBL.C:252` -- `"+%ld"` when in credit, `l2as` (a bare or negative
/// number) otherwise.
pub fn tvar_tckavl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let creds = account_int(call, host, Field::new(USRACC_CREDS, 4))?;
    if creds > 0 {
        return answer(call, host, &format!("+{creds}"));
    }
    answer(call, host, &creds.to_string())
}

/// `TXTVBL.C:259` -- `l2as(usaptr->totcreds)`.
pub fn tvar_tcktot<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let total = account_int(call, host, Field::new(USRACC_TOTCREDS, 4))?;
    answer(call, host, &total.to_string())
}

/// `TXTVBL.C:265` -- `l2as(usaptr->totpaid)`.
pub fn tvar_tckpai<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let paid = account_int(call, host, Field::new(USRACC_TOTPAID, 4))?;
    answer(call, host, &paid.to_string())
}

/// `TXTVBL.C:271` -- `(usrptr->minut4+2)/4` minutes, pluralised.
pub fn tvar_timonl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let minut4 = user_int(call, host, user_minut4::<A>())?;
    answer(call, host, &minutes(i64::from((minut4 + 2) / 4)))
}

/// `TXTVBL.C:280` -- `usrptr->cltptr->limcal`. This host has no class
/// table; the branch a `-1` limit takes is the one it answers.
pub fn tvar_timcal<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "UNLIMITED")
}

/// `TXTVBL.C:287` -- `usrptr->cltptr->limday`; see [`tvar_timcal`].
pub fn tvar_timday<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "UNLIMITED")
}

/// `TXTVBL.C:294` -- `(usaptr->timtdy+30)/60` minutes, pluralised.
pub fn tvar_usdtdy<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let secs = account_int(call, host, Field::new(USRACC_TIMTDY, 4))?;
    answer(call, host, &minutes((i64::from(secs) + 30) / 60))
}

/// `TXTVBL.C:303` -- `daystt` only under a class flagged `DAYEXP`, else
/// `"UNLIMITED"`; no class table, so the latter. See [`tvar_timcal`].
pub fn tvar_dyslft<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "UNLIMITED")
}

/// `TXTVBL.C:312` -- `cltptr->dbtlmt`: `-1` is `"UNLIMITED"`; see
/// [`tvar_timcal`].
pub fn tvar_dbtlmt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "UNLIMITED")
}

/// `TXTVBL.C:322` -- `l2as(usrptr->baud)`.
pub fn tvar_bdrate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let baud = user_int(call, host, user_baud::<A>())?;
    answer(call, host, &baud.to_string())
}

/// `TXTVBL.C:328` -- `spr("%u", usrptr->crdrat)`.
pub fn tvar_ccrate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let slot = user(call, host)?;
    let rate = uint_field::<A>(call.mem(), slot, host.users().user_layout().crdrat)?;
    answer(call, host, &rate.to_string())
}

/// `TXTVBL.C:334` -- the menu page, or `"Logon"` when there is none. This
/// host has no menuing system, so there is none.
pub fn tvar_pagnam<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "Logon")
}

/// `TXTVBL.C:343` -- the parent page, or `"None"`; see [`tvar_pagnam`].
pub fn tvar_parpag<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "None")
}

/// `TXTVBL.C:352` -- the page title, or `"Logon"`; see [`tvar_pagnam`].
pub fn tvar_mnuttl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "Logon")
}

/// `today()` as this host's clock packs it.
fn today<A: Abi>(host: &mut Host<A>) -> Result<u16, ShimError> {
    host.clock()
        .civil()
        .map_err(ShimError::Failed)?
        .dos_date()
        .map_err(|why| ShimError::Failed(format!("today: {why}")))
}

/// `TXTVBL.C:362` -- `ncedat(today())`, `DD-MMM-YY`.
pub fn tvar_sydate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = today(host)?;
    answer(call, host, &ncedat_text(date))
}

/// `TXTVBL.C:368` -- `ncedatl(today())`, `DD-MMM-YYYY`.
pub fn tvar_sydatl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let date = today(host)?;
    answer(call, host, &ncedatl_text(date))
}

/// `TXTVBL.C:374` -- `nctime(now())`, `HH:MM:SS`.
pub fn tvar_sytime<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let time = host.clock().civil().map_err(ShimError::Failed)?.dos_time();
    answer(call, host, &nctime_text(time))
}

/// `TXTVBL.C:380` -- `bbsttl`. The one The Rose's kick asks for.
pub fn tvar_sysnam<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "bbsttl")
}

/// `TXTVBL.C:386` -- `company`.
pub fn tvar_syscmp<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "company")
}

/// `TXTVBL.C:392` -- `addres1`.
pub fn tvar_sysad1<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "addres1")
}

/// `TXTVBL.C:398` -- `addres2`.
pub fn tvar_sysad2<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "addres2")
}

/// `TXTVBL.C:404` -- `dataph`.
pub fn tvar_syspho<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "dataph")
}

/// `TXTVBL.C:410` -- `liveph`.
pub fn tvar_sysrst<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    global_ptr(call, host, "liveph")
}

/// `TXTVBL.C:416` -- `chghour`, the `CHGHOUR` option's string
/// (`MAJORBBS.C:882`). This host has no billing options and charges
/// nothing, which is `"0"`.
pub fn tvar_chhour<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:422` -- `chgmin`; see [`tvar_chhour`].
pub fn tvar_chgmin<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:428` -- `bturno`, the array itself.
pub fn tvar_regnum<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    host.globals()
        .address("bturno")
        .map(abi::Ret::Ptr)
        .ok_or_else(|| ShimError::Failed("bturno is not a placed global".to_owned()))
}

/// `TXTVBL.C:434` -- `spr("%d", nterms)`.
pub fn tvar_nmline<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, &host.users().terms().count().to_string())
}

/// `TXTVBL.C:440` -- every channel `incusr` rates above `VACANT`. This host
/// keeps no `usrcls` (see `Host::go2mnu`); a channel is online exactly
/// while it holds the keyring `connect_state` gave it.
pub fn tvar_ninuse<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let online = host.users().terms().all().filter(|chan| host.users().keys(*chan).is_some()).count();
    answer(call, host, &online.to_string())
}

/// `TXTVBL.C:454` -- `l2as(sv2.totcalls)`. No `sv2` here: nothing counts
/// calls, so the count is zero.
pub fn tvar_ncalls<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:460` -- `l2as(sv.dwnlds)`; see [`tvar_ncalls`].
pub fn tvar_dwnlds<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:466` -- `l2as(sv.uplds)`; see [`tvar_ncalls`].
pub fn tvar_nuplds<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:472` -- `l2as(sv.msgtot)`; see [`tvar_ncalls`].
pub fn tvar_msgtot<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:478` -- `spr("%u", sv.sigopn)`; see [`tvar_ncalls`].
pub fn tvar_sigopn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:484` -- `spr("%u", sv.emlopn)`; see [`tvar_ncalls`].
pub fn tvar_emlopn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:490` -- `spr("%ld", sv2.numact)`. This host has no account
/// database (any User-ID may connect), so it has no accounts to count.
pub fn tvar_numact<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:496` -- `numact - numfem`; see [`tvar_numact`].
pub fn tvar_nummal<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:502` -- `sv2.numfem`; see [`tvar_numact`].
pub fn tvar_numfem<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:508` -- `sv2.numcor`; see [`tvar_numact`].
pub fn tvar_numcor<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:514` -- `sv2.numans`; see [`tvar_numact`].
pub fn tvar_numans<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    answer(call, host, "0")
}

/// `TXTVBL.C:520` -- `version`, with a non-printable last character made
/// ASCII "because some things (Web server, primarily) rely on strictly
/// printable ASCII version codes": CP437 `α` (`0xE0`) to `a`, `β` (`0xE1`)
/// to `b`, anything else to `x`. The source file carries those two as
/// literal bytes; CP437 is the character set every Galacticomm string is
/// in, and alpha/beta is what a version suffix means.
pub fn tvar_vrsion<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = host
        .globals()
        .address("version")
        .ok_or_else(|| ShimError::Failed("version is not a placed global".to_owned()))?;
    let size = host.globals().size("version").unwrap_or(0);
    let mut bytes = at
        .resolve(call.mem(), usize::from(size))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    bytes.truncate(bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len()));
    if bytes.len() > 1
        && let Some(last) = bytes.last_mut()
        && !(32..=126).contains(last)
    {
        *last = match *last {
            0xE0 => b'a',
            0xE1 => b'b',
            _ => b'x',
        };
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    answer(call, host, &text)
}

/// `TXTVBL.C:543` -- `(usrptr->minut4+2)/4`, the bare number.
pub fn tvar_minonl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let minut4 = user_int(call, host, user_minut4::<A>())?;
    answer(call, host, &((minut4 + 2) / 4).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use crate::shims::mudtext::findtvar;
    use crate::testing::Fixture;
    use crate::users::{AccountLayout, Connection};
    use mbbs_machine::m16::Ret;

    /// The row index `findtvar(name)` answers, or `-1` as the module sees it.
    fn find(f: &mut Fixture, name: &str) -> u16 {
        let query = f.text(name);
        match f.invoke(findtvar, &[query.offset, query.selector]).expect("findtvar") {
            Ret::U16(n) => n,
            other => panic!("findtvar answers an int, got {other:?}"),
        }
    }

    /// Call a text variable's routine and read what it points at.
    fn value(f: &mut Fixture, shim: Shim<Wg16>) -> String {
        match f.invoke(shim, &[]).expect("varrou") {
            Ret::Far(at) => f.read(at),
            other => panic!("a varrou answers a pointer, got {other:?}"),
        }
    }

    #[test]
    fn usracc_offsets_agree_with_account_layout() {
        let layout = AccountLayout::of::<Wg16>();
        assert_eq!((USRACC_USERID, USRACC_ANSIFL, USRACC_SCNWID, USRACC_SCNBRK),
                   (layout.userid, layout.ansifl, layout.scnwid, layout.scnbrk));
        assert_eq!(AccountLayout::of::<crate::abi::Wg32>().ansifl, USRACC_ANSIFL);
    }

    #[test]
    fn user_field_offsets_agree_with_user_layout() {
        // `minut4` is six fields past `usrcls`; `baud` sits where the
        // layout's neighbours say. GCV2: usrcls 0, state 6 -> minut4 0x0e.
        let l16 = crate::users::UserLayout::of::<Wg16>();
        assert_eq!(l16.state.at + 4 * 2, user_minut4::<Wg16>().at);
        assert_eq!(l16.flags.at + 4, user_baud::<Wg16>().at);
        let l32 = crate::users::UserLayout::of::<crate::abi::Wg32>();
        assert_eq!(l32.state.at + 4 * 4, user_minut4::<crate::abi::Wg32>().at);
        assert_eq!(l32.usrcls.at - 4, user_baud::<crate::abi::Wg32>().at);
    }

    #[test]
    fn a_fresh_host_has_every_standard_variable_in_vendor_order() {
        let mut f = Fixture::new();
        let table = standard::<Wg16>();
        assert_eq!(table.len(), 61, "TXTVBL.C:53-116 registers sixty-one");
        assert_eq!(f.host.textvars().len(), 61);
        for (i, (name, _, _)) in table.iter().enumerate() {
            assert_eq!(find(&mut f, name), i as u16, "{name} is row {i}");
        }
        assert_eq!(find(&mut f, "SYSTEM_NAME"), 37, "The Rose's own lookup");
    }

    #[test]
    fn every_varrou_is_a_host_thunk_that_names_its_routine() {
        let f = Fixture::new();
        for (i, (name, routine, _)) in standard::<Wg16>().iter().enumerate() {
            let row = f.host.textvars().get_mem(f.machine.mem(), i as u16).expect("row").expect("present");
            assert_eq!(row.name, *name);
            let varrou = row.varrou.expect("a registered routine");
            let (index, site) = f
                .host
                .vectors
                .iter()
                .find(|(_, site)| site.symbol == Symbol::Name((*routine).to_owned()))
                .expect("the thunk is a host vector");
            assert_eq!(varrou, f.machine.thunk_address(*index), "{name} points at its own thunk");
            assert_eq!(site.module, MAJORBBS);
        }
    }

    #[test]
    fn system_name_is_the_board_title_global() {
        let mut f = Fixture::new();
        let bbsttl = f.host.globals().pointer_mem(f.machine.mem(), "bbsttl").expect("bbsttl");
        let Ret::Far(at) = f.invoke(tvar_sysnam, &[]).expect("varrou") else { panic!() };
        assert_eq!(at, bbsttl, "the pointer itself, not a copy");
        assert_eq!(f.read(at), "Worldgroup");
    }

    #[test]
    fn a_per_user_variable_with_nobody_current_is_refused_not_guessed() {
        let mut f = Fixture::new();
        f.host.globals().write_mem(f.machine.mem_mut(), "usrnum", &0xFFFFu16.to_le_bytes()).expect("usrnum");
        let err = f.invoke(tvar_userid, &[]).expect_err("no user is current");
        assert!(err.to_string().contains("names no channel"), "{err}");
    }

    #[test]
    fn per_user_variables_read_the_current_channels_records() {
        let mut f = Fixture::new();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        f.host.point_curusr(&mut f.machine, chan).expect("current");
        assert_eq!(value(&mut f, tvar_userid), "dan");
        assert_eq!(value(&mut f, tvar_portno), "0");
        assert_eq!(value(&mut f, tvar_channo), "0", "channel[0] is the local console");
        assert_eq!(value(&mut f, tvar_ansifl), "ANSI");
        assert_eq!(value(&mut f, tvar_scnwid), "80");
        assert_eq!(value(&mut f, tvar_usrage), "N/A", "age 0");
        assert_eq!(value(&mut f, tvar_usrsex), "Unknown");
        assert_eq!(value(&mut f, tvar_credat), "", "date zero is ncdate's empty string");
        assert_eq!(value(&mut f, tvar_tckavl), "0", "no credit is a bare zero, not +0");
        assert_eq!(value(&mut f, tvar_timonl), "0 minutes");
        assert_eq!(value(&mut f, tvar_usdtdy), "0 minutes");
        assert_eq!(value(&mut f, tvar_minonl), "0");
    }

    #[test]
    fn minutes_pluralises_the_way_the_vendor_does() {
        assert_eq!(minutes(0), "0 minutes");
        assert_eq!(minutes(1), "1 minute");
        assert_eq!(minutes(2), "2 minutes");
    }

    #[test]
    fn board_wide_variables_answer_from_host_state() {
        let mut f = Fixture::new();
        assert_eq!(value(&mut f, tvar_nmline), crate::globals::NTERMS.to_string());
        assert_eq!(value(&mut f, tvar_ninuse), "0");
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        assert_eq!(value(&mut f, tvar_ninuse), "1");
        let Ret::Far(at) = f.invoke(tvar_regnum, &[]).expect("varrou") else { panic!() };
        assert_eq!(at, f.host.globals().address("bturno").expect("bturno"));
        assert_eq!(value(&mut f, tvar_timcal), "UNLIMITED");
        assert_eq!(value(&mut f, tvar_pagnam), "Logon");
        assert_eq!(value(&mut f, tvar_parpag), "None");
        assert_eq!(value(&mut f, tvar_ncalls), "0");
    }

    #[test]
    fn date_and_time_follow_the_dntapi_formats() {
        let mut f = Fixture::new();
        let date = value(&mut f, tvar_sydate);
        assert_eq!(date.len(), 9, "DD-MMM-YY: {date}");
        assert_eq!(&date[2..3], "-");
        let long = value(&mut f, tvar_sydatl);
        assert_eq!(long.len(), 11, "DD-MMM-YYYY: {long}");
        assert_eq!(&long[..6], &date[..6]);
        let time = value(&mut f, tvar_sytime);
        assert_eq!(time.len(), 8, "HH:MM:SS: {time}");
        assert_eq!(&time[2..3], ":");
    }

    #[test]
    fn version_suffixes_alpha_and_beta_become_ascii() {
        let mut f = Fixture::new();
        let at = f.host.globals().address("version").expect("version");
        f.machine.write(at, b"3.30\xE1\0").expect("version");
        assert_eq!(value(&mut f, tvar_vrsion), "3.30b");
        f.machine.write(at, b"3.30\xE0\0").expect("version");
        assert_eq!(value(&mut f, tvar_vrsion), "3.30a");
        f.machine.write(at, b"3.30\xFE\0").expect("version");
        assert_eq!(value(&mut f, tvar_vrsion), "3.30x");
        f.machine.write(at, b"3.30\0").expect("version");
        assert_eq!(value(&mut f, tvar_vrsion), "3.30");
    }
}
