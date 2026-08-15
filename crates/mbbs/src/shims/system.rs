//! The clock, the audit trail, and registering a module.
//!
//! Everything here that reads the world reads it through [`Host`], so a test
//! can point it at a directory of its own.
//!
//! # Generic core, all nineteen now
//!
//! Every routine here is generic:
//! `fn(&mut Call<A>, &mut Host<A>) -> Result<abi::Ret<A>, ShimError>`, the
//! same shape `shims::user`/`shims::text` already established. `shocst` and
//! `catastro` route their varargs through [`crate::fmt::format_call`], which
//! needed no word-index parameter the way the old `Args::Call { first: N }`
//! did -- see `fmt`'s own doc comment.
//!
//! **`register_module`, `register_agent` and `rtkick` were the last three.**
//! Each builds a [`Registration`], [`Agent`] or [`Kick`], which used to be
//! plain, non-generic structs holding `FarPtr` fields directly -- pushed into
//! `Host<A>`'s own `modules`/`agents`/`kicks` fields, which held
//! `Vec<Registration>`/`Vec<Agent>`/`Vec<Kick>` **regardless of `A`**, not
//! `Vec<Registration<A>>`. `4d5bab4` ("Host over the ABI rather than the
//! machine") generified every other `Host` field this way and *named* the
//! ones it moved onto `A::Ptr` in its own commit message -- `spr`, `l2as`,
//! `mdf`, `empty`, `strtok`, `fsdscb`, `fsdtmp`, `fsd_ascii`, `fsd_scratch`,
//! plus `DateBuffers` and `FsdSession` -- and deliberately did not name
//! these three, because making them generic also genericises
//! [`Registration::dispatch`], which `Host::poll`'s `state_entry`/
//! `fsd_dispatch` call directly. That conversion is now done: `Kick<A>`,
//! `Registration<A>` and `Agent<A>` (each defaulting to `Wg16`, the
//! technique `Users<A>`, `Globals<A>` and the rest of this crate's
//! subsystems already established) hold `A::Ptr` instead of `FarPtr`, and
//! `Registration::dispatch` takes `&A::Mem` instead of `&Machine` -- every
//! call site in `impl Host<Wg16>` reborrows one out of the `Machine` it
//! already has (`Machine::mem`), so the change does not reach `Host::poll`'s
//! own signature or its dispatch *logic*, only the one line that reads an
//! entry point. `dispatch`'s null test moves from `FarPtr::selector != 0` to
//! "every byte zero" ([`Abi::ptr_to_bytes`]), the same substitution [`time`]
//! already made and for the same reason -- see `Registration::dispatch`'s
//! own doc comment.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;
use mbbs_machine::ptr::ModulePtr;

use crate::{DateBuffers, Host};
use crate::abi::{self, Abi, Call, Wg16};
use crate::fmt::format_call;
use crate::random::Random;
use crate::shims::{NO, ShimError};
use crate::shims::text::write_cstr_mem;

/// `MAJORBBS.H:37` -- maximum size for module names, terminator included.
///
/// A **size**, not an offset. It bounds `descrp`'s own bytes -- what
/// [`register_module`] reads and refuses on -- and it happens to equal
/// `Wg16`'s header stride because Borland's 16-bit compiler byte-packs
/// `struct module`. It is not `Wg32`'s stride: see [`ModuleLayout`] for the
/// padded offset [`Registration::dispatch`] actually reads the routine
/// pointers from.
const MNMSIZ: u16 = 25;

/// `GCSP.H:19` -- application id size, terminator included.
const AIDSIZ: u16 = 9;

/// Bytes of `struct agent`: the appid, then four far vectors.
///
/// 25, and the binary agrees: `register_agent` multiplies every index by
/// `0x19`.
const AGENT_SIZE: u16 = AIDSIZ + 4 * 4;

/// Bytes of the buffer `gmdnam` returns a pointer into.
///
/// `static char tmpbuf[40]` in the real one
/// (`mbbs625sdk/MBBS_SDK/INSTALLA/MAJORBBS.C:1141`), and it holds a whole line
/// of the `.MDF` before the name is picked out of it.
const MDF_LINE: u16 = 40;

/// `USHORT now(VOID)` -- `DNTAPI.H:205-206` -- the time of day, packed as
/// DOS packs it.
///
/// **Correction, found converting this file to a cursor
/// (docs/plans/2026-08-11-abi-abstraction-implementation.md's Task 4-5):**
/// this and its neighbours below were long cited to `DOSFACE.H`, which does
/// not exist anywhere in `re/wg33src/INC`'s 125 headers -- not even under a
/// different name; grepping for it repo-wide finds nothing. The real
/// declaration is `DNTAPI.H`'s, which also declares `today`, `ncdate`,
/// `nctime`, `ncedat`, `cofdat` and the `moname` table below, all corrected
/// in this diff. Hours in bits 15..11, minutes in 10..5, and *two-second*
/// units in 4..0, because five bits will not hold sixty.
///
/// # Errors
///
/// If the host's clock cannot say what time it is.
///
/// Generic: reads no argument of its own, and [`Host::clock`] is not
/// `A`-dependent at all.
pub fn now<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let t = host.clock().civil().map_err(ShimError::Failed)?;
    Ok(abi::Ret::Int(A::Int::from(t.dos_time())))
}

/// `USHORT today(VOID)` -- `DNTAPI.H:199-200` -- the date, packed as DOS
/// packs it.
///
/// Years since 1980 in bits 15..9, month in 8..5, day in 4..0.
///
/// # Errors
///
/// If the host's clock cannot say what day it is, or the year is one those
/// seven bits will not hold. The old shim clamped with `.max(0)`, which turned
/// 1970 into 1980 -- a date that is wrong rather than absent, and the one
/// outcome this crate exists to avoid.
///
/// Generic: reads no argument of its own, matching [`now`].
pub fn today<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let t = host.clock().civil().map_err(ShimError::Failed)?;
    let packed = t
        .dos_date()
        .map_err(|why| ShimError::Failed(format!("today: {why}")))?;
    Ok(abi::Ret::Int(A::Int::from(packed)))
}

/// `long time(long *tloc)` -- seconds since 1970, and stored if asked.
///
/// No vendor prototype: Borland's own runtime, re-exported by `MAJORBBS.DLL`
/// like `access` below, with no Galacticomm header redeclaring it.
///
/// # Errors
///
/// If the host's clock cannot say, or `tloc` names memory the module does not
/// own.
///
/// Generic: the null test is every byte of `tloc` being zero
/// ([`Abi::ptr_to_bytes`]), the same reading `shims::user::begin_polling`
/// and `shims::msg::tokopt` already established for a null routine/list
/// pointer -- not `FarPtr::selector != 0` as the original word-indexed shim
/// wrote it, which `A::Ptr` is opaque to. The two agree on every value this
/// crate's own tests exercise (`tloc` is either a real allocation or exactly
/// `[0, 0]`), and the byte test is the one every other converted shim in
/// this crate already uses for "is this pointer null".
pub fn time<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let seconds = host.clock().epoch().map_err(ShimError::Failed)?;
    let tloc = call.ptr();

    // A null pointer is how C spells "do not store it", and is the ordinary
    // case rather than an error.
    if !A::ptr_to_bytes(tloc).iter().all(|&b| b == 0) {
        tloc.write(call.mem(), &seconds.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Long(seconds))
}

/// Bytes of the three date statics, measured from their spacing in
/// `MAJORBBS-wg101.EXE`'s `DGROUP`: `0x40`, `0x49`, `0x52`.
///
/// `GALFIL.C:1210` corroborates the first two independently --
/// `stzcpy(answer, nctime(dctime(nts)), 9)`.
const DATE_LEN: u16 = 9;
const TIME_LEN: u16 = 9;
const EDAT_LEN: u16 = 10;

/// The buffers the date routines format into, allocated the first time one of
/// them runs.
///
/// See [`DateBuffers`] for why they are allocated once rather than per call.
///
/// # Errors
///
/// If the module's heap cannot give up four small blocks.
///
/// Generic: calls [`Heap::reserve`](crate::heap::Heap::reserve) directly,
/// and [`write_cstr_mem`] is `write_cstr`'s. `DateBuffers<A>` was already
/// generic (`4d5bab4`), so nothing about the struct itself needed to move.
fn buffers_mem<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>) -> Result<DateBuffers<A>, ShimError> {
    if let Some(already) = host.datebuf {
        return Ok(already);
    }

    let date = host.heap.reserve(mem, DATE_LEN).map_err(ShimError::Failed)?;
    let time = host.heap.reserve(mem, TIME_LEN).map_err(ShimError::Failed)?;
    let edat = host.heap.reserve(mem, EDAT_LEN).map_err(ShimError::Failed)?;
    let empty = host.heap.reserve(mem, 1).map_err(ShimError::Failed)?;
    // Written explicitly rather than trusted to the heap's zero-fill -- see
    // `Host::empty` (`lib.rs:212`) for the sibling that gets the same
    // treatment eagerly, in `Host::new`, because it has to exist before this
    // one would ever be allocated.
    write_cstr_mem::<A>(mem, empty, b"", 1)?;

    let all = DateBuffers {
        date,
        time,
        edat,
        empty,
    };
    host.datebuf = Some(all);
    Ok(all)
}

/// `const CHAR *nctime(USHORT time)` -- `DNTAPI.H:216-218` -- a DOS-packed
/// time as `HH:MM:SS`.
///
/// No C source (the `.C`, as opposed to the header) survives for this one.
/// Transcribed from `MAJORBBS-wg101.EXE seg 33:0x0c56`, which is
/// `sprintf(buf, "%02d:%02d:%02d", (t>>11)&0x1f, (t>>5)&0x3f, (t<<1)&0x3e)`
/// and hands back the buffer.
///
/// **The low five bits are two-second units and are doubled, not masked** --
/// five bits will not hold 59, so an odd second cannot be represented at all
/// and the routine never prints one. That is the field a reader gets wrong by
/// working from the name instead of the instructions.
///
/// There is no null case: unlike [`ncdate`], `nctime(0)` formats `00:00:00`.
///
/// # Errors
///
/// If the module's heap cannot give the buffer its first time through.
pub fn nctime<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let packed = Into::<u32>::into(call.int()) as u16;
    let at = buffers_mem(call.mem(), host)?.time;
    let text = format!(
        "{:02}:{:02}:{:02}",
        (packed >> 11) & 0x1f,
        (packed >> 5) & 0x3f,
        (packed << 1) & 0x3e,
    );
    write_cstr_mem::<A>(call.mem(), at, text.as_bytes(), TIME_LEN)?;
    Ok(abi::Ret::Ptr(at))
}

/// `const CHAR *ncdate(USHORT date)` -- `DNTAPI.H:208-210` -- a DOS-packed
/// date as `MM/DD/YY`.
///
/// No C source (the `.C`) survives. Transcribed from
/// `MAJORBBS-wg101.EXE seg 33:0x0c02`.
///
/// **Date zero is not a date, and the original says so** by returning a
/// separate empty string at `DS:0x82` *without touching its buffer* -- so a
/// result taken earlier is still standing after a null date goes through.
/// Reproduced here, because the alternative reading, formatting `00/00/00`, is
/// a date that is wrong rather than one that is absent.
///
/// The year is `% 100`, so nothing downstream can tell 2007 from 2107. That
/// limitation is the original's, not this host's -- `seg 33:0x0c26` divides by
/// `0x64` and keeps the remainder.
///
/// # Errors
///
/// If the module's heap cannot give the buffer its first time through.
pub fn ncdate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let packed = Into::<u32>::into(call.int()) as u16;
    let all = buffers_mem(call.mem(), host)?;

    // `or cx,cx / jnz` at `seg 33:0x0c10`, and the branch it does not take
    // writes nothing at all.
    if packed == 0 {
        return Ok(abi::Ret::Ptr(all.empty));
    }

    let text = format!(
        "{:02}/{:02}/{:02}",
        (packed >> 5) & 0xf,
        packed & 0x1f,
        (((packed >> 9) & 0x7f) + 1980) % 100,
    );
    write_cstr_mem::<A>(call.mem(), all.date, text.as_bytes(), DATE_LEN)?;
    Ok(abi::Ret::Ptr(all.date))
}

/// Days before each month in a non-leap year, measured -- not reasoned out --
/// at `DGROUP:0x68` of `MAJORBBS-wg101.EXE`: 13 words, index 0 unused and
/// 1..=12 the running total of days before that month. The table ends exactly
/// where the empty-string constant (`0x82`) and [`ncdate`]'s own format string
/// (`0x83`) begin, which is independent corroboration that this is where it
/// starts and how long it is.
const CUMULATIVE_DAYS: [u16; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// `USHORT cofdat(USHORT date)` -- `DNTAPI.H:276-278` -- a DOS-packed date
/// as a day count, so that two dates can be subtracted to find how many days
/// apart they are.
///
/// No C source (the `.C`) survives. Transcribed from
/// `MAJORBBS-wg101.EXE seg 33:0x0e9e` (ordinal 134, twelve call sites); the
/// fields unpack exactly as [`ncdate`]'s do:
///
/// ```text
/// year  = (date >> 9) & 0x7f      years since 1980
/// month = (date >> 5) & 0xf
/// day   =  date       & 0x1f
///
/// days  = year * 365
///       + (year + 3) / 4                leap days strictly before this year
///       + CUMULATIVE_DAYS[month]
///       + (month > 2 && year % 4 == 0)  this year's leap day, once it has passed
///       + day
///       - 1
/// ```
///
/// **1980 is year 0, and it is itself a leap year.** `(year + 3) / 4` counts
/// leap years strictly *before* the current one, so 1980's own leap day never
/// shows up in that term -- it is what the trailing `month > 2 && year % 4 ==
/// 0` adds, and only once 29 February has actually gone by. Get the `+ 3`
/// wrong and every single date still formats fine through [`ncdate`], because
/// nothing here touches that routine, while every *difference* comes out one
/// day off.
///
/// # Errors
///
/// If `date` unpacks to a month the table has no entry for. The four-bit field
/// can hold 13..=15; `CUMULATIVE_DAYS` only has indices 0..=12, and the real
/// host would read whatever bytes happen to follow it -- the empty-string
/// constant and then [`ncdate`]'s format string -- and call the result a day
/// count. This host refuses instead.
///
/// # This routine is unreachable by any test in this crate
///
/// Its callers are the polling routines, which nothing here drives yet. A flat
/// meter after this commit is not this shim breaking -- it is this shim never
/// running.
pub fn cofdat<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let packed = Into::<u32>::into(call.int()) as u16;
    let year = i64::from((packed >> 9) & 0x7f);
    let month = usize::from((packed >> 5) & 0xf);
    let day = i64::from(packed & 0x1f);

    let cumulative = *CUMULATIVE_DAYS
        .get(month)
        .ok_or_else(|| ShimError::Failed(format!("cofdat: {month} is not a month")))?;
    let leap_before = (year + 3) / 4;
    let leap_this_year = i64::from(month > 2 && year % 4 == 0);

    let days = year * 365 + leap_before + i64::from(cumulative) + leap_this_year + day - 1;
    Ok(abi::Ret::Int(A::Int::from(days as u16)))
}

/// `EXPWGSV(CHAR) moname[16][4]` -- `DNTAPI.H:195` -- sixteen four-byte
/// entries, measured at **NE segment 88** of `MAJORBBS-wg101.EXE` (file
/// offset `0xc9a00`), DGROUP offset `0x00`. Segment 88 is this module's real
/// DGROUP: it is what the relocation on the `mov ax,0xffff` at
/// `seg 33:0x0c9f` (immediately before the `mov ds,ax` that `ncedat` runs
/// before indexing this table) targets.
///
/// The measured bytes:
///
/// `000\0JAN\0FEB\0MAR\0APR\0MAY\0JUN\0JUL\0AUG\0SEP\0OCT\0NOV\0DEC\0XXX\0XXX\0XXX\0`
///
/// Upper case, and sixteen entries rather than twelve: slot 0 is a `"000"`
/// sentinel and slots 13..=15 are `"XXX"`, which is exactly what a table built
/// for a 4-bit index (0..=15) with no bounds check needs. See [`ncedat`] for
/// why this table is indexed directly rather than `month - 1`, and how a
/// previous version of this comment cited an address that was never in this
/// segment.
const MONAME: [&str; 16] = [
    "000", "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    "XXX", "XXX", "XXX",
];

/// `const CHAR *ncedat(USHORT date)` -- `DNTAPI.H:220-222` -- a DOS-packed
/// date as `DD-MON-YY`, e.g. `07-AUG-26`.
///
/// No C source (the `.C`) survives. Transcribed from
/// `MAJORBBS-wg101.EXE seg 33:0x0c98` (ordinal 429, seven call sites); the
/// fields unpack exactly as [`cofdat`]'s do. The call it builds is
/// `spr(buf, "%02d-%s-%02d", day, moname[month], (year + 0x7bc) % 100)` --
/// `0x7bc` is 1980, and the format string (`DGROUP:0xa1`) is the same static
/// [`ncdate`] and [`nctime`] already measured.
///
/// **`moname[month]`, not `moname[month - 1]`.** The disassembly is
///
/// ```text
/// mov ax, cx          ; cx is the packed date
/// sar ax, 5
/// and ax, 0xf          ; month, 0..=15
/// shl ax, 2            ; * 4 (entry size)
/// add ax, 0             ; base of moname is 0, not moname - 4
/// ```
///
/// -- base `0`, not `moname`'s address minus one entry. `month = 8` (August)
/// reaches byte offset `0x20` into [`MONAME`], which is slot 8 (`AUG`), not
/// slot 7. A previous version of this comment claimed a `month - 1` index and
/// a 12-entry table; both were wrong. See [`MONAME`] for where the table
/// actually lives and why it has 16 entries, not 12.
///
/// **There is no null case, and `ncedat` is total.** The disassembly goes
/// straight from `mov cx,[bp+6]` into the shifts -- no `or cx,cx` guard
/// anywhere -- so `ncedat(0)` does not hand back an empty string the way
/// [`ncdate`] does. It computes `month = 0`, which is `moname[0]`, the `"000"`
/// sentinel: `ncedat(0)` is `"00-000-80"`. Likewise `month` in `13..=15` is
/// `moname[13..=15]`, `"XXX"`. A previous version of this shim refused those
/// four values, reasoning that `moname` had only 12 entries and month 0 read
/// into an unrelated weekday table one slot before it -- built on the same
/// wrong address as the `month - 1` mistake above. Once the table is measured
/// correctly, every 4-bit value has a real, in-bounds answer, and refusing
/// four of them was refusing behaviour the original host actually has.
///
/// # Errors
///
/// If the module's heap cannot give the buffer its first time through.
///
/// # This routine is unreachable by any test in this crate
///
/// Its callers are the polling routines, which nothing here drives yet. A flat
/// meter after this commit is not this shim breaking -- it is this shim never
/// running.
pub fn ncedat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let packed = Into::<u32>::into(call.int()) as u16;
    let all = buffers_mem(call.mem(), host)?;

    let month = usize::from((packed >> 5) & 0xf);
    let name = MONAME[month];

    let text = format!(
        "{:02}-{}-{:02}",
        packed & 0x1f,
        name,
        (((packed >> 9) & 0x7f) + 1980) % 100,
    );
    write_cstr_mem::<A>(call.mem(), all.edat, text.as_bytes(), EDAT_LEN)?;
    Ok(abi::Ret::Ptr(all.edat))
}

/// `void srand(unsigned seed)`.
///
/// No vendor prototype: Borland's own runtime, re-exported by `MAJORBBS.DLL`,
/// with no Galacticomm header redeclaring it.
///
/// MajorMUD calls this once, six calls into initialisation, with the low word
/// of `time()` -- so the seed is the wall clock and no two runs of the real host
/// agreed either. See [`mbbs::random`](crate::random).
pub fn srand<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let seed = Into::<u32>::into(call.int()) as u16;
    host.random = Random::new(seed);
    Ok(abi::Ret::Void)
}

/// `int rand(void)` -- Borland's own, re-exported by `MAJORBBS.DLL` in 16-bit
/// and imported from `cw3220mt.DLL` in 32-bit.
///
/// The same generator [`genrdn`] draws from, exposed raw. `WCCMMUD.DLL`
/// never imports it -- it always goes through `genrdn`/`lngrnd` -- but
/// LunatiX calls it directly, twice during init.
///
/// [`Random::rand`](crate::random::Random::rand) already masks to `RAND_MAX`,
/// so the value is in `[0, RAND_MAX]` exactly as C promises. Returned through
/// [`Abi::int_from_u32`] rather than `A::Int::from(u16)`: both are correct for
/// a value this small, and the former is the one that stays correct if
/// `RAND_MAX` ever stops fitting in sixteen bits.
pub fn rand<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(host.random.rand()))))
}

/// `INT genrdn(INT min, INT max)` -- `BBSUTILS.H:69` -- a random number in
/// `[min, max)`.
///
/// The upper bound is exclusive and the routine's own comment says so. See
/// [`between`](crate::random::between), which is the ported algorithm; this is
/// only the two arguments and the draw.
///
/// # Errors
///
/// If the generator stops generating. See
/// [`Runaway`](crate::random::Runaway).
pub fn genrdn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let min = Into::<u32>::into(call.int()) as i16;
    let max = Into::<u32>::into(call.int()) as i16;
    host.random
        .genrdn(min, max)
        .map(|n| abi::Ret::Int(A::Int::from(n as u16)))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// `LONG lngrnd(LONG min, LONG max)` -- `BBSUTILS.H:70` -- [`genrdn`] in
/// `long` arithmetic. `BBSUTILS.C:76-93`, and ordinal 390 of the genuine
/// host.
///
/// The upper bound is exclusive, as it is for [`genrdn`]. See
/// [`between_long`](crate::random::between_long), which is the ported
/// algorithm; this is only the two arguments and the draw.
///
/// # Two words each, and which two
///
/// Before this shim read its arguments through a cursor, `arg_u16` was
/// indexed in **words**, so a pair of `long`s was `arg_u32(0)` and
/// `arg_u32(2)` -- not `(0)` and `(1)`, which is [`genrdn`]'s spacing and
/// would have read `min`'s high half as `max`'s low one. `Cursor::long`
/// removes that footgun by construction: it always advances by exactly one
/// `long`'s width, so `args.long()` twice in a row cannot land on the wrong
/// half the way a hand-picked word offset could. Kept here as the reason the
/// two shims, sitting next to each other, differ in more than name.
///
/// # Why this was missing for so long, and what it cost
///
/// MajorMUD calls it from 13 sites and **initialisation reaches none of them**
/// (`tests/wccmmud.rs`'s own record of the init call census says so), so every
/// in-process test this crate has ever run went green without it. What does
/// reach it is the module's self-sustaining heartbeat -- the spawner's
/// boot-fill -- which only runs when something drives `Host::cycle` freely, as
/// `mbbs-server` does and no test did. The first live telnet session died on
/// it immediately.
///
/// # Errors
///
/// If the generator stops generating. See
/// [`Runaway`](crate::random::Runaway).
pub fn lngrnd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let min = call.long() as i32;
    let max = call.long() as i32;
    host.random
        .lngrnd(min, max)
        .map(|n| abi::Ret::Long(n as u32))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// `int access(char *path, int amode)` -- is this file there, and may I use it?
///
/// Borland's, re-exported by `MAJORBBS.DLL` as ordinal 850. `amode` is a mask:
/// 0 asks only whether the file exists, 2 whether it can be written, 4 whether
/// it can be read, 6 both. Zero means yes and -1 means no.
///
/// **-1 is an answer, not a refusal.** This is the one routine in the host so
/// far whose whole purpose is to report an absence, so returning "no" for a
/// file that is not there is exactly right where everywhere else it would be
/// the lie this crate is built to avoid.
///
/// It is here rather than with the Btrieve routines it arrived among because it
/// is not one -- but answering it is what lets initialisation finish opening its
/// data files. MajorMUD builds a sixteenth filename, asks
/// `access(".\WCCVACN.DAT", 0)`, is told -1, and **does not open it**. There is
/// no `WCCVACN.VIR` to install one from and no working board has the file, so
/// -1 is both the true answer and the one that lets the module continue.
pub fn access<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let mode = Into::<u32>::into(call.int()) as u16;
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    // A path this host will not look in is not a file that is missing -- it is
    // a question it cannot answer, and answering "no" would tell the module the
    // file is absent when nobody looked.
    //
    // `Host::<Wg16>::dos_name`, not `Host::<A>::dos_name`: `dos_name` has no
    // `self` and no `A`-mentioning parameter, so it lives in `impl
    // Host<Wg16>` rather than the generic block (`rustc` cannot infer which
    // `Abi` a bare `impl<A: Abi> Host<A>` copy would mean, with nothing in
    // its signature to pin `A`) -- the same reading `shims::stream::fopen`/
    // `unlink` already established for the identical call.
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;
    let Some(path) = host.find(&name) else {
        return Ok(abi::Ret::Int(A::Int::from(NO)));
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(abi::Ret::Int(A::Int::from(NO)));
    };

    // Bit 1 is write and bit 2 is read. Nothing else is defined, and a mode
    // with anything else in it is a call this host has misread rather than a
    // question about a file.
    if mode & !0b110 != 0 {
        return Err(ShimError::Failed(format!(
            "access({named}, {mode}), and only 0, 2, 4 and 6 are modes"
        )));
    }
    if mode & 2 != 0 && metadata.permissions().readonly() {
        return Ok(abi::Ret::Int(A::Int::from(NO)));
    }
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `VOID getFileTm(const CHAR *fname, USHORT *dtim, USHORT *ddat)` -- a
/// file's last-modified time and date, DOS-packed.
///
/// `re/wg33src/SRC/api/gcommlib/FIOAPI.C:407-437` (Worldgroup 3.3, 1997),
/// the non-`GCWINNT` half (the `GCWINNT`/`FindFirstFile` half is the same
/// answer, through Win32 instead of `stat`):
///
///
/// **The vendor tolerates a missing file -- so does this.** `*ddat=*dtim=0`
/// runs unconditionally before `stat` is even attempted, and a failed `stat`
/// returns with those zeros left in place -- the routine's own caller
/// comments it explicitly (`FIOAPI.C:448`: "getFileTm() returns dat == 0 if
/// the file doesn't exist"). This host reproduces exactly that: zero both
/// outputs first, and if the sandboxed lookup ([`Host::find`], the same one
/// [`access`] uses) finds nothing -- or the metadata read otherwise fails --
/// stop there and hand back the zeros. Not a refusal; the documented answer.
///
/// `dddate`/`dttime`'s packing (`re/wg33src/INC/DNTAPI.H:184,190`:
/// `((year-1980)<<9)+(mon<<5)+day` / `(hour<<11)+(min<<5)+(sec>>1)`) is the
/// ordinary DOS FAT date/time this crate already has a packer for --
/// [`crate::clock::Civil::dos_date`]/[`dos_time`](crate::clock::Civil::dos_time)
/// -- the same pair `shims::stream`'s `fnd1st`/`fndnxt` already use for a
/// file's modified time (`write_fndblk`'s own doc comment there names the
/// identical `Clock::pinned` + `Civil::dos_date`/`dos_time` conversion).
///
/// One import, one call site, 32-bit only: MajorMUD NT (both `wccnt7pk` and
/// `wccnt8pj`, `tmp/gapsurvey/round2/out_mmud_nt7pk.txt`/
/// `out_mmud_nt8pj.txt`), `MAJORBBS` ordinal -- registered in
/// `WG32_ROUTINES`, no 16-bit build imports it.
///
/// # Errors
///
/// If `fname` cannot be read as a string, `dtim`/`ddat` cannot be written,
/// or a file this host *did* find has a modified time outside
/// [`crate::clock::Civil::dos_date`]'s `1980..=2107` range.
pub fn getfiletm<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let fname = call.ptr();
    let dtim = call.ptr();
    let ddat = call.ptr();

    let named = String::from_utf8_lossy(
        fname
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(format!("getfiletm: fname: {e}")))?,
    )
    .into_owned();

    dtim.write(call.mem(), &0u16.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    ddat.write(call.mem(), &0u16.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;
    let Some(path) = host.find(&name) else {
        return Ok(abi::Ret::Void);
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(abi::Ret::Void);
    };
    let Ok(modified) = metadata.modified() else {
        return Ok(abi::Ret::Void);
    };
    let modified = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ShimError::Failed(format!("getfiletm: {named}: {e}")))?
        .as_secs();
    let modified = u32::try_from(modified).map_err(|_| {
        ShimError::Failed(format!("getfiletm: {named}: modified time does not fit this host's clock"))
    })?;
    let civil = crate::clock::Clock::pinned(modified)
        .civil()
        .map_err(|e| ShimError::Failed(format!("getfiletm: {named}: {e}")))?;
    let date = civil
        .dos_date()
        .map_err(|e| ShimError::Failed(format!("getfiletm: {named}: {e}")))?;
    let time = civil.dos_time();

    dtim.write(call.mem(), &time.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    ddat.write(call.mem(), &date.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Void)
}

/// `GBOOL vtmsndok(INT tochan)` -- is it OK to send to this channel right now?
///
/// `re/wg33src/INC/GCSPSRV.H:220-222` (Worldgroup 3.3, 1997) documents `INT
/// tochan` directly as "c/s user's usrnum". No `.C` implementing it survives
/// in `re/wg33src` -- WGSERVER's own Virtual Terminal Multiplexer (VTM),
/// which owns it, is not among the recovered source files, only its two
/// prototypes (`vtmsndok`/[`vtmsend`], `GCSPSRV.H:220-228`) and the one real
/// call site this host has evidence for
/// (`re/wg33src/SRC/apps/galmjd/GALMJD.C:1605-1607`, a door gateway: `if
/// (xfrbyts > 0 && vtmsndok(mjdptr->othchn)) { vtmsend(...); }`) --
/// MajorMUD NT's own decompile
/// (`re/wg_nt_ghidra/exports/WCCMMUD_decompiled.c:65011`) gates an identical
/// `vtmsend` call the same way.
///
/// This host has no VTM at all -- no cross-process routing table, because a
/// module this host runs is native, not a spawned door on the far side of
/// one -- so the only readiness question this host can honestly answer is
/// whether `tochan` names a channel of this host at all, the same check
/// [`crate::shims::gsbl::btuxmn`]/[`crate::shims::gsbl::btuxct`] already make
/// before transmitting. `GBOOL`/`TRUE`/`FALSE`
/// (`re/wg33src/INC/GCTYPDEF.H:105-109`) are plain `0`/`1`, not the `-1`/`0`
/// [`access`]'s own convention uses -- this returns `1`/`0` accordingly.
///
/// # Errors
///
/// Never -- reporting "not ready" for a channel this host does not have is
/// this routine's whole purpose, the same absence-reporting exception
/// [`access`] already claims.
pub fn vtmsndok<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let tochan = Into::<u32>::into(call.int()) as i16;
    let ok = host.users().terms().chan(tochan).is_some();
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(ok))))
}

/// `VOID vtmsend(INT srcid, INT length, VOID *value)` -- send `length` bytes
/// of `value` through the VTM. "Call right after `vtmsndok() == TRUE`"
/// (`GCSPSRV.H:224`).
///
/// Same source situation as [`vtmsndok`]'s own doc comment: no surviving
/// body, one real call site each in `GALMJD.C:1607` and MajorMUD NT's own
/// decompile (`WCCMMUD_decompiled.c:65011-65014`). The decompile is worth
/// reading closely, because it rules out the obvious guess for `srcid`:
///
/// ```text
/// vtmsend(*(undefined4*)(DAT_00479100+0x10+param_1*0x14), sVar7, uVar8)
/// ```
///
/// `srcid` here is **not** the channel `vtmsndok(param_1)` was just asked
/// about -- it is looked up in a per-channel table the module keeps
/// privately, and only `param_1` (the channel) indexes that lookup. This
/// matches the header's own description of `srcid` as a "source identifier
/// (hwnd)": WGSERVER's real VTM is a cross-process relay (how a spawned door
/// pushes bytes back through the server that spawned it), and `srcid` names
/// one leg of that relay, not a channel number.
///
/// **Recorded uncertainty, not a guess dressed up as an answer.** This host
/// has no cross-process VTM and no window-handle table to resolve `srcid`
/// against -- a module this host runs *is* the channel, with nothing else in
/// between, so the hwnd-indirection `vtmsend` was designed for has no
/// counterpart here, only the channel number itself. This reads `srcid` as
/// that channel number directly -- the one numeric handle a native module
/// actually has, matching how every channel-addressing routine elsewhere in
/// this crate (`btuxmn`/`btuxct`/[`vtmsndok`] above) already takes a channel
/// number as its first argument -- rather than refuse a call whose own
/// header contract says it only ever follows a successful [`vtmsndok`]. If a
/// future build is found routing genuinely unrelated `srcid` values through
/// this call, that would falsify this reading, and this comment says so
/// plainly rather than hiding behind silence.
///
/// Binary, not ASCIIZ: `length` is given explicitly, matching
/// [`crate::shims::gsbl::btuxct`]'s own "genuinely wide" length argument
/// (read at full width, never narrowed to `u16` first), not
/// [`crate::shims::gsbl::btuxmn`]'s NUL scan.
///
/// # Errors
///
/// If `srcid` does not name a channel of this host -- the header's own
/// contract says a caller checks [`vtmsndok`] first, so a caller that
/// reaches here on a bad channel has broken that contract, not asked a
/// legitimate question with a "no" answer.
pub fn vtmsend<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let srcid = Into::<u32>::into(call.int()) as i16;
    let length = Into::<u32>::into(call.int()) as usize;
    let value = call.ptr();

    let Some(chan) = host.users().terms().chan(srcid) else {
        return Err(ShimError::Failed(format!(
            "vtmsend({srcid}): no such channel -- vtmsndok should have refused first"
        )));
    };
    let data = value
        .resolve(call.mem(), length)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit_raw(chan, &data);
    Ok(abi::Ret::Void)
}

/// `CHAR *gmdnam(CHAR *mdfnam)` -- `GCOMM.H:954-956` -- a module's name, out
/// of its `.MDF`.
///
/// The real one (`MAJORBBS.C:1137`) opens the file, finds the line beginning
/// `Module Name:`, unpads it and returns a pointer past the label into its own
/// static buffer. This does the same into a buffer the host owns, so the
/// pointer the module keeps stays valid.
///
/// A file it cannot open is `catastro` in the original. Here it stops the
/// module with the path, which is the same outcome and says more.
pub fn gmdnam<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mdfnam = call.ptr();
    let name = mdfnam
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let name = String::from_utf8_lossy(&name).into_owned();

    let path = host
        .find(&name)
        .ok_or_else(|| ShimError::Failed(format!("gmdnam: no {name} under {:?}", host.root)))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| ShimError::Failed(format!("gmdnam: {}: {e}", path.display())))?;

    const LABEL: &str = "Module Name:";
    let module = text
        .lines()
        .find_map(|line| line.strip_prefix(LABEL))
        .map(str::trim)
        .ok_or_else(|| ShimError::Failed(format!("gmdnam: no module name in {name}")))?;

    let at = host.mdf_buffer();
    write_cstr_mem::<A>(call.mem(), at, module.as_bytes(), MDF_LINE)?;
    Ok(abi::Ret::Ptr(at))
}

/// `VOID shocst(const CHAR *brief, const CHAR *detail, ...)` --
/// `MAJORBBS.H:1083-1087` -- one line of audit trail.
///
/// Two strings then printf arguments, as every call site has it:
/// `shocst("C/S FILE PAGE FILE MISSING","%s %s",mnutmp2.pagnam,fpath)`
/// (`BBSMAINM.C:498`). The real host writes it to the audit-trail Btrieve file
/// and the console; this keeps it, and [`Host::audit`] is where it can be read.
///
/// Generic: [`crate::fmt::format_call`] replaces `format`/`Args::Call { first:
/// 4 }` -- `brief` and `template` are `call.ptr()`, and by the time both are
/// read, `call`'s position already marks where the varargs begin.
pub fn shocst<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let brief = call.ptr();
    let template = call.ptr();
    let headline = brief
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let (detail, _) = format_call(call, template)?;
    host.audit.push(format!(
        "{}: {}",
        String::from_utf8_lossy(&headline),
        String::from_utf8_lossy(&detail)
    ));
    Ok(abi::Ret::Void)
}

/// `VOID rtkick(INT delay, VOID (*dstrou)())` -- `GCOMM.H:228-231` -- run
/// this later.
///
/// The host remembers it and **nothing runs it**, because running it needs a
/// main loop and a clock that this host does not have. That is a debt rather
/// than a lie: `rtkick` returns `void`, so it promises the caller nothing at
/// call time, and a module cannot observe a second that never passes. See
/// [`Host::kicks`] for what the main loop will read when there is one.
///
/// # Errors
///
/// If `delay` is negative, which no caller can mean and a misread argument
/// list would produce.
///
/// Generic: the negativity test widens `call.int()` to `u32` via
/// `Abi::Int`'s own `Into<u32>` bound, then reads the *actual* sign bit of a
/// caller's `int` -- bit `A::INT_WIDTH * 8 - 1`, bit 15 under `Wg16` and bit
/// 31 under `Wg32` -- rather than a bare `0x8000` literal. That literal
/// happens to equal `Wg16`'s sign bit, but under `Wg32` an `int` is four
/// bytes: `0x8000` is an ordinary positive value's bit 15, and a genuinely
/// negative 32-bit delay like `0x8000_0000` has bit 15 *clear*, so the old
/// test let it straight through. `Kick::delay` then keeps the value whole
/// (`u32`, not `u16`) -- Task 17 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`: `rtkick(86400)`
/// (one day, which LunatiX ships daily events for) has low 16 bits
/// `0x5180`, whose own bit 15 is clear, so it passed the old sign test too
/// and then `as u16` truncated it to `86400 mod 65536 == 20864` seconds --
/// silently, with no error at all.
pub fn rtkick<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let raw: u32 = call.int().into();
    let dstrou = call.ptr();
    let sign_bit = 1u32 << (A::INT_WIDTH * 8 - 1);
    if raw & sign_bit != 0 {
        return Err(ShimError::Failed(format!(
            "rtkick: a negative delay ({raw:#x} under a {}-byte int)",
            A::INT_WIDTH
        )));
    }
    let delay = raw; // u32 end to end; no truncation
    if delay == 0 {
        // `RTKICK.C:50`'s free-slot marker is `countr == 0`, and `:65` skips any
        // entry holding it -- so the original writes this kick into a slot that
        // remains free and never runs it. Recording nothing is that behaviour;
        // a zero entry in this `Vec` would instead never expire.
        host.note(format!(
            "rtkick: a zero delay for {dstrou:?}, which RTKICK.C would never fire"
        ));
        return Ok(abi::Ret::Void);
    }
    host.kicks.push(Kick { delay, dstrou });
    Ok(abi::Ret::Void)
}

/// `VOID dclvda(INT size)` -- `MAJORBBS.H:771` -- declare how much volatile
/// data area this module needs.
///
/// `MAJORBBS.C:1157`, in full: `if (size > vdasiz) vdasiz=size`. The largest
/// declaration wins, because every module shares one area per channel.
pub fn dclvda<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = Into::<u32>::into(call.int()) as i16;
    let current = host
        .globals()
        .word_mem(call.mem(), "vdasiz")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    if size > current {
        host.globals()
            .write_int_mem(call.mem(), "vdasiz", size as u32)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Void)
}

/// `INT register_module(struct module *mod)` -- `MAJORBBS.H:769` -- take a
/// module online.
///
/// `struct module` itself is `MAJORBBS.H:301-312` (corrected here -- long
/// cited as `:241`, which is a run of `#define`d sub-state codes, not the
/// struct): 25 bytes of description, then nine far pointers, which are
/// every entry point the host will ever call back into. **The pointer is kept,
/// not the contents.** The real host stores `mod` itself
/// (`MAJORBBS.C:1327`, `module[nmods]=mod`) and the module is free to change
/// its own block afterwards, so a snapshot would go stale.
///
/// Two things the real one does that this does not, both deliberate. It
/// allocates a `mdstats` record out of Btrieve, which is a subsystem that does
/// not exist yet. And it fills a null `stsrou` with the host's own `dfsthn` --
/// pointless here, because a null `stsrou` simply means the host has no status
/// routine to call, which is what it would mean either way.
///
/// Generic: `block.resolve` replaces `Machine::resolve`, the same
/// substitution [`register_textvar`]'s own read makes, and `host.register`
/// now takes `A::Ptr` rather than `FarPtr`.
/// `void globalcmd(int (*rouptr)())` -- install a global command handler.
///
/// `MAJORBBS.C:1114`, transcribed:
///
///
/// A global command is one the host offers on every channel regardless of
/// which module has it -- the real host walks `globs[]` before handing a
/// line to the module that owns the session. This registers into the
/// module's own memory rather than a Rust-side list, because `nglobs` and
/// `globs` are host globals the module can read and write itself (see
/// `crate::globals`'s module doc on why a second copy is the bug it exists
/// to prevent).
///
/// # The overflow is a refusal, not a truncation
///
/// The real host calls `catastro`, which takes the whole system down. This
/// host stops the module instead and names the limit -- the same trade every
/// `ShimError::Failed` here makes. What it must not do is silently drop the
/// fifty-first handler, which would leave the module believing a command is
/// installed that no line will ever reach.
pub fn globalcmd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let routine = call.ptr();

    let n = host
        .globals()
        .word_mem(call.mem(), "nglobs")
        .map_err(|e| ShimError::Failed(format!("globalcmd: {e}")))?;
    if n >= crate::globals::GLBMAX {
        return Err(ShimError::Failed(format!(
            "globalcmd: TOO MANY GLOBAL COMMAND HANDLERS ({n} of {})",
            crate::globals::GLBMAX
        )));
    }

    // `globs[nglobs] = rouptr`, addressed through the table rather than a
    // hand-built pointer: the slot stride is `A::PTR_WIDTH`, which is 4 under
    // both ABIs, but saying so through the constant keeps the arithmetic
    // honest if that ever stops being true.
    let base = host
        .globals()
        .address("globs")
        .ok_or_else(|| ShimError::Failed("globalcmd: globs is not placed".to_owned()))?;
    let slot = A::ptr_offset(base, n * A::PTR_WIDTH as u16);
    slot.write(call.mem(), &A::ptr_to_bytes(routine))
        .map_err(|e| ShimError::Failed(format!("globalcmd: {e}")))?;

    // `nglobs++`, at `A`'s own int width -- see `Globals::write_int_mem`.
    host.globals()
        .write_int_mem(call.mem(), "nglobs", u32::from(n) + 1)
        .map_err(|e| ShimError::Failed(format!("globalcmd: {e}")))?;

    Ok(abi::Ret::Void)
}

pub fn register_module<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = call.ptr();

    // `descrp` is a fixed-width field, so the string inside it is read bounded
    // rather than scanned: a module whose description fills all 25 bytes has no
    // terminator, and scanning would run into `lonrou`.
    let bytes = block
        .resolve(call.mem(), usize::from(MNMSIZ))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let description = String::from_utf8_lossy(&bytes[..end]).into_owned();

    // The same two refusals the real one makes, and for the same reason: this
    // name is the key a module's records are stored under.
    if description.len() < 3 {
        return Err(ShimError::Failed(format!(
            "register_module: the name {description:?} is too short"
        )));
    }
    if description.len() > usize::from(MNMSIZ) - 1 {
        return Err(ShimError::Failed(format!(
            "register_module: the name {description:?} is too long"
        )));
    }

    Ok(abi::Ret::Int(A::Int::from(host.register(description, block))))
}

/// `VOID register_agent(struct agent *agdptr)` -- `GCSPSRV.H:141` -- take a
/// client/server agent online.
///
/// An *agent* is a module's server-side handler for a Worldgroup client, and
/// its `appid` is the name a client addresses it by (`GCSPSRV.H:21`). MajorMUD
/// registers exactly one, `WCCMMUD`.
///
/// **The record is copied, not pointed at**, and that is the one way this
/// differs from [`register_module`]. The real routine ends in
/// `movmem(agdptr, &agents[nagents], 25)` (seg 30:0x0121 of
/// `MAJORBBS-wg200.EXE`) -- so the caller's block is free to go out of scope
/// afterwards, and a host that kept the pointer would be reading whatever
/// replaced it.
///
/// **Nothing dispatches to these vectors**, because dispatching needs a client
/// and this host has none. A debt rather than a lie, on the same terms as
/// [`Host::kicks`](crate::Host::kicks): the routine returns `void`, so it
/// promises the module nothing.
///
/// Two things the real one does that this does not. It grows the table twenty
/// slots at a time out of the *host's* heap, which the module never sees and
/// cannot observe. And it fills a null vector with a host default -- see
/// [`Agent`] for what those defaults are and why filling one in here would say
/// less than leaving it `None`.
///
/// # Errors
///
/// If the block does not name 25 readable bytes, or the `appid` is empty. The
/// second is this host's own refusal and not the original's: an agent with no
/// name can never be addressed by a client, so no caller can mean it, and a
/// misread argument list is what would produce one.
///
/// Generic: each vector is `A::PTR_WIDTH` bytes wide, not a hardcoded 4 --
/// the stride [`write_parse`](crate::shims::text)'s own `margv`/`margn` walk
/// already established for a packed array of pointers. The null test is
/// every byte of the decoded pointer being zero, the same reading
/// [`Registration::dispatch`]'s own doc comment gives -- which for this
/// four-byte `A::Ptr` is exactly the "both words zero" the real routine's
/// `or` tests, so the two agree on every value either can produce.
pub fn register_agent<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = call.ptr();
    let bytes = block
        .resolve(call.mem(), usize::from(AGENT_SIZE))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // `appid` is a fixed-width field, so the name inside it is read bounded
    // rather than scanned -- an agent whose name fills all nine bytes has no
    // terminator, and scanning would run into the `read` vector.
    let field = &bytes[..usize::from(AIDSIZ)];
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    let appid = String::from_utf8_lossy(&field[..end]).into_owned();
    if appid.is_empty() {
        return Err(ShimError::Failed(
            "register_agent: an agent with no appid can never be addressed".to_owned(),
        ));
    }

    // A vector is null when **every** byte of it is zero -- see the doc
    // comment above for why that agrees with the real routine's `or` of its
    // two words. Offset zero is a perfectly good address, and `seg 26:0x0000`
    // of `WCCMMUD.DLL` is the very routine that makes this call, so only an
    // all-zero pointer is refused.
    let vector = |n: usize| {
        let at = usize::from(AIDSIZ) + n * A::PTR_WIDTH;
        let ptr = A::ptr_from_bytes(&bytes[at..at + A::PTR_WIDTH]);
        let is_null = A::ptr_to_bytes(ptr).iter().all(|&b| b == 0);
        (!is_null).then_some(ptr)
    };
    let agent = Agent {
        appid,
        read: vector(0),
        write: vector(1),
        xferdone: vector(2),
        abort: vector(3),
    };

    host.agents.push(agent);
    Ok(abi::Ret::Void)
}

/// `INT register_textvar(CHAR *name, CHAR *(*varrou)())` -- `MAJORBBS.H:767`
/// -- register a text variable.
///
/// `MAJORBBS.C:1279`, and this one has surviving source -- unlike
/// [`register_agent`], which had to be transcribed. It is checked against the
/// wg200 binary anyway (`seg 4:0x21b0`, ordinal 494) because the source is
/// Worldgroup 1's and the module is built against Worldgroup 2. They agree.
///
/// A *text variable* is a substitution: the module hands over a name and a
/// routine, and the routine's return value replaces that name wherever a
/// message mentions it. MajorMUD registers exactly one, `MUDCHARINFO`.
///
/// **The table is module memory, not a `Vec`**, and that is the difference from
/// [`register_agent`]. `WCCMMUD.DLL` addresses `txtvars` at ten sites and walks
/// the table through it -- see [`TextVars`](crate::TextVars) for the access
/// pattern that settles it.
///
/// **It returns the index**, which `register_agent` did not: the original ends
/// `return(ntvars++)`, and the binary's `mov ax,[0x44]` before its `inc` is
/// that.
///
/// Two things the real one does that this does not. It keeps a `ntvars` global
/// (ordinal 861) which `WCCMMUD.DLL` never addresses, so the count stays on the
/// Rust side and `Host::load` is the guard if that changes. And it leaves the
/// bytes past a short name's terminator as whatever the heap last held; this
/// zeroes the record first, which no correct reader can tell apart.
///
/// # Errors
///
/// If the name is empty, if the pointers do not name readable memory, or if the
/// heap has no room. The empty name is this host's own refusal and not the
/// original's -- weaker than the agent's, since `findtvar("")` could genuinely
/// match one, and carried instead by the realistic cause being a misread
/// argument list.
///
/// Generic: [`TextVars::push_mem`](crate::textvar::TextVars::push_mem) is
/// what `push`'s `Wg16` facade already delegated into.
pub fn register_textvar<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name_ptr = call.ptr();
    let varrou = call.ptr();
    let name = String::from_utf8_lossy(
        name_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let mut table = std::mem::take(&mut host.textvars);
    let pushed = table.push_mem(call.mem(), &mut host.heap, &name, varrou);
    host.textvars = table;
    let n = pushed?;

    // The module reaches the table only through this. A host that filled the
    // table and left the global null would have registered nothing.
    let at = host.textvars.at().expect("a row was just added");
    host.globals()
        .write_mem(call.mem(), "txtvars", &A::ptr_to_bytes(at))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(n)))
}

/// `INT findtvar(CHAR *name)` -- `MAJORBBS.H:768`, "find text variable &
/// return number". `MAJORBBS.C:1297`:
///
///
/// The lookup counterpart to [`register_textvar`], and case-insensitive
/// because `sameas` is. `-1` for "no such variable" is the original's own
/// answer and a legitimate one -- a caller is expected to test it -- so this
/// does not refuse an unknown name.
///
/// Reached on MajorMUD's **quit** path (`_CMD_QUIT`), which is why it went
/// missing until movement worked: nothing could quit the Realm before, so
/// nothing reached this. Same class of gap as `echonu`, and the same reason no
/// survey named it -- an unreachable call site is invisible to one.
///
/// The table is walked through [`TextVars`](crate::TextVars) rather than the
/// `txtvars` global, because that is where this host keeps it; the global is
/// what the *module* reads it through, and `register_textvar` keeps the two
/// pointing at the same rows.
pub fn findtvar<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name_ptr = call.ptr();
    let name = String::from_utf8_lossy(
        name_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let mut found: i16 = -1;
    for n in 0..host.textvars.len() {
        if let Some(var) = host.textvars.get_mem(call.mem(), n)?
            && var.name.eq_ignore_ascii_case(&name)
        {
            found = n as i16;
            break;
        }
    }

    Ok(abi::Ret::Int(A::Int::from(found as u16)))
}

/// `VOID catastro(CHAR *string, ...)` -- `GCOMM.H:287-290` -- the module has
/// given up.
///
/// Stops it, deliberately. `catastro` is a module saying it cannot continue,
/// and a host that formatted the message and returned would be resuming code
/// that has already decided it is in an impossible state.
///
/// Generic: [`crate::fmt::format_call`] replaces `format`/`Args::Call { first:
/// 2 }`, the same substitution [`shocst`] makes -- `template` is `call.ptr()`,
/// and by the time it is read, `call`'s position already marks where the
/// varargs begin.
pub fn catastro<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let template = call.ptr();
    let (text, _) = format_call(call, template)?;
    Err(ShimError::Failed(format!(
        "catastro: {}",
        String::from_utf8_lossy(&text)
    )))
}

/// A module routine the host has been asked to run later.
///
/// `rtkick(delay, dstrou)` is a **one-shot** timer: `dstrou` runs once, `delay`
/// seconds from the call, and a callback that wants to keep going re-arms
/// itself. `GALMJD.C:180` registers `mjdrtk` with `rtkick(1,mjdrtk)` and
/// `GALMJD.C:1106` is that same call *inside* `mjdrtk` -- which is only
/// necessary, and only correct, if a kick fires once.
///
/// `delay` is kept as a countdown rather than converted to a deadline: it is
/// live, decremented by one every elapsed second inside
/// [`crate::Host::prcrtk`], which [`crate::Host::cycle`] calls on that
/// schedule.
///
/// Generic over `A: Abi` since `dstrou` is a module pointer -- `FarPtr` for
/// `Wg16`, and something else for a future 32-bit ABI. Not derived: the
/// derive macro would generate an `A: Trait` bound, which is wrong here
/// (`Kick<A>`'s fields are `u32` and `A::Ptr`, never `A` itself) -- see
/// `crate::abi::Ret`'s own doc comment for the fuller account of why this
/// crate hand-writes these instead of deriving them. `Clone`/`Copy`/`PartialEq`/
/// `Eq` all typecheck unconditionally for any `A: Abi`, with no `where`
/// clause needed, because `Abi::Ptr` already requires `Copy + Eq` in the
/// trait itself; `Debug` needs `A::Ptr: Debug` spelled out because
/// `mbbs_machine::ptr::ModulePtr`'s own `Debug` supertrait is not visible to the
/// compiler without it being named at the impl site.
///
/// `delay` is `u32`, not `u16` -- Task 17 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`: `Wg16`'s `int` is
/// two bytes and every 16-bit kick fits regardless, but a `Wg32` module's
/// `int` is four, and `rtkick(86400)` (one day) does not fit in `u16`.
pub struct Kick<A: Abi> {
    /// Seconds yet to go, counted down one per elapsed second by
    /// [`crate::Host::prcrtk`]. Never `0`: `rtkick` refuses to record a
    /// zero-delay kick, because `RTKICK.C` would never have fired it.
    pub delay: u32,

    /// The module routine to call. Far, and into the module's own code -- the
    /// one MajorMUD registers is an `INTERNALREF` to its NE segment 6.
    pub dstrou: A::Ptr,
}

impl<A: Abi> std::fmt::Debug for Kick<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kick")
            .field("delay", &self.delay)
            .field("dstrou", &self.dstrou)
            .finish()
    }
}

impl<A: Abi> Clone for Kick<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for Kick<A> {}

impl<A: Abi> PartialEq for Kick<A> {
    fn eq(&self, other: &Self) -> bool {
        self.delay == other.delay && self.dstrou == other.dstrou
    }
}

impl<A: Abi> Eq for Kick<A> {}

/// A module that has been taken online, or a host-native handler occupying a
/// `state` slot the same way one would.
///
/// `MAJORBBS.C:2703`'s `(*(module[usrptr->state]->sttrou))()` does not care
/// whether `module[n]` is a loaded NE module or `inifsd()` registering
/// FSDBBS as one -- both are just an entry in the table. This enum is that
/// indifference, made explicit.
///
/// Generic over `A: Abi`, and hand-written rather than derived -- see
/// [`Kick`]'s own doc comment for why.
pub enum Registration<A: Abi> {
    /// A module that has been taken online.
    Module {
        /// The name from `descrp`, which is the key its records are kept
        /// under.
        description: String,

        /// The module's own `struct module`, in its own memory. Every entry
        /// point the host will ever call is read back through here rather
        /// than copied, because the module may change them.
        block: A::Ptr,
    },

    /// A handler implemented by this host rather than by module code.
    /// `inifsd()` registering FSDBBS as an ordinary module is the reason
    /// this variant exists; see [`Native`].
    Native(Native),

    /// Slot zero: the BBS's own menuing system, which this host does not
    /// have.
    ///
    /// `MAJORBBS.C:3097-3106`'s `inimod()` calls
    /// `register_module(&module00)` *before* `callinits()` lets any DLL
    /// register itself, so on a real host `module[0]` is the BBS and real
    /// modules start at one. A channel's `state` is an index into that same
    /// table, so `state == 0` means "this user is at the BBS menu", and a
    /// module hands a user back by writing it.
    ///
    /// This host is headless -- there is no menuing system, no `module00`,
    /// and nothing above a module to return to. Reserving the slot anyway is
    /// what keeps every other index matching the real host's, and it turns
    /// the handback into something nameable: `state == 0` here means the
    /// session is over, because the thing it names does not exist.
    ///
    /// Without this the first real module registered at zero and caught its
    /// own goodbye: MajorMUD's "Exit Game" set `state = 0`, this host read
    /// that as "dispatch to MajorMUD", and the module redrew the menu it had
    /// just been asked to leave.
    AbsentBbs,
}

impl<A: Abi> std::fmt::Debug for Registration<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module { description, block } => f
                .debug_struct("Module")
                .field("description", description)
                .field("block", block)
                .finish(),
            Self::Native(native) => f.debug_tuple("Native").field(native).finish(),
            Self::AbsentBbs => f.write_str("AbsentBbs"),
        }
    }
}

impl<A: Abi> Clone for Registration<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Module { description, block } => Self::Module {
                description: description.clone(),
                block: *block,
            },
            Self::Native(native) => Self::Native(*native),
            Self::AbsentBbs => Self::AbsentBbs,
        }
    }
}

impl<A: Abi> PartialEq for Registration<A> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Module { description: d1, block: b1 },
                Self::Module { description: d2, block: b2 },
            ) => d1 == d2 && b1 == b2,
            (Self::Native(n1), Self::Native(n2)) => n1 == n2,
            // Carries nothing, so two of them are the same slot.
            //
            // Missing until 2026-08-15, and the catch-all below answered
            // `false` for it -- making `AbsentBbs != AbsentBbs`, a
            // non-reflexive `PartialEq` beneath an `impl Eq` that promises
            // reflexivity. `209d2ff` added the variant; nothing compared two
            // of them until an `--ignored` integration test did, three weeks
            // later.
            //
            // **The catch-all is the hazard.** It is needed for genuinely
            // different variants, and it also absorbs any same-variant pair a
            // future arm forgets -- turning a missing case into a wrong
            // answer rather than a compile error. Add the arm with the
            // variant; `equality_is_reflexive_for_every_variant` is the guard
            // that notices if you do not.
            (Self::AbsentBbs, Self::AbsentBbs) => true,
            _ => false,
        }
    }
}

impl<A: Abi> Eq for Registration<A> {}

/// A host-native handler occupying a `state` slot. One variant today; a
/// second module (MajorMUD Plus) would add a second.
///
/// Not generic -- a native handler has no module pointer of its own to vary
/// by ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Native {
    /// The full-screen data entry engine, `FSDBBS.C`'s `inifsd()` registers.
    Fsd,
}

/// A client/server agent that has been taken online.
///
/// A **snapshot**, unlike [`Registration`]: `register_agent` copies the
/// caller's 25 bytes into the host's own table, so these vectors are what the
/// module registered and not what its memory says now.
///
/// A `None` vector is one the module left null, and the real host would fill it
/// with its own default at registration time -- `rejectreq` for `read` and
/// `write` (seg 30:0x251e and 0x252f, both of which call seg 31:0x5f6), and a
/// bare `retf` for `xferdone` and `abort`. That substitution is *not* made
/// here, because this host has nothing to dispatch and a `None` says which
/// vector the module actually supplied. Whoever builds the dispatcher owes
/// those four defaults, and the table above is what they are.
///
/// Generic over `A: Abi`, and hand-written rather than derived -- see
/// [`Kick`]'s own doc comment for why.
pub struct Agent<A: Abi> {
    /// The name a client addresses this agent by. MajorMUD's is `WCCMMUD`.
    pub appid: String,

    /// Deliver a dynapak to the agent, or `None` -- which rejects the request.
    pub read: Option<A::Ptr>,

    /// Take a dynapak from the agent, or `None` -- which rejects the request.
    pub write: Option<A::Ptr>,

    /// A transfer finished, or `None` -- which does nothing.
    pub xferdone: Option<A::Ptr>,

    /// A transfer was abandoned, or `None` -- which does nothing.
    pub abort: Option<A::Ptr>,
}

impl<A: Abi> std::fmt::Debug for Agent<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("appid", &self.appid)
            .field("read", &self.read)
            .field("write", &self.write)
            .field("xferdone", &self.xferdone)
            .field("abort", &self.abort)
            .finish()
    }
}

impl<A: Abi> Clone for Agent<A> {
    fn clone(&self) -> Self {
        Self {
            appid: self.appid.clone(),
            read: self.read,
            write: self.write,
            xferdone: self.xferdone,
            abort: self.abort,
        }
    }
}

impl<A: Abi> PartialEq for Agent<A> {
    fn eq(&self, other: &Self) -> bool {
        self.appid == other.appid
            && self.read == other.read
            && self.write == other.write
            && self.xferdone == other.xferdone
            && self.abort == other.abort
    }
}

impl<A: Abi> Eq for Agent<A> {}

/// What [`Registration::dispatch`] found at a channel's state: a module's
/// far pointer (which may be null, meaning the module supplies no handler
/// for this vector), or a native handler to run directly.
///
/// Public rather than `pub(crate)`, matching the visibility [`Registration`]
/// and its old `entry` method already had: a test outside this crate (an
/// integration test under `tests/`) reads a registered module's entry points
/// back the same way `Host::state_entry` does.
///
/// Generic over `A: Abi`, and hand-written rather than derived -- see
/// [`Kick`]'s own doc comment for why.
pub enum Dispatch<A: Abi> {
    /// A module's far pointer for this entry, or `None` if it left the entry
    /// null.
    Module(Option<A::Ptr>),
    /// A host-native handler, run directly rather than through a far call.
    Native(Native),

    /// The channel's `state` names [`Registration::AbsentBbs`]: it has been
    /// handed back to a BBS this host does not have, so the session is over.
    SessionOver,
}

impl<A: Abi> std::fmt::Debug for Dispatch<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(ptr) => f.debug_tuple("Module").field(ptr).finish(),
            Self::Native(native) => f.debug_tuple("Native").field(native).finish(),
            Self::SessionOver => f.write_str("SessionOver"),
        }
    }
}

impl<A: Abi> Clone for Dispatch<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for Dispatch<A> {}

impl<A: Abi> PartialEq for Dispatch<A> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Module(p1), Self::Module(p2)) => p1 == p2,
            (Self::Native(n1), Self::Native(n2)) => n1 == n2,
            // The same omission as `Registration::AbsentBbs` above, in the
            // same commit, found in the same minute: `SessionOver` carries
            // nothing and two of them are the same outcome, but there was no
            // arm for it and the catch-all made `SessionOver != SessionOver`
            // beneath an `impl Eq`.
            //
            // Two hand-written `PartialEq`s in one file, each given a new
            // variant by `209d2ff`, each silently wrong the same way. That is
            // the argument against a catch-all in a hand-written equality:
            // the compiler cannot tell you what it swallowed.
            (Self::SessionOver, Self::SessionOver) => true,
            _ => false,
        }
    }
}

impl<A: Abi> Eq for Dispatch<A> {}

/// `struct module`'s header stride at `A`'s own layout: how many bytes come
/// before the nine routine pointers `re/wg33src/INC/MAJORBBS.H:301` declares
/// right after `descrp` (`lonrou`, `sttrou`, `stsrou`, `injrou`, `lofrou`,
/// `huprou`, `mcurou`, `dlarou`, `finrou`, in that order).
///
/// # Not a `GCV2` question
///
/// [`Abi::GCV2`](crate::abi::Abi::GCV2) picks between two different
/// *declarations* of a struct -- see [`crate::users::UserLayout`]'s own doc
/// comment. This is not that: `MAJORBBS.H:301` declares `struct module`
/// exactly once, with no `#ifdef` anywhere in it. What differs between
/// `Wg16` and `Wg32` is not which fields exist but a fact about the compiler
/// that built each host: whether it packs a struct byte-tight or aligns a
/// pointer member to its own width. Borland's 16-bit compiler byte-packs, so
/// `MNMSIZ` (25) is already the correct offset for `Wg16` -- every test in
/// this file that predates this type already assumes that and none of them
/// had to change. A 32-bit compiler 4-byte-aligns the pointer array that
/// follows, so the same 25-byte `descrp` leaves 3 bytes of padding before
/// `lonrou`.
///
/// That is the same axis [`FndblkLayout`](crate::shims::stream::FndblkLayout)
/// already tests, for the same underlying reason (`struct ffblk`'s 16-bit
/// DOS-DTA shape vs. Borland's incompatible 32-bit one) -- so this reuses
/// its discriminator, `A::INT_WIDTH >= 4`, rather than inventing a
/// differently-named test for what is the same fact about the same two
/// compilers.
///
/// # Measured, not derived from the header alone
///
/// See [`tests::module_layout_pads_the_header_to_four_bytes_at_wg32`] for
/// both independent confirmations: LunatiX's own registered block (a real
/// in-image code pointer starts at byte 28, not 25) and three separate PE32
/// `WGSERVER.EXE` builds dispatching through this same table at header
/// offset 28.
struct ModuleLayout {
    /// Bytes before the first routine pointer (`lonrou`, `n == 0`).
    header: u16,
}

impl ModuleLayout {
    /// `struct module`'s header as `A`'s host compiler laid it out.
    fn of<A: Abi>() -> Self {
        if A::INT_WIDTH >= 4 {
            // Wg32: MNMSIZ padded to a 4-byte boundary.
            Self { header: 28 }
        } else {
            // Wg16: byte-packed, so MNMSIZ is already the offset.
            Self { header: MNMSIZ }
        }
    }
}

impl<A: Abi> Registration<A> {
    /// Where one of the nine entry points is, or which native handler runs
    /// instead.
    ///
    /// `n` is its position in `struct module` after `descrp`: 0 is `lonrou`,
    /// 1 `sttrou`, 2 `stsrou`, and so on to 8 for `finrou`. Meaningless for a
    /// [`Registration::Native`] -- it has no `struct module` to index -- so
    /// it is not read.
    ///
    /// Read every time a [`Registration::Module`]'s pointer is wanted. That
    /// is the whole reason the block address is kept instead of a copy.
    ///
    /// Takes `&A::Mem` rather than `&Machine`: reading an entry point is a
    /// memory read, not a call, and every caller in `impl Host<Wg16>` already
    /// has a `Machine` to reborrow one out of (`Machine::mem`). The null test
    /// is every byte of the decoded pointer being zero
    /// ([`Abi::ptr_to_bytes`]), not `FarPtr::selector != 0` as the original
    /// wrote it -- the same substitution [`time`]'s own doc comment makes,
    /// for the same reason: `A::Ptr` is opaque to a generic caller, and the
    /// two tests agree on every value this crate's own tests exercise.
    ///
    /// # Errors
    ///
    /// If a `Module`'s block no longer names memory the module owns.
    pub fn dispatch(&self, mem: &A::Mem, n: usize) -> Result<Dispatch<A>, ShimError> {
        match self {
            Self::Module { block, .. } => {
                let header = ModuleLayout::of::<A>().header;
                let at = A::ptr_offset(*block, header + (n as u16) * A::PTR_WIDTH as u16);
                let bytes = at
                    .resolve(mem, A::PTR_WIDTH)
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                let ptr = A::ptr_from_bytes(bytes);
                let is_null = A::ptr_to_bytes(ptr).iter().all(|&b| b == 0);
                Ok(Dispatch::Module((!is_null).then_some(ptr)))
            }
            Self::Native(native) => Ok(Dispatch::Native(*native)),
            Self::AbsentBbs => Ok(Dispatch::SessionOver),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a == a`, for every variant of both hand-written `PartialEq`s.
    ///
    /// Both `Registration` and `Dispatch` write `eq` by hand with a
    /// `_ => false` catch-all, and on 2026-08-15 both were found
    /// non-reflexive: `Registration::AbsentBbs` and `Dispatch::SessionOver`
    /// were each added by `209d2ff` without an arm, and the catch-all
    /// answered `false` for a value compared with itself. Both types also
    /// `impl Eq`, which *promises* reflexivity, so the bug was a broken
    /// contract rather than a surprising result -- anything using them as a
    /// `HashMap` key or sorting them was entitled to assume otherwise.
    ///
    /// Nothing compared two of either until an `--ignored` integration test
    /// did, three weeks later. This test is the cheap version of that
    /// discovery: add a variant without an arm and it fails immediately.
    #[test]
    fn equality_is_reflexive_for_every_variant() {
        // Exhaustive by construction: a new variant makes this `match` fail
        // to compile, which is the point -- it forces whoever adds one to
        // come here, and coming here means seeing the `eq` arm they owe.
        fn all_registrations<A: Abi>(r: &Registration<A>) -> &'static str {
            match r {
                Registration::Module { .. } => "Module",
                Registration::Native(_) => "Native",
                Registration::AbsentBbs => "AbsentBbs",
            }
        }
        fn all_dispatches<A: Abi>(d: &Dispatch<A>) -> &'static str {
            match d {
                Dispatch::Module(_) => "Module",
                Dispatch::Native(_) => "Native",
                Dispatch::SessionOver => "SessionOver",
            }
        }

        let registrations: [Registration<Wg16>; 3] = [
            Registration::Module {
                description: "MajorMUD".to_owned(),
                block: FarPtr { offset: 136, selector: 351 },
            },
            Registration::Native(Native::Fsd),
            Registration::AbsentBbs,
        ];
        for r in &registrations {
            assert_eq!(r, r, "Registration::{} is not equal to itself", all_registrations(r));
        }

        let dispatches: [Dispatch<Wg16>; 3] = [
            Dispatch::Module(Some(FarPtr { offset: 8, selector: 16 })),
            Dispatch::Native(Native::Fsd),
            Dispatch::SessionOver,
        ];
        for d in &dispatches {
            assert_eq!(d, d, "Dispatch::{} is not equal to itself", all_dispatches(d));
        }

        // And still distinguishing: a reflexive `eq` that answered `true` for
        // everything would pass the loops above and be just as wrong.
        assert_ne!(registrations[1], registrations[2]);
        assert_ne!(dispatches[1], dispatches[2]);
    }
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

    /// A DOS packed date: `(year - 1980) << 9 | month << 5 | day`.
    ///
    /// Spelled as a helper rather than inline so the three fields stay named
    /// at each call site. Written inline, a year offset of 0 reads as
    /// `(0 << 9) | ...`, which documents the field but computes nothing and
    /// which clippy correctly flags as a no-op operation.
    const fn dos_date(year_from_1980: u16, month: u16, day: u16) -> u16 {
        (year_from_1980 << 9) | (month << 5) | day
    }

    /// A `struct module` in module memory: 25 bytes of name, then nine far
    /// pointers.
    fn module_block(f: &mut Fixture, name: &str, entries: &[FarPtr]) -> FarPtr {
        let mut bytes = vec![0u8; usize::from(MNMSIZ)];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        for entry in entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes.resize(usize::from(MNMSIZ) + 9 * 4, 0);
        f.bytes(&bytes, false)
    }

    /// A registered module's shutdown vector is the one `finalize` calls.
    ///
    /// `finrou` is entry 8 -- the last of the nine -- so an off-by-one in
    /// either direction reads a different routine or runs off the end of the
    /// block. The other eight entries are deliberately left null here: if
    /// `finalize` dispatched any of them the count would be wrong, which is
    /// the cheapest way to pin the index without a second module.
    #[test]
    fn finalize_dispatches_finrou_and_nothing_else() {
        let mut f = Fixture::new();
        let module = f.minimal_module();

        let mut entries = vec![FarPtr { offset: 0, selector: 0 }; 9];
        entries[8] = f.machine.code_ptr(0);
        let block = module_block(&mut f, "MajorMUD", &entries);
        f.invoke(register_module, &Fixture::far(block)).expect("registered");

        // After the `invoke`, not before: `Fixture::invoke` builds its own
        // trampoline at offset 0 of the scratch code segment, so a routine
        // written there first is gone by the time `finalize` calls it -- and
        // what runs instead is the trampoline's thunk, which stops the
        // machine on an unimplemented import rather than returning.
        f.machine.load_code(&[0xcb]).expect("a retf fits");

        let mut dispatched = 0;
        let stopped = f
            .host
            .finalize(&mut f.machine, &module, &mut dispatched)
            .expect("finalize ran");

        assert!(stopped.is_none(), "a retf shutdown routine returns, it does not stop: {stopped:?}");
        assert_eq!(dispatched, 1, "exactly the one module's finrou, and only entry 8");
    }

    /// A module with no `finrou` is skipped, not called through a null.
    ///
    /// `mjrfin`'s own `if ((rouptr=module[i]->finrou) != NULL)` is the guard
    /// this mirrors. Without it the sweep would call address zero, which on
    /// this host is a fault and on the original was a reboot.
    #[test]
    fn finalize_skips_a_module_that_supplies_no_finrou() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let block = module_block(&mut f, "MajorMUD", &[FarPtr { offset: 0, selector: 0 }; 9]);
        f.invoke(register_module, &Fixture::far(block)).expect("registered");

        let mut dispatched = 0;
        let stopped = f
            .host
            .finalize(&mut f.machine, &module, &mut dispatched)
            .expect("finalize ran");

        assert!(stopped.is_none());
        assert_eq!(dispatched, 0, "a null finrou is skipped, not dispatched");
    }

    /// A `struct agent` in module memory: nine bytes of appid, then four far
    /// vectors.
    fn agent_block(f: &mut Fixture, appid: &str, vectors: &[FarPtr]) -> FarPtr {
        let mut bytes = vec![0u8; usize::from(AIDSIZ)];
        bytes[..appid.len()].copy_from_slice(appid.as_bytes());
        for vector in vectors {
            bytes.extend_from_slice(&vector.to_bytes());
        }
        bytes.resize(usize::from(AGENT_SIZE), 0);
        f.bytes(&bytes, false)
    }

    /// `ModuleLayout` at both ABIs -- `Wg16`'s header is `MNMSIZ` itself
    /// (Borland's 16-bit compiler byte-packs `struct module`), `Wg32`'s pads
    /// that same 25-byte `descrp` to a 4-byte boundary before the routine
    /// pointers start.
    ///
    /// # Where 28 comes from
    ///
    /// Not the header alone -- `MAJORBBS.H:301` declares one `struct module`
    /// with no `#ifdef` in it, so the header cannot say which compiler pads
    /// it. Measured two ways, independently:
    ///
    /// * LunatiX's own registered block, printed raw by
    ///   `tests/lunatix.rs`'s `a_wg32_channel_entering_lunatix_surveys`:
    ///   bytes `7..28` are zero padding after `"Lunatix\0"`, and byte `28` is
    ///   where a real in-image code pointer starts (`0x40xxxxxx`, matching
    ///   the loaded module's own base) -- not byte 25, which is the last
    ///   zero byte of `descrp`'s own padding.
    /// * The real PE32 `WGSERVER.EXE` oracle
    ///   (`archive/_acquire/pools/full/cfca0b96eae9602a_WGSERVER.EXE`)
    ///   dispatches through this same table at VA `0x44dab7`/`0x44dac7`:
    ///   `lea ecx,[ebx+ebx*2]` (stride-3 index into the module array),
    ///   `mov edx,[eax+ecx*4]` (the module pointer), then
    ///   `call [edx+0x24]` immediately followed by `call [edx+0x30]` --
    ///   `0x24` (36) and `0x30` (48) are `stsrou` and `huprou` at header
    ///   offsets `28 + 2*4` and `28 + 5*4`, which only lands on the header's
    ///   own field order if the header is 28. Byte-for-byte identical code
    ///   (only the global data addresses differ) at VA `0x44a3c3`/`0x44a3d3`
    ///   in the sibling build `bfe3ab588c1273a4_WGSERVER.EXE` and VA
    ///   `0x44a393`/`0x44a3a3` in `c9e8ff33f5b80c65_WGSERVER.EXE` -- three
    ///   independent binaries, same offsets.
    ///
    /// # Why the discriminator is not `Abi::GCV2`
    ///
    /// `struct module` has one declaration, not two -- unlike `struct user`
    /// ([`crate::users::UserLayout`]), nothing about its *field set* changes
    /// between builds. What changes is a fact about the compiler that built
    /// the host: whether it packs a struct byte-tight or aligns a pointer
    /// member to its own width. That is the same fact
    /// [`FndblkLayout`](crate::shims::stream::FndblkLayout) already
    /// encodes for `struct ffblk`'s two incompatible shapes, so this reuses
    /// its discriminator (`A::INT_WIDTH >= 4`) rather than inventing a
    /// second name for the same axis.
    #[test]
    fn module_layout_pads_the_header_to_four_bytes_at_wg32() {
        use crate::abi::Wg32;

        assert_eq!(
            ModuleLayout::of::<Wg16>().header,
            25,
            "Wg16: Borland's 16-bit compiler byte-packs, MNMSIZ is already right"
        );
        assert_eq!(
            ModuleLayout::of::<Wg32>().header,
            28,
            "Wg32: MNMSIZ (25) padded to a 4-byte boundary -- the oracle's own \
             call sites land on stsrou/huprou only if this is 28, not 25"
        );
    }

    #[test]
    fn now_and_today_are_packed_the_way_dos_packs_them() {
        let mut f = Fixture::new();

        let Ret::U16(time) = f.invoke(now, &[]).expect("now") else {
            panic!("now returns an int");
        };
        let (hour, minute, second) = (time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2);
        assert!(hour < 24, "{hour}");
        assert!(minute < 60, "{minute}");
        assert!(second < 60, "{second}");

        let Ret::U16(date) = f.invoke(today, &[]).expect("today") else {
            panic!("today returns an int");
        };
        let (year, month, day) = (1980 + (date >> 9), (date >> 5) & 0x0f, date & 0x1f);
        assert!((1..=12).contains(&month), "{month}");
        assert!((1..=31).contains(&day), "{day}");
        assert!(year >= 2020, "{year}");
    }

    /// MajorMUD 1.11p's build stamp: `Dec 30 2005 14:20:05` UTC.
    const BUILD: u32 = 1_135_952_405;

    #[test]
    fn a_pinned_clock_packs_the_instant_it_was_pinned_to() {
        // Both numbers are derived rather than observed:
        //   today = (2005-1980)<<9 | 12<<5 | 30 = 13214
        //   now   = 14<<11 | 20<<5 | 5/2        = 29314
        // and the seconds field is *two-second units*, so 5 packs as 2.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(BUILD));

        assert_eq!(f.invoke(today, &[]).expect("today"), Ret::U16(13214));
        assert_eq!(f.invoke(now, &[]).expect("now"), Ret::U16(29314));
        assert_eq!(f.invoke(time, &[0, 0]).expect("time"), Ret::U32(BUILD));
    }

    #[test]
    fn all_three_describe_one_instant() {
        // The bug this rules out: three independent `SystemTime::now()` calls,
        // which is what these shims used to be. Under a pin they cannot drift,
        // and `time` is the one that has to agree with the other two rather
        // than merely be plausible.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(BUILD));

        let Ret::U32(seconds) = f.invoke(time, &[0, 0]).expect("time") else {
            panic!("time returns a long");
        };
        let civil = crate::Clock::pinned(seconds).civil().expect("in range");

        let Ret::U16(date) = f.invoke(today, &[]).expect("today") else {
            panic!("today returns an int");
        };
        assert_eq!(u32::from(date >> 9) + 1980, civil.year as u32);
        assert_eq!(u32::from((date >> 5) & 0x0f), civil.month);
        assert_eq!(u32::from(date & 0x1f), civil.day);
    }

    #[test]
    fn a_year_dos_cannot_pack_is_refused_rather_than_clamped() {
        // `today` has seven bits for `year - 1980`. The old shim wrote
        // `.max(0)`, which turned 1970 into 1980 and handed the module a date
        // that was wrong rather than absent -- the one outcome this crate is
        // built to avoid.
        //
        // Only the lower bound can be reached. A `u32` of epoch seconds runs
        // out on 2106-02-07, so the 2107 ceiling those seven bits impose is
        // unreachable while the clock is a `u32` -- the check is there because
        // the format has the limit, not because a test can provoke it.
        let mut f = Fixture::new();

        f.host.set_clock(crate::Clock::pinned(0));
        let e = f.invoke(today, &[]).expect_err("1970 is not a DOS year");
        assert!(format!("{e}").contains("1970"), "{e}");

        // The last second a `u32` can hold is still inside the range, so the
        // ceiling stays a refusal nothing trips over.
        f.host.set_clock(crate::Clock::pinned(u32::MAX));
        assert!(f.invoke(today, &[]).is_ok(), "2106 is a DOS year");
    }

    #[test]
    fn time_stores_through_a_pointer_and_ignores_a_null_one() {
        let mut f = Fixture::new();
        let tloc = f.buffer(4);

        let Ret::U32(seconds) = f.invoke(time, &Fixture::far(tloc)).expect("time") else {
            panic!("time returns a long");
        };
        let stored = f.machine.resolve(tloc, 4).expect("in bounds");
        assert_eq!(u32::from_le_bytes(stored.try_into().unwrap()), seconds);

        // A null pointer means "do not store it", which is the ordinary call.
        assert!(f.invoke(time, &[0, 0]).is_ok());
    }

    #[test]
    fn dclvda_keeps_the_largest_declaration() {
        let mut f = Fixture::new();
        let vdasiz = |f: &Fixture| f.host.globals().word(&f.machine, "vdasiz").expect("vdasiz");

        f.invoke(dclvda, &[512]).expect("declared");
        assert_eq!(vdasiz(&f), 512);

        // Every module shares one volatile data area per channel, so a smaller
        // declaration must not shrink it.
        f.invoke(dclvda, &[128]).expect("declared");
        assert_eq!(vdasiz(&f), 512);

        f.invoke(dclvda, &[1024]).expect("declared");
        assert_eq!(vdasiz(&f), 1024);
    }

    #[test]
    fn gmdnam_returns_the_name_after_the_label() {
        let mut f = Fixture::new();
        let name = f.text("SAMPLE.MDF");
        let Ret::Far(at) = f.invoke(gmdnam, &Fixture::far(name)).expect("read") else {
            panic!("gmdnam returns a pointer");
        };
        assert_eq!(f.read(at), "Sample Module");
    }

    #[test]
    fn gmdnam_finds_a_file_whatever_case_it_was_named_in() {
        // A DOS module names its own files in whatever case it likes, and the
        // filesystem underneath is not as forgiving as DOS was.
        let mut f = Fixture::new();
        let name = f.text("sample.mdf");
        assert!(f.invoke(gmdnam, &Fixture::far(name)).is_ok());
    }

    #[test]
    fn gmdnam_stops_the_module_rather_than_inventing_a_name() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCH.MDF");
        assert!(f.invoke(gmdnam, &Fixture::far(name)).is_err());
    }

    #[test]
    fn shocst_keeps_the_headline_and_the_formatted_detail() {
        let mut f = Fixture::new();
        let headline = f.text("MODULE ONLINE");
        let detail = f.text("%s on channel %d");
        let who = f.text("rangerdan");
        let args = [
            headline.offset,
            headline.selector,
            detail.offset,
            detail.selector,
            who.offset,
            who.selector,
            3,
        ];
        f.invoke(shocst, &args).expect("recorded");
        assert_eq!(f.host.audit(), ["MODULE ONLINE: rangerdan on channel 3"]);
    }

    #[test]
    fn register_module_keeps_the_pointer_and_hands_back_a_number() {
        let mut f = Fixture::new();
        // `Fixture::new` runs `finish_init`, which registers the FSD's own
        // native slot (`Host::fsd_state`) before any module can -- so "the
        // first module is module zero" is no longer true; the number wanted
        // is read back rather than assumed, the same way a real caller would
        // only ever know it by what `register_module` hands back.
        let want = f.host.modules().len() as u16;
        let entries: Vec<FarPtr> = (0..9)
            .map(|n| FarPtr {
                offset: 0x100 + n * 0x10,
                selector: f.machine.code_selector(),
            })
            .collect();
        let block = module_block(&mut f, "MajorMUD", &entries);

        assert_eq!(
            f.invoke(register_module, &Fixture::far(block)).expect("ok"),
            Ret::U16(want),
            "a module registers into the next free slot, past the FSD's own"
        );
        let registered = &f.host.modules()[want as usize];
        let Registration::Module { description, .. } = registered else {
            panic!("register_module always registers a Module, not {registered:?}");
        };
        assert_eq!(description, "MajorMUD");

        for (n, expect) in entries.iter().enumerate() {
            assert_eq!(
                registered.dispatch(f.machine.mem(), n).expect("readable"),
                Dispatch::Module(Some(*expect))
            );
        }
    }

    #[test]
    fn a_registered_module_may_change_its_own_entry_points() {
        // The real host stores the module's own block rather than a copy
        // (`MAJORBBS.C:1327`), and the module is free to rewrite it. A snapshot
        // would go stale and the host would call the wrong address.
        let mut f = Fixture::new();
        let want = f.host.modules().len();
        let block = module_block(&mut f, "MajorMUD", &[]);
        f.invoke(register_module, &Fixture::far(block)).expect("ok");

        assert_eq!(
            f.host.modules()[want]
                .dispatch(f.machine.mem(), 1)
                .expect("readable"),
            Dispatch::Module(None),
            "a null entry point is no entry point"
        );

        let sttrou = FarPtr {
            offset: 0x0200,
            selector: f.machine.code_selector(),
        };
        let at = FarPtr {
            offset: block.offset + MNMSIZ + 4,
            selector: block.selector,
        };
        f.machine.write(at, &sttrou.to_bytes()).expect("in bounds");

        assert_eq!(
            f.host.modules()[want]
                .dispatch(f.machine.mem(), 1)
                .expect("readable"),
            Dispatch::Module(Some(sttrou)),
            "read back, not remembered"
        );
    }

    #[test]
    fn register_module_refuses_a_name_the_real_host_would_refuse() {
        // Both are `catastro` in the original: the name is the key a module's
        // records are stored under, so a bad one is not something to carry on
        // from.
        let mut f = Fixture::new();
        let short = module_block(&mut f, "AB", &[]);
        assert!(f.invoke(register_module, &Fixture::far(short)).is_err());

        let mut f = Fixture::new();
        let full = module_block(&mut f, "0123456789012345678901234", &[]);
        assert!(f.invoke(register_module, &Fixture::far(full)).is_err());
    }

    #[test]
    fn catastro_stops_the_module_with_its_own_message() {
        let mut f = Fixture::new();
        let template = f.text("BAD LIBRARY FILE DATA POINTER (%d)");
        let failed = f
            .invoke(catastro, &[template.offset, template.selector, 7])
            .expect_err("catastro never returns");
        assert!(
            failed
                .to_string()
                .contains("BAD LIBRARY FILE DATA POINTER (7)"),
            "{failed}"
        );
    }

    #[test]
    fn srand_starts_the_generator_over() {
        // What `srand` is *for*. The seed was stored and unused from step 7
        // until now; this is the first test that can see it do anything.
        let mut f = Fixture::new();
        f.invoke(srand, &[0x1234]).expect("seeded");
        let first: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();

        f.invoke(srand, &[0x1234]).expect("seeded again");
        let again: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();
        assert_eq!(first, again);

        f.invoke(srand, &[0x1235]).expect("a different seed");
        let other: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();
        assert_ne!(first, other);
    }

    #[test]
    fn genrdn_answers_inside_the_range_the_module_asked_for() {
        // Measured: the two calls initialisation makes are both
        // `genrdn(0, 343)`, so this is that call, a thousand times over.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        for _ in 0..1000 {
            let Ret::U16(n) = f.invoke(genrdn, &[0, 343]).expect("a number") else {
                panic!("genrdn returns an int");
            };
            assert!(n < 343, "{n} is outside 0..343");
        }
    }

    #[test]
    fn genrdn_draws_rather_than_repeating() {
        // A shim that read its arguments and returned one of them would pass
        // the bounds check above.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        let drawn: std::collections::HashSet<u16> = (0..100)
            .map(|_| match f.invoke(genrdn, &[0, 343]).expect("a number") {
                Ret::U16(n) => n,
                other => panic!("genrdn returns an int, not {other:?}"),
            })
            .collect();
        assert!(drawn.len() > 50, "100 draws gave {} values", drawn.len());
    }

    #[test]
    fn lngrnd_reads_two_longs_and_not_four_ints() {
        // The argument-spacing trap, pinned. Each `long` is two words, so
        // `min` is words 0-1 and `max` is words 2-3. A shim using genrdn's own
        // `arg_u16(0)`/`arg_u16(1)` spacing would read `min`'s high half as
        // `max`'s low one and draw from a range the module never asked for.
        //
        // The bounds have to be chosen so the wrong reading is *detectable*,
        // which a first attempt at this test got wrong: with min 0 the
        // mis-spaced read yields max 0, `lngrnd` returns 0 by its own first
        // line, and 0 sits happily inside the range the test was asserting.
        // The mutation survived its own test and was caught only by a
        // neighbour. So `min` is given a nonzero *high* word here:
        //
        //   min = 0x0002_0001 = 131073   (words 0,1 = 0x0001, 0x0002)
        //   max = 0x0003_0000 = 196608   (words 2,3 = 0x0000, 0x0003)
        //
        // Read correctly, no answer can be below 131073. Read with genrdn's
        // spacing, min becomes word 0 (1) and max word 1 (2), so the answer is
        // 1 -- outside the asserted range by five orders of magnitude.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        for _ in 0..500 {
            let Ret::U32(n) = f
                .invoke(lngrnd, &[0x0001, 0x0002, 0x0000, 0x0003])
                .expect("a number")
            else {
                panic!("lngrnd returns a long");
            };
            assert!(
                (131_073..196_608).contains(&n),
                "{n} is outside 131073..196608 -- the argument words were paired wrongly"
            );
        }
    }

    #[test]
    fn lngrnd_from_zero_never_exceeds_rand_max_however_wide_the_range() {
        // `rand()` answers 0..=32767 whatever the argument types are, so with
        // min 0 the loop never runs and the whole routine is one `rand()%max`
        // that the modulo cannot bite. The observable property of the
        // generator, through the shim rather than the pure function.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        for _ in 0..2000 {
            // min = 0, max = 0x0003_0000 = 196608.
            let Ret::U32(n) = f.invoke(lngrnd, &[0, 0, 0, 3]).expect("a number") else {
                panic!("lngrnd returns a long");
            };
            assert!(
                n <= u32::from(crate::random::RAND_MAX),
                "{n} is above RAND_MAX, so the first draw was not a single rand()"
            );
        }
    }

    #[test]
    fn lngrnd_accumulates_to_reach_a_minimum_beyond_rand_max() {
        // 100000 is past what one rand() can produce, so the loop is the only
        // way to satisfy it -- and the answer still has to land under max.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        for _ in 0..500 {
            // min = 100000 = 0x0001_86A0, max = 1000000 = 0x000F_4240.
            let Ret::U32(n) = f
                .invoke(lngrnd, &[0x86A0, 0x0001, 0x4240, 0x000F])
                .expect("a number")
            else {
                panic!("lngrnd returns a long");
            };
            assert!(
                (100_000..1_000_000).contains(&n),
                "{n} is outside 100000..1000000"
            );
        }
    }

    #[test]
    fn rtkick_remembers_the_callback_and_when_it_is_due() {
        let mut f = Fixture::new();
        let dstrou = FarPtr {
            offset: 0x0a21,
            selector: 0x0067,
        };

        let args = [1, dstrou.offset, dstrou.selector];
        assert!(matches!(f.invoke(rtkick, &args), Ok(Ret::Void)));

        assert_eq!(f.host.kicks(), [Kick { delay: 1, dstrou }]);
    }

    #[test]
    fn kicks_are_kept_in_the_order_they_were_registered() {
        // `prcrtk` runs them in list order, and the real host's list is a
        // queue appended at the tail, so two kicks due in the same second run
        // in the order they were asked for. Nothing depends on that yet; it is
        // cheaper to be right now than to discover it from a bug later.
        let mut f = Fixture::new();
        let first = FarPtr {
            offset: 0x1111,
            selector: 0x0067,
        };
        let second = FarPtr {
            offset: 0x2222,
            selector: 0x0067,
        };

        f.invoke(rtkick, &[5, first.offset, first.selector])
            .expect("first");
        f.invoke(rtkick, &[5, second.offset, second.selector])
            .expect("second");

        assert_eq!(
            f.host.kicks(),
            [
                Kick {
                    delay: 5,
                    dstrou: first
                },
                Kick {
                    delay: 5,
                    dstrou: second
                },
            ]
        );
    }

    #[test]
    fn a_negative_delay_is_refused_rather_than_stored() {
        // `int delay` is signed and "call this 32,769 seconds ago" is not a
        // thing a caller can mean. The realistic cause is the host reading the
        // arguments in the wrong order, which this catches at the call rather
        // than as a stored pointer nobody looks at until there is a main loop.
        let mut f = Fixture::new();

        let e = f
            .invoke(rtkick, &[0xffff, 0x0a21, 0x0067])
            .expect_err("refused");
        assert!(format!("{e}").contains("negative delay"), "{e}");
        assert!(f.host.kicks().is_empty());
    }

    /// `RTKICK.C:50` uses `countr == 0` as the *free-slot* marker and `:65`
    /// skips any entry holding it, so `rtkick(0, f)` writes a zero into a slot
    /// that stays free and `f` never runs. The `Vec` here has no free-slot
    /// encoding, so the faithful translation is to record nothing at all --
    /// keeping a zero entry would also wedge `Ended::Bound`'s `next_kick` at
    /// `Some(0)` and stop the loop ever reaching `Idle`.
    #[test]
    fn a_zero_delay_kick_is_noted_and_never_recorded() {
        let mut f = Fixture::new();
        let dstrou = f.machine.code_ptr(0);
        assert!(matches!(
            f.invoke(rtkick, &[0, dstrou.offset, dstrou.selector]),
            Ok(Ret::Void)
        ));
        assert!(f.host.kicks().is_empty(), "RTKICK.C would never fire it");
        assert!(
            f.host.notes().iter().any(|n| n.contains("rtkick")),
            "and it does not happen in silence: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn register_agent_keeps_the_appid_and_the_four_vectors() {
        // Measured: MajorMUD's own record, at `seg 67:0x0000` of
        // `WCCMMUD.DLL`, is `WCCMMUD` and four vectors into its segment 26.
        let mut f = Fixture::new();
        let vectors: Vec<FarPtr> = [0x0069, 0x016b, 0x029c, 0x02a1]
            .into_iter()
            .map(|offset| FarPtr {
                offset,
                selector: f.machine.code_selector(),
            })
            .collect();
        let block = agent_block(&mut f, "WCCMMUD", &vectors);

        assert_eq!(
            f.invoke(register_agent, &Fixture::far(block))
                .expect("registered"),
            Ret::Void,
            "register_agent returns nothing"
        );

        let agent = &f.host.agents()[0];
        assert_eq!(agent.appid, "WCCMMUD");
        assert_eq!(agent.read, Some(vectors[0]));
        assert_eq!(agent.write, Some(vectors[1]));
        assert_eq!(agent.xferdone, Some(vectors[2]));
        assert_eq!(agent.abort, Some(vectors[3]));
    }

    #[test]
    fn an_agent_is_copied_rather_than_pointed_at() {
        // The opposite of `register_module`, and measured: `register_agent`
        // ends in `movmem(agdptr, &agents[nagents], 25)`, so the caller's block
        // is the host's to forget. A host that kept the pointer would report
        // whatever the module later put there.
        let mut f = Fixture::new();
        let read = FarPtr {
            offset: 0x0069,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "WCCMMUD", &[read]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        let at = FarPtr {
            offset: block.offset,
            selector: block.selector,
        };
        f.machine.write(at, b"OVERWRIT\0").expect("in bounds");

        assert_eq!(
            f.host.agents()[0].appid,
            "WCCMMUD",
            "the copy is the host's, and the module cannot change it"
        );
        assert_eq!(f.host.agents()[0].read, Some(read));
    }

    #[test]
    fn a_null_vector_is_no_vector() {
        // What the real host does here is substitute its own default --
        // `rejectreq` for read and write, nothing for the other two. This host
        // has nothing to dispatch, so it records the absence instead. See
        // `Agent`.
        let mut f = Fixture::new();
        let block = agent_block(&mut f, "SILENT", &[]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        let agent = &f.host.agents()[0];
        assert_eq!(agent.read, None);
        assert_eq!(agent.write, None);
        assert_eq!(agent.xferdone, None);
        assert_eq!(agent.abort, None);
    }

    #[test]
    fn a_vector_at_offset_zero_is_still_a_vector() {
        // The real routine tests both words -- `mov ax,[es:bx+9]` then
        // `or ax,[es:bx+0xb]` -- and this is why that is not pedantry. Offset
        // zero is a real address: `seg 26:0x0000` of `WCCMMUD.DLL` is the
        // routine that calls `register_agent` in the first place.
        let mut f = Fixture::new();
        let start = FarPtr {
            offset: 0,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "WCCMMUD", &[start]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        assert_eq!(f.host.agents()[0].read, Some(start));
    }

    #[test]
    fn an_appid_filling_its_field_is_read_bounded() {
        // `char appid[AIDSIZ]` is nine bytes and a name that uses all nine has
        // no terminator. Scanning for one would run into the `read` vector and
        // return a name with a pointer stuck to the end of it.
        let mut f = Fixture::new();
        let read = FarPtr {
            offset: 0x0069,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "ABCDEFGHI", &[read]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        assert_eq!(f.host.agents()[0].appid, "ABCDEFGHI");
        assert_eq!(f.host.agents()[0].read, Some(read));
    }

    #[test]
    fn register_textvar_publishes_the_table_through_the_global() {
        // Measured: MajorMUD registers one text variable, `MUDCHARINFO`, whose
        // routine is at `seg 3:0x001e` of `WCCMMUD.DLL`. And the *global* is
        // the point -- the module reaches the table only through `txtvars`, so
        // a host that filled a table and left the pointer null would have
        // registered nothing.
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };

        let args = [name.offset, name.selector, varrou.offset, varrou.selector];
        assert_eq!(
            f.invoke(register_textvar, &args).expect("registered"),
            Ret::U16(0),
            "the first text variable is number zero"
        );

        let published = f
            .host
            .globals()
            .pointer(&f.machine, "txtvars")
            .expect("txtvars");
        assert_ne!(published, mbbs_machine::m16::FarPtr::NULL, "the global was filled in");
        assert_eq!(published, f.host.textvars().at().expect("a table"));

        let row = f
            .host
            .textvars()
            .get_mem(f.machine.mem(), 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, Some(varrou));
    }

    #[test]
    fn a_second_text_variable_moves_the_table_and_the_first_survives() {
        // The table grows one record at a time, so registering a second one
        // reallocates. Two things have to hold: the first row's bytes come with
        // it, and the global points at where they went. An implementation that
        // allocated and forgot to copy would pass every test in Task 5.
        let mut f = Fixture::new();
        let first = f.text("MUDCHARINFO");
        let second = f.text("USERID");
        let a = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };
        let b = FarPtr {
            offset: 0x0200,
            selector: f.machine.code_selector(),
        };

        assert_eq!(
            f.invoke(register_textvar,
                &[first.offset, first.selector, a.offset, a.selector]
            )
            .expect("registered"),
            Ret::U16(0)
        );
        assert_eq!(
            f.invoke(register_textvar,
                &[second.offset, second.selector, b.offset, b.selector]
            )
            .expect("registered"),
            Ret::U16(1),
            "the index counts up"
        );

        assert_eq!(f.host.textvars().len(), 2);
        let published = f
            .host
            .globals()
            .pointer(&f.machine, "txtvars")
            .expect("txtvars");
        assert_eq!(published, f.host.textvars().at().expect("a table"));

        let row0 = f
            .host
            .textvars()
            .get_mem(f.machine.mem(), 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row0.name, "MUDCHARINFO", "the first row came along");
        assert_eq!(row0.varrou, Some(a));

        let row1 = f
            .host
            .textvars()
            .get_mem(f.machine.mem(), 1)
            .expect("readable")
            .expect("a row");
        assert_eq!(row1.name, "USERID");
        assert_eq!(row1.varrou, Some(b));

        assert_eq!(
            f.host.textvars().get_mem(f.machine.mem(), 2).expect("readable"),
            None,
            "and there is no third"
        );
    }

    #[test]
    fn a_name_too_long_for_the_field_is_truncated_rather_than_refused() {
        // `stzcpy(name, name, TVRSIZ)` and not `strncpy`: at most fifteen
        // characters, always terminated. The sixteenth would leave the field
        // unterminated and running into `varrou`, which is the bug `stzcpy`
        // exists to avoid -- so the original truncates, and so does this.
        let mut f = Fixture::new();
        let name = f.text("ABCDEFGHIJKLMNOPQRST");
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };

        f.invoke(register_textvar,
            &[name.offset, name.selector, varrou.offset, varrou.selector],
        )
        .expect("registered");

        let row = f
            .host
            .textvars()
            .get_mem(f.machine.mem(), 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "ABCDEFGHIJKLMNO", "fifteen and a terminator");
        assert_eq!(row.varrou, Some(varrou), "and varrou was not written over");
    }

    #[test]
    fn a_null_routine_is_stored_rather_than_refused() {
        // The opposite of `register_agent`'s null vectors, and measured: the
        // module tests `varrou` before calling it -- `mov ax,[es:bx+0x10]` then
        // `or ax,[es:bx+0x12]` at `seg 23:0x22f5` -- so a null one is a row
        // that produces nothing, not a row that is wrong.
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");

        f.invoke(register_textvar, &[name.offset, name.selector, 0, 0])
            .expect("registered");

        let row = f
            .host
            .textvars()
            .get_mem(f.machine.mem(), 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, None);
        assert_eq!(f.host.textvars().len(), 1, "it is still a row");
    }

    #[test]
    fn a_text_variable_with_no_name_is_refused() {
        // This host's own refusal, and a weaker one than the agent's empty
        // `appid`: `findtvar("")` could genuinely match this. What carries it
        // is that a name arriving empty is a misread argument list, and a
        // nameless row in a table nobody prints is expensive to find later.
        let mut f = Fixture::new();
        let name = f.text("");

        let e = f
            .invoke(register_textvar, &[name.offset, name.selector, 0x1e, 0x67])
            .expect_err("refused");
        assert!(format!("{e}").contains("no name"), "{e}");
        assert!(f.host.textvars().is_empty());
        assert_eq!(
            f.host
                .globals()
                .pointer(&f.machine, "txtvars")
                .expect("txtvars"),
            mbbs_machine::m16::FarPtr::NULL,
            "and nothing was published"
        );
    }

    #[test]
    fn an_agent_with_no_appid_is_refused() {
        // This host's own refusal and not the original's. A client addresses an
        // agent by its appid, so an empty one is an agent nobody can reach --
        // no caller can mean it, and a misread argument list is what produces
        // one. Same grounds as `rtkick`'s negative delay.
        let mut f = Fixture::new();
        let block = agent_block(&mut f, "", &[]);

        let e = f
            .invoke(register_agent, &Fixture::far(block))
            .expect_err("refused");
        assert!(format!("{e}").contains("no appid"), "{e}");
        assert!(f.host.agents().is_empty());
    }

    #[test]
    fn nctime_unpacks_the_three_fields_dos_packed() {
        // 13:45:30, packed the way `now` packs it -- seconds are two-second
        // units, so 30 seconds is 15. The unpacking is read off
        // `MAJORBBS-wg101.EXE seg 33:0x0c56`: `sar 0xb / and 0x1f`,
        // `sar 0x5 / and 0x3f`, and `add ax,ax / and 0x3e`.
        let packed = (13 << 11) | (45 << 5) | 15;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(nctime, &[packed]).expect("nctime") else {
            panic!("nctime returns a far pointer");
        };
        assert_eq!(f.read(at), "13:45:30");
    }

    #[test]
    fn nctime_doubles_the_seconds_rather_than_masking_them() {
        // The one field a reader gets wrong by reading the name instead of the
        // instructions. Five bits will not hold 59, so what is stored is half
        // the seconds and an odd second cannot be represented at all.
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(nctime, &[(23 << 11) | (59 << 5) | 29]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "23:59:58", "29 units is 58 seconds, not 29");
    }

    #[test]
    fn nctime_writes_over_what_the_last_call_left() {
        // The original formats into one static at `DGROUP:0x49`. A module
        // holding the first pointer sees the second call's answer, and this
        // host must not be quietly kinder about it than the thing it
        // reproduces.
        let mut f = Fixture::new();
        let Ret::Far(first) = f.invoke(nctime, &[(1 << 11) | (2 << 5) | 1]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_eq!(f.read(first), "01:02:02");

        let Ret::Far(second) = f.invoke(nctime, &[0]).expect("nctime") else {
            panic!("far pointer");
        };
        assert_eq!(first, second, "one buffer, not two");
        assert_eq!(f.read(first), "00:00:00", "and no null case, unlike ncdate");
    }

    #[test]
    fn ncdate_is_month_day_and_a_two_digit_year() {
        // 2026-08-05, packed the way `today` packs it.
        let packed = ((2026 - 1980) << 9) | (8 << 5) | 5;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncdate, &[packed]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "08/05/26");
    }

    #[test]
    fn ncdate_of_zero_is_empty_and_leaves_the_buffer_alone() {
        // `seg 33:0x0c14` returns `DS:0x82` -- a different address from the
        // buffer at `DS:0x40` -- and it never writes. So a result taken earlier
        // is still standing afterwards, which a shim formatting "00/00/00"
        // would have destroyed.
        let mut f = Fixture::new();
        let Ret::Far(real) = f.invoke(ncdate, &[(46 << 9) | (8 << 5) | 5]).expect("ncdate")
        else {
            panic!("far pointer");
        };
        let Ret::Far(none) = f.invoke(ncdate, &[0]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_ne!(none, real, "the empty string is not the buffer");
        assert_eq!(f.read(none), "");
        assert_eq!(f.read(real), "08/05/26", "a null date did not overwrite it");
    }

    #[test]
    fn ncdate_wraps_the_year_at_a_century() {
        // 2107 is the last year seven bits reach: 127 + 1980. `idiv 100` leaves
        // 7, so the string is a bare "07" and a caller cannot tell it from
        // 2007. That is the original's limitation, reproduced.
        let packed = (127 << 9) | (12 << 5) | 31;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncdate, &[packed]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "12/31/07");
    }

    #[test]
    fn the_date_and_time_buffers_are_not_the_same_block() {
        // Three statics in the original, at DGROUP 0x40, 0x49 and 0x52. A
        // module may hold an ncdate result across an nctime call, so sharing
        // one block here would corrupt it in a way nothing else would catch.
        let mut f = Fixture::new();
        let Ret::Far(date) = f.invoke(ncdate, &[(46 << 9) | (8 << 5) | 5]).expect("ncdate")
        else {
            panic!("far pointer");
        };
        let Ret::Far(time) = f.invoke(nctime, &[(13 << 11) | (45 << 5) | 15]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_ne!(date, time);
        assert_eq!(f.read(date), "08/05/26", "the date survived the time");
        assert_eq!(f.read(time), "13:45:30");
    }

    #[test]
    fn cofdat_of_two_new_years_is_a_year_apart() {
        // 1 Jan 1980 -> 1 Jan 1981 crosses 1980's own leap day, so the gap is
        // 366, not 365. Hand-computable, and the first place `(year+3)/4`
        // could be off by one and still leave every formatted date correct.
        let mut f = Fixture::new();
        let Ret::U16(d1980) = f.invoke(cofdat, &[dos_date(0, 1, 1)]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        let Ret::U16(d1981) = f.invoke(cofdat, &[(1 << 9) | (1 << 5) | 1]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        assert_eq!(d1981 - d1980, 366);
    }

    #[test]
    fn cofdat_of_two_new_years_that_do_not_cross_a_leap_day_is_365() {
        let mut f = Fixture::new();
        let Ret::U16(d1981) = f.invoke(cofdat, &[(1 << 9) | (1 << 5) | 1]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        let Ret::U16(d1982) = f.invoke(cofdat, &[(2 << 9) | (1 << 5) | 1]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        assert_eq!(d1982 - d1981, 365);
    }

    #[test]
    fn cofdat_of_28_feb_and_1_mar_in_a_leap_year_is_2() {
        // Year 20 is 2000 -- divisible by 4, so 29 Feb falls between them.
        let mut f = Fixture::new();
        let Ret::U16(feb28) = f.invoke(cofdat, &[(20 << 9) | (2 << 5) | 28]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        let Ret::U16(mar1) = f.invoke(cofdat, &[(20 << 9) | (3 << 5) | 1]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        assert_eq!(mar1 - feb28, 2);
    }

    /// Every test above this one only asserts a *difference* between two
    /// `cofdat` results, and every one of them is in the first quarter
    /// (months 1..=3). A uniform offset in the formula -- the `- 1` at the
    /// end, say, off by a constant rather than by a leap day -- cancels out
    /// of every difference and would be invisible to all four. Cross-checked
    /// against a real proleptic-Gregorian day count (Python's
    /// `datetime.date`), not hand-derived, so this cannot share whatever
    /// mistake derived the formula in the first place.
    #[test]
    fn cofdat_of_7_aug_2026_is_17_020_days_since_1_jan_1980() {
        // Day 7, month 8 (August), year 46 -- the same date `ncedat`'s own
        // tests use, formatted `07-Aug-26`. `datetime.date(2026, 8, 7) -
        // datetime.date(1980, 1, 1)` is 17,020 days.
        let mut f = Fixture::new();
        let Ret::U16(days) = f.invoke(cofdat, &[(46 << 9) | (8 << 5) | 7]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        assert_eq!(days, 17_020);
    }

    #[test]
    fn cofdat_of_31_dec_2026_is_17_166_days_since_1_jan_1980() {
        // The latest month the table actually holds -- nothing above this
        // exercises month 12, or anything past March. `datetime.date(2026,
        // 12, 31) - datetime.date(1980, 1, 1)` is 17,166 days.
        let mut f = Fixture::new();
        let Ret::U16(days) = f.invoke(cofdat, &[(46 << 9) | (12 << 5) | 31]).expect("cofdat")
        else {
            panic!("cofdat returns an int");
        };
        assert_eq!(days, 17_166);
    }

    #[test]
    fn cofdat_refuses_a_month_the_table_has_no_entry_for() {
        // The four-bit field can hold 13..=15; `CUMULATIVE_DAYS` only has
        // 0..=12. The real host would read into the empty-string constant and
        // `ncdate`'s own format string and call it a day count -- this host
        // refuses instead.
        let mut f = Fixture::new();
        let e = f
            .invoke(cofdat, &[dos_date(0, 13, 1)])
            .expect_err("refused");
        assert!(format!("{e}").contains("13"), "{e}");
    }

    #[test]
    fn ncedat_spells_the_month() {
        // Day 7, month 8 (August), year 46 (2026) -- the plan's own example.
        // Upper case: `moname` is `AUG`, not `Aug` -- measured at NE segment
        // 88, DGROUP:0x00, of `MAJORBBS-wg101.EXE`.
        let packed = (46 << 9) | (8 << 5) | 7;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncedat, &[packed]).expect("ncedat") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "07-AUG-26");
    }

    #[test]
    fn ncedat_wraps_the_year_at_a_century() {
        let packed = (127 << 9) | (12 << 5) | 31;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncedat, &[packed]).expect("ncedat") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "31-DEC-07");
    }

    #[test]
    fn ncedat_is_total_month_zero_is_the_sentinel_not_a_refusal() {
        // No `or cx,cx` guard in the disassembly, and `moname[0]` is a real,
        // measured slot -- the `"000"` sentinel -- not one array element
        // before the table. `ncedat(0)` unpacks to day 0, month 0, year 80.
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncedat, &[0]).expect("ncedat") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "00-000-80");
    }

    #[test]
    fn ncedat_is_total_months_past_december_are_xxx_not_a_refusal() {
        // The 4-bit field can hold 13..=15; `moname` has real slots there
        // too, `"XXX"` each -- table shape, not an out-of-bounds read.
        let packed = dos_date(0, 13, 1);
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncedat, &[packed]).expect("ncedat") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "01-XXX-80");
    }

    #[test]
    fn ncedat_writes_over_what_the_last_call_left() {
        let mut f = Fixture::new();
        let Ret::Far(first) = f
            .invoke(ncedat, &[(46 << 9) | (8 << 5) | 7])
            .expect("ncedat")
        else {
            panic!("far pointer");
        };
        assert_eq!(f.read(first), "07-AUG-26");

        let Ret::Far(second) = f
            .invoke(ncedat, &[(20 << 9) | (3 << 5) | 1])
            .expect("ncedat")
        else {
            panic!("far pointer");
        };
        assert_eq!(first, second, "one buffer, not two");
        assert_eq!(f.read(second), "01-MAR-00");
    }

    // ---- getfiletm ----------------------------------------------------------

    fn word_at(f: &Fixture, at: FarPtr) -> u16 {
        u16::from_le_bytes(f.machine.resolve(at, 2).expect("readable").try_into().unwrap())
    }

    #[test]
    fn getfiletm_reports_a_known_files_exact_dos_date_and_time() {
        // 2024-03-15 10:30:00 UTC, set with `File::set_modified` so the
        // expected bytes are a literal, hand-computed absolute value --
        // not merely "whatever the same formula this shim uses also
        // computes" (memory: difference-based/self-referential tests can be
        // blind to the bug they exist to catch).
        let root = crate::testing::scratch("system-getfiletm-known");
        let mut f = Fixture::rooted(root.clone());
        let path = root.join("TEST.DAT");
        std::fs::write(&path, b"hi").expect("fixture");
        let epoch = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_710_498_600);
        std::fs::File::open(&path).expect("open").set_modified(epoch).expect("set_modified");

        let name = f.text("TEST.DAT");
        let dtim = f.buffer(2);
        let ddat = f.buffer(2);
        f.invoke(
            getfiletm,
            &[name.offset, name.selector, dtim.offset, dtim.selector, ddat.offset, ddat.selector],
        )
        .expect("getfiletm");

        assert_eq!(word_at(&f, ddat), 22639, "(2024-1980)<<9 | 3<<5 | 15");
        assert_eq!(word_at(&f, dtim), 21440, "10<<11 | 30<<5 | 0>>1");
    }

    #[test]
    fn getfiletm_on_a_missing_file_reports_zero_not_a_refusal() {
        // The vendor's own comment: "getFileTm() returns dat == 0 if the
        // file doesn't exist" -- tolerated, not stopped.
        let mut f = Fixture::rooted(crate::testing::scratch("system-getfiletm-missing"));
        let name = f.text("NOSUCH.DAT");
        let dtim = f.buffer(2);
        let ddat = f.buffer(2);
        f.invoke(
            getfiletm,
            &[name.offset, name.selector, dtim.offset, dtim.selector, ddat.offset, ddat.selector],
        )
        .expect("getfiletm tolerates a missing file");
        assert_eq!(word_at(&f, dtim), 0);
        assert_eq!(word_at(&f, ddat), 0);
    }

    #[test]
    fn getfiletm_zeroes_its_outputs_before_the_lookup_not_only_on_failure() {
        // MAJORBBS.C:418/429 -- `*ddat=*dtim=0` runs unconditionally, before
        // stat() is even attempted. Pre-seed non-zero garbage and confirm a
        // missing file really does overwrite it rather than leaving it
        // alone because "there was nothing to fail".
        let mut f = Fixture::rooted(crate::testing::scratch("system-getfiletm-preseeded"));
        let name = f.text("NOSUCH.DAT");
        let dtim = f.buffer(2);
        let ddat = f.buffer(2);
        f.machine.write(FarPtr { offset: dtim.offset, selector: dtim.selector }, &0xBEEFu16.to_le_bytes())
            .expect("preseed");
        f.machine.write(FarPtr { offset: ddat.offset, selector: ddat.selector }, &0xBEEFu16.to_le_bytes())
            .expect("preseed");

        f.invoke(
            getfiletm,
            &[name.offset, name.selector, dtim.offset, dtim.selector, ddat.offset, ddat.selector],
        )
        .expect("getfiletm");
        assert_eq!(word_at(&f, dtim), 0);
        assert_eq!(word_at(&f, ddat), 0);
    }

    // ---- vtmsndok -------------------------------------------------------------

    #[test]
    fn vtmsndok_is_true_for_a_channel_this_host_has() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(vtmsndok, &[0]).expect("vtmsndok"), Ret::U16(1));
    }

    #[test]
    fn vtmsndok_is_false_for_a_channel_this_host_does_not_have() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(vtmsndok, &[99]).expect("vtmsndok"), Ret::U16(0));
    }

    // ---- vtmsend --------------------------------------------------------------

    #[test]
    fn vtmsend_transmits_the_given_bytes_to_the_named_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        let payload = f.bytes(b"hello worldgroup", false);
        f.invoke(vtmsend, &[0, 16, payload.offset, payload.selector])
            .expect("vtmsend");
        assert_eq!(f.host.gsbl_mut().drain_output(console), b"hello worldgroup");
    }

    #[test]
    fn vtmsend_routes_by_srcid_not_always_channel_zero() {
        // A mutation that hardcoded channel 0 regardless of `srcid` would
        // still pass the single-channel test above (srcid happens to be 0
        // there too) -- two channels, and asserting BOTH the target and the
        // untouched sibling, is what actually pins the argument to its own
        // channel.
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let zero = f.host.gsbl().terms().chan(0).expect("channel 0");
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        let payload = f.bytes(b"for channel one", false);

        f.invoke(vtmsend, &[1, 15, payload.offset, payload.selector])
            .expect("vtmsend");

        assert_eq!(f.host.gsbl_mut().drain_output(one), b"for channel one");
        assert!(
            f.host.gsbl_mut().drain_output(zero).is_empty(),
            "srcid 1 must not land on channel 0"
        );
    }

    #[test]
    fn vtmsend_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        let payload = f.bytes(b"x", false);
        assert!(f.invoke(vtmsend, &[99, 1, payload.offset, payload.selector]).is_err());
    }

    #[test]
    fn vtmsend_is_binary_not_nul_scanned() {
        // Length-driven, matching btuxct: an embedded NUL is data, not a
        // terminator.
        let mut f = Fixture::new();
        let console = f.console();
        let payload = f.bytes(b"ab\0cd", false);
        f.invoke(vtmsend, &[0, 5, payload.offset, payload.selector])
            .expect("vtmsend");
        assert_eq!(f.host.gsbl_mut().drain_output(console), b"ab\0cd");
    }
}
