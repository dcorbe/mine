//! `profan`, `c2bcpy`, `b2ccpy`, `findtvar` -- a cluster of four missing
//! `WCCMMUD.DLL` imports (`docs/2026-08-14-majormud-missing-symbols.md`,
//! ranks 3, 5, 5, 5) with nothing else in common: two string-format copies,
//! a profanity scanner, and a text-variable lookup. Grouped in one file
//! because they are this session's assignment, not because they are one
//! subsystem.
//!
//! # What is faithful
//!
//! Faithful, byte-for-byte against the vendor source cited on each:
//! [`profan`], [`c2bcpy`], [`b2ccpy`], [`findtvar`].
//!
//! # `prat` and `hdlinp` used to be here too, both dead duplicates
//!
//! Removed 2026-08-15 (`docs/2026-08-15-dead-twin-shims.md`): each had a
//! twin registered elsewhere (`shims::output::prat`, `shims::echo::hdlinp`)
//! that `mod.rs` actually dispatches to.
//!
//! `prat` here is worth naming because it was not mere duplication: it fed
//! the routine's formatted output into [`crate::shims::text::append_mem`],
//! landing in the *current channel's* own output stream. `GCOMM.H:427`'s
//! own comment files `prat` (with `locate`/`curcurx`/`curcury`) under
//! `/* old MBBST.LIB prototype section */` -- the **local sysop console**,
//! not any remote channel -- and the one fully-legible call site
//! (`re/exports/WCCMMUD_named.c:14246-14288`) is a rotating status-phrase
//! readout gated behind a flag, the textbook shape of an operator status
//! line, never anything a player was meant to see. The registered
//! `shims::output::prat` routes the same text to [`crate::Host::note`]
//! instead -- the "the operator should know this" channel this host
//! actually has. This file's `prat` would have leaked sysop console text
//! into a player's own terminal.

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::strings::sameas;

/// One profanity dictionary entry: the letters that must follow the starting
/// letter [`WORD_LISTS`] indexes by, and the level (1-3) `profan` reports if
/// the whole of it is found before the word ends.
type Entry = (&'static [u8], u8);

// Transcribed from `re/wg33src/SRC/api/gcommlib/PROFAN.C:24-135`'s 26
// `aWords`..`zWords` arrays. Each C array is `{ letters..., level, letters...,
// level, ..., 0 }` -- a packed byte encoding chosen for a 1990s C compiler's
// static-data budget, not for anything [`profan_scan`] needs. Unpacked here
// into `(suffix, level)` pairs of the same content: `'n','a','l',1` becomes
// `(b"nal", 1)`. See [`profan_scan`]'s own doc comment for why the packed
// encoding's scan-position bookkeeping and this flat one are provably the
// same function, not merely "close enough".
const A_WORDS: &[Entry] = &[(b"nal", 1), (b"sshol", 3), (b"sswipe", 3), (b"ss", 1)];
const B_WORDS: &[Entry] = &[(b"low", 1), (b"itch", 1), (b"osom", 2), (b"owel", 2), (b"reast", 1)];
const C_WORDS: &[Entry] = &[
    (b"litor", 2),
    (b"ock", 1),
    (b"rap", 1),
    (b"rotch", 1),
    (b"um", 1),
    (b"unnil", 3),
    (b"unt", 3),
];
const D_WORDS: &[Entry] = &[(b"ick", 1)];
const E_WORDS: &[Entry] = &[(b"jacu", 2), (b"rect", 1)];
const F_WORDS: &[Entry] = &[
    (b"aggot", 3),
    (b"art", 1),
    (b"eca", 2),
    (b"ellatio", 2),
    (b"ondl", 2),
    (b"oreskin", 2),
    (b"uck", 3),
    (b"vck", 3),
];
const G_WORDS: &[Entry] = &[(b"ay", 1)];
const H_WORDS: &[Entry] = &[(b"ardon", 3), (b"omo", 1)];
const I_WORDS: &[Entry] = &[];
const J_WORDS: &[Entry] = &[(b"erk", 1), (b"ew", 1)];
const K_WORDS: &[Entry] = &[];
const L_WORDS: &[Entry] = &[(b"ick", 1)];
const M_WORDS: &[Entry] = &[(b"asturb", 3), (b"ember", 1)];
const N_WORDS: &[Entry] = &[(b"ippl", 2)];
const O_WORDS: &[Entry] = &[(b"rgasm", 2)];
const P_WORDS: &[Entry] = &[
    (b"ee", 1),
    (b"enis", 2),
    (b"iss", 2),
    (b"rick", 1),
    (b"ubic", 2),
    (b"ussy", 2),
];
const Q_WORDS: &[Entry] = &[(b"ueer", 3)];
const R_WORDS: &[Entry] = &[];
const S_WORDS: &[Entry] = &[(b"crotum", 2), (b"hit", 3), (b"uck", 1)];
const T_WORDS: &[Entry] = &[(b"urd", 1), (b"wat", 1)];
const U_WORDS: &[Entry] = &[(b"rinat", 2), (b"rine", 1), (b"terus", 2)];
const V_WORDS: &[Entry] = &[(b"agina", 2), (b"ulva", 2)];
const W_WORDS: &[Entry] = &[(b"hore", 2)];
const X_WORDS: &[Entry] = &[];
const Y_WORDS: &[Entry] = &[];
const Z_WORDS: &[Entry] = &[];

/// `profList[26]`, `PROFAN.C:131-135` -- one dictionary per starting letter,
/// indexed the same way `profan_scan` indexes it: `list[(c - b'a') as usize]`.
const WORD_LISTS: [&[Entry]; 26] = [
    A_WORDS, B_WORDS, C_WORDS, D_WORDS, E_WORDS, F_WORDS, G_WORDS, H_WORDS, I_WORDS, J_WORDS,
    K_WORDS, L_WORDS, M_WORDS, N_WORDS, O_WORDS, P_WORDS, Q_WORDS, R_WORDS, S_WORDS, T_WORDS,
    U_WORDS, V_WORDS, W_WORDS, X_WORDS, Y_WORDS, Z_WORDS,
];

/// Does `text[start..]` spell `suffix`, case-insensitively, skipping any
/// byte that is not an ASCII letter as it goes, and refusing to cross a
/// space or the end of `text`?
///
/// This is [`profan`]'s own innermost loop (`PROFAN.C:153-163`), simplified
/// from a packed-array walk into a direct suffix match. The simplification
/// is provably identical, not merely plausible: the original's innermost
/// loop only ever leaves `profChar <= 3` (a "match" by the outer loop's own
/// `if (profChar <= 3)` test, `:164`) in exactly two cases --
///
/// 1. the source runs out (hits `'\0'` or `' '`) exactly when every suffix
///    letter has been consumed, so `profChar` was last set to the level byte
///    that immediately follows the suffix in the packed array; or
/// 2. the source has more letters after the suffix, the next comparison is
///    against that same already-consumed level byte (which no ASCII letter
///    can equal), and the loop **breaks** with `profChar` still holding it.
///
/// Both leave `profChar` at the level byte -- i.e. the real routine records
/// a match the instant the whole suffix is found, *regardless of what comes
/// after it* (this is the source of the well-known false-positive behaviour
/// these filters have -- `"banal"` flags on `"anal"`, `"analysis"` flags on
/// the same word). The only way to leave the innermost loop *without* a
/// match is a letter mismatch before the suffix is exhausted, or the source
/// running out first. That is exactly what this function decides, without
/// needing to reproduce the packed array's own index bookkeeping to get
/// there.
fn suffix_matches(text: &[u8], start: usize, suffix: &[u8]) -> bool {
    let mut si = 0;
    let mut j = start;
    while si < suffix.len() {
        let Some(&raw) = text.get(j) else {
            return false;
        };
        if raw == b' ' {
            return false;
        }
        let c = raw.to_ascii_lowercase();
        if !c.is_ascii_lowercase() {
            j += 1;
            continue;
        }
        if c != suffix[si] {
            return false;
        }
        si += 1;
        j += 1;
    }
    true
}

/// `profan()`'s scan (`PROFAN.C:140-177`), minus the one piece of state this
/// host has no observable use for -- see [`profan`]'s own doc comment.
///
/// The outer loop is `PROFAN.C:146-175`: **every byte position** in `text`
/// is tried as a possible word start, not merely the ones after a space.
/// That is measured from the source, not assumed -- `for (srcChar=src[0] ;
/// srcChar != '\0' ; srcChar=*(++src))` advances one byte at a time with no
/// word-boundary test at all, which is exactly what makes `"banal"` trip the
/// `a`-list's `"nal"` entry from its second letter. Reproduced here the same
/// way: `for i in 0..text.len()`, no boundary skip.
fn profan_scan(text: &[u8]) -> u8 {
    let mut level = 0u8;
    for i in 0..text.len() {
        let lowered = text[i].to_ascii_lowercase();
        if !lowered.is_ascii_lowercase() {
            continue;
        }
        let entries = WORD_LISTS[(lowered - b'a') as usize];
        for (suffix, entry_level) in entries {
            if *entry_level > level && suffix_matches(text, i + 1, suffix) {
                level = *entry_level;
            }
        }
    }
    level
}

/// `int profan(char *string)` -- `GCOMM.H:1116` (wg1) / `PROFAN.C:137-177`
/// (`re/wg33src/SRC/api/gcommlib/PROFAN.C`) -- "checks level of profanity in
/// string", answering 0-3.
///
/// Faithful. The one thing the real routine also does that this does not is
/// set the file-local `pfnptr` (`PROFAN.C:21`, `:167`) to point at the worst
/// match found -- Galacticomm's own `char *pfnptr` (`GCOMM.H:1107`), a
/// separate symbol from the `pfnlvl`/`pfceil` **host globals**
/// `crate::globals::GLOBALS` already places (`MAJORBBS.H:468-469`). `pfnptr`
/// itself is not one of those globals and `WCCMMUD.DLL` does not address it
/// (`docs/2026-08-14-majormud-missing-symbols.md`'s own count: "None of the
/// 31 are host globals"), so there is no module-observable behaviour left
/// out by not tracking it -- and `profan()` itself never writes `pfnlvl`/
/// `pfceil` either (that is `setpfn()`'s job, `MAJORBBS.H:712`, not on this
/// task's list). Nothing here needs a struct offset or an `Abi`-specific
/// width: one `char *` argument, one `int` answer.
pub fn profan<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let src = call.ptr();
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let level = profan_scan(text);
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(level))))
}

/// `void c2bcpy(char *dest, char *src, unsigned length)` -- `GCOMM.H:332`
/// (wg1) / `re/wg33src/SRC/api/gcommlib/C2BCPY.C:19-33` -- copy a
/// NUL-terminated C string into a fixed-width, space-padded field (the
/// convention `crates/mbbs/src/btrieve`'s own `CHAR` fields already use for
/// Btrieve records: no terminator, padded to the declared width).
///
///
/// Faithful. `length` is read at `A::Int`'s own width and widened into a
/// `usize` (`Into::<u32>::into(call.int()) as usize`) rather than narrowed
/// to `u16` -- the same widening `shims::text::strncpy`/`strncat` already
/// established for an unsigned length argument, chosen because `usize` on
/// every target this crate builds for cannot lose bits a `u32` held. A
/// `length` of 0 writes nothing, matching the real routine (both of its own
/// loops run zero times).
pub fn c2bcpy<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dest = call.ptr();
    let src = call.ptr();
    let length = Into::<u32>::into(call.int()) as usize;

    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let take = text.len().min(length);
    let mut out = text[..take].to_vec();
    out.resize(length, b' ');

    if length > 0 {
        dest.write(call.mem(), &out)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Void)
}

/// `void b2ccpy(char *dest, char *src, unsigned length)` -- `GCOMM.H:331`
/// (wg1) / `re/wg33src/SRC/api/gcommlib/B2CCPY.C:20-42` -- the other
/// direction from [`c2bcpy`]: trim a fixed-width, space-padded field down to
/// a NUL-terminated C string.
///
///
/// Faithful, including two details easy to miss on a re-read:
///
/// - **`length` here means "bytes to copy plus the trailing `'\0'`"**
///   (`B2CCPY.C:24`'s own comment) -- the opposite convention from
///   [`c2bcpy`]'s `length`. The scan only ever looks at `src`'s first
///   `length - 1` bytes (`i` runs `1..length`), which is what leaves room
///   for the one reserved terminator byte in every case. `length == 0`
///   touches `dest` not at all -- not even a terminator -- matching the
///   real routine's own `if (length > 0)` guard exactly.
/// - **The scan stops at the first embedded NUL**, same as the real
///   routine's `*src != '\0'` loop condition -- a VB field that happens to
///   contain a NUL short-circuits the trim there rather than treating the
///   rest as content.
///
/// What survives the trim is the whole **span** from the first non-space
/// byte to the last, copied verbatim -- interior whitespace inside that
/// span is preserved, only the outer run is stripped. The rest of `dest`,
/// from the end of that span through byte `length - 1`, is zero-filled
/// (`setmem(...,0)`), not merely NUL-terminated: a `dest` shorter than the
/// trimmed content overruns exactly where the real `movmem` would, refused
/// by [`mbbs_machine::ptr::ModulePtr::write`] rather than corrupting
/// neighbouring memory.
pub fn b2ccpy<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dest = call.ptr();
    let src = call.ptr();
    let length = Into::<u32>::into(call.int()) as usize;

    if length == 0 {
        return Ok(abi::Ret::Void);
    }

    let scan_len = length - 1;
    let bytes = src
        .resolve(call.mem(), scan_len)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let mut first: Option<usize> = None;
    let mut last: usize = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 {
            break;
        }
        // C's `isspace`, which `B2CCPY.C:31` calls here.
        // `crate::strings::is_white` *is* that set, derived from the
        // measured `_ctype` table -- this file used to carry a second,
        // byte-identical copy under its own name.
        if !crate::strings::is_white(b) {
            last = i;
            if first.is_none() {
                first = Some(i);
            }
        }
    }

    let mut out = vec![0u8; length];
    if let Some(start) = first {
        let movlen = last - start + 1;
        out[..movlen].copy_from_slice(&bytes[start..start + movlen]);
    }

    dest.write(call.mem(), &out)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `int findtvar(char *name)` -- `MAJORBBS.H:660` (wg1) /
/// `MAJORBBS.C:1296-1307` (wg1):
///
///
/// Faithful, and reuses rather than reimplements: [`crate::textvar::TextVars`]
/// is this host's own `txtvars`/`ntvars` (its own doc comment: "the module is
/// what says so" -- ten `WCCMMUD.DLL` sites address the table directly), so
/// this walks it through [`Host::textvars`]/[`crate::textvar::TextVars::get_mem`]
/// exactly as `register_textvar` (`crates/mbbs/src/shims/system.rs`) already
/// does to add a row, and compares each name with [`crate::strings::sameas`]
/// -- the same case-insensitive equality `MAJORBBS.C`'s own `sameas` call
/// makes, already ported for `samend`'s sake (`shims/mod.rs`'s own comment
/// next to that registration).
///
/// Not found answers `-1` ([`super::NO`]), the same "absence is a truth the
/// module is entitled to" convention `super::NO`'s own doc comment sets out.
pub fn findtvar<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name_ptr = call.ptr();
    let name = name_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    for i in 0..host.textvars().len() {
        if let Some(row) = host.textvars().get_mem(call.mem(), i)? {
            if sameas(&name, row.name.as_bytes()) {
                return Ok(abi::Ret::Int(A::int_from_u32(u32::from(i))));
            }
        }
    }
    // Not found is `-1` at `A`'s own width, not at 16 bits. `A::Int::from(NO)`
    // zero-extends the `u16` `0xffff`, which is `-1` under `Wg16` but `65535`
    // under `Wg32` (see `Abi::int_from_u32`'s doc). The 32-bit module tests the
    // result with `cmp eax, 0xffffffff`; handed `65535` it misses that guard
    // and indexes `txtvars[65535*20+0x10]`, far past the table, then calls the
    // null `varrou` it reads there -- a SIGSEGV at 0x0 on the Realm-exit
    // `PAUSE_FU`/`FU_PAUSE` expansion. This is the same trap `toupper(EOF)`
    // documents in `shims::text`.
    Ok(abi::Ret::Int(A::int_from_u32(u32::MAX)))
}

/// The byte that opens and closes a text-variable reference in a buffer
/// `xlttxv` walks: `if (*ptr == 1)` (`MENUING.C:1131`).
const TXV_ESCAPE: u8 = 1;

/// How much headroom an expansion needs before `xlttxv` will attempt one:
/// `strlen(buffer)+80 < size` (`MENUING.C:1131`).
///
/// 80 rather than the variable's own length because the expansion happens in
/// place and `grbtxv` pads to a field width it has not read yet -- `len > 79`
/// is the widest it will accept (`MENUING.C:1195`), so 80 bounds any single
/// expansion.
const TXV_HEADROOM: usize = 80;

/// `CHAR *xlttxv(CHAR *buffer, INT size)` -- `MENUING.C:1120-1141` -- expand
/// the text variables in a buffer, in place.
///
///
/// Byte `0x01` opens a reference; the sequence is
/// `\x01 <justify> <width+32> <name> \x01` (read off `grbtxv`,
/// `MENUING.C:1179-1245`). Three of the four things this routine does need
/// nothing this host lacks, and it does them:
///
/// - **A buffer with no `0x01` in it is returned unchanged**, and the pointer
///   answered is the argument itself. That is the overwhelmingly common case
///   and it is now fully served.
/// - **Too little headroom truncates at the escape.** `*ptr='\0'` and break:
///   the reference is not expanded and everything from it onward is
///   discarded. This branch never reaches `grbtxv` at all.
/// - **An unresolvable reference is deleted**, not expanded. `grbtxv` answers
///   0 after `movmem`ing the tail down over the whole sequence when the width
///   exceeds 79, the justification is not one of `R`/`L`/`C`/`N`, or
///   `findtvar` does not know the name (`MENUING.C:1194-1198`). A reference
///   with no closing `0x01` truncates the buffer instead
///   (`MENUING.C:1187-1191`).
///
/// **What it cannot do is expand a reference that resolves.** `grbtxv` calls
/// the variable's own routine -- `txtptr=(*(txtvars[num].varrou))()` --
/// which is module code. This host stores `varrou`
/// ([`crate::textvar::TextVar`]) but a shim has no way to re-enter the
/// module: `Call<A>` hands out `A::Mem`, not the `Machine`, and the one place
/// this crate does call back (`fsdprc`'s `machine.call(fldvfy, ..)`) is the
/// host's own dispatch loop, not a shim. So a *registered* variable is a
/// refusal that names what is missing, rather than an expansion invented
/// here or a silent deletion that would look like the "unknown name" branch
/// and lie about it.
///
/// # Errors
///
/// If `buffer` is unreadable or unterminated, if the expanded buffer will not
/// fit back where it came from, or if a reference names a text variable that
/// is actually registered -- see above.
pub fn xlttxv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let buffer = call.ptr();
    // `INT size` is a buffer size and no caller has a negative one. The
    // vendor's compare is signed, so the only input on which this differs is
    // a negative `size`, where it would take the truncate branch.
    let size = Into::<u32>::into(call.int()) as usize;

    let mut text = buffer
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("xlttxv: {e}")))?
        .to_vec();

    let mut pos = 0usize;
    while pos < text.len() {
        if text[pos] != TXV_ESCAPE {
            pos += 1;
            continue;
        }
        if text.len() + TXV_HEADROOM < size {
            pos += grbtxv(&mut text, pos, host, call.mem())?;
        } else {
            // `*ptr='\0'; break;` -- the reference and everything after it go.
            text.truncate(pos);
            break;
        }
    }

    text.push(0);
    buffer
        .write(call.mem(), &text)
        .map_err(|e| ShimError::Failed(format!("xlttxv: {e}")))?;
    Ok(abi::Ret::Ptr(buffer))
}

/// `INT grbtxv(CHAR *buffer)` -- `MENUING.C:1178-1246` -- resolve the one
/// text-variable reference at `text[pos]`, and answer how far `xlttxv` should
/// advance.
///
/// Only the branches that answer `0` are reachable here; the expanding branch
/// needs to call module code. See [`xlttxv`]'s doc comment for why, and for
/// what each `0` case means.
///
/// The vendor reads `buffer[pos+1]` and `buffer[pos+2]` before it has checked
/// that either is inside the string, so a `0x01` in the last two bytes sends
/// it reading past the terminator. Here a reference that cannot hold a
/// header is treated as one with no closing escape -- the truncation the
/// vendor's own scan reaches on that input anyway, without the read past the
/// end.
fn grbtxv<A: Abi>(
    text: &mut Vec<u8>,
    pos: usize,
    host: &mut Host<A>,
    mem: &A::Mem,
) -> Result<usize, ShimError> {
    // `\x01 <justify> <width+32> <name> \x01`: the header is three bytes and
    // the name is at least one.
    let name_at = pos + 3;
    let close = text
        .get(name_at..)
        .and_then(|rest| rest.iter().position(|&b| b == TXV_ESCAPE))
        .map(|i| name_at + i);
    let Some(close) = close else {
        // `buffer[pos-3]='\0'; return(0);` -- no closing escape, so the
        // buffer ends at the one that opened it.
        text.truncate(pos);
        return Ok(0);
    };

    let justify = text[pos + 1].to_ascii_uppercase();
    let width = i16::from(text[pos + 2]) - 32;
    let name = text[name_at..close].to_vec();

    let known = width <= 79
        && matches!(justify, b'R' | b'L' | b'C' | b'N')
        && find_textvar(host, mem, &name)?.is_some();

    if !known {
        // `movmem(ptr+1,&buffer[pos-3],strlen(ptr+1)+1); return(0);` -- the
        // whole reference is spliced out and the tail closes up over it.
        text.drain(pos..=close);
        return Ok(0);
    }

    Err(ShimError::Failed(format!(
        "grbtxv: expanding the text variable {:?} means calling its varrou, \
         and a shim cannot re-enter the module -- Call hands out memory, not \
         the Machine, and this crate's only callback (fsdprc's \
         machine.call(fldvfy, ..)) is the host's dispatch loop rather than a \
         shim",
        String::from_utf8_lossy(&name)
    )))
}

/// `findtvar`'s answer, for a name this crate already holds as bytes.
///
/// The same walk [`findtvar`] makes, factored out so the shim and [`grbtxv`]
/// cannot disagree about what "registered" means.
fn find_textvar<A: Abi>(
    host: &mut Host<A>,
    mem: &A::Mem,
    name: &[u8],
) -> Result<Option<u16>, ShimError> {
    for i in 0..host.textvars().len() {
        if let Some(row) = host.textvars().get_mem(mem, i)? {
            if sameas(name, row.name.as_bytes()) {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shims::system::register_textvar;
    use crate::testing::Fixture;
    use mbbs_machine::m16::{FarPtr, Ret};

    // -- profan -----------------------------------------------------------

    #[test]
    fn profan_finds_nothing_in_a_clean_word() {
        let mut f = Fixture::new();
        let src = f.text("hello there");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(0));
    }

    #[test]
    fn profan_matches_a_level_three_word() {
        let mut f = Fixture::new();
        let src = f.text("you are an asshole");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(3));
    }

    #[test]
    fn profan_is_case_insensitive() {
        let mut f = Fixture::new();
        let src = f.text("ASSHOLE");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(3));
    }

    /// The measured false-positive behaviour: the scan tries every byte
    /// position, not just word starts, so `"banal"` trips the `a`-list's
    /// `"nal"` entry from its second letter. See [`profan_scan`]'s own doc
    /// comment.
    #[test]
    fn profan_flags_a_word_that_merely_contains_one_starting_mid_word() {
        let mut f = Fixture::new();
        let src = f.text("banal");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(1));
    }

    /// Non-letter bytes inside a word are skipped, not treated as a
    /// mismatch -- `PROFAN.C`'s own innermost loop `continue`s over them.
    #[test]
    fn profan_skips_punctuation_in_the_middle_of_a_match() {
        let mut f = Fixture::new();
        let src = f.text("a-nal");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(1));
    }

    #[test]
    fn profan_does_not_match_a_word_too_short_to_finish_the_suffix() {
        let mut f = Fixture::new();
        let src = f.text("an");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(0));
    }

    #[test]
    fn profan_reports_the_worst_of_several_matches() {
        let mut f = Fixture::new();
        // "ass" (a-list, level 1) and "shit" (s-list, level 3) both appear.
        let src = f.text("ass shit");
        assert_eq!(f.invoke(profan, &[src.offset, src.selector]).expect("ok"), Ret::U16(3));
    }

    // -- c2bcpy -----------------------------------------------------------

    #[test]
    fn c2bcpy_pads_a_short_string_with_spaces() {
        let mut f = Fixture::new();
        let dest = f.bytes(&[b'#'; 5], false);
        let src = f.text("hi");
        f.invoke(c2bcpy, &[dest.offset, dest.selector, src.offset, src.selector, 5])
            .expect("c2bcpy");
        assert_eq!(f.machine.resolve(dest, 5).expect("readable"), b"hi   ");
    }

    #[test]
    fn c2bcpy_truncates_a_string_longer_than_the_field() {
        let mut f = Fixture::new();
        let dest = f.bytes(&[b'#'; 3], false);
        let src = f.text("hello world");
        f.invoke(c2bcpy, &[dest.offset, dest.selector, src.offset, src.selector, 3])
            .expect("c2bcpy");
        assert_eq!(f.machine.resolve(dest, 3).expect("readable"), b"hel");
    }

    #[test]
    fn c2bcpy_of_zero_length_touches_nothing() {
        let mut f = Fixture::new();
        let dest = f.bytes(&[b'#'; 3], false);
        let src = f.text("hi");
        f.invoke(c2bcpy, &[dest.offset, dest.selector, src.offset, src.selector, 0])
            .expect("c2bcpy");
        assert_eq!(f.machine.resolve(dest, 3).expect("readable"), b"###");
    }

    // -- b2ccpy -----------------------------------------------------------

    #[test]
    fn b2ccpy_trims_leading_and_trailing_spaces_and_zero_pads_the_rest() {
        let mut f = Fixture::new();
        let src = f.bytes(b"  hi  ", false);
        let dest = f.bytes(&[0xffu8; 7], false);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 7])
            .expect("b2ccpy");
        assert_eq!(
            f.machine.resolve(dest, 7).expect("readable"),
            b"hi\0\0\0\0\0"
        );
    }

    #[test]
    fn b2ccpy_preserves_interior_whitespace_within_the_trimmed_span() {
        let mut f = Fixture::new();
        let src = f.bytes(b" a b ", false);
        let dest = f.bytes(&[0xffu8; 6], false);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 6])
            .expect("b2ccpy");
        assert_eq!(f.machine.resolve(dest, 6).expect("readable"), b"a b\0\0\0");
    }

    #[test]
    fn b2ccpy_of_an_all_space_field_zero_fills_the_whole_dest() {
        let mut f = Fixture::new();
        let src = f.bytes(b"     ", false);
        let dest = f.bytes(&[0xffu8; 6], false);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 6])
            .expect("b2ccpy");
        assert_eq!(f.machine.resolve(dest, 6).expect("readable"), &[0u8; 6]);
    }

    #[test]
    fn b2ccpy_of_zero_length_touches_dest_not_at_all() {
        let mut f = Fixture::new();
        let src = f.bytes(b"hi", false);
        let dest = f.bytes(&[0xffu8; 4], false);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 0])
            .expect("b2ccpy");
        assert_eq!(f.machine.resolve(dest, 4).expect("readable"), &[0xffu8; 4]);
    }

    #[test]
    fn b2ccpy_stops_scanning_at_an_embedded_nul() {
        let mut f = Fixture::new();
        let src = f.bytes(b"ab\0cd", false);
        let dest = f.bytes(&[0xffu8; 10], false);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 10])
            .expect("b2ccpy");
        assert_eq!(
            f.machine.resolve(dest, 10).expect("readable"),
            b"ab\0\0\0\0\0\0\0\0"
        );
    }

    // -- findtvar -----------------------------------------------------------

    #[test]
    fn findtvar_finds_a_registered_name_case_insensitively() {
        let mut f = Fixture::new();
        // The host's own standard suite (`shims::txtvbl`) is already in the
        // table; module registrations land after it.
        let base = f.host.textvars().len();
        let name = f.text("MUDCHARINFO");
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };
        f.invoke(register_textvar, &[name.offset, name.selector, varrou.offset, varrou.selector])
            .expect("registered");

        let query = f.text("mudcharinfo");
        assert_eq!(
            f.invoke(findtvar, &[query.offset, query.selector]).expect("ok"),
            Ret::U16(base)
        );
    }

    #[test]
    fn findtvar_finds_the_second_of_two_by_the_right_index() {
        let mut f = Fixture::new();
        let base = f.host.textvars().len();
        let first = f.text("ONE");
        let second = f.text("TWO");
        let varrou = FarPtr {
            offset: 0x0010,
            selector: f.machine.code_selector(),
        };
        f.invoke(register_textvar, &[first.offset, first.selector, varrou.offset, varrou.selector])
            .expect("registered");
        f.invoke(register_textvar, &[second.offset, second.selector, varrou.offset, varrou.selector])
            .expect("registered");

        let query = f.text("TWO");
        assert_eq!(
            f.invoke(findtvar, &[query.offset, query.selector]).expect("ok"),
            Ret::U16(base + 1)
        );
    }

    // -- xlttxv ------------------------------------------------------------

    /// A reference to `name`, laid out the way `grbtxv` reads one:
    /// `\x01 <justify> <width+32> <name> \x01` (`MENUING.C:1183-1186`).
    fn reference(justify: u8, width: u8, name: &str) -> Vec<u8> {
        let mut out = vec![TXV_ESCAPE, justify, width + 32];
        out.extend_from_slice(name.as_bytes());
        out.push(TXV_ESCAPE);
        out
    }

    /// A buffer holding no `0x01` comes back byte-for-byte, and the pointer
    /// answered is the argument -- callers use the return value directly
    /// (`MENUING.C:1140`, `return(buffer)`).
    ///
    /// This is the case nearly every call is, so it is the one that decides
    /// whether the routine is worth serving at all.
    #[test]
    fn xlttxv_returns_a_buffer_with_no_references_unchanged() {
        let mut f = Fixture::new();
        let buf = f.buffer(256);
        f.machine.write(buf, b"Newhaven Narrow Road\0").expect("seed");

        assert_eq!(
            f.invoke(xlttxv, &[buf.offset, buf.selector, 256]).expect("xlttxv"),
            Ret::Far(buf),
            "the argument comes back, not a copy"
        );
        assert_eq!(f.machine.read_cstr(buf).expect("readable"), b"Newhaven Narrow Road");
    }

    /// Too little headroom truncates **at the escape** rather than expanding.
    ///
    /// `strlen(buffer)+80 < size` is the guard (`MENUING.C:1131`); when it
    /// fails the vendor writes `*ptr='\0'` and breaks, so the reference and
    /// everything after it are gone. A port that dropped the guard would
    /// expand here instead, and this is the assertion that says so.
    #[test]
    fn xlttxv_truncates_at_a_reference_it_has_no_headroom_to_expand() {
        let mut f = Fixture::new();
        let buf = f.buffer(256);
        let mut text = b"before".to_vec();
        text.extend_from_slice(&reference(b'L', 10, "MUDCHARINFO"));
        text.extend_from_slice(b"after");
        text.push(0);
        f.machine.write(buf, &text).expect("seed");

        // size 40: strlen is 22, and 22 + 80 is not less than 40.
        f.invoke(xlttxv, &[buf.offset, buf.selector, 40]).expect("xlttxv");
        assert_eq!(
            f.machine.read_cstr(buf).expect("readable"),
            b"before",
            "the reference and the text after it are discarded"
        );
    }

    /// A reference to a name nobody registered is **deleted**, and the text
    /// around it closes up over it (`MENUING.C:1194-1198`).
    ///
    /// Not left in place and not expanded: `grbtxv` `movmem`s the tail down
    /// over the whole sequence and answers 0, so `xlttxv` re-examines the
    /// byte that has moved into its place and carries on.
    #[test]
    fn xlttxv_deletes_a_reference_to_a_name_that_is_not_registered() {
        let mut f = Fixture::new();
        let buf = f.buffer(256);
        let mut text = b"before ".to_vec();
        text.extend_from_slice(&reference(b'L', 10, "NOSUCHVAR"));
        text.extend_from_slice(b" after");
        text.push(0);
        f.machine.write(buf, &text).expect("seed");

        f.invoke(xlttxv, &[buf.offset, buf.selector, 256]).expect("xlttxv");
        assert_eq!(f.machine.read_cstr(buf).expect("readable"), b"before  after");
    }

    /// A justification that is not `R`, `L`, `C` or `N` takes the same
    /// deletion branch even when the name *is* registered
    /// (`MENUING.C:1194-1195`), so the check is on the whole condition rather
    /// than only on the lookup.
    #[test]
    fn xlttxv_deletes_a_reference_whose_justification_is_not_one_of_the_four() {
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");
        let varrou = FarPtr { offset: 0x0010, selector: f.machine.code_selector() };
        f.invoke(register_textvar, &[name.offset, name.selector, varrou.offset, varrou.selector])
            .expect("registered");

        let buf = f.buffer(256);
        let mut text = b"x".to_vec();
        text.extend_from_slice(&reference(b'Q', 10, "MUDCHARINFO"));
        text.extend_from_slice(b"y");
        text.push(0);
        f.machine.write(buf, &text).expect("seed");

        f.invoke(xlttxv, &[buf.offset, buf.selector, 256]).expect("xlttxv");
        assert_eq!(f.machine.read_cstr(buf).expect("readable"), b"xy");
    }

    /// A reference with no closing `0x01` ends the buffer where it started
    /// (`MENUING.C:1187-1191`).
    #[test]
    fn xlttxv_truncates_a_reference_that_is_never_closed() {
        let mut f = Fixture::new();
        let buf = f.buffer(256);
        let mut text = b"keep".to_vec();
        text.extend_from_slice(&[TXV_ESCAPE, b'L', 10 + 32]);
        text.extend_from_slice(b"UNCLOSED");
        text.push(0);
        f.machine.write(buf, &text).expect("seed");

        f.invoke(xlttxv, &[buf.offset, buf.selector, 256]).expect("xlttxv");
        assert_eq!(f.machine.read_cstr(buf).expect("readable"), b"keep");
    }

    /// A reference that **resolves** is refused, naming what is missing.
    ///
    /// This is the one branch this host cannot serve: `grbtxv` calls
    /// `(*(txtvars[num].varrou))()`, which is module code, and a shim has no
    /// way back into the module. The refusal has to be distinguishable from
    /// the unknown-name deletion above -- silently deleting a variable the
    /// module registered would look like success and lose the text.
    #[test]
    fn xlttxv_refuses_a_reference_it_would_have_to_call_the_module_to_expand() {
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");
        let varrou = FarPtr { offset: 0x0010, selector: f.machine.code_selector() };
        f.invoke(register_textvar, &[name.offset, name.selector, varrou.offset, varrou.selector])
            .expect("registered");

        let buf = f.buffer(256);
        let mut text = b"hp: ".to_vec();
        text.extend_from_slice(&reference(b'L', 10, "MUDCHARINFO"));
        text.push(0);
        f.machine.write(buf, &text).expect("seed");

        let err = f
            .invoke(xlttxv, &[buf.offset, buf.selector, 256])
            .expect_err("a registered variable needs its varrou");
        let message = err.to_string();
        assert!(message.contains("varrou"), "{message}");
        assert!(message.contains("MUDCHARINFO"), "{message}");
    }

    #[test]
    fn findtvar_of_an_unregistered_name_answers_negative_one() {
        let mut f = Fixture::new();
        let query = f.text("NOSUCHVAR");
        assert_eq!(
            f.invoke(findtvar, &[query.offset, query.selector]).expect("ok"),
            Ret::U16(super::super::NO)
        );
    }

}
