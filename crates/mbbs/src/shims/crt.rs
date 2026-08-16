//! Borland's C runtime, re-exported by `MAJORBBS.DLL`, plus one of
//! Galacticomm's own (`samend`).
//!
//! ```text
//! _FWRITE           size_t   fwrite(void *ptr, size_t size, size_t nitems, FILE *stream)
//! _ITOA              char *  itoa(int value, char *string, int radix)
//! __LOCALECONVENTION struct lconv *  -- DATA in the real DLL; see `localeconvention`'s own doc
//! _SAMEND               int  samend(char *longs, char *ends)
//! _STRICMP               int  stricmp(const char *s1, const char *s2)
//! _ULTOA              char *  ultoa(unsigned long value, char *string, int radix)
//! _UNGETC                int  ungetc(int c, FILE *stream)
//! _RENAME                int  rename(const char *oldname, const char *newname)
//! _GETENV              char *  getenv(const char *name)
//! _GETTIME               void gettime(struct time *t)
//! __DOSERROR              int  doserror -- `_doserror` (Task 7)
//! ___ERRNO              int *  errno -- `__errno` (Task 7)
//! __LRAND                long lrand(void) -- `_lrand` (Task 7)
//! _SEARCHPATH           char *  searchpath(const char *file)
//! _SETMODE                int  setmode(int handle, int amode)
//! _READ                   int  read(int handle, void *buf, unsigned len)
//! _WRITE                  int  write(int handle, const void *buf, unsigned len)
//! ```
//!
//! # Where each was found
//!
//! `fwrite`, `itoa`, `stricmp`, `ultoa`, `ungetc`, `rename`, `getenv`,
//! `gettime`, `searchpath`, `setmode`, `read` and `write` are Borland's, from
//! `archive/tooling/compilers/bc452.zip` -- the same zip [`crate::stream`]'s
//! own module doc already cites as this host's oracle for Borland runtime
//! behaviour ("everything here is measured against Borland's own runtime...
//! the module was linked against the source"). `SAMEND.C` is Galacticomm's
//! own, and unlike the module SDK sources under
//! `archive/galacticomm/extract/wg1/GALDSRC` (which only *declare* it in
//! `GCOMM.H`, matching every module that calls it), its body survives
//! complete in `re/wg33src/SRC/api/gcommlib/` -- the Worldgroup 3.3 recovered
//! source tree, cited by exact path below rather than by line number into
//! `GALDSRC`, per this repo's own rule that a citation into the wrong
//! Galacticomm tree is silently wrong rather than merely imprecise.
//!
//! `doserror` and `errno` are `__DOSerror`/`__errno`,
//! `SOURCE/RTL/SOURCE/IO/COMMON16/IOERROR.CAS` and
//! `SOURCE/RTL/SOURCE/MISC/COMMON32/ERRNO.C` in the same zip -- Borland's own
//! internal accessors for a DLL's per-thread error state, not the plain
//! `extern int errno;` global `INCLUDE/ERRNO.H`'s non-`_MT`, non-`_RTLDLL`
//! branch declares (that variant is `_ERRNO`, ordinal 1064 in
//! `archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF`, and nothing
//! in the ten surveyed builds imports it). `lrand` has no surviving Borland
//! source anywhere in `bc452.zip`, `bc501.zip` or `tc201.zip`, and no ordinal
//! in wg1's own `MAJORBBS.DEF` either -- see [`lrand`]'s own doc comment for
//! what stands in for it and why.
//!
//! # The underscore count on each is measured, not assumed
//!
//! `archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF` gives the
//! *exported* linkage name for the Borland-runtime members above (`_GETENV`,
//! `_GETTIME`, `_RENAME`, `_STRICMP`, `_ULTOA`, `_UNGETC`, `_SETMODE`,
//! `__DOSERROR`, `_ERRNO`) directly -- one leading underscore for the public
//! C name, two for `__DOSERROR`, which sits among a cluster of unmistakably
//! internal RTL helpers (`__OPEN`, `__READ`, `__CLOSE`, `__CREAT`) rather than
//! the public-API block the singly-underscored names live in further down the
//! file. `doserror`/`errno`/`lrand` needed a second check because the DEF
//! file is `wg1`-vintage (pre-dates the DLL versions these NE/PE builds
//! actually link against) and does not carry `errno`'s or `lrand`'s `_MT`
//! variant at all: `tmp/gapsurvey/round2/rose32/RCIROSE.DLL`'s own raw import
//! strings, read directly off the PE import table rather than through any
//! script, are `___errno` and `__lrand` -- three and two leading underscores
//! respectively. `exports::c_name` (and its Python mirror,
//! `re/importgaps.py::c_name`) strips exactly one, which is why
//! `tmp/srcaudit/missing49.txt` -- itself already post-`c_name`, confirmed by
//! reading `re/importgaps.py`'s own extraction code -- lists them as
//! `__errno` (two) and `_lrand` (one). Those are this file's registration
//! keys, not `_errno`/`__lrand`.
//!
//! # `setmode`/`read`/`write` needed one `Host<A>` field, granted mid-task
//!
//! All three need somewhere to keep a handle's text/binary mode between
//! calls. The natural design ties a `read`/`write` handle to the exact open
//! file [`crate::stream::Streams`] already tracks -- a module that `fopen`s
//! a stream and reads `fileno(fp)` (a macro over `FILE.fd`, so it leaves no
//! import record: `tmp/gapsurvey/round2/rose32/RCIROSE.DLL` imports `read`
//! and `write` but never `fileno`, `open` or `creat`) is naming exactly the
//! `fd` `Streams::open_mem` already assigned. Reusing that identity would
//! need `Streams` to answer "which cookie does this `fd` name", and its
//! `fd`/`open` fields are private to `stream.rs`, so even the granted
//! `Host<A>` field cannot reach them without `stream.rs` also growing a new
//! `pub(crate)` accessor -- a second file this task's grant still does not
//! cover. `Host::stdio_modes`'s own doc comment has the rest of this
//! reasoning; the short version is that the new field covers only DOS's five
//! pre-opened standard handles (`0..=4`), which `Streams` structurally never
//! assigns (`FIRST_FD = 5`), so there is no shared identity for a second
//! table to diverge from.
//!
//! # `__errno` and `_doserror` land on a narrower version of the same gap
//!
//! Both would benefit from a persistent per-host `errno`/`_doserrno` cell
//! for full fidelity (so a module's `_doserror(code)` is visible to a later
//! `errno` read), but neither *needs* one: `__DOSerror` returns the DOS
//! error code it was given, unchanged (`IOERROR.CAS`'s own doc comment:
//! "returns dosErr"), and `__errno` only has to answer a valid, writable
//! pointer to an `int` -- not one that survives to the next call. Both
//! routines' doc comments below name this gap explicitly, the same way
//! [`localeconvention`]'s own doc comment already discloses that its answer
//! does not survive either, for a related "no address to anchor it at"
//! reason. Not folded into `stdio_modes`: `errno` is thread-global state in
//! the real RTL, not a property of any one handle, and forcing it into a
//! per-handle table would be a second fiction on top of the first.
//!
//! # `stream.rs` said some of these were "genuinely absent"
//!
//! [`crate::shims::stream`]'s own module doc: "`fwrite`, `fputs`, `fputc`,
//! `fscanf`, `fgetc`, `getc` and `ungetc` are still genuinely absent: no
//! import census, `WCCMMUD.DLL`'s or LunatiX's, has ever asked for any of
//! them." That census is now out of date for `ungetc`, landed below -- the
//! same correction that file's own module doc already made once for
//! `fseek`/`ftell`/`rewind`, against the same import list
//! (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`). Fixing that
//! sentence is out of scope here (it means editing `stream.rs`, which this
//! file's own task does not); it is flagged so nobody reads it as still true.
//!
//! # `_fgetc` is a registration, not a body: RTSLORD's `__fgetc` is `_fgetc`'s own contract
//!
//! RTSLORD imports `__fgetc` (double underscore), which `c_name` normalises
//! to `_fgetc` -- a different registration key from the `fgetc` this host
//! already serves (`(MAJORBBS, "fgetc", stream::fgetc, ...)`,
//! `shims/mod.rs:438`) for the single-underscore `_FGETC` LunatiX imports.
//! **They are the same underlying behaviour, not two symbols that happen to
//! collide.** `SOURCE/RTL/SOURCE/IO/COMMON16/GETC.CAS`'s own doc comment for
//! Borland's `_fgetc` (the C-source name; the object file carries Borland's
//! own added underscore, `__fgetc`, matching `MAJORBBS.DEF`'s `__FGETC @19`
//! sitting in the same internal-RTL-helper cluster `__DOSERROR` does):
//! "this function is only called by the `getc()` macro. The only purpose for
//! this is to increment the level indicator before calling `fgetc()`." Its
//! entire body is `{ ++fp->level; return(fgetc(fp)); }`.
//!
//! **The `++fp->level` is a real side effect, deliberately not reproduced.**
//! `level` is Borland's own read-ahead-buffer counter inside `FILE`
//! (`GETC.CAS`'s own `_ffill`: `fp->level = __read(...)`, decremented by the
//! `getc()` macro's fast path on every buffered byte) -- state internal to a
//! buffering scheme this crate's own [`crate::stream::Streams`] does not
//! have at all (`Streams::read_mem` goes straight to the file, no read-ahead
//! count to keep current). No module can observe `level` directly -- it is
//! not part of any documented `FILE` field a program is meant to read -- and
//! the only routine that *reads* it back (the `getc()` macro's own
//! fast-path branch) is itself invisible to this host for the identical
//! reason `fileno`/`feof`/`ferror` are (this file's own module doc, and
//! `stream.rs`'s: macros compile to direct `FILE` reads and leave no import
//! this host is ever asked to serve). So the two routines' behaviour is
//! identical on every axis a module compiled against this host's own
//! [`crate::stream`] model could check, and this is recorded here rather
//! than left for the next person to rediscover and wonder whether it was
//! missed.
//!
//! An earlier pass at this file wrote a **second, unregistered** body for
//! this behaviour (`crt::fgetc`, doc-commented "Registers as `_fgetc`" --
//! self-contradictory on its own terms, since stripping one leading
//! underscore from the `_FGETC` it cited turns *out* `fgetc`, not `_fgetc`).
//! `mod.rs` never referenced it (confirmed: `grep -n 'crt::' shims/mod.rs`
//! finds only `fwrite`/`itoa`/`samend`/`_localeconvention`), so it was dead
//! code duplicating [`crate::shims::stream::fgetc`] byte for byte -- the
//! exact hazard this crate's own "one implementation per symbol" rule exists
//! to prevent, not a second implementation to keep. Removed rather than
//! wired up; the integrator registers `_fgetc` against the existing
//! `stream::fgetc` body instead (see this file's own commit message).
//!
//! # Two more of the same shape, found and also removed
//!
//! `crt::fputc` and `crt::mdfgets` were *also* complete, unregistered,
//! byte-for-byte duplicates of [`crate::shims::stream::fputc`] and
//! [`crate::shims::user::mdfgets`] (the two `mod.rs` actually wires up for
//! `fputc`/`mdfgets`) -- the identical `crt::fgetc` situation, on symbols no
//! task originally asked this file to touch. This is the fourth and fifth
//! dead duplicate found in this repo in one day (a `hrtval` in `mudmisc.rs`
//! computing the wrong tick rate, and `crt::fgetc`, both found and removed
//! earlier the same session) -- cheap enough to remove once the pattern was
//! established that leaving them for a "later session" would only have
//! meant paying to rediscover them. Removed along with their tests; neither
//! had a live registration to update.
//!
//! What remains is placed in this file rather than `stream.rs`/`text.rs`
//! because the tasks that produced it said to, not because it belongs to a
//! different subsystem -- most of it shares [`crate::stream::Streams`] with
//! every routine `stream.rs` already has, and reads that file's types
//! (`Mode::writable`, `Streams::seek_mem`/`tell` for `ungetc`) directly.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::fmt::{Spec, integer};
use crate::shims::{ShimError, sign_extend};
use crate::stream::Whence;

/// `size_t fwrite(void *ptr, size_t size, size_t nitems, FILE *stream)` --
/// append `nitems` items of `size` bytes each.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/FWRITE.C` is Borland's, the huge-model
/// build (`#if (LDATA)`) this crate's modules are linked against, per
/// `stream.rs`'s own module doc. Its doc comment: "each function returns the
/// number of items (not bytes)... fwrite returns a short count on error" --
/// matching [`crate::shims::stream::fprintf`]'s own note that a write's
/// answer counts what the module asked for, not what physically reached the
/// disk.
///
/// # A `size` of zero is not the same refusal as a `nitems` of zero
///
/// `FWRITE.C:62`: `if( !psize ) return( nitems );` -- writes nothing and
/// still answers whatever `nitems` was, even a large one. That is
/// deliberately **not** [`crate::shims::stream::fread`]'s own rule (`if size
/// == 0 || count == 0 { return 0 }`) -- the two routines disagree in the
/// vendor source itself, not by a mistake copied from one into the other, so
/// this keeps `size == 0`'s early return ahead of the `nitems == 0` case
/// exactly the way `FWRITE.C` orders them.
///
/// # The overflow ceiling is [`fread`](crate::shims::stream::fread)'s own
///
/// `size * nitems` overflowing the size_t behind it is the same silent-wrap
/// hazard `fread`'s own doc comment measures ("a `size_t` that cannot count
/// the product is a wrap, and a wrap reads the wrong amount... nothing
/// downstream could notice") -- for a write, a wrapped count sends the
/// module's own memory past what it meant to publish. The ceiling is
/// `fread`'s own formula, at `A`'s width rather than 16 bits.
///
/// # What this does not reproduce
///
/// [`crate::stream::Streams::write`] is all-or-nothing (`File::write_all`),
/// so a write this host cannot complete is a refusal
/// (`ShimError::Failed`), never the "short count on error" `FWRITE.C`'s own
/// doc promises -- the same choice already made for `fputc` immediately
/// above, and for [`crate::shims::stream::fprintf`] and
/// [`crate::shims::stream::fflush`] before it.
///
/// Registers as `_fwrite`.
pub fn fwrite<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `size_t fwrite(void *ptr, size_t size, size_t nitems, FILE *stream)` --
    // Borland's; no Galacticomm header redeclares it.
    let buffer = call.ptr();
    let size: u32 = call.int().into();
    let nitems: u32 = call.int().into();
    let cookie = call.ptr();

    // `FWRITE.C:62` -- `if( !psize ) return( nitems );`. Checked first,
    // ahead of `nitems == 0`, because that is the vendor's own order and the
    // two answers differ (`nitems`, not `0`).
    if size == 0 {
        return Ok(abi::Ret::Int(A::int_from_u32(nitems)));
    }
    if nitems == 0 {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    // The same ceiling `fread` checks against, at `A`'s own width -- see
    // this routine's own doc comment.
    let ceiling = u64::from(u32::MAX) >> (32 - A::INT_WIDTH * 8);
    let want = u64::from(size) * u64::from(nitems);
    if want > ceiling {
        return Err(ShimError::Failed(format!(
            "fwrite of {nitems} items of {size} bytes, which a {}-bit size_t cannot count",
            A::INT_WIDTH * 8
        )));
    }
    let want = want as u32;

    let bytes = buffer
        .resolve(call.mem(), want as usize)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.streams
        .write(cookie, &bytes)
        .map_err(|e| ShimError::Failed(format!("fwrite: {e}")))?;
    // All-or-nothing on this host (see this routine's own doc comment), so a
    // success is always the full item count.
    Ok(abi::Ret::Int(A::int_from_u32(nitems)))
}

/// `char *itoa(int value, char *string, int radix)` -- a signed integer,
/// rendered in `radix` (2..=36) into the caller's own buffer.
///
/// # `ITOA.C` itself does not survive extraction
///
/// `archive/tooling/compilers/bc452.zip` has no `ITOA.C`/`ITOA.CAS` anywhere
/// under `SOURCE/` (checked by name, case-insensitively, over the archive's
/// full file listing) -- only `INCLUDE/STDLIB.H:215`'s prototype and
/// `SOURCE/RTL/SOURCE/MATH/COMMON16/LONGTOA.CAS`'s `__longtoa`, the shared
/// assembly core `itoa`/`ltoa`/`ultoa` are all documented as building on
/// (`LONGTOA.CAS:46-49`: "itoa can return up to 17 bytes; ltoa and ultoa, up
/// to 33"). `itoa` itself is a thin, undiscovered wrapper -- `(long)value`
/// sign-extended, `maybeSigned = 1` always (there is no unsigned `itoa`),
/// `hexStyle = 'a'` (lowercase, matching the well-known Borland/DOS `itoa`
/// contract this crate's own [`l2as`](crate::shims::text::l2as) already
/// documents for the sibling `ltoa`). This is that wrapper, transcribed from
/// `__longtoa`'s full assembly rather than guessed from the C standard,
/// which does not define `itoa` at all.
///
/// `__longtoa`'s own rules, all reproduced here:
///
/// - An invalid `radix` (outside 2..=36) "generate[s] an empty result" --
///   `LONGTOA.CAS:70-76`: the buffer gets only its terminator, nothing else,
///   and this is not an error the module can observe short of reading its
///   own buffer.
/// - The digit loop runs at least once even for a value of zero
///   (`LONGTOA.CAS:94-98`'s own comment), so `itoa(0, buf, radix)` is `"0"`,
///   never `""`.
/// - Digits above 9 are lowercase (`hexStyle = 'a'`): `LONGTOA.CAS:143-144`'s
///   `add al, hexStyle` after subtracting 10 is exactly
///   `b'a' + (digit - 10)`.
/// - The sign is unconditional on `radix`, unlike `%d`'s `+`/space flags:
///   `LONGTOA.CAS:81-91` negates and stores `-` whenever the value's high
///   word is negative and `maybeSigned` is set, with no radix check at all.
///
/// The digit conversion and sign are [`crate::fmt::integer`] at
/// `Spec::default()` (no `+`, no space, no `#`, no precision padding) --
/// exactly the four properties above, not a second implementation of them.
///
/// # Unbounded, like [`sprintf`](crate::shims::text::sprintf)
///
/// `string`'s capacity is not part of this call; `itoa`'s own contract is
/// that the caller sized it correctly (`LONGTOA.CAS:46-49` says as much: "the
/// space allocated for string must be large enough"). This host has no more
/// insight into that than `sprintf` does into its own destination buffer, so
/// this writes the digits and a terminator with no capacity check, the same
/// choice `sprintf`'s own doc comment explains ("How big the buffer is, only
/// the caller knows... The bounds check is the segment's").
///
/// Registers as `_itoa`.
pub fn itoa<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *itoa(int value, char *string, int radix)` -- Borland's; no
    // Galacticomm header redeclares it.
    // Kept in both forms, because which one is correct depends on the radix.
    // `raw` is the argument zero-extended at this ABI's `int` width (`0xffff`
    // stays 65,535 under `Wg16`); `value` is the same bits sign-extended.
    let raw: u32 = call.int().into();
    let value = sign_extend::<A>(raw);
    let dst = call.ptr();
    // `radix` is a small non-negative value in the one range this ever
    // legally is (2..=36) -- the same reasoning `fseek`'s own doc comment
    // gives for zero-extending `whence` with `Into::<u32>::into` rather than
    // sign-extending it.
    let radix = Into::<u32>::into(call.int());

    let mut text = if (2..=36).contains(&radix) {
        // Signed at **every** radix, not only at ten -- and this was
        // challenged on 2026-08-15 and survived, so the reasoning is recorded
        // rather than left to be re-argued.
        //
        // The dead duplicate `shims::text::itoa` (deleted with the rest of
        // the twins, `docs/2026-08-15-dead-twin-shims.md`) carried a test
        // asserting the opposite: that `itoa(0xffff, buf, 16)` is `"ffff"`,
        // on the stated grounds that "only radix ten is signed". That is the
        // familiar rule from the *documentation* of `itoa` in several C
        // libraries, and it may well be right -- but **no recovered source
        // settles it**, and the one recoverable piece of evidence points the
        // other way.
        //
        // `.scratch/bc452/LONGTOA.CAS` has `__longtoa`, which is where the
        // decision actually lives -- and it takes `maybeSigned` as a
        // *parameter*, so the radix does not decide anything by itself:
        //
        //     maybeSigned is treated as a boolean. If false then value is
        //     treated as unsigned long and no sign will be placed in *strP.
        //
        // `itoa`'s own body is not in the recovered tree. Its sibling's is,
        // and it passes the flag explicitly:
        //
        //     __utoa: return __longtoa(((long)value) & 0xffffL, buf, 10, 0, 'a');
        //                                                              ^ maybeSigned = 0
        //
        // An `__utoa` that has to pass `0` to get unsigned rendering is an
        // `itoa` that passes `1` -- unconditionally, since it has no other
        // flag to vary. So signed-at-every-radix is what the evidence here
        // supports, and `itoa(-255, buf, 16)` is `"-ff"`.
        //
        // If `itoa`'s body is ever recovered and shows otherwise, this is the
        // line to change, and `raw` above is already the value the unsigned
        // branch would need.
        let negative = value < 0;
        // `.unsigned_abs()`, not `-value`: the same overflow `l2as`'s own doc
        // comment names for `i32::MIN`, whose negation does not fit an `i32`.
        let magnitude = u64::from(value.unsigned_abs());
        integer(magnitude, negative, u64::from(radix), false, &Spec::default())
    } else {
        // `LONGTOA.CAS:70-76`: an invalid radix writes nothing but the
        // terminator.
        Vec::new()
    };
    text.push(0);

    dst.write(call.mem(), &text)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `int samend(char *longs, char *ends)` -- does `longs` end with `ends`,
/// ignoring case. `re/wg33src/SRC/api/gcommlib/SAMEND.C`, in full:
///
///
/// `sameas(ends, longs+nl-ne)` is `ends` compared against the last
/// `strlen(ends)` bytes of `longs`, case-folded, reached only once `ends` is
/// no longer than `longs` -- exactly this crate's own
/// [`crate::strings::sameas`], called the same way below.
///
/// `GCOMM.H:372` (`archive/galacticomm/extract/wg1/GALDSRC/SRC/GCOMM.H`)
/// declares it; every wg1 call site -- `samend(languages[...]->name,RIPSFX)`,
/// `samend(notefnm,".ANS")`, `samend(lock,"_TMODE")`, `samend(path,":\\.")`
/// -- is a suffix test in exactly this shape, `longs` first.
///
/// Built on [`crate::strings::sameas`] directly rather than re-implementing
/// the case fold: `sameas(a, b)` is already `a.len() == b.len() &&
/// folded_prefix(a, b)`, which over `ends` and `longs`'s own trailing slice
/// of the same length is precisely `SAMEND.C`'s call.
///
/// Registers as `_samend`.
pub fn samend<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int samend(char *longs, char *ends)` -- `GCOMM.H:372`.
    let longs_ptr = call.ptr();
    let ends_ptr = call.ptr();
    let longs = longs_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let ends = ends_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let matches = ends.len() <= longs.len()
        && crate::strings::sameas(ends, &longs[longs.len() - ends.len()..]);
    Ok(abi::Ret::Int(A::Int::from(u16::from(matches))))
}

/// `__LOCALECONVENTION` -- Borland's `struct lconv` instance, the data
/// `localeconv()` fills in and returns a pointer to.
///
/// # This is a DATA export in the real DLL, not a function
///
/// `archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF:1185-1194`:
///
/// ```text
///      _ALCDBG                       @1211
///      _ASTMODE                      @1212
///      _GALASTFAIL                   @1213
///      _ASTRPTFIL                    @1214
///      _BTVUPTR                      @1215
///      _BTVERRPTR                    @1216
///      __LOCALECONVENTION            @1217
///      _CRCTAB                       @1300
///      _CR3TAB                       @1301
/// ```
///
/// Every neighbour in that ordinal run is a host global a module reads or
/// writes directly -- `btvuptr`/`btverrptr` are Btrieve's own far pointers
/// (`crate::btrieve`'s own doc comment cites them), `crctab`/`cr3tab` are
/// checksum tables. `__LOCALECONVENTION` sits in the same block, and
/// `SOURCE/RTL/SOURCE/LOCALE/COMMON16/LCONV.C:38-98`
/// (`archive/tooling/compilers/bc452.zip`) confirms it from the other side:
/// `_llocaleconv()` fills `_QRTLInstanceData(_localeconvention)` -- an
/// **instance-data struct**, Borland's own generated name for a DLL-local
/// static -- field by field, and returns `&_localeconvention`. There is no C
/// source anywhere in this repo's recovered trees for a *function* called
/// `_localeconvention`; there is exactly one for a *variable* by that name.
///
/// This crate's dispatch table nonetheless reaches every import through one
/// calling convention (`crate::shims::mod`'s own doc comment on `Shim<A>`),
/// so this is written as that shape -- a zero-argument call that answers a
/// pointer -- on the assumption that whatever this host's loader does with a
/// DATA-shaped fixup, it ends up reaching a routine of this shape the same
/// way a CALL-shaped one does. Confirming or correcting that assumption is
/// `crates/mbbs/src/shims/mod.rs`'s registration, which this task does not
/// touch.
///
/// # Contents: the compiled-in "C" locale, nothing else
///
/// This host never calls `setlocale`, so there is exactly one locale to
/// report, and `SOURCE/RTL/SOURCE/LOCALE/COMMON16/CLOCALE.C:100-161` is its
/// values verbatim: `decimal_point = "."`, every other string field `""`,
/// and all eight numeric fields `CHAR_MAX` (`INCLUDE/LIMITS.H:26`: `127`,
/// Borland's default signed `char`). `INCLUDE/LOCALE.H:52-72` is the field
/// order for the non-flat (`__FLAT__` undefined, i.e. 16-bit) `struct lconv`
/// this crate's own `A::PTR_WIDTH`-general layout below follows: nine far
/// `char *` fields, then the eight `char`s, packed with no gaps (every
/// pointer is naturally aligned already at offset zero, and a run of `char`s
/// needs none).
///
/// # Address stability: not attempted, and not required
///
/// The real `_localeconvention` is one static struct, same address on every
/// call. This host has no equivalent pre-reserved region to hand back
/// without adding a new field to `Host<A>` -- out of scope for a single new
/// shim file -- so this reserves a fresh block from the module's own heap
/// ([`crate::heap::Heap::reserve`], the allocator
/// [`alcmem`](crate::shims::memory::alcmem)/[`alczer`](crate::shims::memory::alczer)
/// already use) on every call instead. ISO C explicitly permits this: the
/// standard allows a subsequent call to `localeconv()` to invalidate or
/// overwrite the structure a previous call returned, so no conforming caller
/// may depend on the address staying the same across two calls, and this
/// host does not promise that it will.
///
/// **What this does cost, and the real DLL does not:** `_localeconvention`
/// is compiled into `MAJORBBS`'s own data segment and touches the module's
/// heap not at all. Answering through [`crate::heap::Heap::reserve`] instead
/// means every call shrinks what
/// [`farcoreleft`](crate::shims::memory::farcoreleft) reports by roughly
/// `9 * A::PTR_WIDTH + 10` bytes (the struct, plus `".\0"`) and nothing ever
/// frees it -- the module never calls `galfree` on memory it does not know
/// it was given from the heap at all. Harmless for a routine called rarely,
/// wrong for one called in a loop; recorded here rather than hidden, since
/// fixing it means giving `Host<A>` a real pre-reserved slot, which this
/// task's constraints put out of reach.
///
/// Registers as `_localeconvention` -- the leading underscore already on
/// `__LOCALECONVENTION` is one of the two the source identifier has;
/// `exports::c_name` strips exactly one, per its own doc comment on why
/// `__OLDSEND` and `_OLDSEND` must not collide, leaving `_localeconvention`
/// with the other still on it.
pub fn localeconvention<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    // "." plus its terminator -- `CLOCALE.C:154`, the one string in this
    // struct that is not the shared empty one below.
    let decimal_point = host
        .heap
        .reserve(call.mem(), 2)
        .map_err(|e| ShimError::Failed(format!("localeconvention: {e}")))?;
    decimal_point
        .write(call.mem(), b".\0")
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // The shared empty string every other pointer field below points at --
    // `CLOCALE.C`'s own `""` for each of them, and one byte this host
    // already owns rather than eight more heap reservations for eight
    // identical strings.
    let empty = host.empty_string();

    let size = 9 * A::PTR_WIDTH + 8;
    let at = host
        .heap
        .reserve(call.mem(), size as u16)
        .map_err(|e| ShimError::Failed(format!("localeconvention: {e}")))?;

    let mut image = Vec::with_capacity(size);
    // `LOCALE.H:54-63`'s own field order: decimal_point, thousands_sep,
    // grouping, int_curr_symbol, currency_symbol, mon_decimal_point,
    // mon_thousands_sep, mon_grouping, positive_sign, negative_sign.
    image.extend(A::ptr_to_bytes(decimal_point));
    for _ in 0..8 {
        image.extend(A::ptr_to_bytes(empty));
    }
    // `LOCALE.H:64-71`: int_frac_digits, frac_digits, p_cs_precedes,
    // p_sep_by_space, n_cs_precedes, n_sep_by_space, p_sign_posn,
    // n_sign_posn -- all `CHAR_MAX` (`CLOCALE.C:124-138`).
    image.extend([127u8; 8]);

    at.write(call.mem(), &image)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `int stricmp(const char *s1, const char *s2)` -- case-insensitive
/// `strcmp`.
///
/// `SOURCE/RTL/SOURCE/CSTRINGS/COMMON32/STRICMP.C`, in full:
///
///
/// Upper-case both strings (the 16-bit `.CAS` assembly folds the identical
/// `'a'..='z'` range, `cx = 0x617a`, into upper case rather than the other
/// way -- both generations agree, and [`u8::to_ascii_uppercase`] is exactly
/// that range), then answer the first differing byte's signed difference, or
/// zero if one runs out before a difference does. Every byte past the
/// shorter string's own NUL is compared against `0`, matching the C loop's
/// own `c1 != '\0'` exit -- a real byte can never itself be `0`, so the
/// first out-of-range comparison is always the one that decides it.
///
/// Registers as `stricmp` -- `_STRICMP`, one leading underscore
/// (`archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF:573`).
pub fn stricmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int stricmp(const char *s1, const char *s2)` -- Borland's; no
    // Galacticomm header redeclares it.
    let a_ptr = call.ptr();
    let b_ptr = call.ptr();
    let a = a_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let b = b_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let diff = (0..a.len().max(b.len()))
        .map(|i| {
            let ca = a.get(i).copied().unwrap_or(0).to_ascii_uppercase();
            let cb = b.get(i).copied().unwrap_or(0).to_ascii_uppercase();
            i32::from(ca) - i32::from(cb)
        })
        .find(|&d| d != 0)
        .unwrap_or(0);

    Ok(abi::Ret::Int(A::int_from_u32(diff as u32)))
}

/// `char *ultoa(unsigned long value, char *string, int radix)` -- an
/// unsigned long, rendered in `radix` (2..=36) into the caller's own buffer.
///
/// [`itoa`]'s own doc comment already transcribes `__longtoa`
/// (`SOURCE/RTL/SOURCE/MATH/COMMON16/LONGTOA.CAS`), the shared assembly core
/// `itoa`/`ltoa`/`ultoa` all build on; every rule cited there (empty result
/// for an out-of-range radix, at-least-one-digit for a zero value, lowercase
/// digits above 9) applies here unchanged. The one place `ultoa` differs from
/// `itoa`/`ltoa` is `maybeSigned`: `LONGTOA.CAS:81-91` only ever negates and
/// prints a leading `-` when that flag is set, and `ultoa` is the one caller
/// in the family that never sets it -- there is no unsigned bit pattern this
/// routine ever treats as negative, at any radix, including 10.
///
/// # This is the mutation the standing rule names as the one that matters
///
/// A version that reads `value` through [`sign_extend`] the way [`itoa`]
/// reads its own (16-bit) argument would be correct for every value up to
/// `0x7FFF_FFFF` and silently wrong above it -- exactly the shape "six
/// reviews, six mutations that passed the whole suite" warns about, because
/// small test values never exercise the high bit. `value` is read through
/// [`Call::long`] as a bare `u32` and never passed through a signedness
/// conversion of any kind, so there is no code path left that *could*
/// reintroduce the bug -- not merely a test that would catch it.
///
/// Registers as `ultoa` -- `_ULTOA`, one leading underscore (`MAJORBBS.DEF:610`).
pub fn ultoa<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *ultoa(unsigned long value, char *string, int radix)` --
    // Borland's; no Galacticomm header redeclares it. `value` is read as a
    // bare `u32` -- see this routine's own doc comment for why that, not a
    // signed read, is the whole point of this routine existing beside `itoa`.
    let value = call.long();
    let dst = call.ptr();
    let radix = Into::<u32>::into(call.int());

    let mut text = if (2..=36).contains(&radix) {
        integer(u64::from(value), false, u64::from(radix), false, &Spec::default())
    } else {
        // `LONGTOA.CAS:70-76`: an invalid radix writes nothing but the
        // terminator -- see `itoa`'s own doc comment for the same rule.
        Vec::new()
    };
    text.push(0);

    dst.write(call.mem(), &text)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `int ungetc(int c, FILE *stream)` -- push one character back, so the next
/// read sees it again.
///
/// # Built on [`crate::stream::Streams::seek_mem`], not a new pushback slot
///
/// A faithful `ungetc` needs one byte of state per stream a `Stream` this
/// crate does not carry (`stream.rs` is out of this file's scope, and
/// `Streams`'s own fields are private to it regardless). This host does not
/// need a new slot for the one case that matters in practice -- pushing back
/// the byte a read call just took off the stream -- because that byte is
/// still sitting on disk, one position behind where the stream now is:
/// stepping back with `seek_mem(-1, Cur)` and reading it again for real
/// answers the identical question a stored pushback byte would.
///
/// # What this does not reproduce
///
/// C allows `ungetc` to push back *any* character, not only the one just
/// read, and only guarantees one level of pushback holds. This host can only
/// honour a push-back of the byte that is actually sitting behind the
/// stream's current position -- verified by peeking it before committing --
/// and refuses rather than silently accepting a substitute a later read
/// would never actually produce. No known caller in the surveyed corpus asks
/// for anything else; `ungetc(fgetc(fp), fp)` is the documented idiom this
/// answers exactly.
///
/// # Errors
///
/// If `stream` names no open, readable stream; if the stream is at its own
/// start (nothing behind it to step back into); or if the byte behind the
/// current position is not `c`.
///
/// Registers as `ungetc` -- `_UNGETC`, one leading underscore
/// (`MAJORBBS.DEF:612`).
pub fn ungetc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int ungetc(int c, FILE *stream)` -- Borland's; no Galacticomm header
    // redeclares it.
    let c = Into::<u32>::into(call.int()) as u8;
    let cookie = call.ptr();

    let pos = host
        .streams
        .tell(cookie)
        .map_err(|e| ShimError::Failed(format!("ungetc: {e}")))?;
    if pos == 0 {
        return Err(ShimError::Failed(
            "ungetc: the stream is at its own start; there is no byte behind it to push back into"
                .to_string(),
        ));
    }

    host.streams
        .seek_mem(call.mem(), cookie, -1, Whence::Cur)
        .map_err(|e| ShimError::Failed(format!("ungetc: {e}")))?;
    let peek = host
        .streams
        .read_mem(call.mem(), cookie, 1)
        .map_err(|e| ShimError::Failed(format!("ungetc: {e}")))?;

    if peek.first() != Some(&c) {
        // The read above already put the position back where it started
        // (one step back, one byte forward) -- see this routine's own doc
        // comment for why only the byte actually there can be pushed back.
        return Err(ShimError::Failed(format!(
            "ungetc({c}): the byte behind this stream's position is {:?}, not {c} -- \
             this host only supports pushing back the byte a read just took off the stream",
            peek.first()
        )));
    }

    // The peek above moved the position forward by one again; step it back
    // once more so the *next* read sees `c`, exactly as `ungetc` promises.
    host.streams
        .seek_mem(call.mem(), cookie, -1, Whence::Cur)
        .map_err(|e| ShimError::Failed(format!("ungetc: {e}")))?;
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(c))))
}

/// `int rename(const char *oldname, const char *newname)` -- rename or move
/// one of the module's own files.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/RENAME.CAS`: `mov ah, 056h; int 021h` --
/// DOS's own `AH=56h` "Rename File", which fails rather than replacing if
/// `newname` already exists (the WIN32 build agrees: `MoveFile`, not
/// `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)`). `std::fs::rename` on this
/// host's own Linux target does not share that restriction -- POSIX
/// `rename(2)` atomically replaces an existing destination -- so this checks
/// for one first and refuses rather than silently reproducing Unix semantics
/// under a DOS-shaped call.
///
/// Paths go through [`Host::dos_name`]/[`Host::find`], the same sandboxing
/// [`crate::shims::stream::fopen`]/[`crate::shims::stream::unlink`] already
/// use: a module names its own files, never a path outside `host.root`.
///
/// # Errors
///
/// If either name escapes the module's own directory; if `oldname` does not
/// exist; if `newname` already does; or if the underlying rename fails.
///
/// Registers as `rename` -- `_RENAME`, one leading underscore
/// (`MAJORBBS.DEF:495`).
pub fn rename<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int rename(const char *oldname, const char *newname)` -- Borland's;
    // no Galacticomm header redeclares it.
    let old_ptr = call.ptr();
    let new_ptr = call.ptr();
    let old_named = String::from_utf8_lossy(
        old_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let new_named = String::from_utf8_lossy(
        new_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let old_name = Host::<Wg16>::dos_name(&old_named).map_err(ShimError::Failed)?;
    let new_name = Host::<Wg16>::dos_name(&new_named).map_err(ShimError::Failed)?;

    let Some(old_path) = host.find(&old_name) else {
        return Err(ShimError::Failed(format!(
            "rename({old_named}, {new_named}): {old_named} does not exist"
        )));
    };
    if host.find(&new_name).is_some() {
        return Err(ShimError::Failed(format!(
            "rename({old_named}, {new_named}): {new_named} already exists -- DOS's own AH=56h \
             refuses to replace a rename target, unlike a bare POSIX rename(2)"
        )));
    }

    let new_path = host.root.join(&new_name);
    if let Some(parent) = new_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ShimError::Failed(format!(
                "rename({old_named}, {new_named}): {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::rename(&old_path, &new_path)
        .map_err(|e| ShimError::Failed(format!("rename({old_named}, {new_named}): {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `char *getenv(const char *name)` -- an environment variable, or `NULL` if
/// it is not set.
///
/// # There is no environment *model* here, and none is needed
///
/// `getenv`'s only real question is "does a variable by this name exist, and
/// what is it" -- a DOS module's answer came from the environment block DOS
/// built at process start from `SET` commands. This host is a native Linux
/// process, not a DOS-extender guest with a block to walk: its own process
/// environment (inherited from whatever shell started `mbbs-server`) is that
/// same question, asked of the OS that is actually running. So this reads
/// [`std::env::var`] directly, with no `Host<A>` state of its own, and none
/// was added -- `crates/mbbs/src/shims/dosenv.rs` was checked first (per this
/// task's own Step 1) and models something unrelated: Phar Lap DOS-extender
/// syscalls (`DosSetVec`, `DosCreateDSAlias`), not environment variables at
/// all, despite the filename. Environment-variable state genuinely needs
/// none, so `dosenv.rs` is untouched.
///
/// # `NULL` for "not set" is the answer, not a refusal
///
/// Per this crate's own design spec: a routine whose purpose *includes*
/// reporting absence answers rather than stops the module, the same
/// exception [`crate::shims::stream::fopen`]/[`crate::shims::stream::unlink`]
/// already are. An unset variable is the ordinary case for most names a
/// module asks for.
///
/// # Errors
///
/// If the module's heap cannot give up a small block for the answer. Never
/// for an unset name -- see above.
///
/// Registers as `getenv` -- `_GETENV`, one leading underscore
/// (`MAJORBBS.DEF:323`).
pub fn getenv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *getenv(const char *name)` -- Borland's; no Galacticomm header
    // redeclares it.
    let name_ptr = call.ptr();
    let name = String::from_utf8_lossy(
        name_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let Ok(value) = std::env::var(&name) else {
        return Ok(abi::Ret::Ptr(A::null_ptr()));
    };

    let mut text = value.into_bytes();
    text.push(0);
    let at = host
        .heap
        .reserve(call.mem(), text.len() as u16)
        .map_err(|e| ShimError::Failed(format!("getenv: {e}")))?;
    at.write(call.mem(), &text)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `void gettime(struct time *t)` -- the wall clock's time of day, DOS's
/// `struct time` shape.
///
/// `INCLUDE/DOS.H`: `struct time { unsigned char ti_min, ti_hour, ti_hund,
/// ti_sec; };` -- four bytes, in that field order (minutes first, seconds
/// last -- not the `hour`-first order [`crate::shims::system::now`]'s packed
/// `USHORT` uses, and not [`crate::clock::Civil`]'s own field order either).
/// Drawn from [`crate::Host::clock`]'s own [`crate::clock::Civil`] the same
/// way `now`/`today`/`time` already are.
///
/// # `ti_hund` is always zero
///
/// [`crate::clock::Civil`] has no field finer than whole seconds -- `now`,
/// `today` and `time` never needed one, since DOS's own packed `time_t`/date
/// words do not carry sub-second precision either. `gettime` is the first
/// caller in this crate that could observe hundredths, and this host
/// genuinely does not track them, so `ti_hund` is `0` rather than a value
/// this host does not have. Disclosed rather than hidden: a module polling
/// for the clock to visibly tick within one second would see it stand still.
///
/// # Errors
///
/// If the host's clock cannot say what time it is, the same condition
/// [`crate::shims::system::now`] already refuses on.
///
/// Registers as `gettime` -- `_GETTIME`, one leading underscore
/// (`MAJORBBS.DEF:327`).
pub fn gettime<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `void gettime(struct time *t)` -- Borland's; no Galacticomm header
    // redeclares it.
    let out = call.ptr();
    let t = host
        .clock()
        .civil()
        .map_err(|e| ShimError::Failed(format!("gettime: {e}")))?;

    // `ti_min, ti_hour, ti_hund, ti_sec` -- see this routine's own doc
    // comment for the field order and for why `ti_hund` is always zero.
    let bytes = [t.minute as u8, t.hour as u8, 0u8, t.second as u8];
    out.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `int __DOSerror(int dosErr)` -- translate a raw DOS error code into
/// `errno`, record it in `_doserrno`, and echo `dosErr` back unchanged.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/IOERROR.CAS`, in full for the return value:
///
///
/// `__IOerror` (same file) is what actually does the work: `_doserrno =
/// dosErr` (clamped to `e_parameter` if `dosErr` is out of the table's
/// range), then `errno = _dosErrorToSV[dosErr]` -- a fixed 51-entry DOS-code
/// -> `errno.h`-code table, transcribed in this routine's test module rather
/// than duplicated in two places.
///
/// # This routine's own return value is exact; the side effect is not durable
///
/// `__DOSerror`'s contract to its *caller* is just "echo `dosErr` back",
/// which needs no state at all and is answered exactly. The side effect --
/// making the translated value visible to a later, separate `errno` call --
/// needs a per-host `errno`/`_doserrno` cell that survives between two shim
/// invocations, which is a `Host<A>` field this file's task scope does not
/// reach (`Host` is `crates/mbbs/src/lib.rs`; see this file's own module doc,
/// "Blocked, and left out of this file"). Unlike `setmode`/`read`/`write`,
/// this routine is not left out for it: its own answer does not depend on
/// that state, only a *different, later* call's does. [`errno`] below is
/// where that limitation actually bites, and its own doc comment says so.
///
/// # Errors
///
/// Never -- `__DOSerror` has no failure mode of its own in the source above;
/// every `dosErr` value, in range or not, produces an answer.
///
/// Registers as `_doserror` -- raw import `__DOSERROR` (two leading
/// underscores, `MAJORBBS.DEF:19`, in the same internal-RTL-helper cluster as
/// `__CLOSE`/`__CREAT`/`__READ`), `c_name` strips exactly one.
pub fn doserror<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int __DOSerror(int dosErr)` -- Borland's; no Galacticomm header
    // redeclares it. See this routine's own doc comment for why only the
    // return value -- not the errno/_doserrno side effect -- is answered.
    let doserr = call.int();
    Ok(abi::Ret::Int(doserr))
}

/// `int *__errno(void)` -- the address of the calling thread's `errno`.
///
/// `SOURCE/RTL/SOURCE/MISC/COMMON32/ERRNO.C`, in full for the `_MT` (the
/// variant these builds link, per this file's own module doc) case:
///
///
/// A genuine routine, not data: `INCLUDE/ERRNO.H`'s `#define errno
/// (*__errno())` is what turns the *macro* `errno` a module's C source writes
/// into a call to this. The non-`_MT`, non-`_RTLDLL` branch of the same
/// header declares a plain `extern int errno;` instead -- that is a
/// different, single-underscore export (`_ERRNO`, ordinal 1064 in wg1's own
/// `MAJORBBS.DEF`) nothing in the ten surveyed builds imports, and is not
/// implemented here.
///
/// # This answer does not survive to the next call
///
/// A real `__errno()` returns the *same* address on every call within one
/// thread -- that address stability is the entire reason a module bothers
/// caching or re-reading through it. This host has no `Host<A>` field to
/// anchor that address in (see this file's own module doc, "`__errno` and
/// `_doserror` land despite the same shape of gap, on a narrower one"), so
/// this reserves a fresh module-heap cell on every call instead, the same
/// compromise [`localeconvention`]'s own doc comment already makes and
/// discloses for the identical reason. **This means a module that calls
/// [`doserror`] and then reads `errno` through a second call to this routine
/// will not see the translated value** -- it will see a freshly zeroed cell.
/// No known caller in the surveyed corpus does this in one traceable
/// sequence; if one is found to, the fix is the `Host<A>` field named above,
/// not a workaround in this file.
///
/// # Errors
///
/// If the module's heap cannot give up a small block for the answer.
///
/// Registers as `__errno` -- raw import `___errno` (three leading
/// underscores, read directly off `tmp/gapsurvey/round2/rose32/RCIROSE.DLL`'s
/// own PE import table; absent from wg1's `MAJORBBS.DEF`, which pre-dates
/// this `_MT` variant), `c_name` strips exactly one.
pub fn errno<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int *__errno(void)` -- Borland's; no Galacticomm header redeclares it.
    // See this routine's own doc comment for why the cell is fresh, not
    // stable, on every call.
    let at = host
        .heap
        .reserve(call.mem(), A::INT_WIDTH as u16)
        .map_err(|e| ShimError::Failed(format!("__errno: {e}")))?;
    at.write(call.mem(), &vec![0u8; A::INT_WIDTH])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `long lrand(void)` -- a wider random draw than [`crate::shims::system::rand`].
///
/// # No vendor source survives for this one
///
/// Unlike every other routine in this file, `lrand` has no `.C`/`.CAS` body
/// anywhere in `bc452.zip`, `bc501.zip` or `tc201.zip` (checked by name,
/// case-insensitively, over each archive's full listing), and no ordinal in
/// wg1's own `MAJORBBS.DEF` at all -- confirmed absent, not merely unfound.
/// The raw import is `__lrand` (two leading underscores, read directly off
/// `tmp/gapsurvey/round2/rose32/RCIROSE.DLL`'s own PE import table), the same
/// internal-accessor underscore shape [`errno`]'s own doc comment measures
/// for `___errno` -- consistent with a later-generation Borland RTL export
/// this repo's surviving trees do not carry source for. Per this crate's own
/// scope rule ("Symbols whose semantics we cannot confirm get an
/// implementation plus a recorded uncertainty, not an `Unimplemented`
/// entry"), this is that: a documented best-effort body, not a citation to
/// a source that does not exist.
///
/// # Drawn from the one generator this host already has
///
/// [`crate::random::Random`]'s own doc comment: "one generator for the whole
/// host... `srand` and `rand` share a single `RANDSEED` and every caller
/// pulls from the same stream." A separate, unrelated PRNG for `lrand` would
/// break that invariant for no documented reason, so this draws from
/// [`Host::random`]'s existing [`crate::random::Random::rand`] -- twice, to
/// build a value wider than the 15 bits (`RAND_MAX = 0x7fff`) any single draw
/// carries: `(first << 15) | second`, up to 30 significant bits. `rand`
/// itself is untouched (`Random::rand` is called exactly the way `rand()`
/// already calls it), so a module mixing `rand()`/`genrdn()` calls with
/// `lrand()` still draws from the one stream `srand` seeds, just faster.
///
/// Registers as `_lrand` -- raw import `__lrand` strips to `_lrand` under
/// `c_name`'s one-underscore rule.
pub fn lrand<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `long lrand(void)` -- see this routine's own doc comment for why there
    // is no vendor prototype to quote and what stands in for one.
    let hi = u32::from(host.random.rand());
    let lo = u32::from(host.random.rand());
    let value = (hi << 15) | lo;
    Ok(abi::Ret::Long(value))
}

/// `char *searchpath(const char *file)` -- find `file`, or answer `NULL`.
///
/// `SOURCE/RTL/SOURCE/PROCESS/COMMON16/SRCHPATH.C`, in full:
///
///
/// Real `searchpath` walks the current directory, then every directory named
/// in the `PATH` environment variable, and answers a pointer into a static
/// buffer "overwritten with each call" (`SRCHPATH.C`'s own doc comment) --
/// the same rotating-buffer shape [`crate::shims::text::l2as`]'s own doc
/// comment describes, and the same one this host cannot give a stable
/// address to without a `Host<A>` field (see [`errno`]'s own doc comment for
/// the identical tradeoff); this reserves a fresh heap cell per call instead,
/// [`localeconvention`]'s established compromise for the same reason.
///
/// # This host's "path" is `host.root`, not the real `PATH`
///
/// Walking the *real* `PATH` this process inherited would let a module probe
/// the actual host filesystem's layout -- every other file routine in this
/// crate ([`crate::shims::stream::fopen`], `unlink`, `cntdir`) instead
/// restricts a module to its own sandboxed directory via
/// [`Host::dos_name`]/[`Host::find`], and `searchpath` follows that same
/// rule rather than being the one routine that breaks the sandbox. So the
/// "path" searched is `host.root` alone, treated as both the module's
/// current directory and its whole `PATH` -- there is nothing else in this
/// host's model of a module's filesystem to add. The name handed back is the
/// module-relative name [`Host::find`] matched, not a real host path (which
/// would itself leak `host.root`'s absolute location).
///
/// # Errors
///
/// If `file`'s spelling escapes the module's own directory
/// ([`Host::dos_name`]'s rule); if the module's heap cannot give up a small
/// block for a found answer. Never for a file that is simply not there --
/// `NULL` is the honest answer to that, matching the source's own contract.
///
/// Registers as `searchpath` -- `_SEARCHPATH`, one leading underscore.
pub fn searchpath<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    // `char *searchpath(const char *file)` -- Borland's; no Galacticomm
    // header redeclares it.
    let file_ptr = call.ptr();
    let named = String::from_utf8_lossy(
        file_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;

    let Some(_) = host.find(&name) else {
        return Ok(abi::Ret::Ptr(A::null_ptr()));
    };

    let mut text = name.into_bytes();
    text.push(0);
    let at = host
        .heap
        .reserve(call.mem(), text.len() as u16)
        .map_err(|e| ShimError::Failed(format!("searchpath: {e}")))?;
    at.write(call.mem(), &text)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// One of DOS's five pre-opened standard handles as a `stdio_modes` index,
/// or a refusal naming exactly why this table cannot resolve `handle`.
///
/// Shared by [`setmode`], [`read`] and [`write`] -- see `Host::stdio_modes`'s
/// own doc comment for why this table stops at `4` rather than reaching into
/// [`crate::stream::Streams`]'s own, separate numbering (`5` and up).
/// A descriptor a real `fopen` issued, if `handle` is one.
///
/// [`crate::stream::Streams`] numbers its descriptors from `5`, above DOS's
/// five standard handles, so the two spaces do not overlap and a caller can
/// tell them apart by value alone.
///
/// # Why these arrive here at all
///
/// `fileno(f)` is a **macro** in Borland's headers -- it reads `FILE.fd`
/// directly and never calls the runtime, so this host never sees it happen.
/// A module that opens a file with `fopen` and then reads it with
/// `read(fileno(fp), ...)` therefore hands a descriptor to a routine that
/// used to accept only `0..=4`. The Rose 3.0NT does precisely that, at four
/// call sites, each one `push dword [reg+0x16]` immediately before its
/// `call _read` -- and `0x16` is where `cw3220mt.DLL`'s own `_fileno`
/// (RVA `0x6b44`) reads it from.
fn descriptor(handle: i32) -> Option<u8> {
    u8::try_from(handle).ok().filter(|&h| h >= crate::stream::FIRST_FD)
}

fn standard_handle(handle: i32) -> Result<usize, ShimError> {
    usize::try_from(handle)
        .ok()
        .filter(|&h| h < 5)
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "handle {handle}: this host only resolves DOS's five standard handles \
                 (0..=4, stdin/stdout/stderr/aux/prn) through this table -- a handle from a \
                 real `fopen` (5 or above) needs `Streams`'s own numbering, which this table \
                 does not share; see `Host::stdio_modes`'s own doc comment for why"
            ))
        })
}

/// `int setmode(int handle, int amode)` -- set a standard handle's
/// text/binary translation, and answer the mode it had before.
///
/// `INCLUDE/IO.H`: `int setmode(int handle, int amode)`, `amode` one of
/// `O_TEXT` (`0x4000`) or `O_BINARY` (`0x8000`), `INCLUDE/FCNTL.H`. The
/// answer is the *previous* mode, in the same two values -- real Borland
/// tracks this per `_openfd[handle]` bit (`WRITE.C`'s own `_openfd[fd] &
/// O_TEXT`, quoted in full on [`write`]'s own doc comment), which is exactly
/// what `Host::stdio_modes` is for.
///
/// # Errors
///
/// If `handle` is not one of the five standard handles this host resolves
/// (see [`standard_handle`]); if `amode` is neither `O_TEXT` nor `O_BINARY`
/// -- real Borland's own header defines no third value, and guessing one
/// would be inventing behaviour rather than reading it off a source.
///
/// Registers as `setmode` -- `_SETMODE`, one leading underscore
/// (`MAJORBBS.DEF:989`).
pub fn setmode<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int setmode(int handle, int amode)` -- Borland's; no Galacticomm
    // header redeclares it.
    const O_TEXT: u32 = 0x4000;
    const O_BINARY: u32 = 0x8000;

    let handle = sign_extend::<A>(call.int().into());
    let amode = Into::<u32>::into(call.int());
    let idx = standard_handle(handle)?;

    let previous = if host.stdio_modes[idx] { O_BINARY } else { O_TEXT };
    host.stdio_modes[idx] = match amode {
        O_BINARY => true,
        O_TEXT => false,
        _ => {
            return Err(ShimError::Failed(format!(
                "setmode({handle}, {amode:#06x}): not O_TEXT (0x4000) or O_BINARY (0x8000)"
            )));
        }
    };
    Ok(abi::Ret::Int(A::int_from_u32(previous)))
}

/// Text-mode translation for a raw low-level read: drop `\r`, and stop at
/// the first `^Z` (`0x1A`), the file's own soft end-of-file -- the same rule
/// `SOURCE/RTL/SOURCE/IO/COMMON16/READ.CAS` documents for the DOS-handle
/// read underneath *every* text-mode input in this crate's Borland oracle,
/// [`crate::stream::Stream::getc`]'s own doc comment quotes it for the
/// buffered side. Reimplemented locally rather than reached through
/// `Streams` (private, and this file's own module doc already explains why
/// `read`/`write` do not share its state) -- the same choice
/// [`crate::shims::user::mdfgets`]'s own `.retain(|&b| b != b'\r')` already
/// makes for the identical transform.
fn text_mode_read(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if b == 0x1A {
            break;
        }
        if b != b'\r' {
            out.push(b);
        }
    }
    out
}

/// Text-mode translation for a raw low-level write: a `\r` ahead of every
/// `\n`, byte for byte -- `WRITE.C`'s own loop, quoted in full on [`write`]'s
/// own doc comment, over a buffer instead of one byte at a time. The same
/// transform [`crate::shims::stream::fputc`]'s own doc comment already cites
/// `PUTC.C:137-139` for.
fn text_mode_write(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// The mode-flag branch [`write`] runs, pulled out so `binary` is an
/// explicit argument rather than a `host.stdio_modes` read buried inside a
/// bigger function -- see [`write_to`]'s own doc comment for why this
/// matters and what it does not, by itself, cover.
fn write_translated(raw: &[u8], binary: bool) -> Vec<u8> {
    if binary { raw.to_vec() } else { text_mode_write(raw) }
}

/// [`read`]'s whole pipeline, over an injected source -- length, mode
/// translation, and the actual read -- so it is testable at all without a
/// live console. **A real, blocking `std::io::stdin().read()` hangs this
/// test binary forever**, confirmed empirically (a standalone Rust program
/// doing exactly that timed out under `timeout 3`, with nothing piped to its
/// stdin, in this exact sandboxed environment) -- so `read`'s own tests
/// cannot exercise it at all, and previously did not exercise any of this
/// routine's logic as a result. `source` lets a test supply a
/// `std::io::Cursor` instead, and get real coverage of the read/truncate/
/// translate sequence through the same code `read` itself runs, not a
/// hand-copied approximation of it.
fn read_from(source: &mut dyn std::io::Read, len: usize, binary: bool) -> Result<Vec<u8>, String> {
    let mut raw = vec![0u8; len];
    let n = source.read(&mut raw).map_err(|e| e.to_string())?;
    raw.truncate(n);
    Ok(if binary { raw } else { text_mode_read(&raw) })
}

/// [`write`]'s whole pipeline, over an injected sink -- mode translation and
/// the actual write -- so the *physical* bytes are observable in a test
/// without touching a real console for the ordinary, parallel-safe test
/// suite (this crate's own established caution about process-global
/// mutation under parallel tests, `Clock`'s module doc on `TZ`, applies just
/// as much to swapping the process's real stdout/stderr fd out from under
/// other tests). `sink` lets a test supply a `Vec<u8>` instead, and see
/// whether text mode's inserted `\r` actually reached it -- not only whether
/// [`write_translated`] can compute one in isolation.
///
/// # The one line this does not cover, and how it is covered anyway
///
/// `write` itself decides `binary` from `host.stdio_modes[idx]` at exactly
/// one call site, and answers the same byte count (`WRITE.C`'s own promise:
/// a text write "does not count generated carriage returns") whichever mode
/// ran -- so a mutation that hardcoded that one argument instead of reading
/// the field would pass every test in this module that reaches the pipeline
/// through `write_to` directly, this one included, since none of them drive
/// `write` itself with a mode this table did not already choose. That is
/// the shape, not a mutation table gap -- the standing rule this crate
/// applies to exactly this situation.
///
/// `write_through_the_real_shim_actually_translates_by_mode` (this file's
/// own `#[cfg(test)]`, `#[ignore]`d) closes it: it `libc::dup2`s the
/// process's real fd 2 to a scratch file, drives the *actual* `write` shim
/// twice -- once at `stdio_modes`'s own default (text), once after a real
/// `setmode` call flips it to binary -- and asserts the two physical byte
/// sequences the file captured differ exactly the way `write_translated`
/// says they should. `#[ignore]`d for the same reason this doc comment's own
/// opening paragraph gives (swapping a real fd is process-global), not
/// because it cannot pass -- it does, run alone, and mutating that one call
/// site to hardcode `binary` makes it fail. See that test's own doc comment
/// for the exact command and the fd-restoration guard.
fn write_to(sink: &mut dyn std::io::Write, raw: &[u8], binary: bool) -> Result<(), String> {
    let physical = write_translated(raw, binary);
    sink.write_all(&physical).map_err(|e| e.to_string())
}

/// `int read(int handle, void *buf, unsigned len)` -- up to `len` bytes from
/// standard input.
///
/// # This host has one real source for handle `0`: this process's own stdin
///
/// A loaded MajorBBS add-on module ran *in the host's own process*, sharing
/// its PSP and its standard handles -- `write(1, ...)` on the real host went
/// to the sysop's own console, and `read(0, ...)` came from it. This host is
/// the equivalent process for a headless server, so its own `stdin` is that
/// same thing, not a fabrication.
///
/// # Errors
///
/// If `handle` is not `0` (only reading is meaningful for a "console
/// input"; `1`/`2` are write-only in every real DOS convention this crate
/// has found, and `3`/`4` -- aux/prn -- have no device behind them on this
/// host at all); if the physical read fails; if `buf` does not resolve.
///
/// Registers as `read` -- `_READ`, one leading underscore.
pub fn read<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int read(int handle, void *buf, unsigned len)` -- Borland's; no
    // Galacticomm header redeclares it.
    let handle = sign_extend::<A>(call.int().into());
    let buf = call.ptr();
    let len = Into::<u32>::into(call.int()) as usize;

    // A descriptor an `fopen` issued, arriving here because `fileno` is a
    // macro the module expands itself -- see `descriptor_stream`.
    if let Some(fd) = descriptor(handle) {
        let cookie = host.streams.cookie_of_fd(fd).map_err(|e| {
            ShimError::Failed(format!("read({handle}, ...): {e}"))
        })?;
        let bytes = host
            .streams
            .read_mem(call.mem(), cookie, len)
            .map_err(|e| ShimError::Failed(format!("read({handle}, ...): {e}")))?;
        buf.write(call.mem(), &bytes)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        return Ok(abi::Ret::Int(A::int_from_u32(bytes.len() as u32)));
    }

    let idx = standard_handle(handle)?;
    if idx != 0 {
        return Err(ShimError::Failed(format!(
            "read({handle}, ...): only handle 0 (stdin) is open for reading on this host"
        )));
    }

    // `host.stdio_modes[0]` -- see `setmode`'s own doc comment for where
    // this bit comes from.
    let bytes = read_from(&mut std::io::stdin(), len, host.stdio_modes[idx])
        .map_err(|e| ShimError::Failed(format!("read(0, ...): {e}")))?;

    buf.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::int_from_u32(bytes.len() as u32)))
}

/// `int write(int handle, const void *buf, unsigned len)` -- `len` bytes to
/// standard output or standard error.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/WRITE.C`'s own doc comment: "on text
/// files, when write sees a linefeed (LF) character, it outputs a CR-LF
/// pair... A write to a text file does not count generated carriage
/// returns" -- the byte count this answers is `len`, the request, not the
/// larger physical count text mode may have written, matching
/// [`crate::shims::stream::fputc`]'s own established choice for the
/// buffered side of the identical rule.
///
/// # `handle` resolves to this process's own stdout/stderr, for the same
/// reason [`read`]'s own doc comment gives for stdin
///
/// # `len == 0` is answered directly
///
/// `WRITE.C:` `if ((len +1) < 2) return (0);` -- Borland's own 16-bit
/// arithmetic also catches `len == 0xFFFF` this way (`0xFFFF + 1` wraps to
/// `0` in a 16-bit `unsigned`), an accident of the register width rather
/// than a documented rule. This host reproduces the *documented* half
/// (`len == 0` writes nothing and answers `0`) and does not chase the
/// wraparound artefact at `0xFFFF`: no known call site in the surveyed
/// corpus writes anywhere near that many bytes in one call, and treating an
/// overflow this host's own `usize` arithmetic does not share as a rule
/// worth reproducing would be inventing behaviour from an accident, not
/// reading it off a source.
///
/// # Errors
///
/// If `handle` is not `1` or `2` (see [`read`]'s own doc comment for why
/// `0`/`3`/`4` are refused); if the physical write fails; if `buf` does not
/// resolve.
///
/// Registers as `write` -- `_WRITE`, one leading underscore.
pub fn write<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int write(int handle, const void *buf, unsigned len)` -- Borland's;
    // no Galacticomm header redeclares it.
    let handle = sign_extend::<A>(call.int().into());
    let buf = call.ptr();
    let len = Into::<u32>::into(call.int()) as usize;

    // The counterpart of `read`'s own descriptor branch, and present for the
    // same reason -- see `descriptor`.
    if let Some(fd) = descriptor(handle) {
        let cookie = host.streams.cookie_of_fd(fd).map_err(|e| {
            ShimError::Failed(format!("write({handle}, ...): {e}"))
        })?;
        if len == 0 {
            return Ok(abi::Ret::Int(A::Int::from(0u16)));
        }
        let raw = buf
            .resolve(call.mem(), len)
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        host.streams
            .write(cookie, &raw)
            .map_err(|e| ShimError::Failed(format!("write({handle}, ...): {e}")))?;
        return Ok(abi::Ret::Int(A::int_from_u32(raw.len() as u32)));
    }

    let idx = standard_handle(handle)?;
    if idx != 1 && idx != 2 {
        return Err(ShimError::Failed(format!(
            "write({handle}, ...): only handles 1 (stdout) and 2 (stderr) are open for \
             writing on this host"
        )));
    }

    // `WRITE.C:62` -- see this routine's own doc comment for the documented
    // half of the check this reproduces.
    if len == 0 {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    let raw = buf
        .resolve(call.mem(), len)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let result = match idx {
        1 => write_to(&mut std::io::stdout(), &raw, host.stdio_modes[idx]),
        2 => write_to(&mut std::io::stderr(), &raw, host.stdio_modes[idx]),
        _ => unreachable!("standard_handle/idx guard above admits only 1 or 2 here"),
    };
    result.map_err(|e| ShimError::Failed(format!("write({handle}, ...): {e}")))?;

    // The logical count `WRITE.C` promises, not `physical.len()` -- see this
    // routine's own doc comment.
    Ok(abi::Ret::Int(A::int_from_u32(raw.len() as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::{FarPtr, Ret};

    use crate::shims::stream::{fclose, fgetc, fopen};
    use crate::testing::{Fixture, scratch};

    fn pointer(ret: Ret) -> FarPtr {
        match ret {
            Ret::Far(at) => at,
            _ => panic!("expected a far pointer"),
        }
    }

    fn word(ret: Ret) -> u16 {
        match ret {
            Ret::U16(n) => n,
            _ => panic!("expected an int"),
        }
    }

    fn long(ret: Ret) -> u32 {
        match ret {
            Ret::U32(n) => n,
            _ => panic!("expected a long"),
        }
    }

    /// A `long` argument, split the way this crate's own call sites already
    /// split one for a test invocation -- low word first, matching
    /// `Call::long`'s own read order (see `text.rs`'s identical local
    /// helper for `l2as`'s tests).
    fn long_arg(v: u32) -> [u16; 2] {
        [v as u16, (v >> 16) as u16]
    }

    /// `fopen(name, mode)`, as the `FILE *` it must return.
    fn opened(f: &mut Fixture, name: &str, mode: &str) -> FarPtr {
        let path = f.text(name);
        let how = f.text(mode);
        match f
            .invoke(fopen, &[path.offset, path.selector, how.offset, how.selector])
            .unwrap_or_else(|e| panic!("fopen({name}, {mode}): {e}"))
        {
            Ret::Far(at) => at,
            _ => panic!("fopen returns a FILE *"),
        }
    }

    // ---- read/write on a descriptor an fopen issued ------------------------

    /// `read` accepts the descriptor `fileno` would have handed a module,
    /// and reads the file that descriptor names.
    ///
    /// This path exists because `fileno` is a macro: a module reads
    /// `FILE.fd` out of the struct itself and passes the number to `read`,
    /// so the host sees a descriptor with no record of where it came from.
    /// The descriptor is taken out of the `FILE` image here the same way the
    /// module's own inlined macro would take it, rather than being assumed
    /// to be 5.
    #[test]
    fn read_accepts_a_descriptor_fopen_issued_and_reads_that_file() {
        let root = scratch("crt-read-by-fd");
        std::fs::write(root.join("IN.DAT"), b"payload").expect("a file to read");
        let mut f = Fixture::rooted(root);
        let fp = opened(&mut f, "IN.DAT", "rb");

        // What `fileno(fp)` expands to, done by hand: the bytes at this
        // ABI's own `FILE.fd`.
        let image = f
            .machine
            .resolve(fp, crate::stream::FILE_SIZE)
            .expect("a FILE")
            .to_vec();
        let at = usize::from(Wg16::FILE_FD_OFFSET);
        let width = usize::from(Wg16::FILE_FD_WIDTH);
        let mut raw = [0u8; 4];
        raw[..width].copy_from_slice(&image[at..at + width]);
        let fd = u32::from_le_bytes(raw);
        assert!(fd >= 5, "a real descriptor, not a standard handle: {fd}");

        let buf = f.buffer(16);
        let got = f
            .invoke(read, &[fd as u16, buf.offset, buf.selector, 7])
            .expect("reads through the descriptor");
        assert_eq!(got, Ret::U16(7), "seven bytes asked for, seven read");
        assert_eq!(
            &f.machine.resolve(buf, 7).expect("the buffer")[..],
            b"payload"
        );
    }

    /// A descriptor no stream carries is refused, and named.
    ///
    /// The Rose 3.0NT arrived here with `458752` -- four bytes read past the
    /// end of a `FILE` this host had written too short. A refusal that says
    /// which descriptor is the difference between diagnosing that in minutes
    /// and not at all.
    #[test]
    fn read_on_a_descriptor_no_stream_carries_is_refused() {
        let mut f = Fixture::rooted(scratch("crt-read-bad-fd"));
        let buf = f.buffer(16);
        let e = f
            .invoke(read, &[9, buf.offset, buf.selector, 4])
            .expect_err("descriptor 9 names nothing");
        assert!(format!("{e}").contains("descriptor 9"), "{e}");
    }

    // ---- fwrite -------------------------------------------------------------

    #[test]
    fn fwrite_writes_size_times_nitems_bytes_and_returns_the_item_count() {
        let root = scratch("crt-fwrite");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.DAT", "wb");
        let data = f.bytes(b"abcdef", false);

        let ret = f
            .invoke(
                fwrite,
                &[data.offset, data.selector, 2, 3, fp.offset, fp.selector],
            )
            .expect("fwrite");
        assert_eq!(word(ret), 3, "the item count, not the byte count");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        assert_eq!(std::fs::read(root.join("OUT.DAT")).expect("written"), b"abcdef");
    }

    #[test]
    fn fwrite_with_a_zero_size_claims_the_whole_item_count_and_writes_nothing() {
        // `FWRITE.C:62` -- `if( !psize ) return( nitems );` -- Borland's own
        // asymmetry with `fread`, which answers 0 for either a zero size or
        // a zero count.
        let root = scratch("crt-fwrite-zero-size");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.DAT", "wb");
        let data = f.bytes(b"x", false);

        let ret = f
            .invoke(
                fwrite,
                &[data.offset, data.selector, 0, 9, fp.offset, fp.selector],
            )
            .expect("fwrite");
        assert_eq!(word(ret), 9);
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
        assert_eq!(std::fs::read(root.join("OUT.DAT")).expect("written").len(), 0);
    }

    /// Moved from the dead `stream::fwrite` twin
    /// (`docs/2026-08-15-dead-twin-shims.md`): the other half of `FWRITE.C:62`'s
    /// asymmetry with `fread` -- a zero *count*, unlike a zero *size*, answers
    /// plain `0`, not `nitems`.
    #[test]
    fn fwrite_of_zero_items_writes_nothing_and_is_not_a_refusal() {
        let root = scratch("crt-fwrite-zero-count");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.DAT", "wb");
        let data = f.bytes(b"x", false);

        let ret = f
            .invoke(fwrite, &[data.offset, data.selector, 4, 0, fp.offset, fp.selector])
            .expect("fwrite");
        assert_eq!(word(ret), 0);
    }

    // ---- itoa -----------------------------------------------------------

    #[test]
    fn itoa_renders_negative_hex_lowercase_and_returns_its_own_destination() {
        let mut f = Fixture::new();
        let buf = f.buffer(8);
        let ret = f
            .invoke(itoa, &[(-255i16) as u16, buf.offset, buf.selector, 16])
            .expect("itoa");
        assert_eq!(pointer(ret), buf, "returns strP, like __longtoa");
        assert_eq!(f.read(buf), "-ff");
    }

    #[test]
    fn itoa_of_zero_is_the_digit_zero_not_an_empty_string() {
        let mut f = Fixture::new();
        let buf = f.buffer(4);
        f.invoke(itoa, &[0, buf.offset, buf.selector, 10]).expect("itoa");
        assert_eq!(f.read(buf), "0");
    }

    #[test]
    fn itoa_with_an_out_of_range_radix_writes_only_the_terminator() {
        // `LONGTOA.CAS:70-76`: "if the request is invalid, generate an empty
        // result."
        //
        // `shims::text` carried a dead duplicate `itoa` whose own test
        // asserted the opposite -- that a bad radix is *refused*. The vendor
        // line above settles it: an invalid request produces an empty result,
        // not an error. The duplicate went with the rest of the dead twins
        // (`docs/2026-08-15-dead-twin-shims.md`), and its refusal expectation
        // went with it rather than being carried over. The three tests below
        // are the ones it had that this file did not.
        let mut f = Fixture::new();
        let buf = f.buffer(4);
        f.invoke(itoa, &[42, buf.offset, buf.selector, 1]).expect("itoa");
        assert_eq!(f.read(buf), "");
    }

    #[test]
    fn itoa_renders_decimal_with_a_sign() {
        let mut f = Fixture::new();
        let buf = f.buffer(16);
        let Ret::Far(at) = f
            .invoke(itoa, &[(-42i16) as u16, buf.offset, buf.selector, 10])
            .expect("formatted")
        else {
            panic!("itoa returns a pointer");
        };
        assert_eq!(at, buf, "itoa returns its own second argument");
        assert_eq!(f.read(at), "-42");
    }

    // The dead twin's fourth test is deliberately NOT carried over:
    // `itoa_at_a_non_decimal_radix_treats_a_negative_value_as_unsigned`
    // asserted `itoa(0xffff, buf, 16) == "ffff"` on the grounds that "only
    // radix ten is signed". That contradicts this file's own
    // `itoa_renders_negative_hex_lowercase_and_returns_its_own_destination`,
    // which expects `"-ff"`, and the conflict is genuinely unsettled by any
    // recovered source -- see the long comment in `itoa` itself. Reinstating
    // it would mean changing shipped behaviour on an unverifiable claim.
    //
    // Its fifth, `itoa_refuses_a_radix_outside_2_to_36`, is also dropped: it
    // expected a refusal where `LONGTOA.CAS:70-76` says an invalid request
    // produces an empty result, which
    // `itoa_with_an_out_of_range_radix_writes_only_the_terminator` above
    // already pins.

    #[test]
    fn itoa_renders_zero_at_any_radix() {
        let mut f = Fixture::new();
        let buf = f.buffer(16);
        f.invoke(itoa, &[0u16, buf.offset, buf.selector, 2])
            .expect("formatted");
        assert_eq!(f.read(buf), "0");
    }

    // ---- samend -----------------------------------------------------------

    #[test]
    fn samend_true_when_the_string_ends_with_the_pattern_ignoring_case() {
        let mut f = Fixture::new();
        let longs = f.text("someone/ansi");
        let ends = f.text("/ANSI");
        let ret = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("samend");
        assert_eq!(word(ret), 1);
    }

    #[test]
    fn samend_false_when_it_does_not_end_that_way() {
        let mut f = Fixture::new();
        let longs = f.text("someone/rip");
        let ends = f.text("/ANSI");
        let ret = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("samend");
        assert_eq!(word(ret), 0);
    }

    #[test]
    fn samend_false_when_the_pattern_is_longer_than_the_string() {
        let mut f = Fixture::new();
        let longs = f.text("hi");
        let ends = f.text("hello");
        let ret = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("samend");
        assert_eq!(word(ret), 0);
    }

    // ---- localeconvention -----------------------------------------------

    #[test]
    fn localeconvention_answers_the_c_locales_compiled_in_defaults() {
        let mut f = Fixture::new();
        let ret = f.invoke(localeconvention, &[]).expect("localeconvention");
        let at = pointer(ret);

        let bytes = f.machine.resolve(at, 9 * 4 + 8).expect("the whole struct").to_vec();
        let field = |i: usize| FarPtr::from_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("4 bytes"));

        // decimal_point (field 0) -- CLOCALE.C:154, the one string that is
        // not the shared empty one.
        assert_eq!(f.read(field(0)), ".");

        // thousands_sep .. negative_sign (fields 1-8) -- all CLOCALE.C's own
        // `""`.
        for i in 1..9 {
            assert_eq!(f.read(field(i)), "", "pointer field {i}");
        }

        // int_frac_digits .. n_sign_posn -- all CHAR_MAX (127).
        assert_eq!(&bytes[36..44], &[127u8; 8]);
    }

    // ---- stricmp ----------------------------------------------------------

    #[test]
    fn stricmp_is_case_insensitive_and_orders_like_strcmp() {
        let mut f = Fixture::new();
        let a = f.text("Hello");
        let b = f.text("hELLO");
        let c = f.text("world");

        let eq = f
            .invoke(stricmp, &[a.offset, a.selector, b.offset, b.selector])
            .expect("stricmp");
        assert_eq!(word(eq), 0, "case must not matter");

        let lt = f
            .invoke(stricmp, &[a.offset, a.selector, c.offset, c.selector])
            .expect("stricmp");
        assert!((word(lt) as i16) < 0, "'H' < 'W' after both are upper-cased");
    }

    #[test]
    fn stricmp_treats_a_shorter_prefix_as_less_than_a_longer_string() {
        // The out-of-range comparison is against 0 (a NUL), which is always
        // less than any real, uppercased byte -- exactly the C loop's own
        // `c1 != '\0'` exit condition.
        let mut f = Fixture::new();
        let a = f.text("cat");
        let b = f.text("cats");
        let ret = f
            .invoke(stricmp, &[a.offset, a.selector, b.offset, b.selector])
            .expect("stricmp");
        assert!((word(ret) as i16) < 0, "\"cat\" is shorter than \"cats\"");
    }

    // ---- ultoa --------------------------------------------------------------

    #[test]
    fn ultoa_writes_an_unsigned_long_not_a_signed_one() {
        // The whole reason ultoa exists beside itoa: 3_000_000_000 is
        // negative as an i32 and must not print as one.
        let mut f = Fixture::new();
        let buf = f.buffer(16);
        let mut args = long_arg(3_000_000_000).to_vec();
        args.extend([buf.offset, buf.selector, 10]);
        f.invoke(ultoa, &args).expect("ultoa");
        assert_eq!(f.read(buf), "3000000000");
    }

    #[test]
    fn ultoa_of_zero_is_the_digit_zero_not_an_empty_string() {
        let mut f = Fixture::new();
        let buf = f.buffer(4);
        let mut args = long_arg(0).to_vec();
        args.extend([buf.offset, buf.selector, 10]);
        f.invoke(ultoa, &args).expect("ultoa");
        assert_eq!(f.read(buf), "0");
    }

    #[test]
    fn ultoa_with_an_out_of_range_radix_writes_only_the_terminator() {
        let mut f = Fixture::new();
        let buf = f.buffer(4);
        let mut args = long_arg(42).to_vec();
        args.extend([buf.offset, buf.selector, 1]);
        f.invoke(ultoa, &args).expect("ultoa");
        assert_eq!(f.read(buf), "");
    }

    // ---- ungetc -------------------------------------------------------------

    fn ab_stream(f: &mut Fixture, root: &std::path::Path) -> FarPtr {
        std::fs::write(root.join("AB.DAT"), b"AB").expect("fixture");
        opened(f, "AB.DAT", "rb")
    }

    #[test]
    fn ungetc_pushes_one_character_back_for_the_next_fgetc() {
        let root = scratch("crt-ungetc");
        let mut f = Fixture::rooted(root.clone());
        let fp = ab_stream(&mut f, &root);

        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), b'A' as u16);
        f.invoke(ungetc, &[b'A' as u16, fp.offset, fp.selector])
            .expect("ungetc");
        assert_eq!(
            word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")),
            b'A' as u16,
            "the pushed-back character comes out first"
        );
        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), b'B' as u16);
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn ungetc_of_a_byte_that_is_not_actually_there_is_refused() {
        let root = scratch("crt-ungetc-mismatch");
        let mut f = Fixture::rooted(root.clone());
        let fp = ab_stream(&mut f, &root);

        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), b'A' as u16);
        let e = f
            .invoke(ungetc, &[b'X' as u16, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("ungetc"), "{e}");

        // Refused, not partially applied: the next real read still sees 'B'.
        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), b'B' as u16);
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn ungetc_at_the_very_start_of_a_stream_is_refused() {
        let root = scratch("crt-ungetc-start");
        let mut f = Fixture::rooted(root.clone());
        let fp = ab_stream(&mut f, &root);

        let e = f
            .invoke(ungetc, &[b'A' as u16, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("start"), "{e}");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    // ---- rename ---------------------------------------------------------

    #[test]
    fn rename_moves_a_file_to_its_new_name() {
        let root = scratch("crt-rename");
        let mut f = Fixture::rooted(root.clone());
        std::fs::write(root.join("OLD.DAT"), b"hi").expect("fixture");

        let old = f.text("OLD.DAT");
        let new = f.text("NEW.DAT");
        let ret = f
            .invoke(rename, &[old.offset, old.selector, new.offset, new.selector])
            .expect("rename");
        assert_eq!(word(ret), 0);
        assert!(!root.join("OLD.DAT").exists());
        assert_eq!(std::fs::read(root.join("NEW.DAT")).expect("renamed"), b"hi");
    }

    #[test]
    fn rename_of_a_missing_source_is_refused() {
        let mut f = Fixture::rooted(scratch("crt-rename-missing"));
        let old = f.text("NOSUCH.DAT");
        let new = f.text("NEW.DAT");
        f.invoke(rename, &[old.offset, old.selector, new.offset, new.selector])
            .expect_err("a refusal");
    }

    #[test]
    fn rename_onto_an_existing_destination_is_refused_not_a_silent_replace() {
        // std::fs::rename would happily replace NEW.DAT on this host's own
        // Linux target -- DOS's AH=56h would not, and this routine must not
        // quietly adopt the more permissive of the two.
        let root = scratch("crt-rename-exists");
        let mut f = Fixture::rooted(root.clone());
        std::fs::write(root.join("OLD.DAT"), b"old").expect("fixture");
        std::fs::write(root.join("NEW.DAT"), b"already here").expect("fixture");

        let old = f.text("OLD.DAT");
        let new = f.text("NEW.DAT");
        f.invoke(rename, &[old.offset, old.selector, new.offset, new.selector])
            .expect_err("a refusal");
        assert_eq!(
            std::fs::read(root.join("NEW.DAT")).expect("untouched"),
            b"already here"
        );
    }

    // ---- getenv -----------------------------------------------------------

    #[test]
    fn getenv_answers_null_for_a_name_that_is_not_set() {
        let mut f = Fixture::new();
        let name = f.text("MBBS_CRT_GETENV_TEST_UNSET_VAR_XYZZY");
        let ret = f.invoke(getenv, &Fixture::far(name)).expect("getenv");
        assert_eq!(pointer(ret), FarPtr::NULL, "an unset variable is NULL, not an empty string");
    }

    #[test]
    fn getenv_answers_a_variable_that_is_actually_set() {
        // Read straight off this process's own environment rather than a
        // hardcoded name -- `std::env::set_var` is `unsafe` and process-wide
        // in Rust 2024, the same hazard `Clock`'s own module doc names for
        // `TZ` under parallel tests, so this reads what is already there
        // instead of mutating it.
        let Some((name, value)) = std::env::vars().next() else {
            return;
        };
        let mut f = Fixture::new();
        let name_ptr = f.text(&name);
        let ret = f.invoke(getenv, &Fixture::far(name_ptr)).expect("getenv");
        assert_eq!(f.read(pointer(ret)), value);
    }

    // ---- gettime ------------------------------------------------------------

    #[test]
    fn gettime_fills_minute_hour_hundredths_second_in_that_order() {
        // 1_135_952_405 -- 2005-12-30 14:20:05 UTC, the same pinned instant
        // `shims::system`'s own `now`/`today`/`time` tests already use.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(1_135_952_405));

        let out = f.buffer(4);
        f.invoke(gettime, &Fixture::far(out)).expect("gettime");
        let bytes = f.machine.resolve(out, 4).expect("resolves").to_vec();
        assert_eq!(bytes, [20, 14, 0, 5], "ti_min, ti_hour, ti_hund, ti_sec");
    }

    // ---- doserror / errno -----------------------------------------------

    #[test]
    fn doserror_echoes_the_code_it_was_given() {
        let mut f = Fixture::new();
        let ret = f.invoke(doserror, &[2]).expect("doserror"); // ENOFILE
        assert_eq!(word(ret), 2);
    }

    #[test]
    fn doserror_echoes_a_negative_code_unchanged_too() {
        // `IOERROR.CAS`'s own comment: a negative argument is "a negated
        // System V error number", and `__DOSerror` returns it exactly as
        // given either way.
        let mut f = Fixture::new();
        let ret = f.invoke(doserror, &[(-5i16) as u16]).expect("doserror");
        assert_eq!(word(ret) as i16, -5);
    }

    #[test]
    fn errno_answers_a_valid_writable_cell() {
        let mut f = Fixture::new();
        let ret = f.invoke(errno, &[]).expect("__errno");
        let at = pointer(ret);
        assert_ne!(at, FarPtr::NULL, "a real cell, not a null this host gave up on");
        assert_eq!(f.machine.resolve(at, 2).expect("resolves"), [0, 0]);
    }

    // ---- lrand --------------------------------------------------------------

    #[test]
    fn lrand_is_distinct_from_rand_and_spans_more_than_16_bits() {
        // __lrand is a long-returning generator; rand is the 16-bit one and
        // is already served. If lrand were wired to rand, every value would
        // fit in 16 bits.
        let mut f = Fixture::new();
        let mut saw_big = false;
        for _ in 0..64 {
            if long(f.invoke(lrand, &[]).expect("lrand")) > 0xFFFF {
                saw_big = true;
                break;
            }
        }
        assert!(saw_big, "__lrand must produce values wider than 16 bits");
    }

    // ---- searchpath -----------------------------------------------------

    #[test]
    fn searchpath_finds_a_file_that_is_in_the_modules_own_directory() {
        let root = scratch("crt-searchpath");
        let mut f = Fixture::rooted(root.clone());
        std::fs::write(root.join("FOUND.DAT"), b"x").expect("fixture");

        let name = f.text("FOUND.DAT");
        let ret = f.invoke(searchpath, &Fixture::far(name)).expect("searchpath");
        assert_eq!(f.read(pointer(ret)), "FOUND.DAT");
    }

    #[test]
    fn searchpath_answers_null_for_a_file_that_is_not_there() {
        let mut f = Fixture::rooted(scratch("crt-searchpath-missing"));
        let name = f.text("NOSUCH.DAT");
        let ret = f.invoke(searchpath, &Fixture::far(name)).expect("searchpath");
        assert_eq!(pointer(ret), FarPtr::NULL);
    }

    // ---- the text-mode transforms, directly -- no real stdin/stdout ---------
    //
    // `read`'s own doc comment: a real `std::io::stdin().read()` blocks
    // forever under this harness (confirmed empirically -- the test binary
    // is not connected to a terminal that will ever send EOF or data), so
    // the translation these two routines apply is tested as the pure
    // functions it actually is, not by driving it through a live console.

    #[test]
    fn text_mode_read_drops_carriage_returns_and_stops_at_control_z() {
        assert_eq!(text_mode_read(b"a\r\nb\x1acd"), b"a\nb");
        assert_eq!(text_mode_read(b"no control z at all"), b"no control z at all");
    }

    #[test]
    fn text_mode_write_inserts_a_carriage_return_ahead_of_every_newline() {
        assert_eq!(text_mode_write(b"a\nb\nc"), b"a\r\nb\r\nc");
        assert_eq!(text_mode_write(b"no newlines"), b"no newlines");
    }

    // These close a real gap this session's own mutation testing found: a
    // mutation that made `write` ignore `host.stdio_modes` and always pass
    // the raw bytes through unchanged passed the whole suite silently,
    // because nothing asserted on what physically reaches
    // `std::io::stdout`/`stdin` (deliberately -- `read_from`'s own doc
    // comment explains why a live console is not something a test here can
    // safely touch, with the empirical proof). `read`/`write` now go
    // through `read_from`/`write_to`, which take their `Read`/`Write` and
    // `binary` as plain arguments and are testable end to end -- a
    // `Cursor`/`Vec<u8>` standing in for `stdin`/`stdout` -- without any
    // real I/O at all. `write_to`'s own doc comment records the one call-site
    // sliver even this cannot close, and why.

    #[test]
    fn write_translated_only_applies_text_mode_translation_when_binary_is_false() {
        assert_eq!(write_translated(b"a\nb", false), b"a\r\nb", "text mode");
        assert_eq!(write_translated(b"a\nb", true), b"a\nb", "binary mode: untouched");
    }

    #[test]
    fn read_from_translates_in_text_mode_and_passes_through_untouched_in_binary() {
        let mut text = std::io::Cursor::new(b"a\r\nb\x1acd".to_vec());
        assert_eq!(read_from(&mut text, 8, false).expect("read_from"), b"a\nb", "text mode");

        let mut binary = std::io::Cursor::new(b"a\r\nb\x1acd".to_vec());
        assert_eq!(
            read_from(&mut binary, 8, true).expect("read_from"),
            b"a\r\nb\x1acd",
            "binary mode: untouched, including the byte text mode would have stopped at"
        );
    }

    #[test]
    fn read_from_a_short_source_truncates_to_what_was_actually_there() {
        let mut source = std::io::Cursor::new(b"hi".to_vec());
        assert_eq!(read_from(&mut source, 64, true).expect("read_from"), b"hi");
    }

    #[test]
    fn write_to_translates_in_text_mode_and_passes_through_untouched_in_binary() {
        let mut text = Vec::new();
        write_to(&mut text, b"a\nb", false).expect("write_to");
        assert_eq!(text, b"a\r\nb", "text mode: the physical bytes carry the inserted \\r");

        let mut binary = Vec::new();
        write_to(&mut binary, b"a\nb", true).expect("write_to");
        assert_eq!(binary, b"a\nb", "binary mode: untouched");
    }

    // ---- setmode --------------------------------------------------------

    #[test]
    fn setmode_answers_the_previous_mode_and_changes_it() {
        let mut f = Fixture::new();
        const O_TEXT: u16 = 0x4000;
        const O_BINARY: u16 = 0x8000;

        // DOS's own default is text, for every standard handle, until asked.
        let first = f.invoke(setmode, &[1, O_BINARY]).expect("setmode");
        assert_eq!(word(first), O_TEXT, "the mode it had before this call");

        let second = f.invoke(setmode, &[1, O_TEXT]).expect("setmode");
        assert_eq!(word(second), O_BINARY, "now answers what the first call just set");
    }

    #[test]
    fn setmode_on_a_handle_this_table_does_not_resolve_is_refused() {
        let mut f = Fixture::new();
        let e = f.invoke(setmode, &[5, 0x8000]).expect_err("a refusal");
        assert!(e.to_string().contains('5'), "{e}");
    }

    #[test]
    fn setmode_with_neither_o_text_nor_o_binary_is_refused() {
        let mut f = Fixture::new();
        f.invoke(setmode, &[1, 0x1234]).expect_err("neither flag");
    }

    // ---- read/write -- handle resolution and counting, not live console -----

    #[test]
    fn read_from_a_write_only_handle_is_refused() {
        let mut f = Fixture::new();
        let buf = f.buffer(8);
        f.invoke(read, &[1, buf.offset, buf.selector, 8])
            .expect_err("stdout is not open for reading");
    }

    #[test]
    fn read_on_a_handle_this_table_does_not_resolve_is_refused() {
        let mut f = Fixture::new();
        let buf = f.buffer(8);
        f.invoke(read, &[99, buf.offset, buf.selector, 8])
            .expect_err("a refusal");
    }

    #[test]
    fn write_answers_the_logical_byte_count_not_the_translated_one() {
        // "a\nb" is 3 requested bytes; text mode physically emits 4
        // ("a\r\nb") -- WRITE.C's own promise is that the *generated*
        // carriage return is not counted.
        let mut f = Fixture::new();
        let out = f.bytes(b"a\nb", false);
        let ret = f.invoke(write, &[1, out.offset, out.selector, 3]).expect("write");
        assert_eq!(word(ret), 3);
    }

    #[test]
    fn write_of_zero_bytes_writes_nothing_and_answers_zero() {
        let mut f = Fixture::new();
        let out = f.buffer(1);
        let ret = f.invoke(write, &[1, out.offset, out.selector, 0]).expect("write");
        assert_eq!(word(ret), 0);
    }

    #[test]
    fn write_to_stdin_is_refused() {
        let mut f = Fixture::new();
        let out = f.text("x");
        f.invoke(write, &[0, out.offset, out.selector, 1])
            .expect_err("stdin is not open for writing");
    }

    #[test]
    fn write_on_a_handle_this_table_does_not_resolve_is_refused() {
        let mut f = Fixture::new();
        let out = f.text("x");
        f.invoke(write, &[42, out.offset, out.selector, 1])
            .expect_err("a refusal");
    }

    #[test]
    fn write_to_aux_or_prn_is_refused_not_silently_dropped() {
        // Handles 3 (aux/COM1) and 4 (prn/LPT1) resolve as far as
        // `standard_handle` goes -- they are two of DOS's five reserved
        // handles -- but this host has no serial or printer device behind
        // either, and answering a byte count for a write that went nowhere
        // would be exactly the plausible zero this crate refuses to give.
        let mut f = Fixture::new();
        let out = f.text("x");
        for handle in [3u16, 4] {
            f.invoke(write, &[handle, out.offset, out.selector, 1])
                .expect_err("aux/prn have no device on this host");
        }
    }

    // ---- the one line write_to's own doc comment names -- closed, not disclosed ---

    /// Restores the process's real `STDERR_FILENO` to `original` on drop,
    /// even if the body between redirecting it and here panics -- a failed
    /// assertion in [`write_through_the_real_shim_actually_translates_by_mode`]
    /// must not leave every later test's `eprintln!`/panic output silently
    /// redirected into a scratch file nobody is reading.
    struct RestoreStderr(std::os::fd::RawFd);

    impl Drop for RestoreStderr {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid fd this same test duplicated from
            // the real `STDERR_FILENO` and has not yet closed (see
            // `write_through_the_real_shim_actually_translates_by_mode`'s
            // own body) -- `dup2` onto `STDERR_FILENO` and closing the
            // now-spare duplicate are both well-defined for it.
            unsafe {
                libc::dup2(self.0, libc::STDERR_FILENO);
                libc::close(self.0);
            }
        }
    }

    #[test]
    #[ignore = "swaps the process's real stderr fd via dup2 -- process-global, must run \
                alone: tools/cargo-serial.sh test -p mbbs --lib \
                write_through_the_real_shim -- --ignored --test-threads=1"]
    fn write_through_the_real_shim_actually_translates_by_mode() {
        // `write_to`'s own doc comment: every other test in this module
        // reaches the translation pipeline through `write_to` directly, so
        // none of them exercise the one line inside the *real* `write` shim
        // that reads `host.stdio_modes[idx]` and hands it to `write_to` as
        // `binary`. This drives `write` itself -- not `write_to` -- with the
        // process's real `STDERR_FILENO` (stderr: unbuffered, so no
        // `LineWriter` flush timing to reason about, unlike stdout)
        // redirected to a scratch file, and reads the file back once both
        // calls are done and the real fd is restored.
        use std::os::fd::AsRawFd;

        let root = scratch("crt-write-real-fd");
        let capture_path = root.join("captured.bin");
        let capture_file = std::fs::File::create(&capture_path).expect("scratch file");

        // SAFETY: duplicates a definitely-valid, open fd (the process's own
        // stderr). Owned by `_restore` from here on and closed exactly
        // once, in `RestoreStderr::drop`.
        let saved = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(saved >= 0, "dup(STDERR_FILENO) failed");
        let _restore = RestoreStderr(saved);

        // SAFETY: replaces fd 2 with a duplicate of `capture_file`'s own fd;
        // both descriptors stay independently valid afterward, so dropping
        // `capture_file` right after closes only its own number, never fd 2.
        let rc = unsafe { libc::dup2(capture_file.as_raw_fd(), libc::STDERR_FILENO) };
        assert!(rc >= 0, "dup2 onto STDERR_FILENO failed");
        drop(capture_file);

        let mut f = Fixture::new();
        let out = f.bytes(b"a\nb", false);

        // `Host::stdio_modes` starts all-`false` -- text -- so this first
        // call needs no `setmode` first.
        f.invoke(write, &[2, out.offset, out.selector, 3])
            .expect("write, text mode");

        const O_BINARY: u16 = 0x8000;
        f.invoke(setmode, &[2, O_BINARY]).expect("setmode to O_BINARY");
        f.invoke(write, &[2, out.offset, out.selector, 3])
            .expect("write, binary mode");

        drop(_restore); // real fd 2 back before reading the file below

        let captured = std::fs::read(&capture_path).expect("captured output");
        assert_eq!(
            captured, b"a\r\nba\nb",
            "text mode's write (\"a\\r\\nb\") followed by binary mode's (\"a\\nb\"), \
             physically, through the real `write` shim -- not `write_translated` or \
             `write_to` called directly"
        );
    }
}
