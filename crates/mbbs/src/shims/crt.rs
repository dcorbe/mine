//! Seven routines this host had not implemented: five of Borland's own C
//! runtime, re-exported by `MAJORBBS.DLL`, and two of Galacticomm's own.
//!
//! ```text
//! _FGETC              int    fgetc(FILE *stream)
//! _FPUTC              int    fputc(int ch, FILE *stream)
//! _FWRITE           size_t   fwrite(void *ptr, size_t size, size_t nitems, FILE *stream)
//! _ITOA              char *  itoa(int value, char *string, int radix)
//! __LOCALECONVENTION struct lconv *  -- DATA in the real DLL; see `localeconvention`'s own doc
//! _MDFGETS           char *  mdfgets(char *buf, int size, FILE *fp)
//! _SAMEND               int  samend(char *longs, char *ends)
//! ```
//!
//! # Where each was found
//!
//! `fgetc`, `fputc`, `fwrite` and `itoa` are Borland's, from
//! `archive/tooling/compilers/bc452.zip` -- the same zip [`crate::stream`]'s
//! own module doc already cites as this host's oracle for Borland runtime
//! behaviour ("everything here is measured against Borland's own runtime...
//! the module was linked against the source"). `SAMEND.C` and `MDFGETS.C`
//! are Galacticomm's own, and unlike the module SDK sources under
//! `archive/galacticomm/extract/wg1/GALDSRC` (which only *declare* these two
//! in `GCOMM.H`, matching every module that calls them), their bodies
//! survive complete in `re/wg33src/SRC/api/gcommlib/` -- the Worldgroup 3.3
//! recovered source tree, cited by exact path below rather than by line
//! number into `GALDSRC`, per this repo's own rule that a citation into the
//! wrong Galacticomm tree is silently wrong rather than merely imprecise.
//!
//! # `stream.rs` said three of these were "genuinely absent"
//!
//! [`crate::shims::stream`]'s own module doc: "`fwrite`, `fputs`, `fputc`,
//! `fscanf`, `fgetc`, `getc` and `ungetc` are still genuinely absent: no
//! import census, `WCCMMUD.DLL`'s or LunatiX's, has ever asked for any of
//! them." That census is now out of date for three of the seven named there
//! -- the same correction that file's own module doc already made once for
//! `fseek`/`ftell`/`rewind`, against the same import list
//! (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`). Fixing that
//! sentence is out of scope here (it means editing `stream.rs`, which this
//! file's own task does not); it is flagged so nobody reads it as still
//! true.
//!
//! These three are placed in a new file rather than in `stream.rs` because
//! the task that produced them said to, not because they belong to a
//! different subsystem -- they share [`crate::stream::Streams`] with every
//! routine `stream.rs` already has, and read that file's types
//! (`Mode::writable`, `Stream::getc` by way of
//! [`crate::stream::Streams::read_mem`]) directly.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::fmt::{Spec, integer};
use crate::shims::{ShimError, sign_extend};

/// `int fgetc(FILE *stream)` -- one byte, or `EOF` at the end of the file.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/GETC.CAS:120-200` (in
/// `archive/tooling/compilers/bc452.zip`) is Borland's own `fgetc`: "the
/// character read, after converting it to an int without sign extension. On
/// end-of-file or error... returns EOF." `getc`, `feof`, `ferror` and
/// `fileno` are the macros built on top of it and never reach this host --
/// see `stream.rs`'s own module doc -- but `fgetc` itself, like `fgets` and
/// `fread` beside it, is a real function MAJORBBS re-exports, and Lunatix
/// 5.3F imports it directly (`_FGETC`).
///
/// # This is [`crate::stream::Streams::read_mem`] at `want = 1`
///
/// Not a new read path: a one-byte [`crate::stream::Streams::read_mem`] call
/// already answers exactly what `fgetc` needs -- an empty `Vec` is
/// end-of-file (the same short-read-as-answer contract [`fread`]'s own doc
/// comment in `stream.rs` describes, at the smallest possible count), and a
/// non-empty one is the byte, "without sign extension" because a `u8`
/// widened through `u32::from` never carries a sign to begin with.
///
/// # `EOF` is `-1` at `A`'s own int width, not at 16 bits
///
/// The same idiom `crate::shims::text::fold`'s own doc comment works through
/// for `toupper(EOF)`: `A::Int::from(0xFFFFu16)` zero-extends, so it answers
/// `65535` under `Wg32` rather than `-1`. `u32::MAX >> (32 -
/// A::INT_WIDTH * 8)` is all-ones at exactly `A`'s width, which
/// [`Abi::int_from_u32`] then carries into `A::Int` unchanged.
///
/// # What this does not reproduce
///
/// `GETC.CAS`'s `fgetc` also answers `EOF` for a stream in `_F_ERR`, or one
/// opened only for writing (`fp->flags & (_F_OUT|_F_ERR)`). Those are host
/// misuse on this crate's own account, not end-of-file, and
/// [`crate::stream::Streams::read_mem`] already refuses them (bad cookie,
/// wrong mode) with a named error rather than the plausible-looking `-1` a
/// real caller could not tell apart from a genuine end of file -- the same
/// choice `fgets` and `fread` already made for the read side of this exact
/// question.
///
/// Registers as `_fgetc` -- `exports::c_name` strips the one leading
/// underscore `_FGETC` already has.
pub fn fgetc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fgetc(FILE *stream)` -- Borland's; no Galacticomm header
    // redeclares it.
    let cookie = call.ptr();
    let bytes = host
        .streams
        .read_mem(call.mem(), cookie, 1)
        .map_err(|e| ShimError::Failed(format!("fgetc: {e}")))?;

    let eof = u32::MAX >> (32 - A::INT_WIDTH * 8);
    let value = match bytes.first() {
        Some(&b) => u32::from(b),
        None => eof,
    };
    Ok(abi::Ret::Int(A::int_from_u32(value)))
}

/// `int fputc(int ch, FILE *stream)` -- one byte.
///
/// `SOURCE/RTL/SOURCE/IO/COMMON16/PUTC.C:54-150` is Borland's `fputc`:
/// assigns `ch` into a `static unsigned char c` (so only the low byte is
/// ever written -- "this assignment *MUST* be done *AFTER* the semaphore
/// lock" is Borland's own concurrency note, irrelevant to a single-threaded
/// host), writes it, and "on success... return[s] the character ch." In text
/// mode `PUTC.C:137-139` writes a `\r` ahead of a `\n` before the byte
/// itself -- exactly [`crate::stream::Stream::write`]'s own `if b == b'\n' {
/// out.push(b'\r') }`, already in place for [`crate::shims::stream::fprintf`]
/// and needing nothing new here.
///
/// # What this does not reproduce
///
/// `fputc` answers `EOF` on a write that fails (`_F_ERR`, wrong mode, a
/// short physical write). This host does not manufacture that plausible
/// `-1`: [`crate::stream::Streams::write`] already refuses a bad cookie or a
/// stream open for reading with a named error, and a genuine disk failure
/// refuses too, the same choice [`crate::shims::stream::fprintf`] and
/// [`crate::shims::stream::fflush`] already made ("a plausible zero is the
/// failure this crate exists to prevent" -- `stream.rs`'s own module doc).
/// So under this host `fputc` either answers `ch` or stops the module; it
/// never answers `EOF`.
///
/// Registers as `_fputc`.
pub fn fputc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fputc(int ch, FILE *stream)` -- Borland's; no Galacticomm header
    // redeclares it. `ch` arrives as a full `A::INT_WIDTH` word; only the low
    // byte is ever written or returned, matching `PUTC.C`'s own `static
    // unsigned char c; c = ch;`.
    let ch = Into::<u32>::into(call.int()) as u8;
    let cookie = call.ptr();

    host.streams
        .write(cookie, &[ch])
        .map_err(|e| ShimError::Failed(format!("fputc: {e}")))?;
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(ch))))
}

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
    let value = sign_extend::<A>(call.int().into());
    let dst = call.ptr();
    // `radix` is a small non-negative value in the one range this ever
    // legally is (2..=36) -- the same reasoning `fseek`'s own doc comment
    // gives for zero-extending `whence` with `Into::<u32>::into` rather than
    // sign-extending it.
    let radix = Into::<u32>::into(call.int());

    let mut text = if (2..=36).contains(&radix) {
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

/// `char *mdfgets(char *buf, int size, FILE *fp)` -- "server flavor of
/// fgets()", `re/wg33src/SRC/api/gcommlib/MDFGETS.C`'s own words.
///
/// Full source, unlike `SAMEND` below only in that it is longer, not less
/// complete:
///
///
/// Its own doc comment: "Unlike fgets(), it converts newline into carriage
/// return, and it expects the last line of the file not to end in a
/// newline." The two known callers agree with that shape: `GALNOTE.C:172`
/// (`mdfgets(txtbuf,BYT2RD,noteptr->notefil) == NULL`) and `MENUING.C:994`
/// (`mdfgets(vdatmp,512,mnuusr->fp) == NULL`) both treat it exactly like
/// `fgets` -- a line, or `NULL` at the end.
///
/// # This is [`crate::stream::Streams::line_mem`], not a second read loop
///
/// `line_mem(mem, cookie, size - 1)` already answers "up to `size - 1`
/// bytes, stopping after and keeping a newline, `None` only when nothing was
/// read and the stream has ended" -- [`crate::shims::stream::fgets`]'s own
/// core, and precisely `MDFGETS.C`'s `for` loop and its `case EOF: if (i ==
/// 0) return(NULL)`. What is left to do here is translate the answer:
/// convert a trailing `\n` into a lone `\r` (`case '\n':` above -- **not**
/// `\r\n`, the terminator is the `\r` alone) and terminate.
///
/// # Two of `MDFGETS.C`'s own cases are dead code on this host, and were
/// already dead on the real one
///
/// - **`case '\r': i--;`** -- a `\r` costs nothing against the `size-1`
///   budget and is never stored. On a *text*-mode stream this never fires in
///   real Borland either: `\r` never reaches `fgetc` to begin with, squeezed
///   out one layer down by the DOS-handle `read()` (`stream.rs`'s own
///   [`Stream::getc`](crate::stream) doc comment, quoting `READ.CAS`). This
///   host's own [`crate::stream::Streams::line_mem`] has the identical
///   property for the identical reason, so the `.retain` below only ever
///   does anything on a *binary*-mode stream -- one no known caller opens
///   this way.
/// - **`else if (buf[i-1] == 26) { buf[i-1]='\0'; }`** -- strips a soft
///   end-of-file marker defensively. `26` (`^Z`) never reaches `fgetc` in
///   text mode for the same reason `\r` does not (`READ.CAS`'s `endSeen`
///   consumes it and reports `EOF` directly) -- and this host's own
///   [`Stream::getc`](crate::stream) does the identical thing (`CTRL_Z =>
///   { self.ended = true; return Ok(None) }`). So this is not reproduced:
///   the byte it would strip can never appear in `line_mem`'s answer in the
///   first place.
///
/// # The one place this host's accounting differs from `MDFGETS.C`'s
///
/// `MDFGETS.C`'s `\r`-skip costs the `size-1` budget nothing, on *any*
/// stream, by construction of its own loop. This host's budget is
/// `line_mem`'s `max`, which is spent on every byte
/// [`Stream::getc`](crate::stream) hands back -- and on a *binary* stream,
/// unlike a text one, `getc` does return `\r` as an ordinary byte. So a
/// binary-mode `mdfgets` on this host can fill its buffer one `\r`-byte
/// earlier than `MDFGETS.C` would. No known caller opens a stream this way
/// (both measured call sites are text-mode reads of announce/menu files),
/// so this is recorded rather than worked around.
///
/// # `size < 1` is refused, not reproduced
///
/// `MDFGETS.C`'s own loop bound is `size - 1`; at `size == 0` that is `-1`,
/// the loop never runs, and the function still writes one byte
/// (`buf[i]='\0'` at `i == 0`) into a buffer the caller said has none. The
/// same reading [`crate::shims::stream::fgets`]'s own doc comment refuses
/// rather than reproduces ("a host cannot tell that from a call it has
/// misread, and this is the reading that would be wrong in silence").
///
/// # `size == 1` is answered directly, not through `line_mem`
///
/// At `size == 1` the vendor loop bound (`size - 1 == 0`) never runs either,
/// but unlike `size == 0` this is not a bug: the vendor still reaches `buf[i]
/// = '\0'` with `i == 0` and returns `buf` -- **always**, never `NULL`,
/// because the `case EOF:` arm that checks for it is inside the loop body
/// that never executed. `line_mem(mem, cookie, 0)` cannot reproduce that: its
/// own `max == 0` short-circuits before calling
/// [`Stream::getc`](crate::stream) even once, so it cannot observe whether
/// the stream had already ended, and answers `None` if it had -- which
/// `MDFGETS.C` itself never would at this exact size. Handled directly here
/// instead, for the one size this host cannot get from `line_mem` by
/// delegation: write a bare terminator and return `buf`, unconditionally.
///
/// Registers as `_mdfgets`.
pub fn mdfgets<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *mdfgets(char *buf, int size, FILE *fp)` -- `GCOMM.H:321`.
    let buf = call.ptr();
    let size = sign_extend::<A>(call.int().into());
    let cookie = call.ptr();

    if size < 1 {
        return Err(ShimError::Failed(format!(
            "mdfgets with size {size}, which leaves no room even for the terminator"
        )));
    }

    // `size == 1`: see this routine's own doc comment for why `line_mem`
    // cannot answer this one size faithfully, and why the vendor's own
    // control flow never answers `NULL` here regardless of end of file.
    if size == 1 {
        buf.write(call.mem(), &[0])
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        return Ok(abi::Ret::Ptr(buf));
    }

    let Some(mut line) = host
        .streams
        .line_mem(call.mem(), cookie, (size - 1) as usize)
        .map_err(|e| ShimError::Failed(format!("mdfgets: {e}")))?
    else {
        return Ok(abi::Ret::Ptr(A::null_ptr()));
    };

    // `MDFGETS.C`'s `case '\r': i--;` -- see this routine's own doc comment
    // for why this only ever does anything on a binary-mode stream.
    line.retain(|&b| b != b'\r');

    // `MDFGETS.C`'s `case '\n': buf[i++]='\r'; buf[i]='\0'; return(buf);` --
    // the newline becomes the record's own terminator, alone, not `\r\n`.
    if line.last() == Some(&b'\n') {
        line.pop();
        line.push(b'\r');
    }
    line.push(0);

    buf.write(call.mem(), &line)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(buf))
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

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::{FarPtr, Ret};

    use crate::shims::stream::{fclose, fopen};
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

    // ---- fgetc ----------------------------------------------------------

    #[test]
    fn fgetc_reads_the_file_byte_by_byte_and_then_reports_eof() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let on_disk = std::fs::read(crate::testing::data().join("LINES.TXT")).expect("fixture");

        let mut got = Vec::new();
        loop {
            let v = word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc"));
            if v == 0xFFFF {
                break;
            }
            got.push(v as u8);
        }
        assert_eq!(got, on_disk, "binary mode delivers exactly what is on disk");

        // EOF is sticky, the same as `fgets`/`fread` past the end.
        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), 0xFFFF);
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn fgetc_of_a_write_only_stream_is_a_refusal_not_a_plausible_eof() {
        let root = scratch("crt-fgetc-write-only");
        let mut f = Fixture::rooted(root);
        let fp = opened(&mut f, "OUT.DAT", "wb");
        let e = f.invoke(fgetc, &Fixture::far(fp)).expect_err("a refusal");
        assert!(e.to_string().contains("fgetc"), "{e}");
    }

    // ---- fputc ------------------------------------------------------------

    #[test]
    fn fputc_writes_the_low_byte_and_returns_it() {
        let root = scratch("crt-fputc");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.DAT", "wb");

        for &b in b"hi" {
            let ret = f
                .invoke(fputc, &[u16::from(b), fp.offset, fp.selector])
                .expect("fputc");
            assert_eq!(word(ret), u16::from(b), "returns the character it wrote");
        }
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        assert_eq!(std::fs::read(root.join("OUT.DAT")).expect("written"), b"hi");
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
        let mut f = Fixture::new();
        let buf = f.buffer(4);
        f.invoke(itoa, &[42, buf.offset, buf.selector, 1]).expect("itoa");
        assert_eq!(f.read(buf), "");
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

    // ---- mdfgets ------------------------------------------------------------

    #[test]
    fn mdfgets_converts_the_trailing_newline_to_a_lone_carriage_return() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let buf = f.buffer(64);

        let ret = f
            .invoke(mdfgets, &[buf.offset, buf.selector, 64, fp.offset, fp.selector])
            .expect("mdfgets");
        assert_eq!(pointer(ret), buf);
        assert_eq!(f.read(buf), "alpha\r", "not \\r\\n -- MDFGETS.C stores only the \\r");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn mdfgets_answers_null_at_the_end_of_the_file() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let buf = f.buffer(256);

        for _ in 0..3 {
            f.invoke(mdfgets, &[buf.offset, buf.selector, 256, fp.offset, fp.selector])
                .expect("mdfgets");
        }
        let ret = f
            .invoke(mdfgets, &[buf.offset, buf.selector, 256, fp.offset, fp.selector])
            .expect("mdfgets");
        assert_eq!(pointer(ret), FarPtr::NULL, "no fourth line in LINES.TXT");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn mdfgets_with_no_room_for_a_terminator_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let buf = f.buffer(8);
        let e = f
            .invoke(mdfgets, &[buf.offset, buf.selector, 0, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("size 0"), "{e}");
    }

    #[test]
    fn mdfgets_at_size_one_always_answers_a_bare_terminator_never_null() {
        // The one size `line_mem` cannot answer faithfully -- see this
        // routine's own doc comment.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let buf = f.buffer(8);
        let ret = f
            .invoke(mdfgets, &[buf.offset, buf.selector, 1, fp.offset, fp.selector])
            .expect("mdfgets");
        assert_eq!(pointer(ret), buf, "never NULL at size 1, whatever state the stream is in");
        assert_eq!(f.read(buf), "");
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
}
