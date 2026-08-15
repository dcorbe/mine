//! The twelve file routines, ten of them over a `FILE *` the module holds.
//!
//! Borland's, re-exported by `MAJORBBS.DLL`:
//!
//!
//! And two of Galacticomm's own, which ask about a file rather than holding
//! one open:
//!
//!
//! `getdtd` takes a descriptor this crate handed out; `cntdir` takes a path and
//! never opens anything, and leaves its whole answer in three host globals.
//! What a *name* is -- the eleven bytes DOS matched on -- is [`crate::dos`]'s.
//!
//! **Correction, found converting these two to a cursor
//! (docs/plans/2026-08-11-abi-abstraction-implementation.md's Task 4-5):**
//! only `getdtd` is `DSKUTL.H`'s, and `DSKUTL.H` genuinely does not survive --
//! it is not among the 125 headers in `re/wg33src/INC/`, so grepping the bare
//! name finds nothing, which is the closest thing to proof of absence this
//! crate can offer. `cntdir` is a different header's: `re/wg33src/INC/FIOAPI.H`
//! declares it, at lines 174-176, alongside the very `numfils`/`numbyts`/
//! `numbytp` globals [`cntdir`]'s own doc comment already cites -- so it was
//! mis-attributed here, not genuinely missing.
//!
//! What a stream *is* -- the struct, the modes, the text translation -- is
//! [`crate::stream`]'s. This is the part that knows about the module.
//!
//! # `fseek`, `ftell` and `rewind` are here now; the census that excluded
//! them was `WCCMMUD.DLL`-only
//!
//! For a long time this module doc said these three were absent on purpose,
//! because `WCCMMUD.DLL` imports none of them and every stream in it is read
//! or written straight through, once -- there was no legal transition from
//! writing a stream to reading it, so there was nothing to implement.
//!
//! That was a fact about one module, stated as if it were a fact about this
//! host. LunatiX 5.3F
//! (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`) imports `_fseek`,
//! `_ftell`, `_fgetc`, `_fputc`, `_fwrite` and `_flushall`, and opens its own
//! `CWDLOPTS.DAT` for update before reading it -- exactly the transition
//! `WCCMMUD.DLL` never needed. [`fseek`], [`ftell`] and [`rewind`] below are
//! that, over [`crate::stream::Streams::seek_mem`] and
//! [`crate::stream::Streams::tell`]; [`crate::stream::Streams::readable`]'s
//! own doc comment has the other half -- why an update stream is readable at
//! all now.
//!
//! `fputs`, `fscanf`, `getc` and `ungetc` are still genuinely absent: no
//! import census, `WCCMMUD.DLL`'s or LunatiX's, has ever asked for any of
//! them.
//!
//! # `fgetc`, `fputc`, `fwrite` and `flushall` landed with Stage 3's Task 8
//!
//! This paragraph used to list `fwrite`/`fputc`/`fgetc` alongside the four
//! above, on the same "no census has asked" reasoning -- wrong by the time it
//! was written, since the census two paragraphs up already names `_fgetc`,
//! `_fputc` and `_fwrite` among LunatiX's imports. [`fgetc`] and [`fputc`]
//! below are two of the C library routines the plan calls the "seven genuine
//! C library" siblings (`docs/plans/2026-08-14-stage3-channel-entry-implementation.md`,
//! Task 8) -- the third, `fwrite`, was implemented here too but turned out
//! to be a dead duplicate of the registered `shims::crt::fwrite` (removed
//! 2026-08-15, `docs/2026-08-15-dead-twin-shims.md`); `shims::crt` carries
//! it now. [`flushall`] is [`fflush`]'s own "everywhere" -- same honesty
//! about buffering nothing, over every open stream instead of one.
//! `cw3220mt.DLL` aliases onto `MAJORBBS` (`shims::mod::canonical_dll`), which
//! is why `fgetc`/`fputc`/`fwrite` plus `flushall` are registered under
//! `MAJORBBS` rather than a `cw3220mt.DLL`-specific table.
//!
//! Each of the three goes through [`crate::stream::Streams::read_mem`] or
//! [`crate::stream::Streams::write`] exactly as [`fread`]/[`fprintf`] already
//! do -- one byte (or `size*nmemb` bytes) at a time through the same
//! text-mode CR-squeeze/`^Z` translation, not a second read/write path with
//! its own rules to keep in sync.
//!
//! # Two of these may answer instead of refusing
//!
//! `fopen` of a file that is not there returns `NULL`, and `unlink` of one
//! returns -1. Everywhere else a host that cannot do what it was asked stops the
//! module, because a plausible zero is the failure this crate exists to prevent.
//! These two are the exception for the same reason `access` is: **reporting an
//! absence is what they are for**, so the null is the truth rather than a guess.
//!
//! The line is between *absent* and *unreadable*. A file that is not there is an
//! answer; a file that is there and will not open is a refusal, because the
//! module can act on the first and has no way to find out about the second.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;
use mbbs_machine::ptr::ModulePtr;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::dos;
use crate::fmt::format_call;
use crate::shims::{NO, ShimError, sign_extend};
use crate::stream::{Mode, Whence};

/// The null pointer, in this ABI's own representation.
///
/// [`Abi`] has no `NULL` constant (see `shims::user::begin_polling`'s own
/// doc comment for why: a pointer's bit pattern is not part of the trait,
/// only how to en-/decode one) -- but [`Abi::ptr_from_bytes`] decoding
/// [`Abi::PTR_WIDTH`] zero bytes is exactly the null representation both
/// ABIs agree on, the same reading `begin_polling`'s own null check and
/// `Host::point_curusr_mem`'s null write already rely on.
fn null_ptr<A: Abi>() -> A::Ptr {
    A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH])
}

/// `FILE *fopen(const char *path, const char *mode)` -- open one of the
/// module's files.
///
/// The path rule is `opnbtv`'s, and for the same reason: [`Host::dos_name`]
/// takes a bare name or a `.\` prefix and refuses any other directory. It is
/// not theoretical here. The log's path is a *sysop's* to set -- `FUN_10f8_0af5`
/// opens it from a buffer filled in from `WCCMMUD.INI`, defaulting to
/// `wccmmud.log` -- so somebody who wrote `D:\LOGS\MUD.LOG` will get a refusal
/// naming it, rather than a log written somewhere they will never look.
///
/// **Case is resolved before creating.** A write or append goes through
/// [`Host::find`] first, so appending to `wccmmud.log` lands in an existing
/// `WCCMMUD.LOG` instead of making a second file beside it.
///
/// **`mode.read` here is the base letter, deliberately.** A file that is not
/// there is `NULL` for `r` and `r+`, and a create for `w`, `w+`, `a` and `a+` --
/// which is `CheckOpenType`'s `O_CREAT` column and not [`Mode::readable`].
///
/// Generic (Task 5): [`Streams::open_mem`](crate::stream::Streams::open_mem)
/// is already `impl<A: Abi> Streams<A>` -- converting this routine is
/// routing through that generic core instead of its `Wg16` facade
/// ([`Streams::open`](crate::stream::Streams::open)). `Host::dos_name` has
/// no `A`-dependent behaviour at all (see its own doc comment for why it is
/// filed under `impl Host<Wg16>` regardless), so it is named through that
/// concrete type here rather than moved.
pub fn fopen<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `FILE *fopen(const char *path, const char *mode)` -- Borland's, this
    // file's own module doc quotes it, and no Galacticomm header redeclares
    // it (see this file's commit message).
    let path = call.ptr();
    let mode = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let spelt = String::from_utf8_lossy(
        mode.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let mode = Mode::parse(&spelt).map_err(ShimError::Failed)?;
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;

    let path = match host.find(&name) {
        Some(path) => path,

        // Not there, and the module asked to read it. `WCCMMUD.INI` is not
        // shipped -- it is something a sysop writes -- so this is the ordinary
        // case rather than the exceptional one.
        None if mode.read => return Ok(abi::Ret::Ptr(null_ptr::<A>())),

        // Not there, and the module asked to write it. That is a create.
        // `name` may now hold a subdirectory (`Host::dos_name` accepts one),
        // and this host never ran the installer that would have made
        // `LUN5DATA` for it -- an `OpenOptions::create` inside `open_mem`
        // cannot make the directory it lands in, only the file. So the
        // directory is made here, and a failure to make it is reported as
        // that rather than surfacing forty lines away as `open_mem`'s own
        // opaque "No such file or directory".
        None => {
            let at = host.root.join(&name);
            if let Some(parent) = at.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ShimError::Failed(format!("fopen({named}, {spelt}): {}: {e}", parent.display()))
                })?;
            }
            at
        }
    };

    let cookie = host
        .streams
        .open_mem(call.mem(), &name, &path, mode)
        .map_err(|e| ShimError::Failed(format!("fopen({named}, {spelt}): {e}")))?;
    Ok(abi::Ret::Ptr(cookie))
}

/// `int fclose(FILE *f)` -- close a stream.
///
/// Zero, always: the failure `fclose` reports with `EOF` is one this host would
/// have refused already. The cookie is retired rather than reused, so using it
/// afterwards names the file it used to be.
///
/// Generic (Task 5): [`Streams::close`](crate::stream::Streams::close) never
/// touched a `Machine`, so this was already `impl<A: Abi> Streams<A>` before
/// this task.
pub fn fclose<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fclose(FILE *f)` -- Borland's; no Galacticomm header redeclares it.
    let cookie = call.ptr();
    // **`EOF`, not a stop.** `fclose` reports failure the way C says to, in
    // its return value, and the only way `Streams::close` fails is a cookie
    // that names no open stream -- a double close, or a close of something
    // never opened. Borland's runtime answers that with `EOF` and carries on;
    // stopping the machine over it is this host being stricter than the
    // runtime it stands in for, about a value the caller is free to ignore.
    //
    // Found on the shutdown path, which is where it would be: teardown closes
    // things it is not always sure are open, and until `d0cc910` this host
    // never ran a module's `finrou` at all. LunatiX's closes `Cwd5igms.txt`
    // twice.
    //
    // The note is kept because a double close still says something about the
    // module -- it is just not this host's place to end the process over it.
    if let Err(e) = host.streams.close(cookie) {
        host.note(format!("fclose: {e}; answered EOF, as the runtime does"));
        return Ok(abi::Ret::Int(A::Int::from(-1i16 as u16)));
    }
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `char *fgets(char *s, int n, FILE *f)` -- a line, or `NULL` at the end.
///
/// Returns its own first argument, which is why the module can chain it. `n`
/// counts the terminator, so at most `n - 1` bytes come back, and the newline is
/// kept -- `FGETS.C` is one line and says all of that:
///
///
/// **`NULL` at end of file is an answer.** It is how the module finds the end,
/// since it imports no `feof`.
///
/// Generic (Task 5): [`Streams::line_mem`](crate::stream::Streams::line_mem)
/// is already `impl<A: Abi> Streams<A>`, and the terminated line is written
/// back through [`Call::mem`] and [`mbbs_machine::ptr::ModulePtr::write`] rather than
/// `Machine::write`.
pub fn fgets<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *fgets(char *s, int n, FILE *f)` -- Borland's; no Galacticomm
    // header redeclares it (`GCOMM.H`'s `mdfgets` is a different routine with
    // the same shape, not this one -- see this file's commit message).
    let buffer = call.ptr();
    // `n` is an `int`, so it is signed at `A::INT_WIDTH` -- not at 16 bits.
    // Sign-extending from `A`'s own width is what makes the `n < 1` check
    // below mean the same thing under both ABIs: `as i16` turned a 32-bit
    // `70000` into `4464`, and a 32-bit `40000` into a *negative* number that
    // this shim would then have refused outright.
    let n = sign_extend::<A>(call.int().into());
    let cookie = call.ptr();

    // Borland would write the terminator into a buffer it was told has no room
    // for one. A host cannot tell that from a call it has misread, and this is
    // the reading that would be wrong in silence.
    if n < 1 {
        return Err(ShimError::Failed(format!(
            "fgets with n of {n}, which leaves no room even for the terminator"
        )));
    }

    let line = host
        .streams
        .line_mem(call.mem(), cookie, (n - 1) as usize)
        .map_err(|e| ShimError::Failed(format!("fgets: {e}")))?;
    let Some(mut line) = line else {
        return Ok(abi::Ret::Ptr(null_ptr::<A>()));
    };

    line.push(0);
    buffer
        .write(call.mem(), &line)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(buffer))
}

/// `size_t fread(void *p, size_t size, size_t n, FILE *f)` -- a block.
///
/// **A short count is an answer**, and the module depends on it. `FUN_10f8_09ca`
/// reads `WCCMMUD.INI` whole and terminates it at whatever came back:
///
///
/// So the count is what bounds a string the module then parses. Note it is bytes
/// **delivered**, not bytes on the disk: in text mode the `\r` squeeze makes
/// those different numbers.
///
/// Only the bytes actually read are written, which leaves the tail of the
/// module's buffer as it found it.
///
/// Generic (Task 5): [`Streams::read_mem`](crate::stream::Streams::read_mem)
/// is already `impl<A: Abi> Streams<A>`, and the block is written back
/// through [`Call::mem`] and [`mbbs_machine::ptr::ModulePtr::write`].
pub fn fread<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `size_t fread(void *p, size_t size, size_t n, FILE *f)` -- Borland's;
    // no Galacticomm header redeclares it.
    let buffer = call.ptr();
    // `size_t` is `A::INT_WIDTH` bytes, and `call.int()` already read exactly
    // that many -- so widening to `u32` is the whole conversion. These used to
    // be `as u16`, which under `Wg32` truncated before the overflow check
    // below could see the real numbers: `fread(buf, 1, 100000, f)` became
    // `count = 34464`, which then *passed* the check and short-read by 65536
    // bytes in silence. That is worse than the refusal it looked like.
    let size: u32 = call.int().into();
    let count: u32 = call.int().into();
    let cookie = call.ptr();

    if size == 0 || count == 0 {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    // A `size_t` that cannot count the product is a wrap, and a wrap reads the
    // wrong amount into a buffer of the right size -- which nothing
    // downstream could notice. The ceiling is `A`'s own, not 16 bits: Borland
    // would have wrapped at `0xFFFF` compiling for DOS and at `0xFFFFFFFF`
    // compiling for NT, and the point of the check is to refuse what the real
    // runtime would have silently got wrong.
    let ceiling = u64::from(u32::MAX) >> (32 - A::INT_WIDTH * 8);
    let want = u64::from(size) * u64::from(count);
    if want > ceiling {
        return Err(ShimError::Failed(format!(
            "fread of {count} items of {size} bytes, which a {}-bit size_t cannot count",
            A::INT_WIDTH * 8
        )));
    }
    let want = want as u32;

    let bytes = host
        .streams
        .read_mem(call.mem(), cookie, want as usize)
        .map_err(|e| ShimError::Failed(format!("fread: {e}")))?;
    buffer
        .write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    // The count of whole items read, at `A`'s int width -- `as u16` here
    // would have wrapped a 32-bit short read back into a plausible-looking
    // small number.
    Ok(abi::Ret::Int(A::int_from_u32(
        (bytes.len() / size as usize) as u32,
    )))
}

/// `int fgetc(FILE *stream)` -- one byte, or `EOF` at the end.
///
/// Borland's; no Galacticomm header redeclares it. Stage 3's Task 8 (this
/// file's own module doc has the fuller account of why it landed eagerly).
///
/// `EOF` is `-1` at `A`'s own int width, not at 16 bits -- the same trap
/// `shims::text::fold`'s own doc comment describes for `toupper(EOF)`:
/// zero-extending a 16-bit `-1` into a 32-bit `int` gives `0x0000FFFF`, which
/// is `65535`, not `-1`. `u32::MAX >> (32 - A::INT_WIDTH * 8)` is that
/// file's own idiom for "all ones at this ABI's width," reused here rather
/// than a second computation of the same number.
///
/// Goes through [`Streams::read_mem`](crate::stream::Streams::read_mem) with
/// `want = 1`, the same text-mode CR-squeeze and soft `^Z` end-of-file
/// [`Stream::getc`](crate::stream::Stream) already applies for [`fgets`] and
/// [`fread`] -- one byte at a time is exactly what `getc` already does
/// underneath either of those, so there is no second translation to keep
/// in sync.
///
/// # Errors
///
/// If `cookie` names no open stream, or it is not open for reading.
pub fn fgetc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fgetc(FILE *stream)` -- Borland's; no Galacticomm header
    // redeclares it.
    let cookie = call.ptr();
    let byte = host
        .streams
        .read_mem(call.mem(), cookie, 1)
        .map_err(|e| ShimError::Failed(format!("fgetc: {e}")))?;

    let eof = u32::MAX >> (32 - A::INT_WIDTH * 8);
    Ok(abi::Ret::Int(A::int_from_u32(
        byte.first().map_or(eof, |&b| u32::from(b)),
    )))
}

/// `int fputc(int ch, FILE *stream)` -- one byte, echoed back on success.
///
/// Borland's; no Galacticomm header redeclares it. Stage 3's Task 8.
///
/// **No `EOF` return for a failed write.** Unlike [`fgetc`], where the end of
/// a file is an ordinary answer a module polls for, a write that does not
/// succeed is something this host has nothing safe to say about in-band --
/// see [`ShimError`]'s own doc comment ("a plausible zero is the failure this
/// whole design exists to avoid") -- so a stream this host cannot write to
/// stops the module rather than answering `EOF` and letting it read `ferror`
/// this crate does not track.
///
/// Only the low 8 bits of `ch` are written, and the value handed back is
/// that same byte zero-extended to `A`'s own int width -- `WRITE.C`'s own
/// `unsigned char` truncation, which [`crate::stream::Stream::write`]'s
/// per-byte `\n` -> `\r\n` translation is applied to exactly as it is for
/// `shims::crt::fwrite` and [`fprintf`].
///
/// # Errors
///
/// If `cookie` names no open stream, or it is not open for writing.
pub fn fputc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fputc(int ch, FILE *stream)` -- Borland's; no Galacticomm header
    // redeclares it.
    let ch: u32 = call.int().into();
    let cookie = call.ptr();
    let byte = ch as u8;

    host.streams
        .write(cookie, &[byte])
        .map_err(|e| ShimError::Failed(format!("fputc: {e}")))?;
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(byte))))
}


/// `int fprintf(FILE *f, const char *fmt, ...)` -- the print buffer's formatter,
/// with a destination.
///
/// Returns the bytes the module asked to write, not the bytes that reached the
/// disk. `WRITE.C` is explicit about the difference -- "a write to a text file
/// does not count generated carriage returns" -- so the answer is the same in
/// both modes, which is what makes it comparable with `sprintf`.
///
/// # The blocker this needed is gone
///
/// [`crate::fmt::format_call`] is what unblocked this: `fmt.rs`'s own module
/// doc comment describes why the generic walk needed to read through
/// `Call<A>`'s own position rather than a `&Machine` and a word index. Once
/// that existed, this routine converted the same way every other one in this
/// file did -- `cookie` and `template` are `call.ptr()` same as always, and
/// by the time both are read, `call`'s position already marks where the
/// format string's own varargs begin, which is all `format_call` needs.
pub fn fprintf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fprintf(FILE *f, const char *fmt, ...)` -- Borland's; no
    // Galacticomm header redeclares it.
    let cookie = call.ptr();
    let template = call.ptr();
    let (text, _) = format_call(call, template)?;
    host.streams
        .write(cookie, &text)
        .map_err(|e| ShimError::Failed(format!("fprintf: {e}")))?;
    // At `A`'s own int width -- see `sprintf`'s own note on the same line.
    Ok(abi::Ret::Int(A::int_from_u32(text.len() as u32)))
}

/// `int fflush(FILE *f)` -- push what is buffered.
///
/// **Honest as a no-op, and only because nothing here buffers.** C's `fflush`
/// moves a stream's own buffer into the operating system; writes here go
/// straight to the file, so there is nothing between the two to move. It is not
/// a promise about the disk and never was -- Borland's own `fflush` does not
/// reach the platter either.
///
/// The handle is still checked, because a `fflush` of something that was never
/// opened is a module bug whether or not this routine has work to do.
///
/// If a write cache is ever added, this stops being free.
///
/// Generic (Task 5): [`Streams::name`](crate::stream::Streams::name) never
/// touched a `Machine`, so this was already `impl<A: Abi> Streams<A>`
/// before this task.
pub fn fflush<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fflush(FILE *f)` -- Borland's; no Galacticomm header redeclares it.
    let cookie = call.ptr();
    host.streams
        .name(cookie)
        .map_err(|e| ShimError::Failed(format!("fflush: {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int flushall(void)` -- [`fflush`], for every open stream at once.
///
/// Borland's; no Galacticomm header redeclares it. Stage 3's Task 8.
///
/// Same honesty as [`fflush`], for the same reason: nothing here buffers, so
/// there is nothing to push anywhere. Borland's own `flushall` reports how
/// many streams it flushed; this host answers with how many are open, since
/// that is the whole of what "flushed" could mean when there was never
/// anything to flush.
///
/// No handle to check, unlike `fflush` -- `flushall` takes none, so there is
/// no single stream whose absence would be a module bug to catch here.
pub fn flushall<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int flushall(void)` -- Borland's; no Galacticomm header redeclares it.
    Ok(abi::Ret::Int(A::int_from_u32(host.streams.len() as u32)))
}

/// `int unlink(const char *path)` -- remove a file.
///
/// One call site: `_INIT__WCCMMUD` removes `WCCRECOV.FLG` on a clean shutdown,
/// having created it on the way up. -1 for a file that is not there is the
/// truth, and the module treats it as one -- it is guarded by an `access` that
/// has already said the same thing.
///
/// A file that *is* there and will not go is a refusal, on the same line
/// `fopen` draws.
///
/// Generic (Task 5): `Host::dos_name` is named through `Host::<Wg16>` for
/// the same reason [`fopen`] does -- see that routine's own doc comment.
pub fn unlink<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int unlink(const char *path)` -- Borland's; no Galacticomm header
    // redeclares it.
    let path = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;

    let Some(path) = host.find(&name) else {
        return Ok(abi::Ret::Int(A::Int::from(NO)));
    };
    std::fs::remove_file(&path)
        .map_err(|e| ShimError::Failed(format!("unlink({named}): {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `long getdtd(int fhdl)` -- when a file was last written, DOS-packed.
///
/// `DSKUTL.H:79`, and no C source survives. Transcribed from
/// `MAJORBBS-wg101.EXE seg 33:0x16cb`, which fills a Borland `union REGS` with
/// `AX = 0x5700` and `BX = fhdl`, calls `intdos`, and returns `DX:AX` from what
/// comes back -- **`DX` is the date and `AX` the time**, which is what DOS's
/// `AH=57h AL=00h` reports in `DX` and `CX`.
///
/// So the `long` is `(date << 16) | time`, and the module takes it apart in
/// exactly that order. `_BEGIN_UPDATING`
/// (`re/exports/WCCMMUD_decompiled.c:57759`) does:
///
/// ```text
/// uVar4 = getdtd(*(byte *)(fp + 4));           // fileno(fp); FD is 4
/// nctime((int)uVar4);                          // the low half is the time
/// ncdate((int)((ulong)uVar4 >> 0x10));         // the high half is the date
/// ```
///
/// which is an independent confirmation of the halves, of `FD`, and of what
/// those two routines take.
///
/// **The argument is a descriptor, not a `FILE *`.** `fileno` is a Borland
/// macro that reads `FILE.fd` and never reaches this host, so the number
/// arriving here is one this crate handed out. See [`crate::stream`].
///
/// # Errors
///
/// If `fhdl` names no open stream, if the file will not say when it was
/// written, or if it was written outside the years DOS can pack. The original
/// returned whatever DOS left in the registers and could not tell a bad handle
/// from a real answer; this host stops instead.
///
/// Generic (Task 5): touches no memory at all --
/// [`Streams::modified`](crate::stream::Streams::modified) and
/// [`crate::clock::Clock`] are both already ABI-independent.
pub fn getdtd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `long getdtd(int fhdl)` -- DSKUTL.H:79 per this routine's own doc
    // comment above, and DSKUTL.H is not among re/wg33src/INC's 125 headers
    // -- grepping `getdtd` case-insensitively across all of them finds
    // nothing, confirming "no C source survives" still holds.
    let fd = Into::<u32>::into(call.int());
    let fd = u8::try_from(fd).map_err(|_| ShimError::Failed(format!("getdtd: fd {fd} is not one")))?;

    let at = host.streams().modified(fd).map_err(ShimError::Failed)?;

    // Through the host's own calendar rather than `localtime_r`, for the reason
    // the clock exists: `TZ` would make this answer depend on the environment
    // the test runs in. See [`crate::clock`].
    let civil = crate::clock::Clock::pinned(at)
        .civil()
        .map_err(ShimError::Failed)?;
    let date = civil
        .dos_date()
        .map_err(|why| ShimError::Failed(format!("getdtd: {why}")))?;

    Ok(abi::Ret::Long(
        (u32::from(date) << 16) | u32::from(civil.dos_time()),
    ))
}

/// `VOID cntdir(const CHAR *path)` -- count the files and bytes a spec names.
/// `re/wg33src/INC/FIOAPI.H:174-176` -- this file's own module doc has the
/// correction: it was long attributed to `DSKUTL.H`, which is the neighbour
/// that genuinely does not survive.
///
/// No C source (the `.C`, as opposed to the header) survives. It returns
/// nothing: everything it produces it leaves in the globals `numfils`,
/// `numbyts` and `numbytp`, which `FIOAPI.H:134-137` declares and which live
/// in module memory. Four recovered
/// call sites pin the semantics -- `ACCOUNT.C:98`, `BBSRIP.C:314`,
/// `GALMHS.C:366` and `CHANDIR.C:98` -- and between them they establish that
/// `numfils` counts what a `fnd1st`/`fndnxt` loop would have returned, that a
/// bare filename is a legal spec, and that a spec matching nothing is
/// `numfils == 0` rather than a failure.
///
/// **`numdirs` is not touched.** That one is `cntdirs`'s, which `WCCMMUD.DLL`
/// does not import.
///
/// # `numbytp` is `numbyts`, knowingly
///
/// The original's `numbytp` is the *physical* count: each file rounded up to the
/// drive's cluster, `clfit(size, clsize(drive))`. This host has no clusters and
/// no drive whose geometry would make one rounding true rather than another, so
/// it reports the logical size for both and says so here. Inventing a cluster
/// size would make up a number; leaving `numbytp` at whatever the last call put
/// there would be the same invention with worse timing. `WCCMMUD.DLL` addresses
/// `numbyts` at six sites and `numbytp` at none, so nothing this host runs can
/// tell the difference.
///
/// # Errors
///
/// If the spec escapes the module's own directory ([`Host::dos_name`]'s
/// rule, the same one `fopen` and `unlink` keep), if it names a subdirectory
/// at all -- `dos::Name::spec` has no field for a path separator, so a spec
/// `Host::dos_name` now accepts (e.g. `LUN5DATA/*.*`) still fails here,
/// naming the file field rather than the directory rule -- if it is a
/// wildcard with no extension ([`dos::Name::spec`]'s), if the module's
/// directory cannot be read, or if the total will not fit in the `long` the
/// module reads it as.
///
/// **Known gap, not fixed here:** `cntdir` counts only `host.root`'s own
/// entries even for a spec `Host::dos_name` now lets through with a leading
/// subdirectory -- it never `read_dir`s into that subdirectory, it just
/// fails one step later at the FCB parse above. No recovered call site asks
/// it to count inside a subdirectory, so this is not a live divergence, but
/// making `cntdir` walk one is a separate task from the fopen path LunatiX's
/// `INSTALL.CFG` measured.
///
/// A directory that will not open is a refusal and not a zero, because "no such
/// file" and "nobody looked" are the same answer to a module and only one of
/// them is true.
///
/// Generic (Task 5): `Host::dos_name` is named through `Host::<Wg16>` for
/// the same reason [`fopen`] does; the three globals are written through
/// [`Globals::write_mem`](crate::globals::Globals::write_mem) rather than
/// [`Globals::write`](crate::globals::Globals::write).
pub fn cntdir<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;
    let spec =
        dos::Name::spec(&name).map_err(|why| ShimError::Failed(format!("cntdir({named}): {why}")))?;

    let failed =
        |what: &str, e: std::io::Error| ShimError::Failed(format!("cntdir({named}): {what}: {e}"));
    let entries =
        std::fs::read_dir(&host.root).map_err(|e| failed(&host.root.display().to_string(), e))?;

    let mut files: i32 = 0;
    let mut bytes: u64 = 0;
    for entry in entries {
        let entry = entry.map_err(|e| failed(&host.root.display().to_string(), e))?;
        let found = entry.file_name();
        let found = found.to_string_lossy();

        // Not a refusal: a name DOS could not have written down is one no
        // `fnd1st` loop could have returned. See `dos::Name::parse`.
        let Some(found) = dos::Name::parse(&found) else {
            continue;
        };
        if !spec.matches(&found) {
            continue;
        }

        // Through the path rather than the entry, so a symlink is measured as
        // the file it names -- which is what `fopen` on the same name would
        // open.
        let path = entry.path();
        let metadata =
            std::fs::metadata(&path).map_err(|e| failed(&path.display().to_string(), e))?;
        if !metadata.is_file() {
            continue;
        }

        files += 1;
        bytes += metadata.len();
    }

    let bytes = i32::try_from(bytes)
        .map_err(|_| ShimError::Failed(format!("cntdir({named}): {bytes} bytes is not a long")))?;

    let write = |mem: &mut A::Mem, host: &Host<A>, name: &str, value: i32| {
        host.globals()
            .write_mem(mem, name, &value.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))
    };
    write(call.mem(), host, "numfils", files)?;
    write(call.mem(), host, "numbyts", bytes)?;
    write(call.mem(), host, "numbytp", bytes)?;
    Ok(abi::Ret::Void)
}

/// `int fseek(FILE *f, long offset, int whence)` -- move a stream's
/// position.
///
/// Zero on success, matching C's convention (and this crate's own `fclose`
/// note above: the only failures a real caller would see here are ones this
/// host would already have refused before returning at all -- see
/// [`Streams::seek_mem`](crate::stream::Streams::seek_mem)'s own `# Errors`).
/// There is no plausible non-zero to invent for a case this host cannot
/// answer, so a seek this host cannot honour stops the module instead of
/// returning one.
///
/// **A seek past the end of the file is allowed, not refused**, on any
/// stream -- see `Streams::seek_mem`'s own doc comment for why: C only
/// promises this for a writable stream (it creates a hole on the next
/// write), and this host does not narrow the read side to match, because an
/// OS-level seek past a regular file's length is not an error either way.
///
/// # Width discipline
///
/// `offset` is a `long` -- [`Abi::LONG_WIDTH`] bytes in every ABI this crate
/// has met, always signed, so `SEEK_CUR`/`SEEK_END` can move backwards.
/// `call.long()` already hands back the raw bits at that width; `as i32`
/// puts the sign back (a `long` is never narrower than 4 bytes here, so
/// there is no [`sign_extend`]-shaped question to ask of it the way there is
/// for `whence`).
///
/// `whence` is a C `int`, which is [`Abi::INT_WIDTH`] bytes -- 2 under
/// `Wg16`, 4 under `Wg32`. `SEEK_SET`/`SEEK_CUR`/`SEEK_END` are small
/// non-negative values, so the zero-extending `Into::<u32>::into(call.int())`
/// is exactly right and needs no sign at all; what it must **not** be is
/// narrowed back down with `as u16`/`as i16` afterwards -- the idiom this
/// crate found and removed from six other shims (`fgets`, `fread` and
/// their neighbours), because it is `Wg16`'s width hard-coded and silently
/// wrong under `Wg32`.
pub fn fseek<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int fseek(FILE *f, long offset, int whence)` -- Borland's; no
    // Galacticomm header redeclares it.
    let cookie = call.ptr();
    let offset = call.long() as i32 as i64;
    let whence = match Into::<u32>::into(call.int()) {
        0 => Whence::Set,
        1 => Whence::Cur,
        2 => Whence::End,
        other => {
            return Err(ShimError::Failed(format!(
                "fseek: whence {other} is none of SEEK_SET (0), SEEK_CUR (1), SEEK_END (2)"
            )));
        }
    };

    host.streams
        .seek_mem(call.mem(), cookie, offset, whence)
        .map_err(|e| ShimError::Failed(format!("fseek: {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `long ftell(FILE *f)` -- a stream's current position.
///
/// **Returns [`abi::Ret::Long`], not `Ret::Int`.** `ftell` is a `long` in
/// both ABIs -- unlike `fseek`'s `whence`, there is no width this crate needs
/// to reconcile between `Wg16` and `Wg32` here, only the right variant of
/// `Ret` to pick, the same trap `Ret<Wg16>`'s own conversion note (`abi.rs`)
/// warns a swap between `Int` and `Long` is not caught by the type checker.
///
/// # Errors
///
/// If `cookie` names no open stream, or the stream's position does not fit
/// the 32-bit `long` the module reads it back as -- which cannot happen for
/// any file this host can actually open (nothing here maps a file larger
/// than `u32::MAX` bytes), but is checked rather than truncated in silence,
/// on this crate's usual principle that a wrap is worse than a refusal.
pub fn ftell<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `long ftell(FILE *f)` -- Borland's; no Galacticomm header redeclares it.
    let cookie = call.ptr();
    let at = host
        .streams
        .tell(cookie)
        .map_err(|e| ShimError::Failed(format!("ftell: {e}")))?;
    let at = u32::try_from(at)
        .map_err(|_| ShimError::Failed(format!("ftell: position {at} does not fit a 32-bit long")))?;
    Ok(abi::Ret::Long(at))
}

/// `void rewind(FILE *f)` -- put a stream back at the start.
///
/// C defines this as `(void)fseek(stream, 0L, SEEK_SET)` plus clearing the
/// error indicator, and that is exactly what this does: [`fseek`]'s own
/// `SEEK_SET` arm, through the same [`Streams::seek_mem`](crate::stream::Streams::seek_mem).
/// This host tracks no error indicator separate from `_F_EOF` -- there is no
/// `ferror`-only bit anywhere in [`crate::stream::Stream`] -- so "clearing
/// the error indicator" and "clearing `_F_EOF`" are the same write here, and
/// `Stream::seek`'s own doc comment is where that clear happens.
///
/// **Void, not "void unless the seek fails".** C's `rewind` has nowhere to
/// report a failure and does not try to; a real caller cannot tell a refused
/// rewind from a successful one by its return value at all. This host does
/// not invent a way to tell it either: a `rewind` this host cannot honour --
/// only reachable if `cookie` is not a stream this host opened, since
/// `offset` 0 and `SEEK_SET` can never themselves be refused -- stops the
/// module the same way any other unanswerable call does, rather than
/// returning silently and leaving the module's next read wherever the seek
/// did not actually happen.
pub fn rewind<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `void rewind(FILE *f)` -- Borland's; no Galacticomm header redeclares it.
    let cookie = call.ptr();
    host.streams
        .seek_mem(call.mem(), cookie, 0, Whence::Set)
        .map_err(|e| ShimError::Failed(format!("rewind: {e}")))?;
    Ok(abi::Ret::Void)
}

/// File attribute masks `fnd1st`'s `attr` argument is built from --
/// `DOSFACE.H:61-66` (this file's own module doc for the header quote),
/// used only by [`fnd1st`]/[`fndnxt`] below.
const FAMRON: u8 = 0x01;
const FAMHID: u8 = 0x02;
const FAMSYS: u8 = 0x04;
const FAMVID: u8 = 0x08;
const FAMDIR: u8 = 0x10;
#[allow(dead_code)] // named for completeness with the vendor header; never tested against, see `fnd1st`'s own doc comment
const FAMARC: u8 = 0x20;

/// Field offsets of `struct fndblk` at `A`'s own width, and the struct's
/// whole size -- what [`write_fndblk`] writes and this file's own
/// `#[cfg(test)]` block pins down per ABI, per [`fnd1st`]'s own doc comment.
struct FndblkLayout {
    attr: usize,
    time: usize,
    date: usize,
    size: usize,
    name: usize,
    total: usize,
}

impl FndblkLayout {
    /// `char junk[21]` -- both ABIs; a `char` array has no width that varies
    /// with `A::INT_WIDTH`.
    const JUNK: usize = 21;

    /// `char name[12+1]` -- both ABIs, same reason.
    const NAME: usize = 13;

    /// The layout, per ABI -- and the two are not the same structure.
    ///
    /// # Measured, because the header is only half the story
    ///
    /// `DOSFACE.H:51` describes the 16-bit record, and it is DOS's own DTA:
    /// `junk[21]`, `attr` at 21, `time` 22, `date` 24, `size` 26,
    /// `name` 30, 43 bytes in all. That is Borland's 16-bit `struct ffblk`
    /// with Galacticomm's field names on it.
    ///
    /// 32-bit Worldgroup does **not** widen that record. It uses Borland's
    /// *32-bit* `struct ffblk`, which is a different shape entirely:
    ///
    ///
    /// Size comes *before* the attribute, the attribute is a `long`, the
    /// times stay 16 bits, and the name starts at 16 rather than 30.
    ///
    /// # How that was established
    ///
    /// Not from the header, which does not describe it, and not from
    /// `WGSERVER.EXE`, which is not in this tree. LunatiX was made to answer
    /// it: `fnd1st` filled the block with a byte-per-offset marker (`0` at
    /// 0, `1` at 1, ... so the first character read back names the offset it
    /// was read from), the module scanned `lun5elev\*.lun`, and it then
    /// opened `"LUN5ELEV\@ABC..."`. `@` is ASCII 64, the marker for offset
    /// **16**.
    ///
    /// Repeated with a write bounded to 43 bytes, in case a longer one had
    /// clobbered a neighbouring stack buffer and produced the same answer by
    /// accident. Same result.
    ///
    /// # What getting it wrong looked like
    ///
    /// Worth recording, because it was not a crash and not obviously a
    /// layout problem. Writing the name at 30 (the DOS offset) or 36 (what
    /// "`unsigned` follows `INT_WIDTH`" would give) left a zero byte where
    /// the module looked, so it read an empty filename, built
    /// `"LUN5ELEV\" + ""`, and opened **the directory**. The failure
    /// surfaced three calls later as `fgets: Is a directory`.
    fn of<A: Abi>() -> Self {
        if A::PTR_WIDTH >= 4 && A::INT_WIDTH >= 4 {
            // Borland 32-bit `struct ffblk`. `total` is what this host
            // writes, not the structure's own 272 bytes: the tail of
            // `ff_name` is the module's and there is nothing to put in it.
            Self { attr: 8, time: 12, date: 14, size: 4, name: 16, total: 16 + Self::NAME }
        } else {
            // Borland 16-bit `struct ffblk`, which is DOS's DTA.
            Self { attr: 21, time: 22, date: 24, size: 26, name: 30, total: 30 + Self::NAME }
        }
    }
}

/// One file [`fnd1st`]/[`fndnxt`] will hand back: where it is on this host's
/// disk, and the DOS name already validated against the spec -- built once,
/// at scan time, so [`fndnxt`] never re-parses a filename it already parsed
/// to decide the match in the first place.
#[derive(Debug, Clone)]
pub(crate) struct FoundEntry {
    at: PathBuf,
    name: dos::Name,
}

/// Identify one scan: which `fbptr` buffer it is behind, and which `Abi`'s
/// own pointer encoding produced those bytes.
///
/// The `Abi` half exists only to be honest about a hypothetical: two ABIs
/// could in principle encode two different addresses to the same raw bytes,
/// and nothing about a raw `Vec<u8>` key alone would tell them apart. In
/// practice this crate's own single-threaded design (see [`SCANS`]'s own
/// doc comment) means one thread's [`SCANS`] table only ever holds one
/// `Abi`'s pointers at a time, so this is a belt no observed scenario needs
/// -- kept because a key collision would be silent corruption, which is the
/// one thing this crate refuses to let through anywhere.
fn scan_key<A: Abi>(fbptr: A::Ptr) -> (&'static str, Vec<u8>) {
    (std::any::type_name::<A>(), A::ptr_to_bytes(fbptr))
}

/// Resolve every component but the last of a `/`-joined path (already
/// through [`Host::dos_name`]) against `root`, case-insensitively -- the
/// same walk [`Host::find`] does, restricted to directory components so it
/// can stop one short of the final, possibly-wildcarded, name.
///
/// `dirs` is empty for a bare filename with no subdirectory at all, which
/// this answers with `root` itself rather than making a caller special-case
/// it.
fn resolve_dir(root: &Path, dirs: &str) -> Option<PathBuf> {
    let mut at = root.to_path_buf();
    for part in dirs.split('/').filter(|p| !p.is_empty()) {
        at = std::fs::read_dir(&at)
            .ok()?
            .filter_map(Result::ok)
            .find(|e| {
                e.file_name().to_string_lossy().eq_ignore_ascii_case(part)
                    && e.path().is_dir()
            })
            .map(|e| e.path())?;
    }
    Some(at)
}

/// Fill `fbptr`'s `fndblk` with what `found` says about one file, at `A`'s
/// own [`FndblkLayout`].
///
/// **`junk` is zeroed, not reproduced.** Nothing in this crate reads it back
/// -- `Host::finds` carries the equivalent state host-side, see its own
/// doc comment -- so there is no DOS DTA byte format to get right here; a
/// zero fill is honest about "this host has nothing to put there" rather
/// than inventing bytes that look like real DOS internals but are not.
fn write_fndblk<A: Abi>(mem: &mut A::Mem, fbptr: A::Ptr, found: &FoundEntry) -> Result<(), ShimError> {
    let failed = |what: &str, e: String| {
        ShimError::Failed(format!("fnd1st/fndnxt({}): {what}: {e}", found.at.display()))
    };

    let metadata = std::fs::metadata(&found.at).map_err(|e| failed("metadata", e.to_string()))?;

    // Only what the filesystem actually says: `FAMDIR` when it is a
    // directory, `FAMRON` when it is not writable. No host equivalent of
    // DOS's hidden/system/archive bits exists, and inventing one would be
    // the plausible-but-wrong answer this crate exists to refuse -- see
    // `fnd1st`'s own doc comment for `FAMHID`/`FAMSYS`/`FAMARC`.
    let mut attr = 0u8;
    if metadata.is_dir() {
        attr |= FAMDIR;
    }
    if metadata.permissions().readonly() {
        attr |= FAMRON;
    }

    // Through the host's own calendar, not `SystemTime` directly -- the
    // same reason `getdtd` above does, and the same conversions:
    // `Clock::pinned` plus `Civil::dos_date`/`dos_time`.
    let modified = metadata
        .modified()
        .map_err(|e| failed("modified", e.to_string()))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| failed("modified", e.to_string()))?
        .as_secs();
    let modified = u32::try_from(modified)
        .map_err(|_| failed("modified", "does not fit this host's clock".to_string()))?;
    let civil = crate::clock::Clock::pinned(modified)
        .civil()
        .map_err(|e| failed("modified", e))?;
    let date = civil.dos_date().map_err(|e| failed("modified", e))?;
    let time = civil.dos_time();

    let size = u32::try_from(metadata.len())
        .map_err(|_| failed("size", format!("{} bytes does not fit a 32-bit long", metadata.len())))?;

    let layout = FndblkLayout::of::<A>();
    let mut bytes = vec![0u8; layout.total];
    if layout.name == 16 {
        // `unsigned long ff_attrib` -- four bytes, not one. See
        // `FndblkLayout::of`.
        bytes[layout.attr..layout.attr + 4].copy_from_slice(&u32::from(attr).to_le_bytes());
    } else {
        bytes[layout.attr] = attr;
    }
    // Two bytes each, and four for the size -- the measured layout, not
    // `A::INT_WIDTH`. See `FndblkLayout::of`.
    bytes[layout.time..layout.time + 2].copy_from_slice(&time.to_le_bytes());
    bytes[layout.date..layout.date + 2].copy_from_slice(&date.to_le_bytes());
    bytes[layout.size..layout.size + 4].copy_from_slice(&size.to_le_bytes());
    let rendered = found.name.display();
    let rendered = rendered.as_bytes();
    // `NAME` (13) is `8 + 1 + 3`, and `display` never produces more than
    // `8 + 1 + 3` non-NUL bytes -- `Name::parse` already refused anything
    // longer on the way in (`dos.rs`'s own "not a name DOS could have had").
    bytes[layout.name..layout.name + rendered.len()].copy_from_slice(rendered);
    // The byte after it is already 0 from the zero-fill above, which is the
    // terminator.

    fbptr.write(mem, &bytes).map_err(|e| failed("write", e.to_string()))
}

/// `int fnd1st(struct fndblk *fbptr, char *filspc, char attr)` -- the first
/// file `filspc` names, `1`/`0` for found/none.
///
/// `struct fndblk` -- `DOSFACE.H:52-59` (this file's own module doc quotes
/// the whole header):
///
///
/// # The struct's layout is ABI-dependent, and half of it is inferred
///
/// `unsigned time`/`unsigned date` are `A::INT_WIDTH` bytes -- 2 under
/// `Wg16`, 4 under `Wg32` -- so this struct has two different shapes, not
/// one shape read at two widths. [`FndblkLayout::of`] computes both; this
/// paragraph is the reasoning, and `#[cfg(test)]`'s
/// `fndblk_layout_matches_the_derived_offset_table_for_both_abis` pins the
/// resulting numbers down so a change to either is a test failure rather
/// than a silent one.
///
/// **`Wg16`: measured, from the vendor header itself.** 16-bit Borland
/// compiled this byte-packed -- `junk` 0..21, `attr` 21, `time` 22, `date`
/// 24, `size` 26, `name` 30..43, total 43. Every field starts exactly where
/// the one before it ends; there is no padding to derive.
///
/// **`Wg32`: INFERRED, NOT MEASURED against a real WGSERVER.** No 32-bit
/// Galacticomm binary this repo has decompiled carries this struct or a
/// caller of it -- `re/wg33src` has never had a 32-bit `DOSFACE.H` pass
/// through it -- so this is Borland C++ 5.x's *documented default* applied
/// to the vendor's own field order, not a fact read out of a binary.
/// `bcc32`'s default is natural member alignment up to an 8-byte ceiling
/// that never engages here (nothing in this struct is wider than 4 bytes):
/// a member aligns to its own size, so the two 4-byte `unsigned`s and the
/// 4-byte `long` each need 4-byte alignment, and the struct's own size
/// rounds up to its largest member's alignment so an array of `fndblk`
/// stays aligned element to element. That inserts padding a byte-packed
/// 16-bit build never had: two bytes between `attr` (21) and `time` (pushed
/// to 24), and three trailing bytes after `name` (49 rounds up to 52).
/// **What would confirm this:** a real `bcc32` (Borland C++ 5.x, Win32
/// target) compiling this exact struct and reporting `sizeof`/`offsetof`
/// for each field -- no such compiler is in `archive/` today (checked while
/// writing this) -- or a decompiled 32-bit `WGSERVER`/`DOSCALLS` binary with
/// a `fnd1st`/`fndnxt` caller whose field accesses pin the same offsets
/// `getdtd`'s own doc comment pins for its own struct.
///
/// # `attr`'s width
///
/// `char attr` is promoted to `int` in a cdecl call, so it is read with
/// `call.int()` like every other C `int` argument -- never narrowed with the
/// `as u16`/`as i16` idiom this crate removed elsewhere. Taking the low byte
/// back out of the zero-extended `u32` (`Into::<u32>::into(call.int()) as
/// u8`) recovers the original `char`'s bits regardless of whether Borland's
/// default `char` was signed: sign- and zero-extension agree on the low 8
/// bits, which is all `attr`'s bitmask ever needed.
///
/// # What `attr` includes
///
/// The FAM masks control inclusion, not the reported `attr` byte -- see
/// `DOSFACE.H`'s own comment, and this file's module doc for the mask
/// values. Ordinary files always match, the same as real `FindFirst`:
/// `FAMDIR` additionally admits subdirectories into the scan. This host has
/// no equivalent of DOS hidden/system/volume-label attributes -- a name
/// [`dos::Name::parse`] accepts is never hidden or system the DOS way to
/// begin with (a Unix dotfile already fails to parse as a DOS name, the
/// same exclusion [`cntdir`]'s own doc comment describes) -- so `FAMHID`,
/// `FAMSYS` and `FAMVID` in `attr` are accepted without error but can never
/// widen a scan on this host: there is nothing here for them to admit.
///
/// # Scan state
///
/// The match list is computed once here, sorted by DOS name for a
/// deterministic order this host has no on-disk equivalent for otherwise
/// (real DOS's order was whatever the FAT directory happened to hold), and
/// the first entry is written and consumed immediately -- `fnd1st` itself
/// counts as the scan's first answer, not a setup step before `fndnxt`'s
/// first one. What is left after that is [`fndnxt`]'s to drain; see
/// `Host::finds`'s own doc comment for where it lives and what interleaving two
/// scans does.
///
/// # Errors
///
/// If `filspc` escapes the module's own directory or names a subdirectory
/// this host cannot see ([`Host::dos_name`]'s rule, the same one [`fopen`]
/// and [`cntdir`] keep), if the final component is not a spec DOS could have
/// parsed ([`dos::Name::spec`]'s), if the directory cannot be read, or if a
/// matched file's size or modified time will not fit what the module reads
/// it back as.
pub fn fnd1st<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let fbptr = call.ptr();
    let filspc = call.ptr();
    let attr = Into::<u32>::into(call.int()) as u8;

    let named = String::from_utf8_lossy(
        filspc.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;

    let (dir, spec_part) = match name.rsplit_once('/') {
        Some((dir, file)) => (dir, file),
        None => ("", name.as_str()),
    };
    let spec = dos::Name::spec(spec_part)
        .map_err(|why| ShimError::Failed(format!("fnd1st({named}): {why}")))?;

    let at = resolve_dir(&host.root, dir).ok_or_else(|| {
        ShimError::Failed(format!("fnd1st({named}): {dir} is not a directory this host can see"))
    })?;

    let entries = std::fs::read_dir(&at)
        .map_err(|e| ShimError::Failed(format!("fnd1st({named}): {}: {e}", at.display())))?;

    let include_dirs = attr & FAMDIR != 0;
    let mut matches = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| ShimError::Failed(format!("fnd1st({named}): {}: {e}", at.display())))?;
        let found = entry.file_name();
        let found = found.to_string_lossy();

        // Not a refusal: a name DOS could not have written down is one no
        // real `fnd1st` loop could have returned. See `dos::Name::parse`.
        let Some(parsed) = dos::Name::parse(&found) else {
            continue;
        };
        if !spec.matches(&parsed) {
            continue;
        }

        let path = entry.path();
        let metadata =
            std::fs::metadata(&path).map_err(|e| ShimError::Failed(format!("fnd1st({named}): {}: {e}", path.display())))?;
        if metadata.is_dir() {
            if !include_dirs {
                continue;
            }
        } else if !metadata.is_file() {
            continue;
        }

        matches.push(FoundEntry { at: path, name: parsed });
    }
    matches.sort_by(|a, b| a.name.display().cmp(&b.name.display()));

    let mut remaining: VecDeque<FoundEntry> = matches.into();
    let first = remaining.pop_front();
    let found = first.is_some();
    if let Some(entry) = &first {
        write_fndblk::<A>(call.mem(), fbptr, entry)?;
    }

    host.finds.insert(scan_key::<A>(fbptr), remaining);

    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `int fndnxt(struct fndblk *fbptr)` -- the next file the same `fnd1st`
/// scan matched, `1`/`0` for one more/no more.
///
/// See [`fnd1st`]'s own doc comment for the struct layout and `Host::finds`'s
/// for how the scan's position is kept and what reusing an `fbptr`
/// mid-scan does.
///
/// # Errors
///
/// If `fbptr` names no scan [`fnd1st`] has started. A stale scan that has
/// already run out answers plain `0` here, same as real `fndnxt` -- the
/// distinction this host draws is "never started" (a host bug, refused,
/// the same principle [`fclose`]'s own doc comment states for a handle
/// this host never issued) versus "started and finished" (an ordinary `0`,
/// same as [`cntdir`]'s "spec matching nothing" is a `0` and not a
/// refusal).
pub fn fndnxt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let fbptr = call.ptr();
    let key = scan_key::<A>(fbptr);

    let next = match host.finds.get_mut(&key) {
        Some(remaining) => remaining.pop_front(),
        None => {
            return Err(ShimError::Failed(
                "fndnxt: no fnd1st scan in progress for this find block".to_string(),
            ));
        }
    };

    match next {
        Some(entry) => {
            write_fndblk::<A>(call.mem(), fbptr, &entry)?;
            Ok(abi::Ret::Int(A::Int::from(1u16)))
        }
        None => Ok(abi::Ret::Int(A::Int::from(0u16))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::FarPtr;

    use crate::stream::FILE_SIZE;
    use crate::testing::{Fixture, scratch, scratch_with};

    /// The flag words, spelt as `STDIO.H` spells them rather than as this crate
    /// does -- a test that imported the host's constants would agree with a host
    /// that had them wrong.
    const F_READ: u16 = 0x0001;
    const F_WRIT: u16 = 0x0002;
    const F_EOF: u16 = 0x0020;
    const F_BIN: u16 = 0x0040;

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

    /// `fseek(fp, offset, whence)`. `offset` is a signed 32-bit `long`, laid
    /// out low word then high word -- the same spacing `lngrnd`'s own tests
    /// (`shims::system`) pin for a `long` argument.
    fn seek(f: &mut Fixture, fp: FarPtr, offset: i32, whence: u16) -> Result<Ret, ShimError> {
        let bits = offset as u32;
        f.invoke(fseek,
            &[fp.offset, fp.selector, bits as u16, (bits >> 16) as u16, whence],
        )
    }

    /// `ftell(fp)`, as the position it answered.
    fn tell(f: &mut Fixture, fp: FarPtr) -> u32 {
        long(f.invoke(ftell, &Fixture::far(fp)).expect("ftell"))
    }

    /// `fopen(name, mode)`.
    fn open(f: &mut Fixture, name: &str, mode: &str) -> Result<Ret, ShimError> {
        let path = f.text(name);
        let how = f.text(mode);
        f.invoke(fopen,
            &[path.offset, path.selector, how.offset, how.selector],
        )
    }

    /// `fopen` that must succeed, as the `FILE *` it returned.
    fn opened(f: &mut Fixture, name: &str, mode: &str) -> FarPtr {
        pointer(open(f, name, mode).unwrap_or_else(|e| panic!("fopen({name}, {mode}): {e}")))
    }

    /// `fgets(buf, n, fp)`, as the string it left behind, or `None` for `NULL`.
    fn gets(f: &mut Fixture, fp: FarPtr, n: u16) -> Option<String> {
        let buffer = f.bytes(&vec![0xff; usize::from(n) + 8], false);
        let ret = f
            .invoke(fgets, &[buffer.offset, buffer.selector, n, fp.offset, fp.selector])
            .expect("fgets");
        match ret {
            Ret::Far(FarPtr {
                offset: 0,
                selector: 0,
            }) => None,
            Ret::Far(at) => {
                assert_eq!(at, buffer, "fgets returns its own first argument");
                Some(f.read(buffer))
            }
            _ => panic!("expected a far pointer"),
        }
    }

    /// The twenty bytes of `FILE` the module can see.
    fn image(f: &Fixture, fp: FarPtr) -> Vec<u8> {
        f.machine.resolve(fp, FILE_SIZE).expect("a FILE").to_vec()
    }

    fn flags_of(f: &Fixture, fp: FarPtr) -> u16 {
        let bytes = image(f, fp);
        u16::from_le_bytes([bytes[2], bytes[3]])
    }

    // ---- 1. absence is an answer -------------------------------------------

    #[test]
    fn opening_a_file_that_is_not_there_is_null_rather_than_a_refusal() {
        // The one thing initialisation depends on: `WCCMMUD.INI` is not shipped
        // with MajorMUD, so this is the ordinary case and not a failure.
        let mut f = Fixture::new();
        let ret = open(&mut f, "wccmmud.ini", "rt").expect("an answer, not a refusal");
        assert_eq!(pointer(ret), FarPtr::NULL);
        assert!(f.host.streams().is_empty());
    }

    #[test]
    fn a_file_that_is_there_and_will_not_open_is_a_refusal() {
        // Absent and unreadable are different facts. A directory where the
        // module wants a file is the deterministic way to arrange the second
        // without depending on who the test runs as.
        let root = scratch("stream-unopenable");
        std::fs::create_dir(root.join("SUB.DAT")).expect("a directory in the way");
        let mut f = Fixture::rooted(root);
        // Write mode, because `Host::find` only reports *files* -- so a read of
        // this name is genuinely "not there" and returns NULL.
        let e = open(&mut f, "SUB.DAT", "w").expect_err("a refusal");
        assert!(e.to_string().contains("SUB.DAT"), "{e}");
    }

    // ---- 2-4. reading lines -------------------------------------------------

    #[test]
    fn a_text_file_is_read_a_line_at_a_time_and_ends_with_null() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");

        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("alpha\n"));
        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("beta\n"));
        assert_eq!(
            gets(&mut f, fp, 64).as_deref(),
            Some("the third line is longer than sixteen bytes\n")
        );
        assert_eq!(gets(&mut f, fp, 64), None, "NULL is how the module finds the end");

        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
    }

    #[test]
    fn the_same_file_reads_differently_in_text_and_binary() {
        // The test that would pass with the translation missing entirely if it
        // used only one mode.
        let mut f = Fixture::new();

        let text = opened(&mut f, "LINES.TXT", "rt");
        assert_eq!(gets(&mut f, text, 64).as_deref(), Some("alpha\n"));

        let binary = opened(&mut f, "LINES.TXT", "rb");
        assert_eq!(gets(&mut f, binary, 64).as_deref(), Some("alpha\r\n"));
    }

    #[test]
    fn every_carriage_return_is_dropped_in_text_mode_not_only_those_before_a_newline() {
        // Borland's `READ.CAS` has no lookahead: `cmp al, 0Dh / je elseSqueeze`
        // deletes a `\r` whether or not a `\n` follows. `be\rta` reads as `beta`.
        let mut f = Fixture::new();

        let text = opened(&mut f, "LINES.TXT", "rt");
        gets(&mut f, text, 64);
        assert_eq!(gets(&mut f, text, 64).as_deref(), Some("beta\n"));

        let binary = opened(&mut f, "LINES.TXT", "rb");
        gets(&mut f, binary, 64);
        assert_eq!(gets(&mut f, binary, 64).as_deref(), Some("be\rta\r\n"));
    }

    #[test]
    fn a_control_z_ends_a_text_file_and_does_not_end_a_binary_one() {
        // DOS's soft end-of-file: `READ.CAS`'s `endSeen` seeks back and latches
        // `_O_EOF`, so nothing past it is ever delivered.
        let mut f = Fixture::new();

        let text = opened(&mut f, "CTRLZ.TXT", "rt");
        assert_eq!(gets(&mut f, text, 64).as_deref(), Some("kept\n"));
        assert_eq!(gets(&mut f, text, 64), None, "^Z is the end of the file");
        assert_eq!(flags_of(&f, text) & F_EOF, F_EOF);

        let binary = opened(&mut f, "CTRLZ.TXT", "rb");
        gets(&mut f, binary, 64);
        assert_eq!(
            gets(&mut f, binary, 64).as_deref(),
            Some("\u{1a}dropped\r\n"),
            "binary mode has no soft end-of-file"
        );
    }

    #[test]
    fn a_short_buffer_returns_part_of_a_line_and_the_next_call_continues_it() {
        // Not "skips to the next line", which is the plausible wrong answer.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");

        assert_eq!(gets(&mut f, fp, 4).as_deref(), Some("alp"));
        assert_eq!(gets(&mut f, fp, 4).as_deref(), Some("ha\n"));
        assert_eq!(gets(&mut f, fp, 4).as_deref(), Some("bet"));
    }

    #[test]
    fn fgets_with_no_room_for_a_terminator_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let buffer = f.buffer(8);
        let e = f
            .invoke(fgets, &[buffer.offset, buffer.selector, 0, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("n of 0"), "{e}");
    }

    // ---- 5, 15. blocks ------------------------------------------------------

    #[test]
    fn reading_past_the_end_is_a_short_count_and_leaves_the_rest_of_the_buffer() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");

        let want = 200u16;
        let buffer = f.bytes(&vec![0xff; usize::from(want)], false);
        let got = word(
            f.invoke(fread,
                &[
                    buffer.offset,
                    buffer.selector,
                    1,
                    want,
                    fp.offset,
                    fp.selector,
                ],
            )
            .expect("fread"),
        );

        let on_disk = std::fs::metadata(crate::testing::data().join("LINES.TXT"))
            .expect("the fixture")
            .len() as u16;
        assert_eq!(got, on_disk, "binary delivers what is there");

        let seen = f.machine.resolve(buffer, usize::from(want)).expect("buffer");
        assert!(
            seen[usize::from(got)..].iter().all(|b| *b == 0xff),
            "the tail of the module's buffer is left alone"
        );
        assert_eq!(flags_of(&f, fp) & F_EOF, F_EOF);
    }

    #[test]
    fn a_text_read_counts_the_bytes_delivered_rather_than_the_bytes_on_disk() {
        // What `FUN_10f8_09ca` terminates `WCCMMUD.INI` at. Four `\r` in the
        // fixture, so text mode is four shorter -- and a host that returned the
        // disk length would leave four bytes of rubbish on the end of the INI.
        let mut f = Fixture::new();
        let on_disk = std::fs::metadata(crate::testing::data().join("LINES.TXT"))
            .expect("the fixture")
            .len() as u16;

        let mut count = |mode| {
            let fp = opened(&mut f, "LINES.TXT", mode);
            let buffer = f.buffer(200);
            word(
                f.invoke(fread,
                    &[buffer.offset, buffer.selector, 1, 200, fp.offset, fp.selector],
                )
                .expect("fread"),
            )
        };

        assert_eq!(count("rb"), on_disk);
        assert_eq!(count("rt"), on_disk - 4, "the four carriage returns are gone");
    }

    #[test]
    fn a_block_count_a_16_bit_size_t_cannot_hold_is_refused() {
        // Borland would have wrapped, and a wrap reads the wrong amount into a
        // buffer of the right size.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let buffer = f.buffer(64);
        let e = f
            .invoke(fread,
                &[buffer.offset, buffer.selector, 256, 256, fp.offset, fp.selector],
            )
            .expect_err("a refusal");
        assert!(e.to_string().contains("16-bit size_t"), "{e}");
    }

    // ---- fgetc/fputc/fwrite/flushall (Task 8) --------------------------------

    #[test]
    fn fgetc_reads_one_byte_at_a_time_and_ends_with_eof() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");

        // "alpha\r\n..." -- binary mode, so the carriage return survives.
        for want in b"alpha\r\n" {
            assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), u16::from(*want));
        }
    }

    #[test]
    fn fgetc_at_end_of_file_answers_eof_not_a_plausible_zero() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        loop {
            if word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")) == 0xffff {
                break;
            }
        }
        // Reading again past the end keeps answering EOF, not 0.
        assert_eq!(word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc")), 0xffff);
    }

    #[test]
    fn fgetc_squeezes_carriage_returns_in_text_mode_same_as_fgets() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let mut got = Vec::new();
        loop {
            let c = word(f.invoke(fgetc, &Fixture::far(fp)).expect("fgetc"));
            if c == 0xffff {
                break;
            }
            got.push(c as u8);
        }
        assert!(!got.contains(&b'\r'), "text mode drops every carriage return");
    }

    #[test]
    fn fputc_writes_one_byte_and_echoes_it_back() {
        let root = scratch("stream-fputc");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.LOG", "wb");

        for &b in b"hi" {
            let echoed = word(
                f.invoke(fputc, &[u16::from(b), fp.offset, fp.selector]).expect("fputc"),
            );
            assert_eq!(echoed, u16::from(b));
        }
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
        assert_eq!(std::fs::read(root.join("OUT.LOG")).expect("the log"), b"hi");
    }

    #[test]
    fn fputc_translates_a_newline_in_text_mode_same_as_fprintf() {
        let root = scratch("stream-fputc-crlf");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.LOG", "wt");
        f.invoke(fputc, &[u16::from(b'\n'), fp.offset, fp.selector])
            .expect("fputc");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
        assert_eq!(std::fs::read(root.join("OUT.LOG")).expect("the log"), b"\r\n");
    }

    #[test]
    fn fputc_to_a_stream_opened_for_reading_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let e = f
            .invoke(fputc, &[u16::from(b'x'), fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("fputc"), "{e}");
    }

    #[test]
    fn flushall_answers_how_many_streams_are_open() {
        let mut f = Fixture::new();
        assert_eq!(word(f.invoke(flushall, &[]).expect("flushall")), 0);

        let a = opened(&mut f, "LINES.TXT", "rt");
        let _b = opened(&mut f, "LINES.TXT", "rt");
        assert_eq!(word(f.invoke(flushall, &[]).expect("flushall")), 2);

        f.invoke(fclose, &Fixture::far(a)).expect("fclose");
        assert_eq!(word(f.invoke(flushall, &[]).expect("flushall")), 1);
    }

    // ---- 13, 14. the struct the module reads without asking -----------------

    #[test]
    fn the_file_the_module_receives_is_filled_in_rather_than_zeroed() {
        // `feof`, `ferror` and `fileno` are macros: they read these bytes and
        // never call the host, so this is the only place they can be checked.
        let mut f = Fixture::new();

        let text = opened(&mut f, "LINES.TXT", "rt");
        let bytes = image(&f, text);
        assert_eq!(bytes.len(), 20, "Borland's FILE is twenty bytes");
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), F_READ);
        assert!(bytes[4] >= 5, "fd 0-4 are stdin, stdout, stderr, stdaux, stdprn");

        let binary = opened(&mut f, "LINES.TXT", "rb");
        assert_eq!(flags_of(&f, binary), F_READ | F_BIN);
        assert_ne!(
            image(&f, binary)[4],
            bytes[4],
            "two open streams have different descriptors"
        );
    }

    #[test]
    fn a_write_stream_says_so_in_its_flags() {
        let mut f = Fixture::rooted(scratch("stream-flags"));
        let fp = opened(&mut f, "OUT.LOG", "at");
        assert_eq!(flags_of(&f, fp), F_WRIT);
    }

    #[test]
    fn opening_a_file_for_write_in_a_subdirectory_makes_the_directory_lunatix_never_installed() {
        // A fresh board never ran LunatiX's installer, so `LUN5DATA` is not
        // there yet -- and the `OpenOptions::create` inside `open_mem` can
        // only make the file, not the directory it lands in. `fopen` has to
        // make that directory itself, the way `INSTALL.CFG`'s `MAKEDIR`
        // would have.
        let root = scratch("stream-subdirectory-create");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "lun5data\\lunrand1.txt", "wt");
        assert_eq!(flags_of(&f, fp), F_WRIT);
        assert!(
            root.join("lun5data").join("lunrand1.txt").is_file(),
            "fopen must create lun5data/ before creating the file inside it"
        );
    }

    #[test]
    fn a_stream_opened_for_update_is_both_in_its_flags_and_truncates() {
        // MajorMUD's one update stream: `fopen("log.log", "w+")` at
        // seg 34:0x010a, and the mode is its own -- `log.log` and `w+` sit
        // adjacent in the module's data at file offset 0xe240a. `w+` is
        // `O_RDWR | O_CREAT | O_TRUNC` and `_F_READ | _F_WRIT`, per
        // `CheckOpenType`'s own table at FOPEN.C:49.
        let root = scratch("stream-update");
        std::fs::write(root.join("LOG.LOG"), b"stale\r\n").expect("a stale log");

        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "log.log", "w+");
        assert_eq!(
            flags_of(&f, fp),
            F_READ | F_WRIT,
            "a `+` is _F_RDWR, whatever the base letter was"
        );

        let template = f.text("a\nb\n");
        f.invoke(fprintf,
            &[fp.offset, fp.selector, template.offset, template.selector],
        )
        .expect("fprintf");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        // Truncated rather than appended to -- the base letter is still `w` --
        // and still a text stream, because a bare `w+` takes `_fmode`'s
        // default. Found as `LOG.LOG` from the module's own `log.log`, which is
        // `Host::find`'s rule and not a second file beside it.
        assert_eq!(
            std::fs::read(root.join("LOG.LOG")).expect("the log"),
            b"a\r\nb\r\n"
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("the directory").count(),
            1,
            "and not a second file beside it"
        );
    }

    #[test]
    fn end_of_file_appears_in_the_flags_only_once_a_read_has_hit_it() {
        // An `_F_EOF` that never becomes true is a read loop with no host call
        // to refuse it. One that is set too early stops the module short.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        assert_eq!(flags_of(&f, fp) & F_EOF, 0, "nothing has been read yet");

        while gets(&mut f, fp, 64).is_some() {
            // The last line still leaves the stream unended: the newline
            // terminated it before the read reached the end of the file.
        }
        assert_eq!(flags_of(&f, fp) & F_EOF, F_EOF);
    }

    // ---- 7, 8, 10. refusals -------------------------------------------------

    #[test]
    fn a_handle_used_after_closing_is_refused_by_name() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        let buffer = f.buffer(64);
        let e = f
            .invoke(fgets, &[buffer.offset, buffer.selector, 64, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(
            e.to_string().contains("LINES.TXT was closed"),
            "the address is retired, so the refusal can name the file: {e}"
        );

        // Closing it a second time is `EOF`, not a stop: that is what C says
        // `fclose` does and what Borland's runtime did. The note still names
        // the file, so the double close is visible without being fatal.
        let again = f.invoke(fclose, &Fixture::far(fp)).expect("a second fclose answers");
        assert_eq!(again, Ret::U16(0xFFFF), "EOF");
        assert!(
            f.host.notes().iter().any(|n| n.contains("LINES.TXT was closed")),
            "the double close is noted by name: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn a_handle_this_host_never_issued_is_answered_with_eof() {
        let mut f = Fixture::new();
        let invented = f.buffer(FILE_SIZE as u16);

        let answer = f.invoke(fclose, &Fixture::far(invented)).expect("fclose answers");

        assert_eq!(answer, Ret::U16(0xFFFF), "EOF, the way C reports a bad fclose");
        assert!(
            f.host.notes().iter().any(|n| n.contains("not a stream this host opened")),
            "and it is still said out loud: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn a_mode_this_host_does_not_understand_is_refused_naming_it() {
        // `"rw"` is NOT one of them any more. Borland's `CheckOpenType`
        // (`~/.cache/bcsrc/SOURCE/RTL/SOURCE/IO/COMMON16/FOPEN.C:60-61`) says
        // it "just stop[s] on mismatch and doesn't care if the string is
        // junk", so `"rw"` opens as plain `"r"` -- and refusing it stopped a
        // module the real host served. Only a missing or wrong FIRST
        // character is an error; see `crate::stream::Mode::parse`.
        let mut f = Fixture::new();
        let e = open(&mut f, "LINES.TXT", "x").expect_err("a refusal");
        assert!(e.to_string().contains("\"x\""), "{e}");

        // And the case that used to be refused now opens, readable.
        open(&mut f, "LINES.TXT", "rw")
            .expect("junk after the first char is Borland's shrug, not an error");
    }

    #[test]
    fn a_stream_opened_for_update_can_now_be_read_once_it_has_been_written_and_rewound() {
        // The exact case `Streams::readable` used to refuse outright: `fopen`'s
        // own documentation (FOPEN.C:261-266) says output may not directly be
        // followed by input without an intervening `fseek` or `rewind`.
        // `WCCMMUD.DLL` imports neither, so there was no point at which
        // reading its one `"w+"` stream meant anything -- but LunatiX imports
        // both (this file's own module doc), and the sequence its own
        // documentation always allowed now works end to end: write, rewind,
        // read back what was written.
        let mut f = Fixture::rooted(scratch("stream-update-read"));
        let fp = opened(&mut f, "LOG.LOG", "w+");

        let template = f.text("hello\n");
        f.invoke(fprintf,
            &[fp.offset, fp.selector, template.offset, template.selector],
        )
        .expect("fprintf");

        assert!(f.invoke(rewind, &Fixture::far(fp)).is_ok(), "rewind");
        assert_eq!(
            gets(&mut f, fp, 64).as_deref(),
            Some("hello\n"),
            "an update stream now reads back what it just wrote"
        );
    }

    #[test]
    fn opening_for_update_without_writing_first_is_also_readable_now() {
        // Not every update-mode read follows a write in the same session --
        // `"r+"` opens an existing file without truncating it, so a module
        // may open one purely to read it, the way `Streams::readable`'s own
        // doc comment now describes.
        let root = scratch("stream-update-read-only");
        std::fs::write(root.join("LOG.LOG"), b"first\r\nsecond\r\n").expect("seed content");
        let mut f = Fixture::rooted(root);
        let fp = opened(&mut f, "LOG.LOG", "r+");

        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("first\n"));
        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("second\n"));
    }

    // ---- 16-18. fseek, ftell, rewind ----------------------------------------

    #[test]
    fn fseek_and_ftell_round_trip_through_all_three_origins() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let len = std::fs::metadata(crate::testing::data().join("LINES.TXT"))
            .expect("the fixture")
            .len() as u32;

        // SEEK_SET: absolute, from the start.
        assert_eq!(word(seek(&mut f, fp, 10, 0).expect("fseek")), 0, "fseek returns 0 on success");
        assert_eq!(tell(&mut f, fp), 10);

        // SEEK_CUR: relative to wherever the stream already is, including
        // backwards -- a negative offset, which is the case `call.long()`'s
        // sign has to survive.
        assert_eq!(word(seek(&mut f, fp, 5, 1).expect("fseek")), 0);
        assert_eq!(tell(&mut f, fp), 15);
        assert_eq!(word(seek(&mut f, fp, -7, 1).expect("fseek")), 0);
        assert_eq!(tell(&mut f, fp), 8);

        // SEEK_END: from the end -- 0 lands exactly on the file's length.
        assert_eq!(word(seek(&mut f, fp, 0, 2).expect("fseek")), 0);
        assert_eq!(tell(&mut f, fp), len);
    }

    #[test]
    fn a_read_after_a_seek_returns_the_bytes_at_the_new_position_not_the_start() {
        // LINES.TXT's own raw bytes (binary mode, so nothing is translated):
        // "alpha\r\n" is seven bytes, then "be\rta\r\n" -- see
        // `every_carriage_return_is_dropped_in_text_mode_not_only_those_before_a_newline`
        // above for the same seven bytes read from the front instead of
        // seeked to.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");

        assert_eq!(word(seek(&mut f, fp, 7, 0).expect("fseek")), 0);
        assert_eq!(
            gets(&mut f, fp, 64).as_deref(),
            Some("be\rta\r\n"),
            "the seek landed past the first line's raw seven bytes, not at the start"
        );
    }

    #[test]
    fn rewind_puts_a_partially_read_stream_back_to_the_start() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("alpha\n"));
        assert_eq!(gets(&mut f, fp, 64).as_deref(), Some("beta\n"));

        assert!(matches!(f.invoke(rewind, &Fixture::far(fp)).expect("rewind"), Ret::Void));
        assert_eq!(
            gets(&mut f, fp, 64).as_deref(),
            Some("alpha\n"),
            "rewind put the stream back at the start"
        );
    }

    #[test]
    fn rewind_clears_the_eof_flag_a_read_to_the_end_set() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "CTRLZ.TXT", "rt");
        while gets(&mut f, fp, 64).is_some() {}
        assert_eq!(flags_of(&f, fp) & F_EOF, F_EOF, "the read hit the end");

        f.invoke(rewind, &Fixture::far(fp)).expect("rewind");
        assert_eq!(
            flags_of(&f, fp) & F_EOF,
            0,
            "rewind clears _F_EOF the same way a plain fseek does"
        );
    }

    #[test]
    fn ftell_after_a_write_reflects_the_bytes_written() {
        let mut f = Fixture::rooted(scratch("stream-ftell-write"));
        let fp = opened(&mut f, "OUT.LOG", "wb");
        assert_eq!(tell(&mut f, fp), 0, "nothing written yet");

        let template = f.text("12345");
        f.invoke(fprintf,
            &[fp.offset, fp.selector, template.offset, template.selector],
        )
        .expect("fprintf");
        assert_eq!(tell(&mut f, fp), 5);
    }

    #[test]
    fn seeking_past_the_end_of_file_is_allowed_and_a_read_there_is_simply_the_end() {
        // The design decision `Streams::seek_mem`'s own doc comment states:
        // this host does not narrow "past the end is fine" to writable
        // streams only, because an OS-level seek past a regular file's
        // length is not an error on the read side either.
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let len = std::fs::metadata(crate::testing::data().join("LINES.TXT"))
            .expect("the fixture")
            .len() as i32;

        assert_eq!(
            word(seek(&mut f, fp, len + 100, 0).expect("fseek")),
            0,
            "a seek past the end is not refused"
        );
        assert_eq!(gets(&mut f, fp, 64), None, "and a read there is just the end");
    }

    #[test]
    fn seek_set_with_a_negative_offset_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let e = seek(&mut f, fp, -1, 0).expect_err("a refusal");
        assert!(e.to_string().contains("negative offset"), "{e}");
    }

    #[test]
    fn seeking_before_the_start_of_the_file_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let e = seek(&mut f, fp, -1, 1).expect_err("a refusal"); // SEEK_CUR at position 0
        assert!(e.to_string().contains("LINES.TXT"), "{e}");
    }

    #[test]
    fn fseek_with_an_unknown_whence_is_refused_naming_it() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let e = seek(&mut f, fp, 0, 3).expect_err("a refusal");
        assert!(e.to_string().contains('3'), "{e}");
    }

    #[test]
    fn fseek_ftell_and_rewind_all_refuse_a_handle_this_host_never_issued() {
        let mut f = Fixture::new();
        let invented = f.buffer(FILE_SIZE as u16);

        let e = seek(&mut f, invented, 0, 0).expect_err("a refusal");
        assert!(e.to_string().contains("not a stream this host opened"), "{e}");

        let e = f.invoke(ftell, &Fixture::far(invented)).expect_err("a refusal");
        assert!(e.to_string().contains("not a stream this host opened"), "{e}");

        let e = f.invoke(rewind, &Fixture::far(invented)).expect_err("a refusal");
        assert!(e.to_string().contains("not a stream this host opened"), "{e}");
    }

    #[test]
    fn a_directory_other_than_the_modules_own_is_refused() {
        // The same rule `opnbtv` is under, and it is not theoretical: the log's
        // path comes out of the sysop's INI.
        let mut f = Fixture::new();
        let e = open(&mut f, "D:\\LOGS\\MUD.LOG", "at").expect_err("a refusal");
        assert!(e.to_string().contains("names a directory"), "{e}");

        // `.\` is the module's own, and is accepted.
        let dot = open(&mut f, ".\\LINES.TXT", "rt").expect("the module's own directory");
        assert_ne!(pointer(dot), FarPtr::NULL);
    }

    // ---- 6, 12. writing -----------------------------------------------------

    #[test]
    fn what_fprintf_writes_is_what_sprintf_would_have_produced() {
        // Both go through `crate::fmt`, so a divergence means one of them is
        // wrong. Binary, so the comparison is byte for byte.
        let root = scratch("stream-fprintf");
        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "OUT.LOG", "wb");

        let template = f.text("%s has %d gold\n");
        let who = f.text("rangerdan");
        let wrote = word(
            f.invoke(fprintf,
                &[
                    fp.offset,
                    fp.selector,
                    template.offset,
                    template.selector,
                    who.offset,
                    who.selector,
                    1234,
                ],
            )
            .expect("fprintf"),
        );
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        let on_disk = std::fs::read(root.join("OUT.LOG")).expect("the log");
        assert_eq!(on_disk, b"rangerdan has 1234 gold\n");
        assert_eq!(usize::from(wrote), on_disk.len());
    }

    #[test]
    fn a_text_stream_writes_dos_line_endings_and_a_binary_one_does_not() {
        // `WRITE.C:111`. A `.LOG` a sysop opens in a DOS editor should have DOS
        // line endings; a record written binary must not gain two bytes a line.
        let root = scratch("stream-crlf");
        let mut f = Fixture::rooted(root.clone());

        for (name, mode, expected) in [
            ("TEXT.LOG", "wt", b"a\r\nb\r\n".to_vec()),
            ("BIN.LOG", "wb", b"a\nb\n".to_vec()),
        ] {
            let fp = opened(&mut f, name, mode);
            let template = f.text("a\nb\n");
            let wrote = word(
                f.invoke(fprintf,
                    &[fp.offset, fp.selector, template.offset, template.selector],
                )
                .expect("fprintf"),
            );
            f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

            assert_eq!(std::fs::read(root.join(name)).expect(name), expected, "{name}");
            // "A write to a text file does not count generated carriage
            // returns" -- WRITE.C. So both modes answer 4.
            assert_eq!(wrote, 4, "{name}");
        }
    }

    #[test]
    fn appending_finds_a_file_the_module_named_in_another_case() {
        // A sysop's `WCCMMUD.LOG` and a module's `wccmmud.log` are one file.
        let root = scratch("stream-append");
        std::fs::write(root.join("WCCMMUD.LOG"), b"first\r\n").expect("a log");

        let mut f = Fixture::rooted(root.clone());
        let fp = opened(&mut f, "wccmmud.log", "at");
        let template = f.text("second\n");
        f.invoke(fprintf,
            &[fp.offset, fp.selector, template.offset, template.selector],
        )
        .expect("fprintf");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        assert_eq!(
            std::fs::read(root.join("WCCMMUD.LOG")).expect("the log"),
            b"first\r\nsecond\r\n"
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("the directory").count(),
            1,
            "and not a second file beside it"
        );
    }

    #[test]
    fn writing_to_a_stream_opened_for_reading_is_refused() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rt");
        let template = f.text("no");
        let e = f
            .invoke(fprintf,
                &[fp.offset, fp.selector, template.offset, template.selector],
            )
            .expect_err("a refusal");
        assert!(e.to_string().contains("open for reading"), "{e}");
    }

    #[test]
    fn flushing_a_stream_that_does_not_buffer_still_checks_the_handle() {
        let root = scratch("stream-flush");
        let mut f = Fixture::rooted(root);
        let fp = opened(&mut f, "OUT.LOG", "wt");
        assert_eq!(word(f.invoke(fflush, &Fixture::far(fp)).expect("fflush")), 0);

        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");
        let e = f.invoke(fflush, &Fixture::far(fp)).expect_err("a refusal");
        assert!(e.to_string().contains("OUT.LOG was closed"), "{e}");
    }

    // ---- 9. unlink ----------------------------------------------------------

    #[test]
    fn unlink_removes_a_file_and_answers_minus_one_for_one_that_is_not_there() {
        let root = scratch_with("stream-unlink", &["LINES.TXT"]);
        let mut f = Fixture::rooted(root.clone());

        let named = f.text("LINES.TXT");
        assert_eq!(word(f.invoke(unlink, &Fixture::far(named)).expect("unlink")), 0);
        assert!(!root.join("LINES.TXT").exists());

        // -1 for a file that is not there is the truth, and `_INIT__WCCMMUD`
        // reads it as one -- its single `unlink` is guarded by an `access` that
        // has already said the same thing.
        let again = f.text("LINES.TXT");
        assert_eq!(word(f.invoke(unlink, &Fixture::far(again)).expect("unlink")), NO);
    }

    #[test]
    fn unlink_outside_the_modules_own_directory_is_refused() {
        let mut f = Fixture::rooted(scratch("stream-unlink-path"));
        let named = f.text("D:\\LOGS\\MUD.LOG");
        let e = f.invoke(unlink, &Fixture::far(named)).expect_err("a refusal");
        assert!(e.to_string().contains("names a directory"), "{e}");
    }

    // ---- the recovery flag, end to end --------------------------------------

    #[test]
    fn the_recovery_flag_is_created_written_and_removed() {
        // `_INIT__WCCMMUD:10556` and `:10685`, which between them are the first
        // file this host ever creates for a module and the module's only
        // `unlink`. Bare `"w"` -- so text mode by `_fmode`'s default.
        let root = scratch("stream-recovery");
        let mut f = Fixture::rooted(root.clone());

        let fp = opened(&mut f, "WCCRECOV.FLG", "w");
        let template = f.text("MajorMUD Recovery required\n");
        f.invoke(fprintf,
            &[fp.offset, fp.selector, template.offset, template.selector],
        )
        .expect("fprintf");
        f.invoke(fclose, &Fixture::far(fp)).expect("fclose");

        assert_eq!(
            std::fs::read(root.join("WCCRECOV.FLG")).expect("the flag"),
            b"MajorMUD Recovery required\r\n",
            "a bare w is text mode"
        );

        let named = f.text("WCCRECOV.FLG");
        assert_eq!(word(f.invoke(unlink, &Fixture::far(named)).expect("unlink")), 0);
        assert!(!root.join("WCCRECOV.FLG").exists());
    }

    #[test]
    fn getdtd_puts_the_date_in_the_high_half_and_the_time_in_the_low() {
        // The half that matters. `seg 33:0x16f4` takes DX from the REGS block's
        // dx and AX from its cx, and `_BEGIN_UPDATING` hands the low half to
        // nctime and the high half to ncdate -- so getting these the wrong way
        // round produces two plausible strings, both wrong, and no error.
        let root = scratch_with("stream-getdtd", &["LINES.TXT"]);
        let mut f = Fixture::rooted(root.clone());
        let _fp = opened(&mut f, "LINES.TXT", "r");

        let Ret::U32(packed) = f
            .invoke(getdtd, &[u16::from(crate::stream::FIRST_FD)])
            .expect("getdtd")
        else {
            panic!("getdtd returns a long");
        };

        let at = std::fs::metadata(root.join("LINES.TXT"))
            .and_then(|m| m.modified())
            .expect("the file this test just made")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs() as u32;
        let civil = crate::clock::Clock::pinned(at).civil().expect("a calendar");

        assert_eq!(
            packed >> 16,
            u32::from(civil.dos_date().expect("a year DOS can hold")),
            "the high half is the date"
        );
        assert_eq!(
            packed & 0xffff,
            u32::from(civil.dos_time()),
            "the low half is the time"
        );

        // And independently of the packing: a file written moments ago cannot
        // predate DOS. Catches a wholesale mistake that the two halves above
        // would agree on, since both sides compute them the same way.
        assert!(
            (packed >> 16) >> 9 >= 1,
            "a file written now is not from 1980"
        );
    }

    #[test]
    fn getdtd_refuses_a_descriptor_nothing_opened() {
        // The original filled a REGS block and returned whatever DOS left
        // behind, so a stale handle came back as a date. There is nothing to
        // report here but the absence.
        let mut f = Fixture::new();
        let e = f.invoke(getdtd, &[99]).expect_err("refused");
        assert!(format!("{e}").contains("no open stream"), "{e}");
    }

    /// A fixture over a directory with known contents, and the three counters
    /// after `cntdir` has run over `spec`.
    fn counted(f: &mut Fixture, spec: &str) -> (i32, i32, i32) {
        let at = f.text(spec);
        let args = Fixture::far(at);
        assert!(matches!(
            f.invoke(cntdir, &args).expect("cntdir"),
            Ret::Void
        ));
        let read = |name| f.host.globals().long(&f.machine, name).expect(name);
        (read("numfils"), read("numbyts"), read("numbytp"))
    }

    /// The three 1,024-byte `.DAT` files, one 433-byte `.MSG` and one 48-byte
    /// `.MSG` from `tests/data`, somewhere a test may add to.
    fn directory(name: &str) -> std::path::PathBuf {
        scratch_with(
            name,
            &["SAMPLE.DAT", "OTHER.DAT", "EMPTY.DAT", "SAMPLE.MSG", "OTHER.MSG"],
        )
    }

    #[test]
    fn cntdir_of_one_name_is_one_file_and_its_size() {
        // ACCOUNT.C:98 passes a bare filename with no wildcard in it at all,
        // and reads `numfils` to find out whether it exists.
        let mut f = Fixture::rooted(directory("cntdir-one"));
        assert_eq!(counted(&mut f, "SAMPLE.DAT"), (1, 1024, 1024));
    }

    #[test]
    fn cntdir_matches_case_insensitively_as_dos_did() {
        // The module's own spec is the lower-case `wccupdat.dat`, and every file
        // beside it on disk is upper case.
        let mut f = Fixture::rooted(directory("cntdir-case"));
        assert_eq!(counted(&mut f, "sample.dat"), (1, 1024, 1024));
    }

    #[test]
    fn cntdir_of_a_file_that_is_not_there_is_zero_and_not_a_refusal() {
        // `numfils == 0` is the answer three of the four recovered call sites
        // are looking for. Refusing would tell the module nothing it can act on.
        let mut f = Fixture::rooted(directory("cntdir-absent"));
        assert_eq!(counted(&mut f, "NOSUCH.DAT"), (0, 0, 0));
    }

    #[test]
    fn cntdir_sums_a_wildcard() {
        let mut f = Fixture::rooted(directory("cntdir-wild"));
        assert_eq!(counted(&mut f, "*.DAT"), (3, 3072, 3072));
        assert_eq!(counted(&mut f, "*.MSG"), (2, 481, 481));
        assert_eq!(counted(&mut f, "SAMPLE.*"), (2, 1457, 1457));
        assert_eq!(counted(&mut f, "*.*"), (5, 3553, 3553));
    }

    #[test]
    fn cntdir_replaces_the_last_answer_rather_than_adding_to_it() {
        // Every recovered caller calls it and reads immediately. A host that
        // accumulated would be right the first time and wrong forever after.
        let mut f = Fixture::rooted(directory("cntdir-again"));
        assert_eq!(counted(&mut f, "*.DAT"), (3, 3072, 3072));
        assert_eq!(counted(&mut f, "SAMPLE.DAT"), (1, 1024, 1024));
    }

    #[test]
    fn cntdir_skips_what_dos_could_not_have_seen() {
        // The module's directory on this host is a Linux one, and may hold
        // names no `fnd1st` loop could ever have returned -- `tmp/` really does
        // hold `slumpos.json` and `control_run.out`. Counting them would report
        // files the module cannot open by the name it was given.
        let at = directory("cntdir-alien");
        std::fs::write(at.join("slumpos.json"), b"0123456789").expect("written");
        std::fs::create_dir(at.join("SUBDIR.D")).expect("a subdirectory");
        let mut f = Fixture::rooted(at);
        assert_eq!(counted(&mut f, "*.*"), (5, 3553, 3553));
    }

    #[test]
    fn cntdir_refuses_a_directory_and_an_ambiguous_wildcard() {
        // `D:\MUD\*.DAT` is `Host::dos_name`'s rule, the same one `fopen` and
        // `unlink` keep -- a drive is somewhere this host does not look.
        // `SUBDIR\*.*` is no longer `dos_name`'s refusal (a real subdirectory
        // is accepted now, see that method's own doc comment) but still
        // fails, one step later: `dos::Name::spec` has no field for a path
        // separator, and `cntdir` never `read_dir`s into a subdirectory
        // anyway (see this routine's own doc comment). `*` is
        // `dos::Name::spec`'s ambiguous-wildcard refusal.
        let mut f = Fixture::rooted(directory("cntdir-refuse"));
        for spec in ["D:\\MUD\\*.DAT", "SUBDIR\\*.*", "*"] {
            let at = f.text(spec);
            let args = Fixture::far(at);
            assert!(f.invoke(cntdir, &args).is_err(), "{spec}");
        }
    }

    // ---- fnd1st / fndnxt -----------------------------------------------------

    /// `struct fndblk`'s field offsets, pinned per ABI -- `Wg16`'s to the
    /// numbers `DOSFACE.H` gives directly (quoted in [`fnd1st`]'s own doc
    /// comment), `Wg32`'s to this crate's inferred natural-alignment layout
    /// (same doc comment, marked there as unmeasured). A change to either
    /// table changes what a real 16- or 32-bit module reads out of this
    /// struct, so it has to fail a test rather than pass one in silence.
    #[test]
    fn fndblk_layout_matches_the_derived_offset_table_for_both_abis() {
        use crate::abi::Wg32;

        let wg16 = FndblkLayout::of::<Wg16>();
        assert_eq!(wg16.attr, 21, "Wg16 attr");
        assert_eq!(wg16.time, 22, "Wg16 time");
        assert_eq!(wg16.date, 24, "Wg16 date");
        assert_eq!(wg16.size, 26, "Wg16 size");
        assert_eq!(wg16.name, 30, "Wg16 name");
        assert_eq!(wg16.total, 43, "Wg16 total -- byte-packed, no trailing pad");

        // Borland's *32-bit* `struct ffblk`, which is a different record and
        // not the 16-bit one widened: size before attribute, a `long`
        // attribute, 16-bit times, and the name at 16. Measured out of
        // LunatiX itself -- see `FndblkLayout::of` for how, and for what the
        // wrong answer looked like (it opened a directory).
        let wg32 = FndblkLayout::of::<Wg32>();
        assert_eq!(wg32.size, 4, "Wg32 ff_fsize -- before the attribute, not after");
        assert_eq!(wg32.attr, 8, "Wg32 ff_attrib -- an unsigned long");
        assert_eq!(wg32.time, 12, "Wg32 ff_ftime -- still 16 bits");
        assert_eq!(wg32.date, 14, "Wg32 ff_fdate");
        assert_eq!(wg32.name, 16, "Wg32 ff_name -- the offset LunatiX read from");
        assert_eq!(wg32.total, 29, "Wg32: what this host writes, not ff_name's own 256");

        // The two layouts genuinely differ; a formula that collapsed them
        // would pass every assertion above only if it produced both.
        assert_ne!(wg16.name, wg32.name, "the two ABIs' records are not one record");
    }

    /// A `fndblk` buffer, zeroed, sized for `Wg16` -- every behavioural test
    /// below is `Wg16`-only for the same reason every other dual-ABI shim's
    /// behavioural tests are (see `shims::text`'s own note on why a real
    /// `Wg32` `Call`/`Machine` cannot be built inside `--lib`): the layout
    /// table above is what actually varies by ABI, and it is tested
    /// directly, above, at both widths.
    fn fndblk(f: &mut Fixture) -> FarPtr {
        f.buffer(FndblkLayout::of::<Wg16>().total as u16)
    }

    /// `fnd1st(fbptr, filspc, attr)`.
    fn fnd1st_(f: &mut Fixture, fbptr: FarPtr, spec: &str, attr: u16) -> Result<Ret, ShimError> {
        let path = f.text(spec);
        f.invoke(fnd1st, &[fbptr.offset, fbptr.selector, path.offset, path.selector, attr])
    }

    /// `fndnxt(fbptr)`.
    fn fndnxt_(f: &mut Fixture, fbptr: FarPtr) -> Result<Ret, ShimError> {
        f.invoke(fndnxt, &Fixture::far(fbptr))
    }

    /// The `name` field a `fnd1st`/`fndnxt` call just wrote, as a string --
    /// read back through the same [`FndblkLayout`] the shim wrote it with,
    /// so a test of the offsets and a test of the behaviour cannot silently
    /// agree by both being wrong the same way.
    fn found_name(f: &Fixture, fbptr: FarPtr) -> String {
        let layout = FndblkLayout::of::<Wg16>();
        let bytes = f.machine.resolve(fbptr, layout.total).expect("a fndblk");
        let name = &bytes[layout.name..layout.total];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        String::from_utf8_lossy(&name[..end]).into_owned()
    }

    #[test]
    fn fnd1st_finds_the_one_file_a_literal_spec_names() {
        let mut f = Fixture::rooted(directory("fnd1st-one"));
        let blk = fndblk(&mut f);
        let ret = fnd1st_(&mut f, blk, "SAMPLE.DAT", 0).expect("fnd1st");
        assert_eq!(word(ret), 1);
        assert_eq!(found_name(&f, blk), "SAMPLE.DAT");
    }

    #[test]
    fn fndnxt_drains_the_remaining_matches_of_a_wildcard_scan_in_order() {
        // `directory()` seeds SAMPLE.DAT, OTHER.DAT and EMPTY.DAT -- three
        // matches for `*.DAT`, in the alphabetical order `fnd1st` sorts its
        // matches into (this host has no on-disk directory order to match
        // real DOS's FAT order with -- see `fnd1st`'s own doc comment).
        let mut f = Fixture::rooted(directory("fnd1st-several"));
        let blk = fndblk(&mut f);

        assert_eq!(word(fnd1st_(&mut f, blk, "*.DAT", 0).expect("fnd1st")), 1);
        assert_eq!(found_name(&f, blk), "EMPTY.DAT");

        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 1);
        assert_eq!(found_name(&f, blk), "OTHER.DAT");

        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 1);
        assert_eq!(found_name(&f, blk), "SAMPLE.DAT");

        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 0, "no more after the third");
    }

    #[test]
    fn fnd1st_of_a_literal_name_matching_nothing_is_zero_not_a_refusal() {
        let mut f = Fixture::rooted(directory("fnd1st-none"));
        let blk = fndblk(&mut f);
        assert_eq!(word(fnd1st_(&mut f, blk, "NOSUCH.DAT", 0).expect("fnd1st")), 0);
    }

    #[test]
    fn fnd1st_of_a_wildcard_matching_nothing_is_also_zero() {
        // Distinct from the literal-name case above: a real extension field
        // that simply has no files in it, exercised through the wildcard
        // path rather than the exact-name path.
        let mut f = Fixture::rooted(directory("fnd1st-wild-none"));
        let blk = fndblk(&mut f);
        assert_eq!(word(fnd1st_(&mut f, blk, "*.XYZ", 0).expect("fnd1st")), 0);
    }

    #[test]
    fn fnd1st_scans_a_subdirectory_the_module_named() {
        // The exact shape LunatiX's own init reaches for --
        // `fnd1st("lun5data\*.txt", ...)` -- see this file's module doc
        // comment on `fopen`'s subdirectory-creation test for the same
        // install layout.
        let root = scratch("fnd1st-subdir");
        std::fs::create_dir(root.join("LUN5DATA")).expect("a subdirectory");
        std::fs::write(root.join("LUN5DATA").join("LUNRAND1.TXT"), b"one").expect("a file");
        std::fs::write(root.join("LUN5DATA").join("LUNJOKES.TXT"), b"two").expect("a file");
        let mut f = Fixture::rooted(root);
        let blk = fndblk(&mut f);

        assert_eq!(word(fnd1st_(&mut f, blk, "lun5data\\*.txt", 0).expect("fnd1st")), 1);
        assert_eq!(found_name(&f, blk), "LUNJOKES.TXT", "alphabetically first");

        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 1);
        assert_eq!(found_name(&f, blk), "LUNRAND1.TXT");

        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 0);
    }

    #[test]
    fn fnd1st_admits_a_subdirectory_entry_only_when_famdir_is_set() {
        let root = scratch("fnd1st-famdir");
        std::fs::create_dir(root.join("SUB.DIR")).expect("a directory entry");
        let mut f = Fixture::rooted(root);

        let blk = fndblk(&mut f);
        assert_eq!(
            word(fnd1st_(&mut f, blk, "*.DIR", 0).expect("fnd1st")),
            0,
            "directories are excluded by default, same as real FindFirst"
        );

        let blk = fndblk(&mut f);
        assert_eq!(word(fnd1st_(&mut f, blk, "*.DIR", u16::from(FAMDIR)).expect("fnd1st")), 1);
        assert_eq!(found_name(&f, blk), "SUB.DIR");
    }

    #[test]
    fn fndnxt_without_a_prior_fnd1st_is_refused_rather_than_answered_zero() {
        // The distinction `fndnxt`'s own doc comment draws: "never started"
        // is a host bug and is refused, "started and ran out" is an
        // ordinary 0 -- see `fndnxt_drains_the_remaining_matches...` above
        // for the second half.
        let mut f = Fixture::new();
        let blk = fndblk(&mut f);
        let e = fndnxt_(&mut f, blk).expect_err("a refusal");
        assert!(e.to_string().contains("no fnd1st scan"), "{e}");
    }

    #[test]
    fn reusing_one_fbptr_for_a_second_fnd1st_replaces_the_first_scan() {
        // The interleaving hazard `SCANS`'s own doc comment names: real DOS
        // kept scan state in the DTA (`fndblk`'s own `junk`), so a second
        // `fnd1st` into the same buffer before the first scan finished threw
        // the first scan's position away. This host's map-keyed-by-pointer
        // reproduces exactly that, on purpose.
        let mut f = Fixture::rooted(directory("fnd1st-reuse"));
        let blk = fndblk(&mut f);

        assert_eq!(word(fnd1st_(&mut f, blk, "*.DAT", 0).expect("fnd1st")), 1);
        assert_eq!(found_name(&f, blk), "EMPTY.DAT", "first scan's first match");

        // A second `fnd1st`, same buffer, different spec -- before the first
        // scan's `fndnxt` chain ever ran.
        assert_eq!(word(fnd1st_(&mut f, blk, "*.MSG", 0).expect("fnd1st")), 1);
        assert_eq!(found_name(&f, blk), "OTHER.MSG", "the second scan's own first match");

        // `fndnxt` now continues the *second* scan, not the first's leftover
        // `OTHER.DAT`/`SAMPLE.DAT`.
        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 1);
        assert_eq!(found_name(&f, blk), "SAMPLE.MSG");
        assert_eq!(word(fndnxt_(&mut f, blk).expect("fndnxt")), 0);
    }
}
