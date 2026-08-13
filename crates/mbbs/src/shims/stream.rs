//! The nine file routines, seven of them over a `FILE *` the module holds.
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
//! `fseek`, `ftell`, `rewind`, `fwrite`, `fputs`, `fputc`, `fscanf`, `fgetc`,
//! `getc` and `ungetc` are absent on purpose: `WCCMMUD.DLL` imports none of
//! them. Every stream in it is read or written straight through, once -- and
//! that census is what makes a stream opened `"w+"` unreadable rather than
//! merely unread. Without a seek there is no legal transition from writing it
//! to reading it, so there is nothing to implement.
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
use mbbs16::Ret;
use mbbs_ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::dos;
use crate::fmt::format_call;
use crate::shims::{NO, ShimError};
use crate::stream::Mode;

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
    let name = Host::<Wg16>::dos_name(&named)
        .map_err(ShimError::Failed)?
        .to_owned();

    let path = match host.find(&name) {
        Some(path) => path,

        // Not there, and the module asked to read it. `WCCMMUD.INI` is not
        // shipped -- it is something a sysop writes -- so this is the ordinary
        // case rather than the exceptional one.
        None if mode.read => return Ok(abi::Ret::Ptr(null_ptr::<A>())),

        // Not there, and the module asked to write it. That is a create.
        None => host.root.join(&name),
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
    host.streams
        .close(cookie)
        .map_err(|e| ShimError::Failed(format!("fclose: {e}")))?;
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
/// back through [`Call::mem`] and [`mbbs_ptr::ModulePtr::write`] rather than
/// `Machine::write`.
pub fn fgets<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `char *fgets(char *s, int n, FILE *f)` -- Borland's; no Galacticomm
    // header redeclares it (`GCOMM.H`'s `mdfgets` is a different routine with
    // the same shape, not this one -- see this file's commit message).
    let buffer = call.ptr();
    let n = Into::<u32>::into(call.int()) as i16;
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
/// through [`Call::mem`] and [`mbbs_ptr::ModulePtr::write`].
pub fn fread<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `size_t fread(void *p, size_t size, size_t n, FILE *f)` -- Borland's;
    // no Galacticomm header redeclares it.
    let buffer = call.ptr();
    let size = Into::<u32>::into(call.int()) as u16;
    let count = Into::<u32>::into(call.int()) as u16;
    let cookie = call.ptr();

    if size == 0 || count == 0 {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    // `size_t` is 16 bits here, so Borland would have wrapped. A wrap reads the
    // wrong amount into a buffer of the right size, which nothing downstream
    // could notice.
    let want = u32::from(size) * u32::from(count);
    if want > u32::from(u16::MAX) {
        return Err(ShimError::Failed(format!(
            "fread of {count} items of {size} bytes, which a 16-bit size_t cannot count"
        )));
    }

    let bytes = host
        .streams
        .read_mem(call.mem(), cookie, want as usize)
        .map_err(|e| ShimError::Failed(format!("fread: {e}")))?;
    buffer
        .write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(
        (bytes.len() / usize::from(size)) as u16,
    )))
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
    Ok(abi::Ret::Int(A::Int::from(text.len() as u16)))
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

    let Some(path) = host.find(name) else {
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
/// If the spec names a directory ([`Host::dos_name`]'s rule, the same one
/// `fopen` and `unlink` keep), if it is a wildcard with no extension
/// ([`dos::Name::spec`]'s), if the module's directory cannot be read, or if the
/// total will not fit in the `long` the module reads it as.
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
        dos::Name::spec(name).map_err(|why| ShimError::Failed(format!("cntdir({named}): {why}")))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs16::FarPtr;

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

        let e = f.invoke(fclose, &Fixture::far(fp)).expect_err("a refusal");
        assert!(e.to_string().contains("LINES.TXT was closed"), "{e}");
    }

    #[test]
    fn a_handle_this_host_never_issued_is_refused() {
        let mut f = Fixture::new();
        let invented = f.buffer(FILE_SIZE as u16);
        let e = f.invoke(fclose, &Fixture::far(invented)).expect_err("a refusal");
        assert!(e.to_string().contains("not a stream this host opened"), "{e}");
    }

    #[test]
    fn a_mode_this_host_does_not_understand_is_refused_naming_it() {
        let mut f = Fixture::new();
        let e = open(&mut f, "LINES.TXT", "rw").expect_err("a refusal");
        assert!(e.to_string().contains("\"rw\""), "{e}");
    }

    #[test]
    fn reading_a_stream_opened_for_update_is_refused_rather_than_answered_with_the_end() {
        // The mode opens; the read does not. `fopen`'s own documentation
        // (FOPEN.C:261-266) says input may not directly follow output without
        // an intervening `fseek` or `rewind`, and `WCCMMUD.DLL` imports
        // neither, nor `ftell` -- so there is no point at which reading one of
        // these means anything. The alternative is not an implementation, it is
        // a silent end-of-file on a stream whose flags say `_F_READ`.
        let mut f = Fixture::rooted(scratch("stream-update-read"));
        let fp = opened(&mut f, "LOG.LOG", "w+");

        let buffer = f.buffer(64);
        let e = f
            .invoke(fgets,
                &[buffer.offset, buffer.selector, 64, fp.offset, fp.selector],
            )
            .expect_err("a refusal");
        assert!(e.to_string().contains("LOG.LOG is open for update"), "{e}");
        assert!(e.to_string().contains("fseek"), "and says why: {e}");
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
        // The first is `Host::dos_name`'s rule, the same one `fopen` and
        // `unlink` keep. The second is `dos::Name::spec`'s.
        let mut f = Fixture::rooted(directory("cntdir-refuse"));
        for spec in ["D:\\MUD\\*.DAT", "SUBDIR\\*.*", "*"] {
            let at = f.text(spec);
            let args = Fixture::far(at);
            assert!(f.invoke(cntdir, &args).is_err(), "{spec}");
        }
    }
}
