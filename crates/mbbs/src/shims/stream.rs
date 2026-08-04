//! The seven stream routines, over a `FILE *` the module holds.
//!
//! Borland's, re-exported by `MAJORBBS.DLL`:
//!
//!
//! What a stream *is* -- the struct, the modes, the text translation -- is
//! [`crate::stream`]'s. This is the part that knows about the module.
//!
//! `fseek`, `ftell`, `rewind`, `fwrite`, `fputs`, `fputc`, `fscanf`, `fgetc`,
//! `getc` and `ungetc` are absent on purpose: `WCCMMUD.DLL` imports none of
//! them. Every stream in it is read or written straight through, once.
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

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::fmt::format;
use crate::shims::{NO, ShimError};
use crate::stream::Mode;

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
pub fn fopen(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let named = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(0))?).into_owned();
    let spelt = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(2))?).into_owned();

    let mode = Mode::parse(&spelt).map_err(ShimError::Failed)?;
    let name = Host::dos_name(&named).map_err(ShimError::Failed)?.to_owned();

    let path = match host.find(&name) {
        Some(path) => path,

        // Not there, and the module asked to read it. `WCCMMUD.INI` is not
        // shipped -- it is something a sysop writes -- so this is the ordinary
        // case rather than the exceptional one.
        None if mode.read => return Ok(Ret::Far(FarPtr::NULL)),

        // Not there, and the module asked to write it. That is a create.
        None => host.root.join(&name),
    };

    let cookie = host
        .streams
        .open(machine, &name, &path, mode)
        .map_err(|e| ShimError::Failed(format!("fopen({named}, {spelt}): {e}")))?;
    Ok(Ret::Far(cookie))
}

/// `int fclose(FILE *f)` -- close a stream.
///
/// Zero, always: the failure `fclose` reports with `EOF` is one this host would
/// have refused already. The cookie is retired rather than reused, so using it
/// afterwards names the file it used to be.
pub fn fclose(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let cookie = machine.arg_far(0);
    host.streams
        .close(cookie)
        .map_err(|e| ShimError::Failed(format!("fclose: {e}")))?;
    Ok(Ret::U16(0))
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
pub fn fgets(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let buffer = machine.arg_far(0);
    let n = machine.arg_u16(2) as i16;
    let cookie = machine.arg_far(3);

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
        .line(machine, cookie, (n - 1) as usize)
        .map_err(|e| ShimError::Failed(format!("fgets: {e}")))?;
    let Some(mut line) = line else {
        return Ok(Ret::Far(FarPtr::NULL));
    };

    line.push(0);
    machine.write(buffer, &line)?;
    Ok(Ret::Far(buffer))
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
pub fn fread(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let buffer = machine.arg_far(0);
    let size = machine.arg_u16(2);
    let count = machine.arg_u16(3);
    let cookie = machine.arg_far(4);

    if size == 0 || count == 0 {
        return Ok(Ret::U16(0));
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
        .read(machine, cookie, want as usize)
        .map_err(|e| ShimError::Failed(format!("fread: {e}")))?;
    machine.write(buffer, &bytes)?;
    Ok(Ret::U16((bytes.len() / usize::from(size)) as u16))
}

/// `int fprintf(FILE *f, const char *fmt, ...)` -- the print buffer's formatter,
/// with a destination.
///
/// [`crate::fmt::format`]'s `first` is an **absolute** word index into the call
/// frame, so it is 4: the far `FILE *` is words 0-1 and the far template words
/// 2-3. The same layout `sprintf` has, and unlike `prfmsg`, whose fixed argument
/// is one word.
///
/// Returns the bytes the module asked to write, not the bytes that reached the
/// disk. `WRITE.C` is explicit about the difference -- "a write to a text file
/// does not count generated carriage returns" -- so the answer is the same in
/// both modes, which is what makes it comparable with `sprintf`.
pub fn fprintf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let cookie = machine.arg_far(0);
    let (text, _) = format(machine, machine.arg_far(2), 4)?;
    host.streams
        .write(cookie, &text)
        .map_err(|e| ShimError::Failed(format!("fprintf: {e}")))?;
    Ok(Ret::U16(text.len() as u16))
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
pub fn fflush(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let cookie = machine.arg_far(0);
    host.streams
        .name(cookie)
        .map_err(|e| ShimError::Failed(format!("fflush: {e}")))?;
    Ok(Ret::U16(0))
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
pub fn unlink(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let named = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(0))?).into_owned();
    let name = Host::dos_name(&named).map_err(ShimError::Failed)?;

    let Some(path) = host.find(name) else {
        return Ok(Ret::U16(NO));
    };
    std::fs::remove_file(&path)
        .map_err(|e| ShimError::Failed(format!("unlink({named}): {e}")))?;
    Ok(Ret::U16(0))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        f.invoke(
            fopen,
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
            f.invoke(
                fread,
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
                f.invoke(
                    fread,
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
            .invoke(
                fread,
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
    fn opening_for_update_is_refused_rather_than_treated_as_one_or_the_other() {
        let mut f = Fixture::new();
        let e = open(&mut f, "LINES.TXT", "r+").expect_err("a refusal");
        assert!(e.to_string().contains("update"), "{e}");
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
            f.invoke(
                fprintf,
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
                f.invoke(
                    fprintf,
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
        f.invoke(
            fprintf,
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
            .invoke(
                fprintf,
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
        f.invoke(
            fprintf,
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
}
