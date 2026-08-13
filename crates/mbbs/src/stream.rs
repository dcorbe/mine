//! Streams: the module's own files, opened by name and read or written through.
//!
//! Seven routines over a handle -- `fopen`, `fclose`, `fgets`, `fread`,
//! `fprintf`, `fflush`, `unlink` -- and no `fseek`, `ftell` or `rewind`
//! anywhere in `WCCMMUD.DLL`. Every stream is read or written straight through,
//! once. The design is `docs/plans/2026-08-04-streams.md`.
//!
//! One stream is neither: `_GENERATE_TOP_LIST` opens `log.log` `"w+"` at
//! `seg 34:0x010a`, the module's only update mode. It is written like any other
//! and reading it is refused -- see [`Streams::readable`], which is where the
//! reason lives.
//!
//! # The import census does not cover this one
//!
//! Everywhere else in this host, what a module can ask for is bounded by what it
//! imports, and an import the host does not have stops the module by name. Here
//! that is not true. `feof`, `ferror`, `fileno`, `getc` and `putc` are **macros**
//! in Borland's `stdio.h`; they compile to direct reads of the `FILE` struct and
//! emit no import record at all. The host is never called and has nothing to
//! refuse.
//!
//! `WCCMMUD.DLL` does exactly this. `_CHECK_BEGIN_UPDATING`
//! (`re/exports/WCCMMUD_decompiled.c:57759`) reads `fp->fd` and hands it to
//! `getdtd`. So the struct this module hands back is **filled in, not zeroed**,
//! and [`Stream::flags`] has to stay current for the whole life of the stream --
//! an `_F_EOF` written one call late is a module reading past the end with
//! nothing to stop it.
//!
//! # Everything here is measured against Borland's own runtime
//!
//! Not against C's standard, which is looser than the module's behaviour. The
//! source is in `archive/tooling/compilers/bc452.zip`, and where it and the
//! standard differ this follows the source, because the module was linked
//! against the source.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use mbbs_ptr::ModulePtr;

use crate::abi::Abi;
use crate::arena::Arena;

/// Bytes of Borland's `FILE`, as `INCLUDE/STDIO.H:104-114` declares it: two
/// `int`s, two `char`s, an `int`, two far pointers, an `unsigned` and a `short`.
///
/// Large model, so the pointers are four bytes each. Twenty in total, and no
/// padding -- every field lands on its natural boundary already.
pub const FILE_SIZE: usize = 2 + 2 + 1 + 1 + 2 + 4 + 4 + 2 + 2;

/// Where `flags` is, which `feof(f)` and `ferror(f)` expand to a read of.
const FLAGS: u16 = 2;

/// Where `fd` is, which `fileno(f)` expands to a read of. **One byte.**
const FD: u16 = 4;

/// `STDIO.H:59-69` -- the bits of `FILE.flags`.
///
/// Only the ones this host can set truthfully are here. `_F_BUF`, `_F_LBUF`,
/// `_F_IN`, `_F_OUT` and `_F_TERM` describe a buffering arrangement this host
/// does not have, and a module reading one of them would be told about a
/// runtime that is not underneath it.
mod flags {
    /// `_F_READ` -- open for reading.
    pub const READ: u16 = 0x0001;
    /// `_F_WRIT` -- open for writing.
    pub const WRIT: u16 = 0x0002;
    /// `_F_EOF` -- a read has hit the end.
    pub const EOF: u16 = 0x0020;
    /// `_F_BIN` -- binary, so no `\r` translation in either direction.
    pub const BIN: u16 = 0x0040;
}

/// DOS's soft end-of-file. A text-mode read stops here and does not look past
/// it, which `READ.CAS`'s `cmp al, _ctlZ / je endSeen` is the whole of.
const CTRL_Z: u8 = 0x1a;

/// The first file descriptor a module's own stream may have.
///
/// 0 to 4 are `stdin`, `stdout`, `stderr`, `stdaux` and `stdprn`, which this
/// host does not implement and a module must not be handed. Starting past them
/// also means **a zeroed `FILE` cannot be mistaken for one of ours**: `fd` 0 in
/// an uninitialised struct reads as `stdin` rather than as a live stream.
pub(crate) const FIRST_FD: u8 = 5;

/// What `fopen`'s mode string asked for.
///
/// `r`, `w` or `a`, then at most one `+` and at most one of `t` or `b`.
///
/// **`read`, `write` and `append` are the base letter, not the access.** They
/// are what decides `O_CREAT` and `O_TRUNC`, which is why the `+` does not
/// fold into them. Ask [`Self::readable`] and [`Self::writable`] for what the
/// module may actually do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub update: bool,
    pub binary: bool,
}

impl Mode {
    /// Read a mode string, or say why it could not be read.
    ///
    /// **Neither `t` nor `b` means text**, because that is `_fmode`'s default and
    /// the module relies on it: two of its eleven resolved `fopen` sites pass a
    /// bare `"w"` or `"a"`. A host that defaulted to binary would write
    /// `WCCRECOV.FLG` and the list dump with Unix line endings, and nothing that
    /// reads either would complain.
    ///
    /// # Errors
    ///
    /// If the string is not a mode. Guessing at one would mean a stream opened
    /// for reading when it meant append -- which loses a log -- or as text when
    /// it meant binary, which corrupts a record by two bytes a line. Neither
    /// fails loudly on its own.
    pub fn parse(mode: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "fopen mode {mode:?}: expected r, w or a, then at most one + \
                 and at most one of t or b"
            )
        };

        let mut rest = mode.chars();
        let (read, write, append) = match rest.next() {
            Some('r') => (true, false, false),
            Some('w') => (false, true, false),
            Some('a') => (false, true, true),
            _ => return Err(bad()),
        };

        let mut update = false;
        let mut binary = None;
        for c in rest {
            match c {
                '+' if !update => update = true,
                't' | 'b' if binary.is_none() => binary = Some(c == 'b'),
                _ => return Err(bad()),
            }
        }

        Ok(Self {
            read,
            write,
            append,
            update,
            binary: binary.unwrap_or(false),
        })
    }

    /// Whether the module may read this stream.
    ///
    /// **Not `self.read`.** `read`, `write` and `append` are the base *letter*,
    /// and a `+` adds the other direction without disturbing it -- `w+` has
    /// `read == false` and is readable all the same. That is what `_F_RDWR`
    /// means at `FOPEN.C:107`, and reading the field instead of asking this
    /// would report `_F_WRIT` alone for the one update stream the module opens.
    pub fn readable(&self) -> bool {
        self.read || self.update
    }

    /// Whether the module may write this stream.
    ///
    /// The mirror of [`Self::readable`], and the one with teeth: a plain `r+`
    /// read through `self.write` would be told it is open for reading, and a
    /// host that let it through on the field alone would write nothing and say
    /// nothing. Neither mode occurs in `WCCMMUD.DLL`; both are one call site
    /// away from occurring.
    pub fn writable(&self) -> bool {
        self.write || self.update
    }
}

/// An open file, and how the module is reading or writing it.
///
/// Reading is buffered because it is done a byte at a time -- see [`Self::getc`]
/// -- and writing is not, which is what makes `fflush` an honest no-op rather
/// than a convenient one.
enum Io {
    Read(BufReader<File>),
    Write(File),

    /// Opened for update -- `O_RDWR`. Written exactly like [`Self::Write`] and
    /// deliberately **not** read: see [`Streams::readable`].
    ///
    /// Unbuffered, like `Write` and unlike `Read`, which is not an oversight.
    /// A `BufReader` over a handle this host also writes through would answer
    /// from a buffer filled before the write.
    Update(File),
}

/// One open stream.
struct Stream<A: Abi> {
    /// What the module called it, in the module's own spelling.
    name: String,

    /// The `FILE *` the module holds. Unique for the life of the host.
    cookie: A::Ptr,

    /// What `fileno(fp)` reads out of the struct. One byte, so it is reused
    /// after a close -- unlike the cookie. See [`Streams::close`].
    fd: u8,

    mode: Mode,
    io: Io,

    /// Whether a read has hit the end. `_F_EOF`, and mirrored into module
    /// memory rather than only kept here, because `feof` never asks the host.
    ended: bool,
}

impl<A: Abi> Stream<A> {
    /// The `flags` word the module should see.
    ///
    /// Both direction bits for an update stream, which is `_F_RDWR` --
    /// `CheckOpenType` sets `_F_READ | _F_WRIT` for every mode with a `+`, and
    /// `STDIO.H:63` names the pair.
    fn flags(&self) -> u16 {
        let mut bits = 0;
        if self.mode.readable() {
            bits |= flags::READ;
        }
        if self.mode.writable() {
            bits |= flags::WRIT;
        }
        if self.mode.binary {
            bits |= flags::BIN;
        }
        if self.ended {
            bits |= flags::EOF;
        }
        bits
    }

    /// The next byte the module should see, or `None` at the end.
    ///
    /// The text-mode rule is Borland's, from the assembly in
    /// `IO/COMMON16/READ.CAS`, and it is **not** the one usually described:
    ///
    /// ```text
    /// squeeze:  lods al
    ///           cmp  al, _ctlZ ; je endSeen      -- ^Z ends the file
    ///           cmp  al, 0Dh   ; je elseSqueeze  -- and every \r is dropped
    ///           stosb
    /// ```
    ///
    /// There is no lookahead. A carriage return is deleted whether or not a
    /// newline follows it, so `"a\rb"` in text mode reads as `"ab"`. The one
    /// exception in the RTL fires only when a `\r` is the last byte of an
    /// internal buffer, which is an artefact of where the buffer happened to
    /// end rather than a rule about the file, and is not reproduced here.
    fn getc(&mut self) -> io::Result<Option<u8>> {
        let Io::Read(reader) = &mut self.io else {
            return Ok(None);
        };
        if self.ended {
            return Ok(None);
        }

        loop {
            let mut one = [0u8; 1];
            if reader.read(&mut one)? == 0 {
                self.ended = true;
                return Ok(None);
            }
            if !self.mode.binary {
                match one[0] {
                    // `endSeen`: the file stops here, and stays stopped --
                    // the real runtime seeks back over it and latches `_O_EOF`.
                    CTRL_Z => {
                        self.ended = true;
                        return Ok(None);
                    }
                    b'\r' => continue,
                    _ => {}
                }
            }
            return Ok(Some(one[0]));
        }
    }

    /// Up to `max` bytes, stopping after a newline and keeping it.
    ///
    /// `FGETS.C` is one line and this is it:
    ///
    fn line(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.getc()? {
                Some(b) => {
                    out.push(b);
                    if b == b'\n' {
                        break;
                    }
                }
                None => break,
            }
        }
        Ok(out)
    }

    /// Up to `want` bytes. A short answer is the end of the file.
    fn read(&mut self, want: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(want);
        while out.len() < want {
            match self.getc()? {
                Some(b) => out.push(b),
                None => break,
            }
        }
        Ok(out)
    }

    /// Put `bytes` on the end, translating if this is a text stream.
    ///
    /// `WRITE.C:111` -- `if ((c = *sbuf++) == '\n') *tbuf++ = '\r';` -- so a
    /// `.LOG` a sysop opens in a DOS editor has DOS line endings.
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let (Io::Write(file) | Io::Update(file)) = &mut self.io else {
            return Ok(());
        };
        if self.mode.binary {
            return file.write_all(bytes);
        }
        let mut out = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
        file.write_all(&out)
    }
}

/// The streams that are open, and every cookie ever issued.
///
/// # Generic throughout
///
/// `Stream::cookie` and `retired`'s addresses are typed `A::Ptr` rather than
/// `FarPtr`, and `arena` is `Arena<A>`, so this is genuinely `Streams<A>`.
/// Every method that never touched a `Machine` -- `close`, `name`,
/// `modified`, `write`, `len`, `is_empty`, and the private `find`/`readable`/
/// `free_fd` -- lives on `impl<A: Abi> Streams<A>`, `cookie` widened from
/// `FarPtr` to `A::Ptr`.
///
/// `open_mem`, `line_mem`, `read_mem` and the private `sync` touch memory and
/// take `&mut A::Mem` for it. There was a period when each of the first three
/// also had a `Wg16` facade -- `open`/`line`/`read`, keeping the original
/// `&mut Machine` signature and reborrowing through `Machine::mem_mut` -- to
/// spare shim call sites built against the pre-generic shape. Those facades
/// are gone: once the shim layer took `Call<A>`, every call site had an
/// `A::Mem` of its own via `Call::mem` and went straight to the `_mem` core,
/// which left all three facades with **zero callers** while still forcing
/// `mbbs16::FarPtr` and `mbbs16::Machine` into this file's imports. Deleting
/// them is what took `stream.rs` off `no_direct_farptr.rs`'s `ALLOWED` list.
///
/// The `_mem` suffix is now vestigial -- there is no unsuffixed sibling left
/// to distinguish them from -- but renaming three public methods to drop it
/// is churn against every call site for no behaviour, so it stays. Read it as
/// naming the parameter, not as implying a facade.
///
/// `A` carries no default; every caller spells its ABI. It was `= Wg16` until
/// Task 3 of `docs/plans/2026-08-12-abi-border-implementation.md`.
/// Not `#[derive(Default)]`: the derive macro bounds
/// `A: Default` on the generated impl, which the bare marker struct `Wg16`
/// does not satisfy -- see `crates/mbbs/src/abi.rs`'s `Ret<A>` for the same
/// problem and fix.
pub struct Streams<A: Abi> {
    /// Where the `FILE` structs live. Deliberately **not** the module heap: a
    /// Borland `FILE` belongs to the runtime's own static `_streams[]` and the
    /// module never allocates or frees one, and putting them on the heap would
    /// make `farcoreleft` depend on how many files had been opened.
    arena: Arena<A>,

    open: Vec<Stream<A>>,

    /// Every cookie that has been closed, and what it named.
    ///
    /// The addresses are never reissued, so a use-after-close is a refusal that
    /// can say *which file* -- rather than a write into whichever stream had
    /// since landed on that address.
    retired: Vec<(A::Ptr, String)>,
}

impl<A: Abi> Default for Streams<A> {
    fn default() -> Self {
        Self {
            arena: Arena::default(),
            open: Vec::new(),
            retired: Vec::new(),
        }
    }
}

impl<A: Abi> Streams<A> {
    /// Open `path` and give the module a `FILE *` to name it by, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// Open `path` and give the module a `FILE *` to name it by.
    ///
    /// The `_mem` suffix is vestigial -- see the struct's own doc comment.
    ///
    /// # Errors
    ///
    /// If the mode asks for something this host does not do, if the file will
    /// not open, or if there is no descriptor left.
    pub fn open_mem(
        &mut self,
        mem: &mut A::Mem,
        name: &str,
        path: &Path,
        mode: Mode,
    ) -> Result<A::Ptr, String> {
        let fd = self.free_fd().ok_or_else(|| {
            format!(
                "{name}: all {} descriptors are in use",
                u16::from(u8::MAX) + 1 - u16::from(FIRST_FD)
            )
        })?;

        // The base letter decides create and truncate; the `+` decides only
        // that the handle is `O_RDWR`. `CheckOpenType`'s table, FOPEN.C:44-50:
        // `w+` creates and truncates, `a+` creates and appends, `r+` does
        // neither and fails if the file is not there.
        let io = if mode.update {
            Io::Update(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(!mode.read)
                    .append(mode.append)
                    .truncate(mode.write && !mode.append)
                    .open(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
            )
        } else if mode.read {
            Io::Read(BufReader::new(
                File::open(path).map_err(|e| format!("{}: {e}", path.display()))?,
            ))
        } else {
            Io::Write(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(mode.append)
                    .truncate(!mode.append)
                    .open(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
            )
        };

        let cookie = self
            .arena
            .reserve(mem, FILE_SIZE)
            .map_err(|e| format!("{name}: {e}"))?;

        let stream = Stream {
            name: name.to_owned(),
            cookie,
            fd,
            mode,
            io,
            ended: false,
        };

        // The two fields a module reads without asking the host. Written before
        // the stream is recorded, so a failure here cannot leave a stream the
        // host believes in behind a struct that says nothing.
        let mut image = [0u8; FILE_SIZE];
        let at = usize::from(FLAGS);
        image[at..at + 2].copy_from_slice(&stream.flags().to_le_bytes());
        image[usize::from(FD)] = fd;
        cookie
            .write(mem, &image)
            .map_err(|e| format!("{name}: {e}"))?;

        self.open.push(stream);
        Ok(cookie)
    }

    /// Close a stream.
    ///
    /// The cookie is retired rather than reused, which is what makes a later use
    /// of it a refusal. **The descriptor is not**: `fd` is one byte, so never
    /// reusing it would run out after 251 opens, and the real runtime reuses it
    /// too. The asymmetry is deliberate -- the cookie is what every host call is
    /// validated against, and the descriptor is only ever read out of a `FILE`
    /// the module has open in front of it.
    ///
    /// Never touched a `Machine`, so this is generic outright -- see the
    /// struct's own doc comment for why `cookie: A::Ptr` costs nothing at any
    /// existing call site.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream.
    pub fn close(&mut self, cookie: A::Ptr) -> Result<(), String> {
        let at = self.find(cookie)?;
        let stream = self.open.remove(at);
        self.retired.push((cookie, stream.name));
        Ok(())
    }

    /// What a stream was opened as.
    ///
    /// Generic outright, for the same reason `close` is.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream.
    pub fn name(&self, cookie: A::Ptr) -> Result<&str, String> {
        Ok(&self.open[self.find(cookie)?].name)
    }

    /// When the file behind `fd` was last written, in seconds since 1970.
    ///
    /// **Keyed by descriptor rather than by `FILE *`**, because the one caller
    /// is `getdtd`, whose argument is `fileno(fp)` -- and `fileno` is a Borland
    /// macro that reads `FILE.fd` directly and never reaches this host. So the
    /// module hands over a number this crate assigned and nothing else.
    ///
    /// Taken from the open handle, not from the path, which is what DOS's
    /// `AH=57h` does: it takes a handle and cannot be fooled by a rename
    /// between the `fopen` and the ask.
    ///
    /// Generic outright: never touched a `Machine` or a pointer of any kind.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, or the file will not say when it was
    /// written, or it was written before 1970.
    pub fn modified(&self, fd: u8) -> Result<u32, String> {
        let stream = self
            .open
            .iter()
            .find(|s| s.fd == fd)
            .ok_or_else(|| format!("fd {fd} names no open stream"))?;

        let file = match &stream.io {
            Io::Read(reader) => reader.get_ref(),
            Io::Write(file) | Io::Update(file) => file,
        };
        let at = file
            .metadata()
            .and_then(|m| m.modified())
            .map_err(|e| format!("{}: {e}", stream.name))?;
        at.duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .map_err(|_| format!("{} was written before 1970", stream.name))
    }

    /// A line, or `None` if the stream ended before one could start, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// `None` is `fgets` returning `NULL`, which is an answer.
    ///
    /// A line, or `None` if the stream ended before one could start.
    ///
    /// The `_mem` suffix is vestigial -- see the struct's own doc comment.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream, if it is not open for reading, or if
    /// the read fails.
    pub fn line_mem(
        &mut self,
        mem: &mut A::Mem,
        cookie: A::Ptr,
        max: usize,
    ) -> Result<Option<Vec<u8>>, String> {
        let at = self.readable(cookie)?;
        let line = self.open[at]
            .line(max)
            .map_err(|e| format!("{}: {e}", self.open[at].name))?;
        self.sync(mem, at)?;

        // `FGETS.C`: `if (EOF == c && P == s) return NULL`. Nothing read *and*
        // the stream is over -- a zero-length answer from a stream that is still
        // going is a caller who asked for no bytes.
        Ok((!line.is_empty() || !self.open[at].ended).then_some(line))
    }

    /// Up to `want` bytes. A short answer means the file ended, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// Up to `want` bytes. A short answer means the file ended.
    ///
    /// The `_mem` suffix is vestigial -- see the struct's own doc comment.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream, if it is not open for reading, or if
    /// the read fails.
    pub fn read_mem(
        &mut self,
        mem: &mut A::Mem,
        cookie: A::Ptr,
        want: usize,
    ) -> Result<Vec<u8>, String> {
        let at = self.readable(cookie)?;
        let bytes = self.open[at]
            .read(want)
            .map_err(|e| format!("{}: {e}", self.open[at].name))?;
        self.sync(mem, at)?;
        Ok(bytes)
    }

    /// Put `bytes` on the end of a stream.
    ///
    /// Never touched a `Machine`: the write lands in the host's own file
    /// handle ([`Stream::write`]), not in module memory, so this is generic
    /// outright.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream, if it is not open for writing, or if
    /// the write fails.
    pub fn write(&mut self, cookie: A::Ptr, bytes: &[u8]) -> Result<(), String> {
        let at = self.find(cookie)?;
        let stream = &mut self.open[at];
        if !stream.mode.writable() {
            return Err(format!("{} is open for reading", stream.name));
        }
        stream
            .write(bytes)
            .map_err(|e| format!("{}: {e}", stream.name))
    }

    /// How many streams are open.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether nothing is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Where the stream `cookie` names is, or why it names none.
    fn find(&self, cookie: A::Ptr) -> Result<usize, String> {
        if let Some(at) = self.open.iter().position(|s| s.cookie == cookie) {
            return Ok(at);
        }
        // Retired addresses are never reissued, so this can name the file --
        // which is the difference between a refusal somebody can act on and one
        // that says only that a pointer was wrong.
        match self.retired.iter().find(|(at, _)| *at == cookie) {
            Some((_, name)) => Err(format!("{name} was closed")),
            None => Err(format!("{cookie} is not a stream this host opened")),
        }
    }

    /// Where the stream `cookie` names is, given it must be readable.
    ///
    /// Two refusals, for two different things. The first is the module asking
    /// to read a stream it opened `w` or `a`. The second is subtler and is why
    /// this is not one check: an update stream **is** readable as far as its
    /// mode and its `flags` word go, and there is still no defined moment at
    /// which reading it would mean anything.
    fn readable(&self, cookie: A::Ptr) -> Result<usize, String> {
        let at = self.find(cookie)?;
        let stream = &self.open[at];
        if !stream.mode.readable() {
            return Err(format!("{} is open for writing", stream.name));
        }

        // `fopen`'s own documentation, FOPEN.C:261-266: "output may not be
        // directly followed by input without an intervening fseek or rewind".
        // `WCCMMUD.DLL` imports no `fseek`, no `ftell` and no `rewind`, so
        // every read it could make of an update stream is one the original had
        // no defined answer for. A host that answered anyway would be inventing
        // behaviour, and the answer it would invent -- end of file, from
        // `getc`'s `else` arm -- is a plausible zero rather than a visible one.
        if matches!(stream.io, Io::Update(_)) {
            return Err(format!(
                "{} is open for update, and this module imports no fseek, ftell \
                 or rewind -- so there is no point at which reading it would \
                 mean anything",
                stream.name
            ));
        }
        Ok(at)
    }

    /// Put the stream's `flags` back where the module reads it.
    ///
    /// Private, with no shim call site to preserve, so this takes `&mut
    /// A::Mem` outright rather than needing a `Wg16` facade of its own --
    /// unlike `open`/`line`/`read`, which are public and do need one.
    fn sync(&mut self, mem: &mut A::Mem, at: usize) -> Result<(), String> {
        let stream = &self.open[at];
        let field = A::ptr_offset(stream.cookie, FLAGS);
        field
            .write(mem, &stream.flags().to_le_bytes())
            .map_err(|e| format!("{}: {e}", stream.name))
    }

    /// The lowest descriptor no open stream is using.
    fn free_fd(&self) -> Option<u8> {
        (FIRST_FD..=u8::MAX).find(|fd| !self.open.iter().any(|s| s.fd == *fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_mode_is_text() {
        // `_fmode`'s default, and the module relies on it: `WCCRECOV.FLG` is
        // opened `"w"` and the list dump `"a"`.
        for bare in ["r", "w", "a"] {
            assert!(!Mode::parse(bare).expect("a mode").binary, "{bare}");
        }
    }

    #[test]
    fn every_mode_the_module_uses_parses() {
        // Every mode-shaped string in `re/WCCMMUD.DLL`, by occurrence: `r` 17,
        // `a` 12, `rt` 5, `w` 4, `wt` 3, `at` 2, `rb` 1, and `w+` once at file
        // offset 0xe2412 -- the only update mode in the module.
        for used in ["w", "a", "rt", "wt", "at", "rb", "w+"] {
            Mode::parse(used).unwrap_or_else(|e| panic!("{used}: {e}"));
        }
    }

    #[test]
    fn a_plus_adds_the_other_direction_without_changing_the_base_letter() {
        // `CheckOpenType`, FOPEN.C:100-108 -- "same modes, but both read and
        // write". The base letter still decides create and truncate, so it has
        // to survive the `+` rather than be overwritten by it.
        let w = Mode::parse("w+").expect("a mode");
        assert!(w.write && !w.read, "the base letter is still `w`");
        assert!(w.readable() && w.writable(), "and a `+` is both");

        let r = Mode::parse("r+").expect("a mode");
        assert!(r.read && !r.write, "the base letter is still `r`");
        assert!(r.readable() && r.writable(), "and a `+` is both");

        let a = Mode::parse("a+").expect("a mode");
        assert!(a.append, "the base letter is still `a`");
        assert!(a.readable() && a.writable());
    }

    #[test]
    fn a_mode_without_a_plus_is_one_direction_only() {
        let r = Mode::parse("rt").expect("a mode");
        assert!(r.readable() && !r.writable());
        for one_way in ["wt", "at", "w", "a"] {
            let m = Mode::parse(one_way).expect("a mode");
            assert!(m.writable() && !m.readable(), "{one_way}");
        }
    }

    #[test]
    fn a_mode_is_read_or_written_but_not_guessed() {
        let r = Mode::parse("rt").expect("a mode");
        assert!(r.read && !r.write && !r.append && !r.binary);
        let a = Mode::parse("ab").expect("a mode");
        assert!(!a.read && a.write && a.append && a.binary);
        let w = Mode::parse("wt").expect("a mode");
        assert!(!w.read && w.write && !w.append && !w.binary);
    }

    #[test]
    fn a_mode_this_host_cannot_read_is_refused_naming_it() {
        // Each of these would otherwise be silently treated as something.
        for bad in ["", "x", "rw", "rtb", "r++", "rz", " r"] {
            let e = Mode::parse(bad).expect_err(bad);
            assert!(e.contains(&format!("{bad:?}")), "{bad}: {e}");
        }
    }
}
