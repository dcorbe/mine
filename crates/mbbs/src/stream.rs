//! Streams: the module's own files, opened by name and read or written through.
//!
//! Ten routines over a handle -- `fopen`, `fclose`, `fgets`, `fread`,
//! `fprintf`, `fflush`, `unlink`, `fseek`, `ftell`, `rewind`. `WCCMMUD.DLL`
//! imports none of the last three -- every stream in it is read or written
//! straight through, once -- but a second module now does (see
//! [`Streams::readable`]'s own doc comment), so this crate carries them. The
//! design is `docs/plans/2026-08-04-streams.md`.
//!
//! One stream in `WCCMMUD.DLL` is neither read-only nor write-only:
//! `_GENERATE_TOP_LIST` opens `log.log` `"w+"` at `seg 34:0x010a`, the
//! module's only update mode. It is written like any other, and -- now that
//! `fseek`/`ftell`/`rewind` exist somewhere in this host -- reading it is
//! *mechanically* possible; `WCCMMUD.DLL` itself never asks to, so this is
//! inert for that module and only load-bearing for the one that does.
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
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use mbbs_machine::ptr::ModulePtr;

use crate::abi::Abi;

/// Bytes of Borland's `FILE`, as `INCLUDE/STDIO.H:104-114` declares it: two
/// `int`s, two `char`s, an `int`, two far pointers, an `unsigned` and a `short`.
///
/// Large model, so the pointers are four bytes each. Twenty in total, and no
/// padding -- every field lands on its natural boundary already.
///
/// `Wg16`'s `sizeof(FILE)`, for tests that name a concrete ABI.
///
/// **Unified with [`Abi::FILE_SIZE`] as of Phases 3+4 Task 4.4**: it is now
/// *defined as* `Wg16::FILE_SIZE` rather than being a second, independently
/// written sum of the same field list. It used to be described as "one
/// reservation size for every ABI" -- true while every `FILE` came out of an
/// arena, and wrong the moment `_streams` became a real array, because an
/// array whose stride disagrees with the structs in it is worse than no
/// array. Nothing reserves or strides by this constant now; every such site
/// uses `A::FILE_SIZE`.
pub const FILE_SIZE: usize = <crate::abi::Wg16 as Abi>::FILE_SIZE;

/// Where `fd` is, which `fileno(f)` expands to a read of. **One byte.**
///
/// **Not per-ABI, unlike [`Abi::FILE_FLAGS_OFFSET`], and that is a known gap
/// rather than an oversight fixed here.** `cw3220mt`'s own exported
/// `_fileno` (`re/wg/CW3220MT.DLL`, RVA `0x6b44`, right after `_ferror`)
/// reads `mov eax,[eax+0x16]` -- a full **four**-byte `int` at offset
/// **22**, not this crate's one byte at offset 4. That is the same class of
/// bug `FILE_FLAGS_OFFSET` exists to fix, and by the same evidence: `flags`
/// sitting at 0x12 and a 4-byte gap before `fd` at 0x16 is consistent with
/// both being full `int` fields in `cw3220mt`'s own layout, not Borland
/// 16-bit `STDIO.H`'s packed one.
///
/// Left as `Wg16`'s own offset and width for every ABI because it is
/// currently **dormant**, not because it is right: a full disassembly of
/// `archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL` (the one 32-bit
/// module this host runs) for the `_fileno` pattern -- `mov eXX,[reg+0x16]`
/// -- found zero matches, unlike `flags`'s `test byte ptr [reg+0x12],0x20`,
/// which appears dozens of times throughout that same module. `fileno` is
/// what `WCCMMUD.DLL`'s (16-bit) `_CHECK_BEGIN_UPDATING` calls (this file's
/// own module doc comment), not anything LunatiX reaches. A future 32-bit
/// module that does call `fileno` would hit this exact bug, one byte
/// truncated and twelve bytes short of where its own runtime looks.
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

/// How many `FILE` slots `_streams` holds -- Borland's `_NFILE`.
///
/// **Twenty, and this is a documented choice rather than a measurement.**
/// `_NFILE` is 20 in Borland's 16-bit runtime, but it is defined in
/// `INCLUDE/STDIO.H`, which is not in this repository's tracked tree --
/// `re/wg33src/INC/` is Galacticomm's headers, not Borland's, and the Turbo C
/// headers under `tmp/` are gitignored and so cannot be cited. No oracle
/// build exports anything that would reveal the array's length either: the
/// datum's address is exported (ordinal 43, `__STREAMS`) but its extent is
/// not.
///
/// The number is load-bearing in one way and one way only: it bounds how
/// many files may be open at once, because [`crate::stream::Streams`] puts
/// each stream's `FILE` at the slot its own descriptor names. Five of the
/// twenty are DOS's standard handles, so fifteen remain -- which is what the
/// real runtime allowed too.
pub const NFILE: u16 = 20;

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
    /// **Trailing spaces are padding, not a mode; anything else trailing is a
    /// contradiction.** Rose 3.0NT's `cw3220mt.DLL` calls `fopen` with
    /// `"r  "` -- a mode padded into a fixed-width buffer -- and Borland's own
    /// `CheckOpenType` (`FOPEN.C:60-61`,
    /// `~/.cache/bcsrc/SOURCE/RTL/SOURCE/IO/COMMON16/FOPEN.C`) says outright:
    /// "We require the first char of the type string to be r, w, or a, but
    /// after that we just stop on mismatch and don't care if the string is
    /// junk." Measuring the function itself (lines 66-128) shows it is even
    /// looser than that sentence suggests: it inspects at most three
    /// positions (the letter, one `+`/`t`/`b`, and -- only if that second
    /// character was `+` -- one more `t`/`b`) and never looks at anything
    /// past them, so a real `"rw"` or `"rz"` would open exactly like `"r"`.
    /// This host does not go that far: it still refuses a second letter that
    /// isn't `+`, `t`, or `b` (`"rw"`, `"rz"`) and still refuses a repeated or
    /// misplaced modifier (`"rtb"`, `"r++"`) -- those are contradictions a
    /// working caller does not produce, and silently ignoring them would mask
    /// a real bug in some *other* call site the way accepting `"r  "` does
    /// not. The only trailing input this host treats as padding rather than
    /// contradiction is whitespace: once the valid `letter[+][tb]` prefix is
    /// parsed, every character after it must be a space, or the mode is
    /// refused.
    ///
    /// # Errors
    ///
    /// If the string is not a mode, or a valid mode followed by anything
    /// other than space padding. Guessing at one would mean a stream opened
    /// for reading when it meant append -- which loses a log -- or as text
    /// when it meant binary, which corrupts a record by two bytes a line.
    /// Neither fails loudly on its own.
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
        for c in rest.by_ref() {
            match c {
                '+' if !update => update = true,
                't' | 'b' if binary.is_none() => binary = Some(c == 'b'),
                // **Stop on mismatch, and do not care what follows.** This
                // is Borland's own rule, not a guess and not a relaxation
                // chosen here -- `CheckOpenType`'s own comment, at
                // `~/.cache/bcsrc/SOURCE/RTL/SOURCE/IO/COMMON16/FOPEN.C:60-61`:
                //
                //     We require the first char of the type string to be r, w,
                //     or a, but after that we just stop on mismatch and don't
                //     care if the string is junk.
                //
                // The function is as loose as its comment: it inspects at most
                // three fixed positions and never looks past them, so `"r  "`
                // (Rose 3.0NT's real, fixed-width-padded mode), `"rw"` and
                // `"rz"` all open exactly like plain `"r"`.
                //
                // This host refused all three until 2026-08-15, which stopped
                // a module the real host would have served. The mode string is
                // module-supplied data reaching us through the `fopen` shim --
                // never a string this crate builds -- so strictness here can
                // only police someone else's module, and stopping the machine
                // is a far worse answer than opening the file the way the
                // vendor did. The first character is still required, because
                // that is the one thing Borland does require.
                _ => break,
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

/// `fseek`'s three origins, `STDIO.H`'s own numbering (`SEEK_SET` 0,
/// `SEEK_CUR` 1, `SEEK_END` 2) already resolved into a type the host cannot
/// mis-widen -- decoding the raw `int` into one of these three is
/// [`crate::shims::stream::fseek`]'s job, not this module's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whence {
    /// `SEEK_SET` -- from the start of the file.
    Set,
    /// `SEEK_CUR` -- from the stream's current position.
    Cur,
    /// `SEEK_END` -- from the end of the file.
    End,
}

/// An open file, and how the module is reading or writing it.
///
/// Reading is buffered because it is done a byte at a time -- see [`Self::getc`]
/// -- and writing is not, which is what makes `fflush` an honest no-op rather
/// than a convenient one.
enum Io {
    Read(BufReader<File>),
    Write(File),

    /// Opened for update -- `O_RDWR`. Written exactly like [`Self::Write`],
    /// and readable too -- see [`Streams::readable`]'s own doc comment for
    /// why that changed and what still gates it.
    ///
    /// Unbuffered, like `Write` and unlike `Read`, which is not an oversight.
    /// A `BufReader` over a handle this host also writes through would answer
    /// from a buffer filled before the write -- so [`Stream::getc`] reads
    /// this variant directly off the `File` rather than through a second
    /// `BufReader`.
    Update(File),
}

/// One open stream.
struct Stream<A: Abi> {
    /// What the module called it, in the module's own spelling.
    name: String,

    /// The `FILE *` the module holds. Unique for the life of the host.
    ///
    /// **`None` for a stream `open`/`creat` produced.** Those are raw DOS
    /// handles: Borland's low-level I/O allocates no `FILE` for them, and the
    /// module never has a pointer to hand back. Everything a raw handle can
    /// do is reached by descriptor instead -- see [`Streams::find_fd`].
    ///
    /// Widening this rather than adding a second table is the whole design
    /// decision of the descriptor work. `lseek`/`tell`/`filelength`/`read`/
    /// `write` all have to work on a descriptor that came from *either*
    /// `open` or `fileno(fopen(...))`, and two tables would mean two possible
    /// answers to "what is fd 7" -- with nothing to stop both being live at
    /// once.
    cookie: Option<A::Ptr>,

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
    ///
    /// **Reads `Io::Update` too, now.** Until `Streams::readable` stopped
    /// refusing an update stream outright, nothing ever called this with
    /// `self.io` in that variant, so the byte-at-a-time read below only ever
    /// matched `Io::Read`'s `BufReader` and answered `None` for anything
    /// else -- silently correct only because the caller it was silently
    /// correct *for* could never be reached. `Io::Update` reads straight off
    /// its `File`, unbuffered, the same reason `Io::Update`'s own doc
    /// comment gives for why it is not a second `BufReader`.
    fn getc(&mut self) -> io::Result<Option<u8>> {
        if self.ended {
            return Ok(None);
        }

        loop {
            let mut one = [0u8; 1];
            let n = match &mut self.io {
                Io::Read(reader) => reader.read(&mut one)?,
                Io::Update(file) => file.read(&mut one)?,
                // A write-only stream has nothing to read. `Streams::readable`
                // already refuses this case before `getc` is ever reached; this
                // arm exists so the match is exhaustive rather than because
                // anything is expected to hit it.
                Io::Write(_) => return Ok(None),
            };
            if n == 0 {
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

    /// Put `bytes` on the end **without** translating, whatever the mode
    /// says.
    ///
    /// What `_write` does where [`Stream::write`] is what `write` does. The
    /// underscore is the whole difference between the two Borland symbols,
    /// and this is where it lives -- one layer, so a caller cannot translate
    /// a second time on top of a layer that already did.
    fn write_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let (Io::Write(file) | Io::Update(file)) = &mut self.io else {
            return Ok(());
        };
        file.write_all(bytes)
    }

    /// Move this stream's real, physical position, and answer where it
    /// landed.
    ///
    /// **A raw byte offset into the file, not the module's logical one.**
    /// Borland's own `FSEEK.C` calls `lseek` on the underlying DOS handle;
    /// the CR-squeeze and soft `^Z` end-of-file [`Self::getc`] layers on top
    /// of that never see this call, and neither does this host's -- see this
    /// file's own module doc ("measured against Borland's own runtime") for
    /// why that is the answer being matched rather than a looser one.
    ///
    /// Clears [`Self::ended`] unconditionally on success, which is what
    /// zeroes `_F_EOF` in the module's `FILE.flags` (through
    /// [`Streams::seek_mem`]'s own call to `Streams::sync`, after this
    /// returns): `FSEEK.C` and `REWIND.C` both clear it whether or not the
    /// new position is provably before the end, and a stream a module has
    /// just repositioned must be readable again even if the read right
    /// before the seek had hit the end.
    ///
    /// A [`BufReader`]'s own `Seek` discards whatever it had buffered, so a
    /// read immediately after this is never answered out of bytes read
    /// before the seek.
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let at = match &mut self.io {
            Io::Read(reader) => reader.seek(pos)?,
            Io::Write(file) | Io::Update(file) => file.seek(pos)?,
        };
        self.ended = false;
        Ok(at)
    }

    /// This stream's real, physical position -- what `ftell` reports.
    ///
    /// A [`BufReader`] answers this without discarding its buffer (unlike a
    /// bare `seek(SeekFrom::Current(0))`, which would), so calling this does
    /// not itself disturb a read in progress.
    fn tell(&mut self) -> io::Result<u64> {
        match &mut self.io {
            Io::Read(reader) => reader.stream_position(),
            Io::Write(file) | Io::Update(file) => file.stream_position(),
        }
    }
}

/// The streams that are open, and every cookie ever issued.
///
/// # Generic throughout
///
/// `Stream::cookie` and `retired`'s addresses are typed `A::Ptr` rather than
/// `FarPtr`, and `arena` is `Arena<A>`, so this is genuinely `Streams<A>`.
/// Every method that never touched a `Machine` -- `close`, `name`,
/// `modified`, `write`, `tell`, `len`, `is_empty`, and the private
/// `find`/`readable`/`free_fd` -- lives on `impl<A: Abi> Streams<A>`,
/// `cookie` widened from `FarPtr` to `A::Ptr`.
///
/// `open_mem`, `line_mem`, `read_mem`, `seek_mem` and the private `sync`
/// touch memory and take `&mut A::Mem` for it. `seek_mem` needs it for the
/// same reason `sync` exists at all: a successful seek clears `_F_EOF` in
/// the module's own `FILE.flags` (see `Stream::seek`'s own doc comment),
/// which `tell` never touches -- finding out where a stream is changes
/// nothing a module can observe, which is why `tell` is in the first list
/// and `seek_mem` is in this one. There was a period when each of the first
/// three also had a `Wg16` facade -- `open`/`line`/`read`, keeping the
/// original `&mut Machine` signature and reborrowing through
/// `Machine::mem_mut` -- to spare shim call sites built against the
/// pre-generic shape. Those facades are gone: once the shim layer took
/// `Call<A>`, every call site had an `A::Mem` of its own via `Call::mem` and
/// went straight to the `_mem` core, which left all three facades with
/// **zero callers** while still forcing `mbbs_machine::m16::FarPtr` and
/// `mbbs_machine::m16::Machine` into this file's imports. Deleting them is
/// what took `stream.rs` off `no_direct_farptr.rs`'s `ALLOWED` list.
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
    /// Where `_streams` was placed, once the host knows.
    ///
    /// **`FILE` structs are carved out of the module-visible `_streams`
    /// array, not out of an arena of this type's own.** Borland's `FILE`s
    /// live in `_streams[]` and a module may compare a `FILE *` against
    /// `&_streams[n]`, walk the array, or reach `stdin`/`stdout`/`stderr` as
    /// `&_streams[0..3]`; a cookie at some arena address would satisfy none
    /// of that, and the two were genuinely two address spaces for one concept
    /// until Phases 3+4 Task 4.4.
    ///
    /// `None` only before [`Streams::place`] has run.
    base: Option<A::Ptr>,

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
            base: None,
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

        let io = Self::io_for(path, mode)?;

        let cookie = self.slot(fd).map_err(|e| format!("{name}: {e}"))?;

        let stream = Stream {
            name: name.to_owned(),
            cookie: Some(cookie),
            fd,
            mode,
            io,
            ended: false,
        };

        // The two fields a module reads without asking the host. Written before
        // the stream is recorded, so a failure here cannot leave a stream the
        // host believes in behind a struct that says nothing.
        let mut image = vec![0u8; A::FILE_SIZE];
        let at = usize::from(A::FILE_FLAGS_OFFSET);
        image[at..at + 2].copy_from_slice(&stream.flags().to_le_bytes());
        // `fd` at this ABI's own offset and width, little-endian. `fileno` is
        // a macro: the module reads these bytes itself and never asks, so a
        // byte written at the wrong offset is never noticed here -- only much
        // later, by whatever the module passes the result to.
        let at = usize::from(A::FILE_FD_OFFSET);
        let width = usize::from(A::FILE_FD_WIDTH);
        image[at..at + width].copy_from_slice(&u32::from(fd).to_le_bytes()[..width]);
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
        self.close_at(at);
        Ok(())
    }

    /// Drop the stream at `at`, retiring its cookie if it had one.
    ///
    /// A raw descriptor has nothing to retire: the descriptor itself is
    /// reused (it is one byte, and the real runtime reuses it too), and there
    /// is no `FILE` address that must never be handed out again.
    fn close_at(&mut self, at: usize) {
        let stream = self.open.remove(at);
        if let Some(cookie) = stream.cookie {
            self.retired.push((cookie, stream.name));
        }
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

    /// Move a stream's position -- `SEEK_SET` from the start, `SEEK_CUR` from
    /// where it is, `SEEK_END` from the end -- and answer where it landed.
    ///
    /// Takes `mem` (unlike [`Self::write`], which never touches it): a
    /// successful seek clears `_F_EOF` in the module's own `FILE.flags`
    /// ([`Stream::seek`]'s own doc comment), the same field [`Self::sync`]
    /// keeps current everywhere else in this file, and `feof` is a macro
    /// that never asks the host (this file's own module doc) -- so a seek
    /// that left a stale `_F_EOF` behind would make the module believe it
    /// was still at the end of a file it had just been moved off of.
    ///
    /// **A seek past the end of the file is allowed, on any stream, not only
    /// a writable one.** C only promises this for a writable stream -- seek
    /// past the end, then write, leaves a hole -- and says nothing about the
    /// read side. This host does not distinguish them: an OS-level seek past
    /// a regular file's length is not an error either way, so refusing it
    /// here for a read-only stream would be inventing a restriction neither
    /// POSIX's `lseek` nor DOS's own enforces. Reading after such a seek
    /// answers zero bytes, which is [`Stream::getc`]'s ordinary
    /// end-of-file arm -- not a fabricated value, and not a refusal.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream; if `whence` is [`Whence::Set`] and
    /// `offset` is negative (`SEEK_SET`'s offset is measured from zero, so a
    /// negative one names no position at all); or the underlying seek fails
    /// (`SEEK_CUR`/`SEEK_END` landing before the start of the file, which
    /// this host refuses the same way the OS call underneath it does rather
    /// than clamping to zero and pretending the module asked for that).
    pub fn seek_mem(
        &mut self,
        mem: &mut A::Mem,
        cookie: A::Ptr,
        offset: i64,
        whence: Whence,
    ) -> Result<u64, String> {
        let at = self.find(cookie)?;

        let from = match whence {
            Whence::Set => SeekFrom::Start(u64::try_from(offset).map_err(|_| {
                format!(
                    "{}: fseek(SEEK_SET, {offset}) -- a negative offset names no position",
                    self.open[at].name
                )
            })?),
            Whence::Cur => SeekFrom::Current(offset),
            Whence::End => SeekFrom::End(offset),
        };

        let pos = self.open[at]
            .seek(from)
            .map_err(|e| format!("{}: {e}", self.open[at].name))?;
        self.sync(mem, at)?;
        Ok(pos)
    }

    /// A stream's current position -- what `ftell` reports.
    ///
    /// Never touches `mem`, unlike [`Self::seek_mem`]: finding out where the
    /// stream is changes nothing a module could observe through
    /// `FILE.flags`.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream. The position this returns is a
    /// plain `u64`; whether it fits the `long` the module reads it back as
    /// is [`crate::shims::stream::ftell`]'s question to ask, not this one's.
    pub fn tell(&mut self, cookie: A::Ptr) -> Result<u64, String> {
        let at = self.find(cookie)?;
        self.open[at]
            .tell()
            .map_err(|e| format!("{}: {e}", self.open[at].name))
    }

    /// How many streams are open.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether nothing is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Open the underlying file for `mode`.
    ///
    /// The base letter decides create and truncate; the `+` decides only that
    /// the handle is `O_RDWR`. `CheckOpenType`'s table, `FOPEN.C:44-50`: `w+`
    /// creates and truncates, `a+` creates and appends, `r+` does neither and
    /// fails if the file is not there.
    ///
    /// Shared by [`Streams::open_mem`] and [`Streams::open_raw`] so that a
    /// raw descriptor and a `FILE` opened the same way cannot end up with
    /// different `OpenOptions`.
    fn io_for(path: &Path, mode: Mode) -> Result<Io, String> {
        Ok(if mode.update {
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
        })
    }

    /// Open a file as a **raw descriptor**, with no `FILE` behind it.
    ///
    /// What `open` and `creat` do. The answer is the descriptor itself,
    /// because that is all the module gets: Borland's low-level I/O allocates
    /// nothing from `_streams[]` for these, and there is no cookie to hand
    /// back.
    ///
    /// The stream lands in the same table `fopen`'s do, so a descriptor is
    /// unique across both and `lseek`/`tell`/`read`/`write` do not care which
    /// call produced it.
    ///
    /// # Errors
    ///
    /// If every descriptor is in use, or the file cannot be opened.
    pub fn open_raw(&mut self, name: &str, path: &Path, mode: Mode) -> Result<u8, String> {
        let fd = self.free_fd().ok_or_else(|| {
            format!(
                "{name}: all {} descriptors are in use",
                u16::from(u8::MAX) + 1 - u16::from(FIRST_FD)
            )
        })?;
        let io = Self::io_for(path, mode)?;
        self.open.push(Stream {
            name: name.to_owned(),
            cookie: None,
            fd,
            mode,
            io,
            ended: false,
        });
        Ok(fd)
    }

    /// Where the stream with descriptor `fd` is, or why there is none.
    ///
    /// The counterpart of [`Streams::find`], and the reason there is one
    /// table rather than two: this resolves a descriptor from `open` and one
    /// from `fileno(fopen(...))` identically, because both are rows here.
    fn find_fd(&self, fd: u8) -> Result<usize, String> {
        self.open
            .iter()
            .position(|s| s.fd == fd)
            .ok_or_else(|| format!("descriptor {fd} names no stream this host has open"))
    }

    /// Close the stream with descriptor `fd`.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream.
    pub fn close_fd(&mut self, fd: u8) -> Result<(), String> {
        let at = self.find_fd(fd)?;
        self.close_at(at);
        Ok(())
    }

    /// Read at most `want` bytes from `fd`.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, it is not readable, or the read fails.
    pub fn read_fd(&mut self, fd: u8, want: usize) -> Result<Vec<u8>, String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        if !stream.mode.readable() {
            return Err(format!("{} is open for writing", stream.name));
        }
        stream.read(want).map_err(|e| format!("{}: {e}", stream.name))
    }

    /// Write `bytes` to `fd`, translating `\n` if the handle is in text
    /// mode.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, it is not writable, or the write fails.
    pub fn write_fd(&mut self, fd: u8, bytes: &[u8]) -> Result<(), String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        if !stream.mode.writable() {
            return Err(format!("{} is open for reading", stream.name));
        }
        stream.write(bytes).map_err(|e| format!("{}: {e}", stream.name))
    }

    /// Write `bytes` to `fd` with **no** translation, whatever the mode says.
    ///
    /// `_write`'s half of the pair. The translation lives in exactly one
    /// layer ([`Stream::write`] versus [`Stream::write_raw`]) so that no
    /// caller can apply it twice -- which is a real hazard here rather than a
    /// hypothetical one: `crt::write`'s descriptor branch was briefly written
    /// to translate before calling this type, on top of a stream layer that
    /// already did, and would have turned one `\n` into `\r\r\n`.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, it is not writable, or the write fails.
    pub fn write_raw_fd(&mut self, fd: u8, bytes: &[u8]) -> Result<(), String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        if !stream.mode.writable() {
            return Err(format!("{} is open for reading", stream.name));
        }
        stream.write_raw(bytes).map_err(|e| format!("{}: {e}", stream.name))
    }

    /// Move `fd`'s position, answering the new one.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, or the seek fails.
    pub fn seek_fd(&mut self, fd: u8, pos: SeekFrom) -> Result<u64, String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        // A seek clears end-of-file, the same as `fseek`'s does: the position
        // has moved, so whatever a previous read concluded no longer holds.
        stream.ended = false;
        stream.seek(pos).map_err(|e| format!("{}: {e}", stream.name))
    }

    /// Where `fd`'s position is.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, or the position cannot be read.
    pub fn tell_fd(&mut self, fd: u8) -> Result<u64, String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        stream.tell().map_err(|e| format!("{}: {e}", stream.name))
    }

    /// How long the file behind `fd` is, **without moving its position**.
    ///
    /// `filelength` is specified not to disturb the file pointer, so this
    /// saves the position, seeks to the end, and puts it back. Doing it any
    /// other way would leave a module's next read at the wrong place, which
    /// is the kind of bug that surfaces far from its cause.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream, or a seek fails.
    pub fn length_fd(&mut self, fd: u8) -> Result<u64, String> {
        let at = self.find_fd(fd)?;
        let stream = &mut self.open[at];
        let here = stream.tell().map_err(|e| format!("{}: {e}", stream.name))?;
        let end = stream
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("{}: {e}", stream.name))?;
        stream
            .seek(SeekFrom::Start(here))
            .map_err(|e| format!("{}: {e}", stream.name))?;
        Ok(end)
    }

    /// Whether `fd` was opened in binary mode.
    ///
    /// What decides whether `write` translates `\n` -- and what `_write`
    /// ignores. See [`crate::shims::crt::_write`].
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream.
    pub fn binary_fd(&self, fd: u8) -> Result<bool, String> {
        Ok(self.open[self.find_fd(fd)?].mode.binary)
    }

    /// Set whether `fd` translates -- `setmode`'s half of [`Streams::binary_fd`]
    /// -- and answer what it was before.
    ///
    /// Real Borland flips the `O_TEXT` bit in `_openfd[fd]` (`WRITE.C`'s own
    /// `_openfd[fd] & O_TEXT`, quoted on `crate::shims::crt::write`'s doc
    /// comment), and every read and write consults it at call time -- which
    /// [`Stream::write`]/[`Stream::getc`] already do here, so a mid-stream
    /// flip takes effect on the very next call, exactly as it does there.
    ///
    /// # Errors
    ///
    /// If `fd` names no open stream.
    pub fn setmode_fd(&mut self, fd: u8, binary: bool) -> Result<bool, String> {
        let at = self.find_fd(fd)?;
        let was = self.open[at].mode.binary;
        self.open[at].mode.binary = binary;
        Ok(was)
    }

    /// Where the stream `cookie` names is, or why it names none.
    fn find(&self, cookie: A::Ptr) -> Result<usize, String> {
        if let Some(at) = self.open.iter().position(|s| s.cookie == Some(cookie)) {
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
    /// One refusal now: the module asking to read a stream it opened `w` or
    /// `a`.
    ///
    /// # History: the second refusal this used to have
    ///
    /// Until this crate implemented `fseek`/`ftell`/`rewind` anywhere at
    /// all, an update stream was refused here too, on top of the mode check
    /// above. `fopen`'s own documentation (`FOPEN.C:261-266`) says "output
    /// may not be directly followed by input without an intervening fseek
    /// or rewind", and `WCCMMUD.DLL` -- the only module measured against
    /// this host when that refusal was written -- imports none of the
    /// three. So every read it could have made of its one update stream
    /// (`log.log`, `"w+"`) was one the original had no defined answer for;
    /// answering anyway would have meant inventing behaviour, and the
    /// answer this host would have invented -- end of file, from
    /// [`Stream::getc`]'s `else` arm -- was a plausible zero rather than a
    /// visible one.
    ///
    /// That census does not survive LunatiX 5.3F
    /// (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`), a second real
    /// 32-bit module that imports `_fseek`, `_ftell`, `_fgetc`, `_fputc`,
    /// `_fwrite` and `_flushall`, and opens its own `CWDLOPTS.DAT` for
    /// update before reading it. This host now has `fseek`/`ftell`/`rewind`
    /// ([`Streams::seek_mem`], [`Streams::tell`], and
    /// [`crate::shims::stream::rewind`]) with a real position behind them,
    /// so a read of an update stream has a defined answer: whatever is at
    /// its current position, the same as any other readable stream --
    /// [`Stream::getc`] reads `Io::Update` directly now too (see that
    /// method's own doc comment), which is the other half of what made the
    /// old refusal here true in the first place: even removing this check
    /// alone would not have produced a real read, only a stream that opened
    /// readable and delivered nothing.
    fn readable(&self, cookie: A::Ptr) -> Result<usize, String> {
        let at = self.find(cookie)?;
        let stream = &self.open[at];
        if !stream.mode.readable() {
            return Err(format!("{} is open for writing", stream.name));
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
        // A raw descriptor has no `FILE` to mirror the flags into, and
        // nothing reads them: `feof`/`ferror` are macros over a `FILE`, and a
        // module holding only a descriptor has none to hand them.
        let Some(cookie) = stream.cookie else {
            return Ok(());
        };
        let field = A::ptr_offset(cookie, A::FILE_FLAGS_OFFSET);
        field
            .write(mem, &stream.flags().to_le_bytes())
            .map_err(|e| format!("{}: {e}", stream.name))
    }

    /// The `FILE *` of the stream a descriptor names.
    ///
    /// `fileno` is a macro, so a module that has a `FILE *` can hand the host
    /// a bare descriptor at any moment -- The Rose 3.0NT does exactly that,
    /// `read(fileno(fp), buf, 5000)` at four call sites. Everything else in
    /// this type is keyed by cookie, so rather than grow a second I/O path
    /// keyed by descriptor, this translates one to the other and the existing
    /// path is reused.
    ///
    /// # Errors
    ///
    /// If no open stream carries that descriptor.
    pub fn cookie_of_fd(&self, fd: u8) -> Result<A::Ptr, String> {
        self.open
            .iter()
            .find(|s| s.fd == fd)
            .ok_or_else(|| format!("descriptor {fd} names no stream this host has open"))?
            .cookie
            .ok_or_else(|| {
                format!(
                    "descriptor {fd} is a raw handle from open/creat, which has no \
                     FILE -- reach it by descriptor rather than by cookie"
                )
            })
    }

    /// The descriptor a `FILE *` carries -- what `fileno(fp)` reads out of
    /// the struct, answered by the host instead.
    ///
    /// The inverse of [`Streams::cookie_of_fd`]. `fileno` is a macro, so a
    /// module reads this byte itself and never calls here; this exists for
    /// the host's own tests, which need to know which descriptor an `fopen`
    /// was given in order to check that a raw `open` did not collide with it.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open stream.
    pub fn fd_of_cookie(&self, cookie: A::Ptr) -> Result<u8, String> {
        Ok(self.open[self.find(cookie)?].fd)
    }

    /// The lowest descriptor no open stream is using.
    /// The lowest descriptor no open stream is using.
    ///
    /// **Bounded by `NFILE`, not by `u8::MAX`**, because a descriptor is also
    /// an index into `_streams` now: a handle the array has no slot for is a
    /// handle whose `FILE` would have nowhere to live. Five of the twenty
    /// slots are DOS's standard handles, so fifteen files may be open at
    /// once -- which is what the real runtime allowed.
    fn free_fd(&self) -> Option<u8> {
        let last = NFILE.saturating_sub(1) as u8;
        (FIRST_FD..=last).find(|fd| !self.open.iter().any(|s| s.fd == *fd))
    }

    /// Tell this type where `_streams` was placed.
    ///
    /// Called once, by `Host::new`, after the globals are laid out. Nothing
    /// may open a stream before it.
    pub fn place(&mut self, base: A::Ptr) {
        self.base = Some(base);
    }

    /// The address of `_streams[fd]`.
    ///
    /// **The slot is the descriptor.** That is the invariant that makes the
    /// array meaningful to a module: `fileno(fp)` and `(fp - _streams) /
    /// sizeof(FILE)` are the same number, so a module that indexes the array
    /// by a descriptor it holds finds the very stream that descriptor names.
    /// Borland's own runtime has the same correspondence for the standard
    /// handles, and this host extends it to every stream rather than keeping
    /// two numberings that agree only by luck.
    ///
    /// # Errors
    ///
    /// If `_streams` has not been placed, or `fd` is past the end of it.
    fn slot(&self, fd: u8) -> Result<A::Ptr, String> {
        let base = self
            .base
            .ok_or_else(|| "_streams has not been placed yet".to_owned())?;
        if u16::from(fd) >= NFILE {
            return Err(format!(
                "descriptor {fd} is past the {} slots of _streams",
                NFILE
            ));
        }
        Ok(A::ptr_offset(base, u16::from(fd) * A::FILE_SIZE as u16))
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
        // Only what Borland itself refuses: a missing or wrong FIRST
        // character. `CheckOpenType` requires `r`/`w`/`a` there and stops on
        // mismatch everywhere after, so `"rw"`, `"rz"`, `"rtb"` and `"r++"`
        // are NOT errors -- they open as plain `"r"`, and this host now says
        // so too. They were refused here until 2026-08-15; see
        // `Mode::parse`'s citation.
        for bad in ["", "x", " r"] {
            let e = Mode::parse(bad).expect_err(bad);
            assert!(e.contains(&format!("{bad:?}")), "{bad}: {e}");
        }
    }

    #[test]
    fn a_mode_padded_into_a_fixed_width_buffer_still_parses() {
        // The actual bug: Rose 3.0NT's `cw3220mt.DLL` calls `fopen(path,
        // "r  ")`, a mode padded into a fixed-width buffer. Borland's
        // `CheckOpenType` never looks past the second character it inspects,
        // so it opens this exactly like plain `"r"` -- and so must this host.
        let r = Mode::parse("r  ").expect("padding is not a refusal");
        assert!(r.read && !r.write && !r.append && !r.binary);
        assert!(r.readable() && !r.writable());

        // Padding survives after every other valid prefix shape too.
        assert!(Mode::parse("w   ").is_ok());
        assert!(Mode::parse("a+ ").is_ok());
        assert!(Mode::parse("rb ").is_ok());

        // And everything Borland shrugs at, this host now shrugs at too:
        // once the first character is accepted, the rest cannot make the
        // call fail. Each of these opens exactly like plain `"r"`.
        for shrugged in ["r x", "r  x", "r + ", "rw", "rz", "rtb", "r++"] {
            let m = Mode::parse(shrugged).unwrap_or_else(|e| panic!("{shrugged}: {e}"));
            assert!(m.read && !m.write, "{shrugged} must open like plain \"r\"");
        }
    }
}
