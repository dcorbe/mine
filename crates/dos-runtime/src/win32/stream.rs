//! C streams, over the root jail the DOS guest already goes through.
//!
//! Every path here reaches the filesystem through [`dos::files::Files`], which
//! resolves with `openat2(RESOLVE_BENEATH)` against one directory descriptor
//! rather than by inspecting path strings. That is deliberate and not merely
//! tidy: it is the same sandbox the real-mode guest gets, and a Win32 host that
//! opened host paths directly would hand this program weaker isolation than the
//! DOS one for no reason at all.
//!
//! # The `FILE` is a real struct, not a cookie
//!
//! `feof`, `ferror` and `fileno` are **macros in Borland's headers, not
//! imported functions** -- they read fields out of the `FILE` inline, in the
//! program's own code. So the import table cannot tell you whether they are
//! used, and `wccmmutl.exe` imports none of the three. A host that handed back
//! an opaque token would work until the first `while (!feof(fp))`.
//!
//! Measured before writing this: every `fopen` call site in `wccmmutl.exe`
//! (thunk `0x413373`) does nothing with the result but test it against zero and
//! pass it on -- there is no field access at any of them. That is evidence the
//! layout is not *contradicted*, and it is not evidence that no code anywhere
//! reads a `FILE` it fetched from a struct field later. Proving that negative
//! statically is harder than simply being right, so the layout below is
//! Borland's real one and the question stops mattering.
//!
//! `crates/mbbs/src/shims/stream.rs:1621` records the same trap on the 16-bit
//! side, and `crates/mbbs/src/stream.rs` has the 16-bit offsets. Those are a
//! *reference*, not the answer: this is a different word size, and the padding
//! moves.

use dos::files::Files;
use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::format::{self, ArgCursor, ArgSource};
use crate::win32::kernel32::Answer;
use crate::win32::process::Process;
use crate::win32::wintime;

/// Borland's 32-bit `FILE`, field by field:
///
/// ```text
/// off  size  field    C type
///   0     4  level    int             fill/empty level of buffer
///   4     4  flags    unsigned        file status flags   <- feof, ferror
///   8     1  fd       char            file descriptor     <- fileno
///   9     1  hold     unsigned char   ungetc char if no buffer
///  10     2  --       padding to align the int below
///  12     4  bsize    int             buffer size
///  16     4  buffer   unsigned char * data transfer buffer
///  20     4  curp     unsigned char * current active pointer
///  24     4  istemp   unsigned        temporary file indicator
///  28     2  token    short           validity checking
///  30     2  --       tail padding
/// ```
///
/// The two padding holes are the part a 16-bit layout cannot tell you: on the
/// segmented side `fd` and `hold` are followed immediately by a 16-bit `bsize`,
/// so `buffer` lands at a different offset entirely. Copying those offsets
/// across is the mistake this table exists to prevent.
pub const FILE_SIZE: usize = 32;

/// Offsets into [`FILE_SIZE`]. Only the three the macros read are named
/// individually, because those are the ones whose being wrong is silent.
pub const FILE_LEVEL: u32 = 0;
pub const FILE_FLAGS: u32 = 4;
pub const FILE_FD: u32 = 8;
pub const FILE_BSIZE: u32 = 12;
pub const FILE_TOKEN: u32 = 28;

/// Borland's `flags` bits, from its `stdio.h`.
pub const F_READ: u32 = 0x0001;
pub const F_WRIT: u32 = 0x0002;
pub const F_BUF: u32 = 0x0004;
pub const F_ERR: u32 = 0x0010;
pub const F_EOF: u32 = 0x0020;
pub const F_BIN: u32 = 0x0040;

/// `EOF`, which C spells `-1` and this ABI carries as `0xffff_ffff`.
pub const EOF: u32 = 0xffff_ffff;

/// What `access` and most `int`-returning stream calls answer for failure.
const MINUS_ONE: u32 = 0xffff_ffff;

/// One open stream: the DOS handle behind it, and where its `FILE` lives in
/// the guest.
#[derive(Debug, Clone, Copy)]
struct Stream {
    /// The handle [`Files`] knows it by.
    dos: u16,
    /// The guest address of this stream's `FILE`, which is what the program
    /// holds as its `FILE *`.
    ///
    /// The stream's *flags* are deliberately not duplicated here. They live in
    /// the guest's `FILE` and nowhere else, because `feof` and `ferror` are
    /// macros that read them straight out of it -- a host-side copy could
    /// disagree with what the program's own code sees, and the program would be
    /// right.
    at: u32,
}

/// The open streams, and the jail they resolve through.
///
/// `files` is an `Option` so that [`Process::new`] stays infallible -- a
/// `Files` needs a directory descriptor, and a unit test that never touches a
/// file should not have to make one. `None` is not a silent no-op: every call
/// answers its own failure value, which is what a program sees when a file is
/// genuinely absent, so a test that *does* reach a stream call gets a
/// diagnosable NULL rather than a panic.
pub struct Streams {
    files: Option<Files>,
    open: Vec<Option<Stream>>,
}

impl Default for Streams {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Streams {
    pub fn new(files: Option<Files>) -> Self {
        Self {
            files,
            open: Vec::new(),
        }
    }

    /// Whether this host can reach the filesystem at all.
    pub fn has_files(&self) -> bool {
        self.files.is_some()
    }

    /// The stream a `FILE *` refers to.
    ///
    /// Looked up by the pointer's own value rather than by reading the `fd`
    /// byte back out of guest memory. Both would work, and this one keeps
    /// working when the program scribbles on its own `FILE` -- the host's idea
    /// of which descriptor is open must not be something the guest can edit.
    fn slot(&self, fp: u32) -> Option<usize> {
        self.open
            .iter()
            .position(|s| s.is_some_and(|s| s.at == fp))
    }

    /// `access(path, mode)` -- 0 if the file has the requested access, -1 if
    /// not.
    ///
    /// **The return is inverted from what reads naturally**: zero is success.
    /// A host that answered a bool here tells the program every file is
    /// missing, or that every file exists, depending on which way it got it.
    ///
    /// C's `mode` is a bitmask -- 0 existence, 2 write, 4 read, 6 both -- and
    /// is *not* the 0/1/2 that [`Files::open_existing`] takes. Translating
    /// between the two is the whole of this function; passing C's mode straight
    /// through would ask for read-write access on an existence check.
    pub fn access(&mut self, path: &[u8], mode: u32) -> u32 {
        let Some(files) = self.files.as_mut() else {
            return MINUS_ONE;
        };
        let want = if mode & 0x02 != 0 { 1 } else { 0 };
        match files.open_existing(path, want) {
            Ok(dos) => {
                let _ = files.close(dos);
                0
            }
            Err(_) => MINUS_ONE,
        }
    }

    /// `fopen(path, mode)` -- a `FILE *`, or NULL.
    ///
    /// The `FILE` is allocated in the program's own arena so that the pointer
    /// it hands back resolves like any other, and is filled in with the layout
    /// above so that `fileno` and `feof` read the right bytes.
    pub fn fopen(&mut self, mem: &mut Memory, path: &[u8], mode: &[u8]) -> u32 {
        let Some(open) = Mode::parse(mode) else {
            return 0;
        };
        let Some(files) = self.files.as_mut() else {
            return 0;
        };

        // `w` truncates whatever is there; `r` and `a` want what already
        // exists, and `a` falls back to creating because appending to a file
        // that is not there is how a log gets started.
        let dos = match open.disposition {
            Disposition::Truncate => files.create(path),
            Disposition::Existing => files.open_existing(path, open.access),
            Disposition::Append => files
                .open_existing(path, open.access)
                .or_else(|_| files.create(path)),
        };
        let Ok(dos) = dos else { return 0 };

        if matches!(open.disposition, Disposition::Append) {
            // Seek to the end now rather than before each write: C says an
            // append stream's writes always go to the end, and this program
            // does not seek backwards on one.
            let _ = files.seek(dos, 0, 2);
        }

        let Ok(at) = mem.alloc(FILE_SIZE) else {
            let _ = files.close(dos);
            return 0;
        };
        let index = self.free_slot();
        self.open[index] = Some(Stream { dos, at: at.0 });
        if write_file_struct(mem, at.0, open.flags, index).is_err() {
            self.open[index] = None;
            let _ = self.files.as_mut().expect("checked above").close(dos);
            return 0;
        }
        at.0
    }

    /// `fclose` -- 0 on success, `EOF` on failure, as C has it.
    pub fn fclose(&mut self, fp: u32) -> u32 {
        let Some(index) = self.slot(fp) else {
            return EOF;
        };
        let stream = self.open[index].take().expect("slot() found it");
        match self.files.as_mut().map(|f| f.close(stream.dos)) {
            Some(Ok(())) => 0,
            _ => EOF,
        }
    }

    /// Write bytes to a stream, answering how many went.
    ///
    /// Zero for a `FILE *` this host never handed out, which is what a caller
    /// checking the count will read as failure.
    pub fn write(&mut self, fp: u32, bytes: &[u8]) -> u32 {
        let Some(index) = self.slot(fp) else {
            return 0;
        };
        let dos = self.open[index].expect("slot() found it").dos;
        match self.files.as_mut().map(|f| f.write(dos, bytes)) {
            Some(Ok(n)) => u32::try_from(n).unwrap_or(u32::MAX),
            _ => 0,
        }
    }

    /// Read up to `len` bytes from a stream.
    ///
    /// A short read is how end-of-file announces itself, so the caller is told
    /// the real count and the stream's `F_EOF` flag is set in the guest's own
    /// `FILE` -- which is where Borland's `feof` macro looks, and the reason
    /// this host writes a real struct rather than a cookie.
    pub fn read(&mut self, mem: &mut Memory, fp: u32, len: usize) -> Vec<u8> {
        let Some(index) = self.slot(fp) else {
            return Vec::new();
        };
        let stream = self.open[index].expect("slot() found it");
        let mut buf = vec![0u8; len];
        let n = match self.files.as_mut().map(|f| f.read(stream.dos, &mut buf)) {
            Some(Ok(n)) => n,
            _ => 0,
        };
        buf.truncate(n);
        if n < len {
            set_flag(mem, stream.at, F_EOF);
        }
        buf
    }

    /// `fseek`/`ftell`'s shared seek. `whence` is C's 0/1/2, which is also what
    /// [`Files::seek`] takes.
    ///
    /// Seeking **clears** end-of-file, which is the whole reason a program
    /// rewinds a stream it has read to the end. A host that left `F_EOF` set
    /// would make the next `feof` loop exit immediately.
    pub fn seek(&mut self, mem: &mut Memory, fp: u32, offset: i64, whence: u8) -> Option<u64> {
        let index = self.slot(fp)?;
        let stream = self.open[index].expect("slot() found it");
        let at = self.files.as_mut()?.seek(stream.dos, offset, whence).ok()?;
        clear_flag(mem, stream.at, F_EOF);
        Some(at)
    }

    /// `CreateFileA` for a real file -- a DOS handle, or `Err` for failure.
    ///
    /// Win32's `dwCreationDisposition` is an enum, not a flag word, and its
    /// five values do not line up with C's mode strings:
    ///
    /// ```text
    /// 1 CREATE_NEW        fail if it exists
    /// 2 CREATE_ALWAYS     truncate or create
    /// 3 OPEN_EXISTING     fail if it does not exist
    /// 4 OPEN_ALWAYS       open, creating if absent
    /// 5 TRUNCATE_EXISTING truncate, but fail if absent
    /// ```
    ///
    /// The two that must not be confused are 2 and 4: `CREATE_ALWAYS`
    /// **destroys** an existing file and `OPEN_ALWAYS` keeps it. A host that
    /// treated them alike would silently empty a data file the program meant to
    /// append to.
    pub fn create_file(&mut self, path: &[u8], access: u32, disposition: u32) -> Option<u16> {
        let files = self.files.as_mut()?;
        // GENERIC_WRITE, GENERIC_READ.
        let want = match (access & 0x4000_0000 != 0, access & 0x8000_0000 != 0) {
            (true, true) => 2,
            (true, false) => 1,
            _ => 0,
        };
        let exists = files.open_existing(path, 0).map(|h| {
            let _ = files.close(h);
        });
        match disposition {
            1 if exists.is_ok() => None,
            1 | 2 => files.create(path).ok(),
            3 => files.open_existing(path, want).ok(),
            4 => files
                .open_existing(path, want)
                .or_else(|_| files.create(path))
                .ok(),
            5 if exists.is_err() => None,
            5 => files.create(path).ok(),
            _ => None,
        }
    }

    /// `FindFirstFileA` -- the first match, as a filled-in `WIN32_FIND_DATAA`.
    pub fn find_first(&mut self, path: &[u8]) -> Option<[u8; FIND_DATA_SIZE]> {
        // Attribute mask zero: ordinary files. A DOS search with a zero mask
        // still returns normal files -- the mask *adds* hidden, system and
        // directory entries rather than filtering to them.
        let entry = self.files.as_mut()?.find_first(path, 0).ok()?;
        Some(find_data(&entry))
    }

    /// `FindNextFileA`, continuing the one search this host supports.
    pub fn find_next(&mut self) -> Option<[u8; FIND_DATA_SIZE]> {
        let entry = self.files.as_mut()?.find_next().ok()?;
        Some(find_data(&entry))
    }

    /// Raw handle operations, for the Win32 file API rather than the C one.
    ///
    /// These take a DOS handle rather than a `FILE *` because a Win32 `HANDLE`
    /// has no `FILE` behind it -- the program that opened `GALCAT.OUT` with
    /// `CreateFileA` will write to it with `WriteFile`, never `fwrite`.
    pub fn write_handle(&mut self, dos: u16, bytes: &[u8]) -> Option<usize> {
        self.files.as_mut()?.write(dos, bytes).ok()
    }

    pub fn seek_handle(&mut self, dos: u16, offset: i64, whence: u8) -> Option<u64> {
        self.files.as_mut()?.seek(dos, offset, whence).ok()
    }

    pub fn close_handle(&mut self, dos: u16) -> bool {
        self.files.as_mut().is_some_and(|f| f.close(dos).is_ok())
    }

    /// The index of a reusable slot, growing the table if there is none.
    fn free_slot(&mut self) -> usize {
        match self.open.iter().position(Option::is_none) {
            Some(i) => i,
            None => {
                self.open.push(None);
                self.open.len() - 1
            }
        }
    }
}

/// Fill in a `FILE` at `at`.
///
/// `fd` carries the host's *slot index*, not the DOS handle. Nothing in the
/// program can act on the number -- it has no `read`/`write` imports to pass a
/// descriptor to, only stream calls -- so what matters is that `fileno` returns
/// something stable and distinct per stream, which an index is and a recycled
/// DOS handle need not be.
fn write_file_struct(mem: &mut Memory, at: u32, flags: u32, index: usize) -> Result<(), String> {
    let mut bytes = [0u8; FILE_SIZE];
    let put32 = |b: &mut [u8; FILE_SIZE], off: u32, v: u32| {
        let off = off as usize;
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put32(&mut bytes, FILE_LEVEL, 0);
    put32(&mut bytes, FILE_FLAGS, flags);
    bytes[FILE_FD as usize] = u8::try_from(index).unwrap_or(0xff);
    put32(&mut bytes, FILE_BSIZE, 0);
    // `token` is Borland's own validity check. A non-zero value is what a real
    // runtime leaves here; zero is what freshly-zeroed memory has, so writing
    // one distinguishes "a FILE this host made" from "a pointer into a cleared
    // buffer" for anything that looks.
    bytes[FILE_TOKEN as usize..FILE_TOKEN as usize + 2].copy_from_slice(&0x4321u16.to_le_bytes());
    Flat32Ptr(at).write(mem, &bytes).map_err(|e| e.to_string())
}

/// `WIN32_FIND_DATAA`:
///
/// ```text
///   0  dwFileAttributes     4  ftCreationTime (8)
///  12  ftLastAccessTime(8) 20  ftLastWriteTime (8)
///  28  nFileSizeHigh       32  nFileSizeLow
///  36  dwReserved0         40  dwReserved1
///  44  cFileName[260]     304  cAlternateFileName[14]
/// ```
///
/// 318 bytes of fields, and the struct is 320 with tail padding. The name is at
/// **44**, not at the end -- a host that appended it would write the filename
/// over `dwReserved0` and leave the real name field empty, and the caller would
/// see a match with no name.
pub const FIND_DATA_SIZE: usize = 320;

/// Turn a DOS directory entry into a `WIN32_FIND_DATAA`.
///
/// The timestamps are converted from FAT's packed date/time into `FILETIME`
/// (100-nanosecond ticks since 1601). All three -- creation, access and write --
/// get the same value, because FAT as this jail reads it carries one timestamp
/// and inventing a spread between them would be fabricating detail.
fn find_data(entry: &dos::files::FindEntry) -> [u8; FIND_DATA_SIZE] {
    let mut b = [0u8; FIND_DATA_SIZE];
    let put32 = |b: &mut [u8; FIND_DATA_SIZE], off: usize, v: u32| {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put32(&mut b, 0, u32::from(entry.attr));
    let ticks = wintime::ticks_from_unix(wintime::unix_from_dos(entry.dos_date, entry.dos_time));
    #[allow(clippy::cast_possible_truncation)]
    for off in [4usize, 12, 20] {
        put32(&mut b, off, ticks as u32);
        put32(&mut b, off + 4, (ticks >> 32) as u32);
    }
    put32(&mut b, 28, 0);
    put32(&mut b, 32, entry.size);

    let name = entry.name.as_bytes();
    let n = name.len().min(259);
    b[44..44 + n].copy_from_slice(&name[..n]);
    // `cAlternateFileName` is the 8.3 short name. These names *are* 8.3
    // already -- the jail upper-cases and truncates them -- so the same bytes
    // serve, and leaving it empty would break a caller that prefers it.
    let n = name.len().min(13);
    b[304..304 + n].copy_from_slice(&name[..n]);
    b
}

/// Set a bit in the guest's own `FILE.flags`.
///
/// The guest's copy is the only copy -- see [`Stream::at`]. `feof(fp)` is a
/// macro reading these very bytes, so a flag the host tracked privately would
/// be a flag the program could never see.
fn set_flag(mem: &mut Memory, fp: u32, bit: u32) {
    let current = read_flags(mem, fp);
    let _ = Flat32Ptr(fp + FILE_FLAGS).write(mem, &(current | bit).to_le_bytes());
}

fn clear_flag(mem: &mut Memory, fp: u32, bit: u32) {
    let current = read_flags(mem, fp);
    let _ = Flat32Ptr(fp + FILE_FLAGS).write(mem, &(current & !bit).to_le_bytes());
}

fn read_flags(mem: &Memory, fp: u32) -> u32 {
    Flat32Ptr(fp + FILE_FLAGS)
        .resolve(mem, 4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
}

/// What `fopen`'s mode string asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// `r` -- it must already exist.
    Existing,
    /// `w` -- truncate or create.
    Truncate,
    /// `a` -- create if absent, and write at the end.
    Append,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mode {
    disposition: Disposition,
    /// As [`Files::open_existing`] numbers it: 0 read, 1 write, 2 both.
    access: u8,
    /// The `FILE`'s own flags word.
    flags: u32,
}

impl Mode {
    /// Parse `"rb"`, `"w+"`, `"a+b"` and the rest.
    ///
    /// The first character decides the disposition; `+` adds the other
    /// direction; `b` and `t` choose the translation mode, of which only `b`
    /// leaves a mark, because this host does no newline translation either way
    /// and saying so is more honest than pretending `t` does something.
    fn parse(mode: &[u8]) -> Option<Self> {
        let first = *mode.first()?;
        let plus = mode.contains(&b'+');
        let binary = mode.contains(&b'b');
        let (disposition, access, mut flags) = match first.to_ascii_lowercase() {
            b'r' if plus => (Disposition::Existing, 2, F_READ | F_WRIT),
            b'r' => (Disposition::Existing, 0, F_READ),
            b'w' if plus => (Disposition::Truncate, 2, F_READ | F_WRIT),
            b'w' => (Disposition::Truncate, 1, F_WRIT),
            b'a' if plus => (Disposition::Append, 2, F_READ | F_WRIT),
            b'a' => (Disposition::Append, 1, F_WRIT),
            _ => return None,
        };
        if binary {
            flags |= F_BIN;
        }
        flags |= F_BUF;
        Some(Self {
            disposition,
            access,
            flags,
        })
    }
}

/// Answer a `cw3220mt.DLL` stream import, or `None` for one still
/// unimplemented.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // int access(const char *path, int mode)
        "_access" => {
            let path_at = machine.arg_u32(mem.stack(), 0);
            let mode = machine.arg_u32(mem.stack(), 1);
            let path = read_path(mem, path_at)?;
            Some(Answer::cdecl(process.streams.access(&path, mode)))
        }
        // FILE *fopen(const char *path, const char *mode)
        "_fopen" => {
            let path_at = machine.arg_u32(mem.stack(), 0);
            let mode_at = machine.arg_u32(mem.stack(), 1);
            let path = read_path(mem, path_at)?;
            let mode = read_path(mem, mode_at)?;
            Some(Answer::cdecl(process.streams.fopen(mem, &path, &mode)))
        }
        // int fclose(FILE *fp)
        "_fclose" => {
            let fp = machine.arg_u32(mem.stack(), 0);
            Some(Answer::cdecl(process.streams.fclose(fp)))
        }
        // int fseek(FILE *fp, long offset, int whence)
        //
        // `whence` is SEEK_SET/SEEK_CUR/SEEK_END as 0/1/2, matching what
        // `Streams::seek` (and `dos::files::Files::seek` beneath it) already
        // expects, so it passes through unmodified. `fseek` returns 0 on
        // success and non-zero on failure -- the opposite polarity to the
        // `Option` this host's `seek` returns.
        "_fseek" => {
            let fp = machine.arg_u32(mem.stack(), 0);
            let offset = machine.arg_u32(mem.stack(), 1) as i32;
            let whence = machine.arg_u32(mem.stack(), 2) as u8;
            let ok = process
                .streams
                .seek(mem, fp, i64::from(offset), whence)
                .is_some();
            Some(Answer::cdecl(u32::from(!ok)))
        }
        // size_t fread(void *buf, size_t size, size_t count, FILE *fp)
        //
        // Answers the number of *complete elements* read, not the byte count
        // -- a short read (end-of-file mid-element) truncates down rather than
        // rounding up, matching the C standard's "the value of a partially
        // read element is indeterminate" by simply not counting it.
        "_fread" => {
            let buf = machine.arg_u32(mem.stack(), 0);
            let size = machine.arg_u32(mem.stack(), 1) as usize;
            let count = machine.arg_u32(mem.stack(), 2) as usize;
            let fp = machine.arg_u32(mem.stack(), 3);
            let want = size.saturating_mul(count);
            let bytes = process.streams.read(mem, fp, want);
            let got = bytes.len();
            if Flat32Ptr(buf).write(mem, &bytes).is_err() {
                return Some(Answer::cdecl(0));
            }
            let items = if size == 0 { 0 } else { got / size };
            Some(Answer::cdecl(items as u32))
        }
        // int vsprintf(char *buf, const char *fmt, va_list ap)
        //
        // A `va_list` on 32-bit cdecl is a bare pointer to the first variable
        // argument, so the cursor reads straight out of guest memory.
        "_vsprintf" => {
            let buf = machine.arg_u32(mem.stack(), 0);
            let fmt_at = machine.arg_u32(mem.stack(), 1);
            let ap = machine.arg_u32(mem.stack(), 2);
            let fmt = read_path(mem, fmt_at)?;
            let mut cursor = ArgCursor::new(ArgSource::VaList { at: ap });
            let rendered = format::render(mem, &fmt, &mut cursor);
            Some(Answer::cdecl(finish_sprintf(mem, buf, &rendered)))
        }
        // int sprintf(char *buf, const char *fmt, ...)
        //
        // The varargs are stack slots 2 onward of the call currently
        // suspended, which is the same data `vsprintf` is handed a pointer to.
        "_sprintf" => {
            let buf = machine.arg_u32(mem.stack(), 0);
            let fmt_at = machine.arg_u32(mem.stack(), 1);
            let fmt = read_path(mem, fmt_at)?;
            let mut cursor = ArgCursor::new(ArgSource::Frame { machine, base: 2 });
            let rendered = format::render(mem, &fmt, &mut cursor);
            Some(Answer::cdecl(finish_sprintf(mem, buf, &rendered)))
        }
        // int fprintf(FILE *fp, const char *fmt, ...)
        "_fprintf" => {
            let fp = machine.arg_u32(mem.stack(), 0);
            let fmt_at = machine.arg_u32(mem.stack(), 1);
            let fmt = read_path(mem, fmt_at)?;
            let mut cursor = ArgCursor::new(ArgSource::Frame { machine, base: 2 });
            let rendered = format::render(mem, &fmt, &mut cursor);
            let n = process.streams.write(fp, &rendered);
            Some(Answer::cdecl(n))
        }
        _ => None,
    }
}

/// Store a rendered string and answer the length, as the `printf` family does.
///
/// **The count excludes the terminator**, which is written but not counted. A
/// host that returned the buffer length instead would be off by one everywhere
/// a caller uses the result to advance a cursor -- and this program builds
/// screens by appending.
fn finish_sprintf(mem: &mut Memory, buf: u32, rendered: &[u8]) -> u32 {
    if buf == 0 {
        return 0;
    }
    let mut with_nul = rendered.to_vec();
    with_nul.push(0);
    if Flat32Ptr(buf).write(mem, &with_nul).is_err() {
        return 0;
    }
    u32::try_from(rendered.len()).unwrap_or(u32::MAX)
}

/// A path or mode string out of guest memory, as bytes.
///
/// Bytes rather than a `String`: [`Files`] takes bytes, DOS filenames are not
/// UTF-8, and this program has just told the host to interpret its filenames as
/// OEM (`SetFileApisToOEM`). Decoding and re-encoding here would be two lossy
/// conversions in place of none.
fn read_path(mem: &Memory, at: u32) -> Option<Vec<u8>> {
    if at == 0 {
        return None;
    }
    Flat32Ptr(at).read_cstr(mem).ok().map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root under the worktree's own `tmp/`, never `/tmp` -- a global
    /// constraint, and shared `/tmp` is how parallel jobs clobber each other.
    fn root_at(name: &str) -> Files {
        let dir = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("root dir");
        let fd = std::fs::File::open(&dir).expect("root fd");
        Files::new(fd.into(), dir)
    }

    fn loaded() -> crate::win32::load::Loaded {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        crate::win32::load::load(&file).expect("loads")
    }

    /// The layout, asserted as offsets rather than described in a comment. A
    /// `FILE` whose `fd` moves is a `fileno` that returns a buffer pointer.
    #[test]
    fn the_file_layout_is_borlands_32_bit_one() {
        assert_eq!(FILE_SIZE, 32, "four words, two pointers, and two holes");
        assert_eq!(FILE_LEVEL, 0);
        assert_eq!(FILE_FLAGS, 4, "feof and ferror read this");
        assert_eq!(FILE_FD, 8, "fileno reads this");
        assert_eq!(
            FILE_BSIZE, 12,
            "not 10: fd and hold are followed by two bytes of padding, \
             which is exactly what the 16-bit layout does not have"
        );
    }

    /// Every mode string this program could pass, and what each asks for.
    #[test]
    fn the_mode_string_decides_disposition_and_access() {
        let m = |s: &str| Mode::parse(s.as_bytes()).expect("valid mode");
        assert_eq!(m("r").disposition, Disposition::Existing);
        assert_eq!(m("r").access, 0);
        assert_eq!(m("w").disposition, Disposition::Truncate);
        assert_eq!(m("w").access, 1);
        assert_eq!(m("a").disposition, Disposition::Append);
        assert_eq!(m("r+").access, 2, "+ adds the other direction");
        assert_eq!(m("rb").disposition, Disposition::Existing);
        assert_ne!(m("rb").flags & F_BIN, 0, "b is recorded in the flags");
        assert_eq!(m("r").flags & F_BIN, 0);
        assert_ne!(m("w").flags & F_WRIT, 0);
        assert_eq!(m("w").flags & F_READ, 0, "plain w is not readable");
        assert_ne!(m("w+").flags & F_READ, 0, "w+ is");

        assert!(Mode::parse(b"").is_none(), "an empty mode is not a mode");
        assert!(Mode::parse(b"x").is_none(), "nor is a made-up one");
    }

    /// `access` answers **zero** for success. Getting this backwards tells the
    /// program every file is missing, and it is the commonest way to get an
    /// inverted-return C function wrong.
    #[test]
    fn access_answers_zero_for_a_file_that_exists() {
        let files = root_at("win32-access");
        let dir = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("win32-access");
        std::fs::write(dir.join("THERE.TXT"), b"x").expect("fixture");

        let mut s = Streams::new(Some(files));
        assert_eq!(s.access(b"THERE.TXT", 0), 0, "it exists");
        assert_eq!(s.access(b"GONE.TXT", 0), MINUS_ONE, "it does not");
    }

    /// With no root at all, every call fails the way a missing file fails
    /// rather than panicking. That is what makes `Process::new` able to stay
    /// infallible.
    #[test]
    fn without_a_root_every_call_fails_honestly() {
        let mut l = loaded();
        let mut s = Streams::new(None);
        assert!(!s.has_files());
        assert_eq!(s.access(b"ANY.TXT", 0), MINUS_ONE);
        assert_eq!(s.fopen(&mut l.mem, b"ANY.TXT", b"r"), 0, "NULL, not a panic");
        assert_eq!(s.fclose(0), EOF);
    }

    /// A stream opened, written through the host, closed, and reopened. The
    /// `FILE` the program is handed must carry its descriptor inline where
    /// Borland's `fileno` macro expects it.
    #[test]
    fn a_file_round_trips_and_carries_its_fields_inline() {
        let files = root_at("win32-roundtrip");
        let dir = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("win32-roundtrip");
        std::fs::write(dir.join("IN.TXT"), b"HELLO").expect("fixture");

        let mut l = loaded();
        let mut s = Streams::new(Some(files));
        let fp = s.fopen(&mut l.mem, b"IN.TXT", b"rb");
        assert_ne!(fp, 0, "the file is there, so this is not NULL");

        let raw = Flat32Ptr(fp).resolve(&l.mem, FILE_SIZE).expect("in memory");
        let word = |off: u32| {
            u32::from_le_bytes(raw[off as usize..off as usize + 4].try_into().unwrap())
        };
        assert_ne!(word(FILE_FLAGS) & F_READ, 0, "opened for reading");
        assert_ne!(word(FILE_FLAGS) & F_BIN, 0, "in binary mode");
        assert_eq!(word(FILE_FLAGS) & F_EOF, 0, "and not at end of file yet");
        assert_eq!(raw[FILE_FD as usize], 0, "the first stream is fileno 0");

        assert_eq!(s.fclose(fp), 0);
        assert_eq!(s.fclose(fp), EOF, "closing it twice is an error");
    }

    /// Two streams open at once must be distinguishable. A host keying its
    /// table on anything the two share hands the second one's reads to the
    /// first.
    #[test]
    fn two_open_streams_are_distinct() {
        let files = root_at("win32-two");
        let dir = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("win32-two");
        std::fs::write(dir.join("A.TXT"), b"a").expect("fixture");
        std::fs::write(dir.join("B.TXT"), b"b").expect("fixture");

        let mut l = loaded();
        let mut s = Streams::new(Some(files));
        let a = s.fopen(&mut l.mem, b"A.TXT", b"rb");
        let b = s.fopen(&mut l.mem, b"B.TXT", b"rb");
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b, "two FILEs, two addresses");

        let fd_of = |fp: u32, mem: &Memory| {
            Flat32Ptr(fp).resolve(mem, FILE_SIZE).expect("in memory")[FILE_FD as usize]
        };
        assert_ne!(fd_of(a, &l.mem), fd_of(b, &l.mem), "and two filenos");
    }

    /// A closed slot is reused rather than leaked, so a program that opens and
    /// closes in a loop does not exhaust the table.
    #[test]
    fn a_closed_slot_is_reused() {
        let files = root_at("win32-reuse");
        let dir = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("win32-reuse");
        std::fs::write(dir.join("A.TXT"), b"a").expect("fixture");

        let mut l = loaded();
        let mut s = Streams::new(Some(files));
        for _ in 0..8 {
            let fp = s.fopen(&mut l.mem, b"A.TXT", b"rb");
            assert_ne!(fp, 0);
            assert_eq!(s.fclose(fp), 0);
        }
        assert_eq!(s.open.len(), 1, "one slot, reused eight times");
    }

    /// The jail is not optional: a path that climbs out of the root must be
    /// refused. `Files` enforces this with `openat2(RESOLVE_BENEATH)`, and this
    /// test is here to catch a future change that resolves paths some other
    /// way before handing them over.
    #[test]
    fn a_path_cannot_escape_the_root() {
        let files = root_at("win32-escape");
        let mut l = loaded();
        let mut s = Streams::new(Some(files));
        assert_eq!(
            s.fopen(&mut l.mem, b"..\\..\\etc\\passwd", b"rb"),
            0,
            "climbing out of the root is refused"
        );
        assert_eq!(s.fopen(&mut l.mem, b"/etc/passwd", b"rb"), 0);
        assert_eq!(s.access(b"../../etc/passwd", 0), MINUS_ONE);
    }
}

