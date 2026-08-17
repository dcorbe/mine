//! DOS file services, and the containment boundary underneath them.
//!
//! Path translation is where the sandbox lives. A DOS program hands over
//! `C:\LORD.DAT`, or `..\..\etc\passwd`, or `PRN`, and something has to decide
//! what host file that names -- so this is a security boundary wearing the
//! costume of a convenience layer.
//!
//! Two rules follow from that:
//!
//! 1. Containment is enforced by the kernel, not by string inspection.
//!    `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` against a root
//!    descriptor cannot be walked out of. Rejecting `..` by hand is defeated by
//!    a symlink that is already sitting in the tree.
//! 2. DOS device names are intercepted *before* resolution. In DOS, `NUL.TXT`
//!    is still `NUL`, and a program writing to `PRN` must not leave a file
//!    called `PRN` in the root.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// DOS error codes, as returned in AX with CF set.
pub const ERR_FILE_NOT_FOUND: u16 = 0x02;
pub const ERR_PATH_NOT_FOUND: u16 = 0x03;
pub const ERR_TOO_MANY_OPEN: u16 = 0x04;
pub const ERR_ACCESS_DENIED: u16 = 0x05;
pub const ERR_INVALID_HANDLE: u16 = 0x06;
/// Another holder has the region. DOS reports this from `5Ch`, and a program
/// that shares files across nodes is written to expect and retry it.
pub const ERR_LOCK_VIOLATION: u16 = 0x21;
/// `4Fh` found no further entries -- and `4Eh` on a search that ends up empty
/// reports `ERR_FILE_NOT_FOUND` instead, the same asymmetry real DOS has.
pub const ERR_NO_MORE_FILES: u16 = 0x12;

/// DOS file attribute bits, as read from `4Eh`/`4Fh`'s CX mask and written
/// into a find record's attribute byte.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;

/// The first handle DOS hands out; 0-2 are the inherited standard ones.
const FIRST_HANDLE: u16 = 5;
/// DOS's own default, and the reason a fixed-capacity table is faithful rather
/// than a shortcut.
const MAX_HANDLES: usize = 20;

const SYS_OPENAT2: libc::c_long = 437;

/// Open-file-description locks. Unlike the POSIX kind they belong to the open
/// file rather than the process, so they are not silently dropped when any
/// unrelated descriptor for the same file is closed -- a footgun DOS programs
/// would trip over constantly, since they open the same data file repeatedly.
const F_OFD_SETLK: libc::c_int = 37;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Names DOS reserves for devices, matched before any path resolution.
const DEVICES: [&str; 12] = [
    "CON", "NUL", "PRN", "AUX", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3", "CLOCK$",
];

/// What a DOS path turned out to name.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// An ordinary file, as a root-relative path.
    File(String),
    /// A character device. Writes to it are discarded, reads see EOF.
    Device(&'static str),
    /// Nothing nameable: an escape attempt, or an empty path.
    Rejected,
}

/// Turn a DOS path into something that can be opened beneath the root.
///
/// Case is folded up because DOS is case-insensitive; the caller retries the
/// lowercase spelling as well, since a host directory may hold either.
pub fn translate(raw: &[u8]) -> Target {
    let text: String = raw
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| (b as char).to_ascii_uppercase())
        .collect();
    let text = text.replace('\\', "/");

    // Strip a drive letter: every drive is the one root.
    let text = match text.as_bytes() {
        [c, b':', rest @ ..] if c.is_ascii_alphabetic() => {
            String::from_utf8_lossy(rest).into_owned()
        }
        _ => text,
    };
    // An absolute DOS path is absolute *within* the root, not on the host.
    let text = text.trim_start_matches('/').to_string();

    // A device name wins over any file, extension included: `NUL.TXT` is NUL.
    let last = text.rsplit('/').next().unwrap_or("");
    let stem = last.split('.').next().unwrap_or("");
    if let Some(dev) = DEVICES.iter().find(|d| **d == stem) {
        return Target::Device(dev);
    }

    if text.is_empty() {
        return Target::Rejected;
    }
    // `openat2` would refuse these anyway; refusing here makes the intent
    // legible and keeps a pointless syscall out of the log.
    if text.split('/').any(|c| c == ".." || c.is_empty()) {
        return Target::Rejected;
    }
    Target::File(text)
}

/// One matched directory entry, ready to become a `4Eh`/`4Fh` DTA record.
///
/// Kept host-shaped -- no far pointers, no guest access -- so it is testable
/// on its own; `dos.rs` is what turns it into the 43-byte wire format, the
/// same division of labour as everywhere else in this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindEntry {
    /// `NAME.EXT`, upper-cased, with the dot omitted when there is no
    /// extension -- exactly what the 13-byte ASCIIZ field holds.
    pub name: String,
    pub attr: u8,
    pub size: u32,
    /// Packed DOS date/time, FAT-style. See `dos.rs`'s `find_record` for the
    /// bit layout and its source.
    pub dos_time: u16,
    pub dos_date: u16,
}

/// The state a `4Eh` search leaves behind for `4Fh` to continue.
///
/// Real DOS keeps this in the DTA's own 21 reserved bytes -- drive, an
/// FCB-style template, the attribute mask, an entry count and a directory
/// cluster -- so a search can resume from nothing but the DTA address, and
/// several searches through several DTAs can run at once. This crate keeps
/// it here instead, host-side and keyed to the one `Files`, which is a real
/// simplification: two concurrent searches would collide. Nothing in this
/// crate does that yet, and `dos.rs` documents the trade where it writes the
/// (all-zero) reserved bytes.
struct FindSearch {
    entries: Vec<FindEntry>,
    next: usize,
}

/// Build the 11-byte, space-padded FCB-style field DOS matches filenames
/// against, from a `NAME.EXT` pattern that may contain `*`/`?`.
///
/// This is the classic FCB wildcard algorithm that `INT 21h AH=4Eh/4Fh`
/// inherited from CP/M: the name and extension are laid into an 11-byte
/// field, space-padded, with an implicit dot between position 8 and 9; a
/// `*` fills the rest of whichever field it is in with `?` and everything
/// else in that field is then ignored until the next `.` or the pattern
/// ends. It is emphatically not shell globbing -- `?` matches a *padding*
/// space too, so `*.???` matches a two-letter extension as readily as a
/// three-letter one, and `*.*` matches a name with no extension at all.
///
/// Source: Raymond Chen, "How did wildcards work in MS-DOS?" (The Old New
/// Thing, 2007-12-17), cross-checked against Ralf Brown's Interrupt List,
/// `INT 21/AH=29h` ("Parse Filename into FCB"), which documents the same
/// 11-byte expansion for the non-ASCIIZ FCB find calls that `4Eh` reuses.
fn wildcard_template(pattern: &str) -> [u8; 11] {
    let mut t = [b' '; 11];
    let upper = pattern.to_ascii_uppercase();
    let mut idx = 0usize; // 0..8 within the name, 8..11 within the extension
    let mut in_ext = false;
    let mut starred = false; // ignoring literals until the field changes
    for c in upper.chars() {
        match c {
            '.' if !in_ext => {
                in_ext = true;
                idx = 8;
                starred = false;
            }
            // A second dot has nothing sane to mean here; DOS paths never
            // reach this with one, since the directory separator was already
            // split off. Stop rather than guess.
            '.' => break,
            '*' => {
                let end = if in_ext { 11 } else { 8 };
                for slot in t.iter_mut().take(end).skip(idx) {
                    *slot = b'?';
                }
                idx = end;
                starred = true;
            }
            _ if starred => {}
            _ if c.is_ascii() => {
                let limit = if in_ext { 11 } else { 8 };
                if idx < limit {
                    t[idx] = c as u8;
                    idx += 1;
                }
            }
            _ => {}
        }
    }
    t
}

/// Fold a plain `NAME.EXT` (no wildcards) into the same 11-byte field layout
/// [`wildcard_template`] produces, so the two can be compared position by
/// position. `None` if the name does not fit an 8.3 shape at all -- more than
/// eight characters of name, more than three of extension, or more than one
/// dot -- which nothing walking this sandbox's own directories should
/// produce, but a host filesystem is not obliged to agree.
fn eight_dot_three(name: &str) -> Option<[u8; 11]> {
    let upper = name.to_ascii_uppercase();
    if !upper.is_ascii() {
        return None;
    }
    let (stem, ext) = match upper.split_once('.') {
        Some((s, e)) => (s, e),
        None => (upper.as_str(), ""),
    };
    if stem.is_empty() || stem.len() > 8 || ext.len() > 3 || ext.contains('.') {
        return None;
    }
    let mut t = [b' '; 11];
    t[..stem.len()].copy_from_slice(stem.as_bytes());
    t[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Some(t)
}

/// Does `name` (already folded by [`eight_dot_three`]) satisfy `template`?
fn matches_template(template: &[u8; 11], name: &[u8; 11]) -> bool {
    template
        .iter()
        .zip(name.iter())
        .all(|(&t, &n)| t == b'?' || t == n)
}

/// The display form of a folded 8.3 name: trailing padding trimmed, the dot
/// present only when there is an extension.
fn display_name(tpl: &[u8; 11]) -> String {
    let stem: String = tpl[..8]
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| b as char)
        .collect();
    let ext: String = tpl[8..11]
        .iter()
        .take_while(|&&b| b != b' ')
        .map(|&b| b as char)
        .collect();
    if ext.is_empty() {
        stem
    } else {
        format!("{stem}.{ext}")
    }
}

const SYS_GETDENTS64: libc::c_long = 217;

/// Entry names directly inside the directory named by `dirfd`.
///
/// `getdents64` rather than `opendir`/`readdir`: those wrap this same
/// syscall behind a `DIR *` that is not safe to allocate from a signal
/// handler, and `files.rs` is shared with the `m16` trap edge, where a
/// future caller may be exactly that. The raw syscall has no such caveat, so
/// using it here costs nothing today and avoids relitigating the choice
/// later against a live trap.
fn read_dir_raw(dirfd: RawFd) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: `buf` is a live, writable buffer of the stated length, and
        // `dirfd` is a directory descriptor the caller owns for the
        // duration of this call.
        let n = unsafe { libc::syscall(SYS_GETDENTS64, dirfd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            // linux_dirent64: u64 d_ino, i64 d_off, u16 d_reclen, u8 d_type,
            // then the NUL-terminated name.
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let name_start = off + 19;
            let name_end = buf[name_start..off + reclen]
                .iter()
                .position(|&b| b == 0)
                .map_or(off + reclen, |p| name_start + p);
            let name = String::from_utf8_lossy(&buf[name_start..name_end]).into_owned();
            if name != "." && name != ".." {
                out.push(name);
            }
            off += reclen;
        }
    }
    Ok(out)
}

/// Fold a Unix mtime into DOS's packed date/time words -- the same format
/// the FAT directory entry and `INT 21/AH=5701h` (Set File Date and Time)
/// use: time bits 15-11 hour (0-23), 10-5 minute (0-59), 4-0 seconds/2;
/// date bits 15-9 year-1980, 8-5 month (1-12), 4-0 day (1-31). Source: Ralf
/// Brown's Interrupt List, `INT 21/AH=57h`, and the FAT directory entry
/// layout it shares.
fn pack_datetime(mtime: libc::time_t) -> (u16, u16) {
    // SAFETY: `localtime_r` fills a caller-owned struct and is safe to call
    // from any thread.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(std::ptr::from_ref(&mtime), std::ptr::from_mut(&mut tm));
        tm
    };
    // DOS cannot represent a year before 1980 or after 2107; clamp rather
    // than wrap, since a wrapped year is a worse lie than a clamped one.
    let year = ((tm.tm_year + 1900).clamp(1980, 2107) - 1980) as u16;
    let month = (tm.tm_mon + 1) as u16;
    let day = tm.tm_mday as u16;
    let hour = tm.tm_hour as u16;
    let min = tm.tm_min as u16;
    let sec2 = (tm.tm_sec / 2) as u16;
    let date = (year << 9) | (month << 5) | day;
    let time = (hour << 11) | (min << 5) | sec2;
    (time, date)
}

/// Entry names in `dir`, or nothing if it cannot be listed.
fn list(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect()
}

struct Handle {
    fd: OwnedFd,
    /// Kept for diagnostics: "which file did it write?" is the whole question.
    name: String,
    device: bool,
}

/// Which host spelling a DOS name refers to.
#[derive(Debug, PartialEq, Eq)]
pub enum Pick {
    /// One entry matches byte for byte.
    Exact(String),
    /// No exact match, but exactly one differing only in case.
    Unique(String),
    /// Several entries differ only in case. DOS cannot name one of them, so
    /// guessing would silently bind the program to the wrong file.
    Ambiguous(Vec<String>),
    /// Nothing matches -- which is not an error for a create.
    Missing,
}

/// Choose the host spelling for a DOS name from a directory's entries.
///
/// Pure so it can be tested without a filesystem, and separate from the open
/// because the interesting behaviour is entirely in the choice.
pub fn pick(entries: &[String], want: &str) -> Pick {
    if let Some(hit) = entries.iter().find(|e| *e == want) {
        return Pick::Exact(hit.clone());
    }
    let mut folded: Vec<String> = entries
        .iter()
        .filter(|e| e.eq_ignore_ascii_case(want))
        .cloned()
        .collect();
    match folded.len() {
        0 => Pick::Missing,
        1 => Pick::Unique(folded.remove(0)),
        _ => {
            folded.sort();
            Pick::Ambiguous(folded)
        }
    }
}

/// The open-file table, and the root everything resolves beneath.
pub struct Files {
    root: OwnedFd,
    /// The same directory by path, used only to *list* it for case folding.
    /// Opens still go through `openat2` against the descriptor, so this cannot
    /// widen what is reachable -- it only decides which name to ask for.
    root_path: PathBuf,
    open: Vec<Option<Handle>>,
    /// Every file the program created or wrote, in order first touched.
    pub touched: Vec<String>,
    /// Names that could not be resolved because the host holds several
    /// spellings of them.
    pub ambiguous: Vec<String>,
    /// Every open or create the program attempted, and how it went. "Which
    /// files did it ask for?" is a different question from "which did it
    /// write", and answering only the second hides the interesting half.
    pub attempts: Vec<(String, &'static str, bool)>,
    /// The search a `4Eh` started, if `4Fh` might still continue it.
    search: Option<FindSearch>,
}

impl Files {
    pub fn new(root: OwnedFd, root_path: PathBuf) -> Self {
        Self {
            root,
            root_path,
            open: (0..MAX_HANDLES).map(|_| None).collect(),
            touched: Vec::new(),
            ambiguous: Vec::new(),
            attempts: Vec::new(),
            search: None,
        }
    }

    /// The directory everything under this jail resolves beneath.
    ///
    /// For a host component that needs to build a real path *outside* this
    /// type's own `openat2` calls -- the `btrieve` crate reads and writes
    /// data files through plain `std::fs`, not through a descriptor this
    /// struct owns, so it cannot ask `Files` to open on its behalf. It still
    /// needs to know where the jail's floor is, which is what this answers.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    fn slot(&mut self) -> Option<usize> {
        self.open.iter().position(Option::is_none)
    }

    fn handle_of(&mut self, dos: u16) -> Option<&mut Handle> {
        let index = usize::from(dos.checked_sub(FIRST_HANDLE)?);
        self.open.get_mut(index)?.as_mut()
    }

    /// Open beneath the root. Nothing here can escape it: the kernel enforces
    /// that, not the path munging above.
    fn openat2(&self, path: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let c_path = std::ffi::CString::new(path)
            .map_err(|_| io::Error::other("path contains a NUL byte"))?;
        let how = OpenHow {
            flags: flags as u64 | libc::O_CLOEXEC as u64,
            mode: mode as u64,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
        };
        // SAFETY: a well-formed openat2 against a descriptor we own.
        let fd = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                self.root.as_raw_fd(),
                c_path.as_ptr(),
                std::ptr::from_ref(&how),
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat2 returned a fresh descriptor we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    /// Resolve a DOS path to the spelling the host actually uses.
    ///
    /// DOS is case-insensitive, so `LORD.DAT` and `lord.dat` are one file to a
    /// DOS program -- and a real LORD directory has both. Trying uppercase then
    /// lowercase, as this used to, silently binds the program to whichever it
    /// guesses first and makes the other unreachable forever: write one, read
    /// the other back, and the setting appears to revert on its own.
    ///
    /// Resolved component by component, so a directory's case matters as little
    /// as a file's. A component that does not exist keeps the spelling DOS
    /// gave, which is what a create needs.
    fn resolve(&mut self, name: &str) -> Result<String, u16> {
        let mut here: PathBuf = self.root_path.clone();
        let mut out: Vec<String> = Vec::new();
        for part in name.split('/') {
            let entries = list(&here);
            match pick(&entries, part) {
                Pick::Exact(found) | Pick::Unique(found) => {
                    here.push(&found);
                    out.push(found);
                }
                Pick::Missing => {
                    here.push(part);
                    out.push(part.to_string());
                }
                Pick::Ambiguous(all) => {
                    let note = format!("{name}: host holds {}", all.join(", "));
                    if !self.ambiguous.contains(&note) {
                        self.ambiguous.push(note);
                    }
                    // Refusing is the honest answer: the program asked for a
                    // file the host cannot uniquely name, and picking one would
                    // be undefined behaviour wearing a filename.
                    return Err(ERR_ACCESS_DENIED);
                }
            }
        }
        Ok(out.join("/"))
    }

    fn install(&mut self, fd: OwnedFd, name: String, device: bool) -> Result<u16, u16> {
        let slot = self.slot().ok_or(ERR_TOO_MANY_OPEN)?;
        self.open[slot] = Some(Handle { fd, name, device });
        Ok(slot as u16 + FIRST_HANDLE)
    }

    fn device_handle(&mut self, dev: &'static str) -> Result<u16, u16> {
        let fd = self
            .openat2("/dev/null", libc::O_RDWR, 0)
            .or_else(|_| {
                // The root may not expose /dev; fall back to an absolute open,
                // which is safe because the path is ours, not the guest's.
                let c = c"/dev/null";
                // SAFETY: a constant path of our own choosing.
                let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
                if fd < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // SAFETY: freshly opened descriptor.
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                }
            })
            .map_err(|_| ERR_ACCESS_DENIED)?;
        self.install(fd, dev.to_string(), true)
    }

    /// `3Dh` -- open an existing file. `access` is 0 read, 1 write, 2 both.
    pub fn open_existing(&mut self, path: &[u8], access: u8) -> Result<u16, u16> {
        match translate(path) {
            Target::Device(dev) => self.device_handle(dev),
            Target::Rejected => Err(ERR_PATH_NOT_FOUND),
            Target::File(name) => {
                let flags = match access & 0x07 {
                    0 => libc::O_RDONLY,
                    1 => libc::O_WRONLY,
                    _ => libc::O_RDWR,
                };
                let name = self.resolve(&name)?;
                let attempt = self.openat2(&name, flags, 0);
                self.attempts
                    .push((name.clone(), "open", attempt.is_ok()));
                let fd = attempt
                    .map_err(|e| match e.raw_os_error() {
                        Some(libc::ENOENT) => ERR_FILE_NOT_FOUND,
                        Some(libc::EACCES) | Some(libc::EPERM) => ERR_ACCESS_DENIED,
                        Some(libc::EXDEV) | Some(libc::ELOOP) => ERR_ACCESS_DENIED,
                        _ => ERR_FILE_NOT_FOUND,
                    })?;
                self.install(fd, name, false)
            }
        }
    }

    /// `3Ch` -- create, truncating anything already there.
    pub fn create(&mut self, path: &[u8]) -> Result<u16, u16> {
        match translate(path) {
            Target::Device(dev) => self.device_handle(dev),
            Target::Rejected => Err(ERR_PATH_NOT_FOUND),
            Target::File(name) => {
                let name = self.resolve(&name)?;
                let attempt =
                    self.openat2(&name, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
                self.attempts
                    .push((name.clone(), "create", attempt.is_ok()));
                let fd = attempt
                    .map_err(|e| match e.raw_os_error() {
                        Some(libc::EACCES) | Some(libc::EPERM) => ERR_ACCESS_DENIED,
                        Some(libc::ENOENT) => ERR_PATH_NOT_FOUND,
                        _ => ERR_ACCESS_DENIED,
                    })?;
                if !self.touched.contains(&name) {
                    self.touched.push(name.clone());
                }
                self.install(fd, name, false)
            }
        }
    }

    pub fn close(&mut self, dos: u16) -> Result<(), u16> {
        let index = usize::from(dos.checked_sub(FIRST_HANDLE).ok_or(ERR_INVALID_HANDLE)?);
        let slot = self.open.get_mut(index).ok_or(ERR_INVALID_HANDLE)?;
        slot.take().ok_or(ERR_INVALID_HANDLE)?;
        Ok(())
    }

    pub fn read(&mut self, dos: u16, buf: &mut [u8]) -> Result<usize, u16> {
        let h = self.handle_of(dos).ok_or(ERR_INVALID_HANDLE)?;
        if h.device {
            return Ok(0);
        }
        // SAFETY: `buf` is a live slice of the stated length.
        let n = unsafe { libc::read(h.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(ERR_ACCESS_DENIED);
        }
        Ok(n as usize)
    }

    pub fn write(&mut self, dos: u16, buf: &[u8]) -> Result<usize, u16> {
        let h = self.handle_of(dos).ok_or(ERR_INVALID_HANDLE)?;
        if h.device {
            return Ok(buf.len());
        }
        let name = h.name.clone();
        // SAFETY: `buf` is a live slice of the stated length.
        let n = unsafe { libc::write(h.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(ERR_ACCESS_DENIED);
        }
        if !self.touched.contains(&name) {
            self.touched.push(name);
        }
        Ok(n as usize)
    }

    /// `41h` -- delete a file.
    ///
    /// `unlinkat` has no `RESOLVE_BENEATH`, so containment here rests on the
    /// normalisation above having rejected `..` and absolute paths, plus the
    /// fact that `unlinkat` does not follow a symlink in the final component.
    /// A symlinked *directory* component would still be followed; the real
    /// subsystem should open the parent with `openat2` and unlink relative to
    /// that.
    pub fn unlink(&mut self, path: &[u8]) -> Result<(), u16> {
        let name = match translate(path) {
            Target::File(name) => name,
            Target::Device(_) => return Ok(()),
            Target::Rejected => return Err(ERR_PATH_NOT_FOUND),
        };
        let name = self.resolve(&name)?;
        let Ok(c_path) = std::ffi::CString::new(name) else {
            return Err(ERR_FILE_NOT_FOUND);
        };
        // SAFETY: unlinking relative to a descriptor we own.
        let rc = unsafe { libc::unlinkat(self.root.as_raw_fd(), c_path.as_ptr(), 0) };
        if rc == 0 { Ok(()) } else { Err(ERR_FILE_NOT_FOUND) }
    }

    /// `5Ch` -- lock or unlock a byte range of an open file.
    ///
    /// This is what makes a multinode door safe. LORD locks a player's record
    /// before touching it, and with no locking two people playing at once write
    /// over each other. Returning "invalid function" for it, as this did until
    /// now, is not a small gap: it is silent data loss under exactly the
    /// conditions a BBS creates.
    pub fn lock(&mut self, dos: u16, offset: u32, len: u32, take: bool) -> Result<(), u16> {
        // DOS asks for a zero-length region now and then, and means "nothing".
        // `fcntl` reads a zero `l_len` as "to end of file", so passing it
        // through would lock the entire file on a request to lock none of it.
        if len == 0 {
            return Ok(());
        }
        let fd = {
            let h = self.handle_of(dos).ok_or(ERR_INVALID_HANDLE)?;
            if h.device {
                return Ok(());
            }
            h.fd.as_raw_fd()
        };
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = if take { libc::F_WRLCK } else { libc::F_UNLCK } as libc::c_short;
        fl.l_whence = libc::SEEK_SET as libc::c_short;
        fl.l_start = i64::from(offset);
        fl.l_len = i64::from(len);
        fl.l_pid = 0; // required to be zero for an OFD lock
        // SAFETY: a well-formed flock against a descriptor we own.
        let rc = unsafe { libc::fcntl(fd, F_OFD_SETLK, std::ptr::from_mut(&mut fl)) };
        if rc == 0 {
            return Ok(());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) | Some(libc::EAGAIN) => Err(ERR_LOCK_VIOLATION),
            _ => Err(ERR_ACCESS_DENIED),
        }
    }

    /// `56h` -- rename, which is also how a program replaces a file: write a
    /// temporary, delete the original, rename over it. Refusing it does not
    /// merely skip a tidy-up -- Turbo Pascal turns the DOS error into a fatal
    /// I/O error, and LORD exits abnormally mid-game.
    pub fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), u16> {
        let from = match translate(from) {
            Target::File(name) => self.resolve(&name)?,
            _ => return Err(ERR_PATH_NOT_FOUND),
        };
        let to = match translate(to) {
            Target::File(name) => self.resolve(&name)?,
            _ => return Err(ERR_PATH_NOT_FOUND),
        };
        let (Ok(c_from), Ok(c_to)) = (
            std::ffi::CString::new(from),
            std::ffi::CString::new(to.clone()),
        ) else {
            return Err(ERR_PATH_NOT_FOUND);
        };
        // SAFETY: both paths are relative to a descriptor we own.
        let rc = unsafe {
            libc::renameat(
                self.root.as_raw_fd(),
                c_from.as_ptr(),
                self.root.as_raw_fd(),
                c_to.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(ERR_FILE_NOT_FOUND);
        }
        if !self.touched.contains(&to) {
            self.touched.push(to);
        }
        Ok(())
    }

    /// `42h` -- seek. `whence` is 0 set, 1 current, 2 end.
    pub fn seek(&mut self, dos: u16, offset: i64, whence: u8) -> Result<u64, u16> {
        let h = self.handle_of(dos).ok_or(ERR_INVALID_HANDLE)?;
        let w = match whence {
            0 => libc::SEEK_SET,
            1 => libc::SEEK_CUR,
            2 => libc::SEEK_END,
            _ => return Err(ERR_ACCESS_DENIED),
        };
        // SAFETY: an ordinary lseek on a descriptor we own.
        let at = unsafe { libc::lseek(h.fd.as_raw_fd(), offset, w) };
        if at < 0 {
            return Err(ERR_ACCESS_DENIED);
        }
        Ok(at as u64)
    }

    /// Resolve only a directory prefix. Unlike [`Files::resolve`], the final
    /// component need not already exist -- callers here pass a directory
    /// that a wildcarded filename sits inside, not a filename of its own. An
    /// empty `dir` names the root itself.
    fn resolve_dir(&mut self, dir: &str) -> Result<String, u16> {
        if dir.is_empty() {
            return Ok(String::new());
        }
        let mut here: PathBuf = self.root_path.clone();
        let mut out: Vec<String> = Vec::new();
        for part in dir.split('/') {
            let entries = list(&here);
            match pick(&entries, part) {
                Pick::Exact(found) | Pick::Unique(found) => {
                    here.push(&found);
                    out.push(found);
                }
                Pick::Missing => return Err(ERR_PATH_NOT_FOUND),
                Pick::Ambiguous(all) => {
                    let note = format!("{dir}: host holds {}", all.join(", "));
                    if !self.ambiguous.contains(&note) {
                        self.ambiguous.push(note);
                    }
                    return Err(ERR_ACCESS_DENIED);
                }
            }
        }
        Ok(out.join("/"))
    }

    /// Attribute, size and packed mtime for `name` inside `dir_fd`, or
    /// `None` if it vanished or cannot be stat'd -- which is not an error for
    /// a search: the entry is simply left out, the same way a directory
    /// listing racing a concurrent delete would drop it.
    fn stat_entry(dir_fd: RawFd, name: &str) -> Option<(u8, u32, u16, u16)> {
        let c_name = std::ffi::CString::new(name).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstatat` against a directory descriptor the caller owns
        // and a NUL-terminated name just read from that same directory.
        let rc = unsafe {
            libc::fstatat(
                dir_fd,
                c_name.as_ptr(),
                std::ptr::from_mut(&mut st),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return None;
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let writable = st.st_mode & libc::S_IWUSR != 0;
        let attr = if is_dir {
            ATTR_DIRECTORY
        } else if !writable {
            ATTR_READ_ONLY
        } else {
            ATTR_ARCHIVE
        };
        let size = if is_dir { 0 } else { st.st_size as u32 };
        let (dos_time, dos_date) = pack_datetime(st.st_mtime);
        Some((attr, size, dos_time, dos_date))
    }

    /// `4Eh` -- start a search for `path`, whose final component may be a
    /// wildcarded `NAME.EXT`. `attr_mask` is CX's low byte, DOS's search
    /// attribute mask; here it decides only whether directories are included
    /// (`ATTR_DIRECTORY` set in the mask), since nothing in this sandbox ever
    /// reports the hidden, system or volume-label bits that would otherwise
    /// need the same subset-matching treatment.
    pub fn find_first(&mut self, path: &[u8], attr_mask: u8) -> Result<FindEntry, u16> {
        let (dir, pattern) = match translate(path) {
            Target::File(name) => match name.rsplit_once('/') {
                Some((d, p)) => (d.to_string(), p.to_string()),
                None => (String::new(), name),
            },
            // A device is not a directory entry; nothing can find it.
            Target::Device(_) => return Err(ERR_FILE_NOT_FOUND),
            Target::Rejected => return Err(ERR_PATH_NOT_FOUND),
        };
        let dir = self.resolve_dir(&dir)?;
        let dir_fd = self
            .openat2(
                if dir.is_empty() { "." } else { &dir },
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )
            .map_err(|_| ERR_PATH_NOT_FOUND)?;

        let template = wildcard_template(&pattern);
        let want_dirs = attr_mask & ATTR_DIRECTORY != 0;

        let mut matched = Vec::new();
        let names = read_dir_raw(dir_fd.as_raw_fd()).map_err(|_| ERR_PATH_NOT_FOUND)?;
        for name in names {
            // Not representable in 8.3: DOS could not have listed it either.
            let Some(name_tpl) = eight_dot_three(&name) else {
                continue;
            };
            if !matches_template(&template, &name_tpl) {
                continue;
            }
            let Some((attr, size, dos_time, dos_date)) =
                Self::stat_entry(dir_fd.as_raw_fd(), &name)
            else {
                continue;
            };
            if attr & ATTR_DIRECTORY != 0 && !want_dirs {
                continue;
            }
            matched.push(FindEntry {
                name: display_name(&name_tpl),
                attr,
                size,
                dos_time,
                dos_date,
            });
        }
        // Directory order is not meaningful here (`getdents64` returns
        // whatever the host filesystem's own order is, which need not match
        // real DOS's either); sorting makes the search deterministic instead
        // of merely host-dependent.
        matched.sort_by(|a, b| a.name.cmp(&b.name));

        let first = matched.first().cloned().ok_or(ERR_FILE_NOT_FOUND)?;
        self.search = Some(FindSearch {
            entries: matched,
            next: 1,
        });
        Ok(first)
    }

    /// `4Fh` -- continue the search the last `4Eh` started.
    pub fn find_next(&mut self) -> Result<FindEntry, u16> {
        let search = self.search.as_mut().ok_or(ERR_NO_MORE_FILES)?;
        let entry = search
            .entries
            .get(search.next)
            .cloned()
            .ok_or(ERR_NO_MORE_FILES)?;
        search.next += 1;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// A scratch directory under the repo's gitignored `tmp/`, and a `Files`
    /// rooted at it.
    fn scratch(name: &str) -> (std::path::PathBuf, Files) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/dos-poc-tests")
            .join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch dir");
        std::fs::write(root.join("SHARED.DAT"), vec![0u8; 4096]).expect("seed file");
        let fd = std::fs::File::open(&root).expect("open root");
        (root.clone(), Files::new(fd.into(), root))
    }

    /// A second, independent view of the same directory -- which is what a
    /// second node is.
    fn second(root: &std::path::Path) -> Files {
        let fd = std::fs::File::open(root).expect("open root");
        Files::new(fd.into(), root.to_path_buf())
    }

    #[test]
    fn a_locked_region_is_refused_to_another_holder() {
        let (root, mut a) = scratch("lock_conflict");
        let mut b = second(&root);
        let ha = a.open_existing(b"SHARED.DAT\0", 2).expect("open in a");
        let hb = b.open_existing(b"SHARED.DAT\0", 2).expect("open in b");

        assert_eq!(a.lock(ha, 0, 100, true), Ok(()), "first holder takes it");
        // The assertion the whole call exists for. A `lock` that quietly did
        // nothing and returned Ok would pass every other test in this file.
        assert_eq!(
            b.lock(hb, 0, 100, true),
            Err(ERR_LOCK_VIOLATION),
            "a second holder must be refused"
        );

        assert_eq!(a.lock(ha, 0, 100, false), Ok(()), "first holder releases");
        assert_eq!(
            b.lock(hb, 0, 100, true),
            Ok(()),
            "and then the second may take it"
        );
    }

    #[test]
    fn regions_that_do_not_overlap_do_not_contend() {
        let (root, mut a) = scratch("lock_disjoint");
        let mut b = second(&root);
        let ha = a.open_existing(b"SHARED.DAT\0", 2).expect("open in a");
        let hb = b.open_existing(b"SHARED.DAT\0", 2).expect("open in b");
        assert_eq!(a.lock(ha, 0, 100, true), Ok(()));
        assert_eq!(b.lock(hb, 200, 100, true), Ok(()));
    }

    #[test]
    fn a_zero_length_lock_takes_nothing_rather_than_the_whole_file() {
        // fcntl reads l_len == 0 as "to end of file", so passing a DOS
        // zero-length request straight through locks everything.
        let (root, mut a) = scratch("lock_zero");
        let mut b = second(&root);
        let ha = a.open_existing(b"SHARED.DAT\0", 2).expect("open in a");
        let hb = b.open_existing(b"SHARED.DAT\0", 2).expect("open in b");
        assert_eq!(a.lock(ha, 0, 0, true), Ok(()));
        assert_eq!(
            b.lock(hb, 0, 100, true),
            Ok(()),
            "a zero-length lock must not have taken the file"
        );
    }

    #[test]
    fn locking_an_unopened_handle_is_an_invalid_handle() {
        let (_root, mut a) = scratch("lock_badhandle");
        assert_eq!(a.lock(99, 0, 100, true), Err(ERR_INVALID_HANDLE));
    }

    #[test]
    fn an_exact_spelling_wins_even_when_others_differ_only_in_case() {
        let entries = names(&["LORD.DAT", "lord.dat"]);
        assert_eq!(pick(&entries, "LORD.DAT"), Pick::Exact("LORD.DAT".into()));
        assert_eq!(pick(&entries, "lord.dat"), Pick::Exact("lord.dat".into()));
    }

    #[test]
    fn one_differing_only_in_case_is_used() {
        let entries = names(&["player.dat"]);
        assert_eq!(pick(&entries, "PLAYER.DAT"), Pick::Unique("player.dat".into()));
    }

    #[test]
    fn several_spellings_and_no_exact_match_is_refused_not_guessed() {
        // The real hazard: a LORD directory holding both, and DOS asking for a
        // third spelling. Picking either would bind the program to one file and
        // make the other unreachable -- write one, read the other back.
        let entries = names(&["LORD.DAT", "lord.dat"]);
        match pick(&entries, "Lord.Dat") {
            Pick::Ambiguous(all) => assert_eq!(all, names(&["LORD.DAT", "lord.dat"])),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn a_name_that_is_not_there_is_missing_so_a_create_can_use_it() {
        assert_eq!(pick(&names(&["OTHER.DAT"]), "NEW.DAT"), Pick::Missing);
    }

    #[test]
    fn a_drive_letter_is_stripped_and_backslashes_normalise() {
        assert_eq!(translate(b"C:\\LORD.DAT\0"), Target::File("LORD.DAT".into()));
        assert_eq!(
            translate(b"sub\\file.txt\0"),
            Target::File("SUB/FILE.TXT".into())
        );
    }

    #[test]
    fn parent_traversal_is_refused_before_it_reaches_the_kernel() {
        assert_eq!(translate(b"..\\..\\etc\\passwd\0"), Target::Rejected);
        assert_eq!(translate(b"C:\\..\\outside\0"), Target::Rejected);
    }

    #[test]
    fn device_names_never_become_files_even_with_an_extension() {
        assert_eq!(translate(b"PRN\0"), Target::Device("PRN"));
        assert_eq!(translate(b"NUL.TXT\0"), Target::Device("NUL"));
        assert_eq!(translate(b"C:\\CON\0"), Target::Device("CON"));
        // But a name that merely starts with one is an ordinary file.
        assert_eq!(translate(b"CONFIG.SYS\0"), Target::File("CONFIG.SYS".into()));
    }

    #[test]
    fn an_empty_path_is_rejected_rather_than_naming_the_root() {
        assert_eq!(translate(b"\0"), Target::Rejected);
        assert_eq!(translate(b"C:\\\0"), Target::Rejected);
    }

    // -- wildcard template construction and matching, no filesystem at all --

    #[test]
    fn star_fills_the_rest_of_its_own_field_with_question_marks() {
        assert_eq!(wildcard_template("*.DAT"), *b"????????DAT");
        assert_eq!(wildcard_template("LORD.*"), *b"LORD    ???");
    }

    #[test]
    fn literal_characters_after_a_star_in_the_same_field_are_ignored() {
        // The Old New Thing's example: everything between the `*` and the
        // next `.` has no effect, since the star already claimed the field.
        assert_eq!(wildcard_template("A*B.TXT"), wildcard_template("A*.TXT"));
    }

    #[test]
    fn question_mark_matches_a_padding_space_not_just_a_character() {
        // The DOS-specific quirk this whole module exists to get right: `?`
        // is satisfied by the *absence* of a character too, which ordinary
        // shell globbing would never allow.
        let tpl = wildcard_template("A?.DAT");
        let short = eight_dot_three("A.DAT").unwrap();
        let long = eight_dot_three("AB.DAT").unwrap();
        assert!(
            matches_template(&tpl, &short),
            "A?.DAT must match A.DAT -- ? tolerates a missing character"
        );
        assert!(matches_template(&tpl, &long), "A?.DAT must still match AB.DAT");
    }

    #[test]
    fn star_dot_star_matches_a_name_with_no_extension_at_all() {
        // Another glob mismatch: `*.*` in a shell requires a literal dot;
        // DOS's `*.*` means "everything", extension or not.
        let tpl = wildcard_template("*.*");
        let no_ext = eight_dot_three("README").unwrap();
        assert!(matches_template(&tpl, &no_ext));
    }

    #[test]
    fn a_fully_literal_pattern_matches_only_its_own_name() {
        let tpl = wildcard_template("LORD.DAT");
        assert!(matches_template(&tpl, &eight_dot_three("LORD.DAT").unwrap()));
        assert!(!matches_template(&tpl, &eight_dot_three("LORD.CFG").unwrap()));
    }

    #[test]
    fn eight_dot_three_rejects_a_name_that_does_not_fit() {
        assert_eq!(eight_dot_three("TOOLONGNAME.DAT"), None, "name over 8 chars");
        assert_eq!(eight_dot_three("A.TOOLONG"), None, "extension over 3 chars");
        assert_eq!(eight_dot_three("A.B.C"), None, "more than one dot");
    }

    #[test]
    fn display_name_round_trips_a_valid_eight_dot_three_name() {
        assert_eq!(display_name(&eight_dot_three("LORD.DAT").unwrap()), "LORD.DAT");
        assert_eq!(
            display_name(&eight_dot_three("README").unwrap()),
            "README",
            "no extension means no trailing dot"
        );
    }

    // -- find_first/find_next against a real, sandboxed directory --

    #[test]
    fn find_first_and_find_next_walk_a_wildcard_match_in_order_then_stop() {
        let (root, mut a) = scratch("find_basic");
        std::fs::write(root.join("LORD.DAT"), vec![0u8; 10]).expect("seed");
        std::fs::write(root.join("LORD.CFG"), vec![0u8; 5]).expect("seed");
        std::fs::write(root.join("OTHER.TXT"), vec![0u8; 3]).expect("seed");

        let first = a.find_first(b"LORD.*\0", 0).expect("a match exists");
        assert_eq!(first.name, "LORD.CFG", "alphabetically first of the two");
        assert_eq!(first.size, 5);
        assert_eq!(first.attr, ATTR_ARCHIVE);

        let second = a.find_next().expect("a second match exists");
        assert_eq!(second.name, "LORD.DAT");
        assert_eq!(second.size, 10);

        assert_eq!(
            a.find_next(),
            Err(ERR_NO_MORE_FILES),
            "OTHER.TXT does not match LORD.*, so only two results exist"
        );
    }

    #[test]
    fn find_first_with_no_match_is_file_not_found_not_no_more_files() {
        let (_root, mut a) = scratch("find_nomatch");
        assert_eq!(a.find_first(b"NOPE.*\0", 0), Err(ERR_FILE_NOT_FOUND));
    }

    #[test]
    fn find_next_with_no_prior_find_first_is_no_more_files() {
        let (_root, mut a) = scratch("find_no_prior");
        assert_eq!(a.find_next(), Err(ERR_NO_MORE_FILES));
    }

    #[test]
    fn find_first_excludes_directories_unless_the_mask_asks_for_them() {
        let (root, mut a) = scratch("find_dirs");
        std::fs::create_dir(root.join("SUBDIR")).expect("seed dir");
        std::fs::write(root.join("A.DAT"), b"x").expect("seed file");

        let mut without_dirs = vec![a.find_first(b"*.*\0", 0).expect("a match exists").name];
        for _ in 0..8 {
            match a.find_next() {
                Ok(e) => without_dirs.push(e.name),
                Err(_) => break,
            }
        }
        assert!(
            without_dirs.len() < 8,
            "find_next did not terminate: {without_dirs:?}"
        );
        assert!(
            !without_dirs.contains(&"SUBDIR".to_string()),
            "a plain search must not report directories: {without_dirs:?}"
        );
        assert!(without_dirs.contains(&"A.DAT".to_string()));

        let mut with_dirs = vec![
            a.find_first(b"*.*\0", ATTR_DIRECTORY)
                .expect("a match exists")
                .name,
        ];
        for _ in 0..8 {
            match a.find_next() {
                Ok(e) => with_dirs.push(e.name),
                Err(_) => break,
            }
        }
        assert!(
            with_dirs.len() < 8,
            "find_next did not terminate: {with_dirs:?}"
        );
        assert!(
            with_dirs.contains(&"SUBDIR".to_string()),
            "with ATTR_DIRECTORY set, directories must be included: {with_dirs:?}"
        );
    }

    #[test]
    fn find_first_reports_read_only_for_a_file_without_the_write_bit() {
        let (root, mut a) = scratch("find_readonly");
        let path = root.join("RO.DAT");
        std::fs::write(&path, b"x").expect("seed");
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).expect("chmod");

        let entry = a.find_first(b"RO.DAT\0", 0).expect("a match exists");
        assert_eq!(entry.attr, ATTR_READ_ONLY);
    }

    #[test]
    fn find_first_stays_inside_the_sandbox_for_a_traversal_attempt() {
        let (_root, mut a) = scratch("find_escape");
        assert_eq!(a.find_first(b"..\\*.*\0", 0), Err(ERR_PATH_NOT_FOUND));
    }
}
