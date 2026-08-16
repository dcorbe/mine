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

/// DOS error codes, as returned in AX with CF set.
pub const ERR_FILE_NOT_FOUND: u16 = 0x02;
pub const ERR_PATH_NOT_FOUND: u16 = 0x03;
pub const ERR_TOO_MANY_OPEN: u16 = 0x04;
pub const ERR_ACCESS_DENIED: u16 = 0x05;
pub const ERR_INVALID_HANDLE: u16 = 0x06;

/// The first handle DOS hands out; 0-2 are the inherited standard ones.
const FIRST_HANDLE: u16 = 5;
/// DOS's own default, and the reason a fixed-capacity table is faithful rather
/// than a shortcut.
const MAX_HANDLES: usize = 20;

const SYS_OPENAT2: libc::c_long = 437;
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

struct Handle {
    fd: OwnedFd,
    /// Kept for diagnostics: "which file did it write?" is the whole question.
    name: String,
    device: bool,
}

/// The open-file table, and the root everything resolves beneath.
pub struct Files {
    root: OwnedFd,
    open: Vec<Option<Handle>>,
    /// Every file the program created or wrote, in order first touched.
    pub touched: Vec<String>,
    /// Every open or create the program attempted, and how it went. "Which
    /// files did it ask for?" is a different question from "which did it
    /// write", and answering only the second hides the interesting half.
    pub attempts: Vec<(String, &'static str, bool)>,
}

impl Files {
    pub fn new(root: OwnedFd) -> Self {
        Self {
            root,
            open: (0..MAX_HANDLES).map(|_| None).collect(),
            touched: Vec::new(),
            attempts: Vec::new(),
        }
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

    /// Try the name as DOS spelled it, then as a host directory is likely to.
    fn open_either_case(&self, name: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        match self.openat2(name, flags, mode) {
            Ok(fd) => Ok(fd),
            Err(first) => self
                .openat2(&name.to_ascii_lowercase(), flags, mode)
                .map_err(|_| first),
        }
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
                let attempt = self.open_either_case(&name, flags, 0);
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
        for spelling in [name.clone(), name.to_ascii_lowercase()] {
            let Ok(c_path) = std::ffi::CString::new(spelling) else {
                continue;
            };
            // SAFETY: unlinking relative to a descriptor we own.
            let rc = unsafe { libc::unlinkat(self.root.as_raw_fd(), c_path.as_ptr(), 0) };
            if rc == 0 {
                return Ok(());
            }
        }
        Err(ERR_FILE_NOT_FOUND)
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
