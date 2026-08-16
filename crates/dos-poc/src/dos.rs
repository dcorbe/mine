//! The DOS services themselves: one match on `AH`, and the state behind it.
//!
//! Nothing here knows how the call arrived. That is the entire claim being
//! demonstrated -- the same `dispatch` serves a real-mode KVM guest and a
//! `Vec<u8>` in a unit test, and would serve an `m16` signal handler without
//! changing a line.

use crate::files::Files;
use crate::guest::{DosFault, DosGuest, DosPtr, DosRegs, Flag};

/// DOS error codes, as returned in AX with CF set.
pub const ERR_INVALID_FUNCTION: u16 = 0x01;
pub const ERR_INVALID_HANDLE: u16 = 0x06;

/// What the caller should do once a call has been serviced.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Resume the program.
    Continue,
    /// The program asked to exit, with this return code.
    Terminate(u8),
    /// The program handed over a pointer that does not name memory.
    ///
    /// Deliberately *not* laundered into a DOS error code. Real DOS would have
    /// read whatever happened to be there; reporting it instead turns silent
    /// corruption into a stop, which is the trade this project makes
    /// everywhere else.
    Fault(DosFault),
}

/// The DOS kernel's state. Small here on purpose -- this is a proof of
/// concept, not the subsystem. The real one grows a handle table, a DTA, a
/// PSP chain and an MCB chain, none of which change the shape of `dispatch`.
pub struct DosState {
    /// Current default drive, 0 = `A:`.
    pub drive: u8,
    /// How many logical drives to claim.
    pub drives: u8,
    /// The version to report to `AH=30`, as `(major, minor)`.
    pub version: (u8, u8),
    /// Everything the program has written to a character device.
    ///
    /// A buffer rather than a `Write` so that a test can assert on it without
    /// a fixture, which is the whole point of the seam.
    pub out: Vec<u8>,
    /// The filesystem, if this program has been given one. `None` means every
    /// file call fails -- which is a legitimate configuration, and is how the
    /// probe ran before file services existed.
    pub files: Option<Files>,
}

impl Default for DosState {
    fn default() -> Self {
        Self {
            drive: 2,
            drives: 26,
            version: (5, 0),
            out: Vec::new(),
            files: None,
        }
    }
}

/// Finish a successful call: registers back, carry clear.
fn ok<G: DosGuest>(g: &mut G, regs: DosRegs) -> Outcome {
    g.set_regs(regs);
    g.set_flag(Flag::Carry, false);
    Outcome::Continue
}

/// Finish a failed call the way DOS does: CF set, code in AX.
fn fail<G: DosGuest>(g: &mut G, mut regs: DosRegs, code: u16) -> Outcome {
    regs.ax = code;
    g.set_regs(regs);
    g.set_flag(Flag::Carry, true);
    Outcome::Continue
}

/// Which `AH` values [`dispatch`] actually services.
///
/// Exposed so a caller can tell "the program asked for something we do not
/// have" apart from "the program made a call that legitimately failed" --
/// both look like CF set from inside the guest.
pub fn is_implemented(ah: u8) -> bool {
    matches!(
        ah,
        0x02 | 0x09 | 0x0e | 0x19 | 0x25 | 0x2a | 0x2b | 0x2c | 0x2d | 0x30 | 0x35 | 0x3c | 0x3d
            | 0x3e | 0x3f | 0x40 | 0x41 | 0x42 | 0x44 | 0x4c | 0x56 | 0x5c
    )
}

/// The host clock, broken out the way DOS reports it.
struct Now {
    year: u16,
    month: u8,
    day: u8,
    weekday: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

fn local_time() -> Now {
    // SAFETY: `time` with a null argument returns the value; `localtime_r`
    // fills a caller-owned struct and so is safe to call from any thread.
    let now = unsafe {
        let secs = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(std::ptr::from_ref(&secs), std::ptr::from_mut(&mut tm));
        tm
    };
    Now {
        year: (now.tm_year + 1900) as u16,
        month: (now.tm_mon + 1) as u8,
        day: now.tm_mday as u8,
        weekday: now.tm_wday as u8,
        hour: now.tm_hour as u8,
        minute: now.tm_min as u8,
        second: now.tm_sec as u8,
    }
}

/// Read an ASCIIZ path argument, bounded by DOS's own 128-byte path limit.
fn path_at<G: DosGuest>(g: &G, at: DosPtr) -> Result<Vec<u8>, DosFault> {
    g.read_until(at, 0, 128).map(<[u8]>::to_vec)
}

/// Service one `int 21h`.
pub fn dispatch<G: DosGuest>(g: &mut G, dos: &mut DosState) -> Outcome {
    let mut regs = g.regs();
    match regs.ah() {
        // 02h -- display character in DL.
        0x02 => {
            let ch = regs.dl();
            dos.out.push(ch);
            regs.set_al(ch);
            ok(g, regs)
        }

        // 09h -- display the `$`-terminated string at DS:DX.
        0x09 => {
            let at = regs.ds_dx();
            let text = match g.read_until(at, b'$', 0xffff) {
                Ok(t) => t.to_vec(),
                Err(f) => return Outcome::Fault(f),
            };
            dos.out.extend_from_slice(&text);
            regs.set_al(b'$');
            ok(g, regs)
        }

        // 0Eh -- select default drive DL, returns the drive count in AL.
        0x0e => {
            dos.drive = regs.dl();
            let count = dos.drives;
            regs.set_al(count);
            ok(g, regs)
        }

        // 19h -- get default drive. The call The Rose's `getdisk()` faults on.
        0x19 => {
            let drive = dos.drive;
            regs.set_al(drive);
            ok(g, regs)
        }

        // 25h -- set interrupt vector AL to DS:DX.
        //
        // In a real-mode guest the IVT *is* guest memory, so this is a plain
        // four-byte store through the seam rather than anything KVM-specific.
        // (A protected-mode edge has no IVT and would have to model one; not
        // every DOS call is as mode-agnostic as the file services.)
        0x25 => {
            let at = DosPtr::new(0, u16::from(regs.al()) * 4);
            let mut entry = [0u8; 4];
            entry[0..2].copy_from_slice(&regs.dx.to_le_bytes());
            entry[2..4].copy_from_slice(&regs.ds.to_le_bytes());
            if let Err(f) = g.write(at, &entry) {
                return Outcome::Fault(f);
            }
            ok(g, regs)
        }

        // 35h -- get interrupt vector AL, answered in ES:BX.
        0x35 => {
            let at = DosPtr::new(0, u16::from(regs.al()) * 4);
            let entry = match g.read(at, 4) {
                Ok(b) => [b[0], b[1], b[2], b[3]],
                Err(f) => return Outcome::Fault(f),
            };
            regs.bx = u16::from_le_bytes([entry[0], entry[1]]);
            regs.es = u16::from_le_bytes([entry[2], entry[3]]);
            ok(g, regs)
        }

        // 30h -- get DOS version.
        0x30 => {
            let (major, minor) = dos.version;
            regs.set_al(major);
            regs.set_ah(minor);
            regs.bx = 0;
            regs.cx = 0;
            ok(g, regs)
        }

        // 40h -- write CX bytes at DS:DX to handle BX.
        0x40 => {
            let at = regs.ds_dx();
            let len = regs.cx as usize;
            let bytes = match g.read(at, len) {
                Ok(b) => b.to_vec(),
                Err(f) => return Outcome::Fault(f),
            };
            if regs.bx == 1 || regs.bx == 2 {
                dos.out.extend_from_slice(&bytes);
                regs.ax = len as u16;
                return ok(g, regs);
            }
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_HANDLE);
            };
            match files.write(regs.bx, &bytes) {
                Ok(n) => {
                    regs.ax = n as u16;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 44h/00h -- get device information for handle BX.
        //
        // A C or Pascal runtime asks this of every handle it opens, to decide
        // whether it is talking to a file or a console. Answering wrongly makes
        // a runtime buffer output it should have flushed, or vice versa.
        0x44 if regs.al() == 0 => {
            // Bit 7 marks a character device; bits 0-1 mark it as the console.
            const CON: u16 = 0x80 | 0x02 | 0x01;
            match regs.bx {
                0 | 1 | 2 => {
                    regs.dx = CON;
                    regs.ax = CON;
                    ok(g, regs)
                }
                _ => fail(g, regs, ERR_INVALID_HANDLE),
            }
        }

        // 2Ah/2Ch -- get date and time, from the host clock.
        //
        // A stub date is not a harmless placeholder. LORD stamps its logs with
        // this, resets each player's daily allowance when the day changes, and
        // deletes players after so many days of inactivity -- all of which read
        // a frozen clock as "no time has passed, ever".
        0x2a => {
            let now = local_time();
            regs.cx = now.year;
            regs.dx = (u16::from(now.month) << 8) | u16::from(now.day);
            regs.set_al(now.weekday);
            ok(g, regs)
        }
        0x2c => {
            let now = local_time();
            regs.cx = (u16::from(now.hour) << 8) | u16::from(now.minute);
            regs.dx = u16::from(now.second) << 8;
            ok(g, regs)
        }
        0x2b | 0x2d => {
            regs.set_al(0);
            ok(g, regs)
        }

        // 3Ch -- create or truncate DS:DX, returning a handle in AX.
        0x3c => {
            let path = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.create(&path) {
                Ok(handle) => {
                    regs.ax = handle;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 3Dh -- open DS:DX with the access mode in AL.
        0x3d => {
            let access = regs.al();
            let path = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.open_existing(&path, access) {
                Ok(handle) => {
                    regs.ax = handle;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 3Eh -- close handle BX.
        0x3e => {
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.close(regs.bx) {
                Ok(()) => ok(g, regs),
                Err(code) => fail(g, regs, code),
            }
        }

        // 3Fh -- read CX bytes from handle BX into DS:DX.
        0x3f => {
            let at = regs.ds_dx();
            let want = regs.cx as usize;
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            let mut buf = vec![0u8; want];
            let n = match files.read(regs.bx, &mut buf) {
                Ok(n) => n,
                Err(code) => return fail(g, regs, code),
            };
            if let Err(f) = g.write(at, &buf[..n]) {
                return Outcome::Fault(f);
            }
            regs.ax = n as u16;
            ok(g, regs)
        }

        // 41h -- delete the file named by DS:DX.
        0x41 => {
            let path = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.unlink(&path) {
                Ok(()) => ok(g, regs),
                Err(code) => fail(g, regs, code),
            }
        }

        // 42h -- seek handle BX to CX:DX by AL.
        0x42 => {
            let offset = (i64::from(regs.cx) << 16) | i64::from(regs.dx);
            let whence = regs.al();
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.seek(regs.bx, offset, whence) {
                Ok(at) => {
                    regs.ax = (at & 0xffff) as u16;
                    regs.dx = ((at >> 16) & 0xffff) as u16;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 56h -- rename DS:DX to ES:DI.
        0x56 => {
            let from = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let to = match path_at(g, DosPtr::new(regs.es, regs.di)) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.rename(&from, &to) {
                Ok(()) => ok(g, regs),
                Err(code) => fail(g, regs, code),
            }
        }

        // 5Ch -- lock (AL=0) or unlock (AL=1) CX:DX for SI:DI bytes on handle BX.
        0x5c => {
            let take = regs.al() == 0;
            let offset = (u32::from(regs.cx) << 16) | u32::from(regs.dx);
            let len = (u32::from(regs.si) << 16) | u32::from(regs.di);
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.lock(regs.bx, offset, len, take) {
                Ok(()) => ok(g, regs),
                Err(code) => fail(g, regs, code),
            }
        }

        // 4Ch -- terminate with the return code in AL.
        0x4c => Outcome::Terminate(regs.al()),

        _ => fail(g, regs, ERR_INVALID_FUNCTION),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::DosPtr;
    use crate::testguest::TestGuest;

    /// A guest with `text` placed at a known address, and DS:DX pointing at it.
    fn with_string(text: &[u8]) -> (TestGuest, DosState) {
        let mut g = TestGuest::new(64 * 1024);
        let at = DosPtr::new(0x100, 0x20);
        g.poke(at, text);
        let mut regs = DosRegs::default();
        regs.ds = at.seg;
        regs.dx = at.off;
        g.call_with(regs);
        (g, DosState::default())
    }

    #[test]
    fn display_string_stops_at_the_terminator_and_drops_it() {
        let (mut g, mut dos) = with_string(b"hello$ and not this");
        let mut regs = g.regs();
        regs.set_ah(0x09);
        g.set_regs(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert_eq!(&dos.out[..], &b"hello"[..]);
        assert_eq!(g.regs().al(), b'$', "09h reports the terminator in AL");
        assert!(!g.carry());
    }

    #[test]
    fn display_string_without_a_terminator_faults_rather_than_running_on() {
        let (mut g, mut dos) = with_string(b"no terminator here");
        let mut regs = g.regs();
        regs.set_ah(0x09);
        g.set_regs(regs);

        // The guest is all zeroes past the string, so a naive implementation
        // would happily emit 64 KiB of NULs instead of stopping.
        match dispatch(&mut g, &mut dos) {
            Outcome::Fault(DosFault::Unterminated { term, .. }) => assert_eq!(term, b'$'),
            other => panic!("expected an Unterminated fault, got {other:?}"),
        }
        assert!(dos.out.is_empty(), "nothing is emitted on a fault");
    }

    #[test]
    fn get_default_drive_reports_the_state_not_a_constant() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState {
            drive: 3,
            ..DosState::default()
        };
        let mut regs = DosRegs::default();
        regs.set_ah(0x19);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert_eq!(g.regs().al(), 3);
    }

    #[test]
    fn select_drive_sets_the_drive_and_returns_the_count() {
        let mut g = TestGuest::new(4096);
        // Distinct values, so swapping the two fields cannot pass.
        let mut dos = DosState {
            drive: 0,
            drives: 7,
            ..DosState::default()
        };
        let mut regs = DosRegs::default();
        regs.set_ah(0x0e);
        regs.dx = 4;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert_eq!(dos.drive, 4, "DL selects the drive");
        assert_eq!(g.regs().al(), 7, "AL returns the drive count");
    }

    #[test]
    fn get_version_splits_major_and_minor_across_al_and_ah() {
        let mut g = TestGuest::new(4096);
        // Distinct so a transposed pair cannot pass.
        let mut dos = DosState {
            version: (6, 22),
            ..DosState::default()
        };
        let mut regs = DosRegs::default();
        regs.set_ah(0x30);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert_eq!(g.regs().al(), 6, "AL is the major version");
        assert_eq!(g.regs().ah(), 22, "AH is the minor version");
    }

    #[test]
    fn write_to_stdout_emits_exactly_cx_bytes_and_reports_the_count() {
        let (mut g, mut dos) = with_string(b"abcdefgh");
        let mut regs = g.regs();
        regs.set_ah(0x40);
        regs.bx = 1;
        regs.cx = 3;
        g.set_regs(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert_eq!(&dos.out[..], &b"abc"[..], "CX bounds the write, not the data");
        assert_eq!(g.regs().ax, 3);
    }

    #[test]
    fn write_to_an_unopened_handle_fails_without_emitting() {
        let (mut g, mut dos) = with_string(b"abcdefgh");
        let mut regs = g.regs();
        regs.set_ah(0x40);
        regs.bx = 7;
        regs.cx = 3;
        g.set_regs(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry(), "DOS reports failure with CF");
        assert_eq!(g.regs().ax, ERR_INVALID_HANDLE);
        assert!(dos.out.is_empty());
    }

    #[test]
    fn an_unimplemented_call_fails_loudly_rather_than_succeeding_silently() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = DosRegs::default();
        regs.set_ah(0x5b);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INVALID_FUNCTION);
    }

    #[test]
    fn terminate_carries_the_code_out_of_al() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = DosRegs::default();
        regs.ax = 0x4c00 | 3;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Terminate(3));
    }

    #[test]
    fn a_pointer_past_the_end_of_memory_faults() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = DosRegs::default();
        regs.set_ah(0x40);
        regs.bx = 1;
        regs.cx = 16;
        regs.ds = 0xf000;
        regs.dx = 0xfff0;
        g.call_with(regs);

        match dispatch(&mut g, &mut dos) {
            Outcome::Fault(DosFault::OutOfBounds { .. }) => {}
            other => panic!("expected OutOfBounds, got {other:?}"),
        }
    }
}
