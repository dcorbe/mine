//! The DOS services themselves: one match on `AH`, and the state behind it.
//!
//! Nothing here knows how the call arrived. That is the entire claim being
//! demonstrated -- the same `dispatch` serves a real-mode KVM guest and a
//! `Vec<u8>` in a unit test, and would serve an `m16` signal handler without
//! changing a line.

use std::collections::BTreeMap;

use crate::files::{self, Files};
use crate::guest::{Fault, Guest, Ptr, Regs, Flag};

/// DOS error codes, as returned in AX with CF set.
pub const ERR_INVALID_FUNCTION: u16 = 0x01;
pub const ERR_INVALID_HANDLE: u16 = 0x06;
/// `AH=48h`/`4Ah` when there is not enough room, carried with the largest
/// size in paragraphs that would have succeeded, per each call's own contract.
pub const ERR_INSUFFICIENT_MEMORY: u16 = 0x08;
/// `AH=49h`/`4Ah` naming a segment nothing has allocated.
pub const ERR_INVALID_MEMORY_BLOCK: u16 = 0x09;

/// Conventional memory ends here: segment `0xa000` is where video RAM
/// (`0xb800` for text mode, `0xa000` itself for EGA/VGA graphics planes)
/// begins, and DOS's own allocator never hands out a paragraph at or past it.
/// `dos-runtime`'s loader picks `PSP_SEG`/`ENV_SEG` far below this for the
/// same reason (`crates/dos-runtime/src/bin/runexe.rs`).
const CONV_TOP: u16 = 0xa000;

/// The smallest number of paragraphs any successful `AH=48h`/`4Ah` leaves a
/// block owning, even when the caller asked for zero.
///
/// Real DOS accepts a zero-paragraph `48h` and does not refuse it, but it
/// does not hand back a zero-footprint alias either: the returned segment is
/// backed by nothing but that block's own one-paragraph MCB (Memory Control
/// Block) header, which is real memory no other block can also start from.
/// (The well-known trick for reading free memory *without* allocating is a
/// deliberately oversized request -- `BX=0FFFFh` -- which is guaranteed to
/// fail and report the largest block in `BX`; it is not `BX=0`, which DOS
/// honours as a genuine, if minimal, allocation.)
///
/// This `Arena` has no separate header representation -- `allocated` maps a
/// segment straight to the paragraphs a caller owns, with no per-block
/// overhead modelled (see the struct's own doc comment). Without a floor,
/// `alloc(0)` takes nothing from the free list, so the very next real
/// allocation first-fits into the identical segment; two different callers
/// then believe they each own it, and whichever frees first silently frees
/// the other's live block out from under it. Reserving one paragraph here
/// is the cheapest way to give a zero-size block the same non-aliasing
/// property its real MCB header gives it, without modelling the header
/// itself.
const MIN_BLOCK: u16 = 1;

/// Why a resize (`AH=4Ah`) failed.
#[derive(Debug, PartialEq, Eq)]
enum ResizeErr {
    /// No block is allocated at the named segment -- the `AH=49h` case as
    /// applied to `4Ah`, so it is reported the same way: `AX=9`.
    NoSuchBlock,
    /// Not enough room to grow the block *in place*. This project's arena
    /// never relocates a block on resize -- nothing walks a guest-visible MCB
    /// chain that a relocation would have to keep honest, and a program that
    /// already holds pointers into the block would have those pointers
    /// invalidated by a move DOS itself does not silently make either. Carries
    /// the largest size that would have succeeded, exactly as `4Ah`'s own
    /// contract requires in `BX`.
    TooSmall(u16),
}

/// Conventional memory above whatever the loaded program occupies, modelled
/// as a host-side list of blocks -- not a guest-visible MCB chain. Nothing
/// measured under `runexe` ever walks one (see the Task 1c brief), and
/// inventing a structure nothing reads is exactly the speculative work this
/// project refuses.
///
/// Two collections, not one, because "allocated" and "free" need different
/// keys: a caller names an allocated block by its *segment* (`AH=49h`/`4Ah`'s
/// `ES`), while satisfying a new request only needs to know free blocks'
/// *sizes*. A single sorted `Vec<Block>` tagged free/allocated would make
/// every free-list scan also skip past allocated entries for nothing.
pub struct Arena {
    /// Segment -> size in paragraphs, for every block currently allocated.
    /// The program's own block (seeded by [`Arena::new`]) lives in here too,
    /// so `AH=4Ah` resizing it is the same code path as resizing anything
    /// `AH=48h` returned -- DOS itself draws no distinction between the two.
    allocated: BTreeMap<u16, u16>,
    /// Free ranges as `(segment, size)`, sorted by segment and coalesced so
    /// that two adjacent free blocks are never left as two entries -- without
    /// that, a resize growing into a block that was itself assembled from two
    /// prior frees would see less contiguous space than genuinely exists.
    free: Vec<(u16, u16)>,
}

impl Arena {
    /// `owner_seg` is the segment `AH=62h` reports as this program's PSP; its
    /// block starts out owning every paragraph up to `first_free`.
    /// `first_free` is the first paragraph the loader did *not* hand to the
    /// program -- `mz::MzImage::paragraphs()` (PSP + image + the header's own
    /// declared `min_alloc`) is exactly that figure, the same one real DOS
    /// would use to size a new process's block before any `4Ah` shrinks it.
    /// Everything from `first_free` to [`CONV_TOP`] starts out free.
    pub fn new(owner_seg: u16, first_free: u16) -> Self {
        let mut allocated = BTreeMap::new();
        allocated.insert(owner_seg, first_free.saturating_sub(owner_seg));
        let free = if first_free < CONV_TOP {
            vec![(first_free, CONV_TOP - first_free)]
        } else {
            Vec::new()
        };
        Self { allocated, free }
    }

    /// The largest single free block, in paragraphs -- what a failed `48h`
    /// or a failed `4Ah` growing with no adjacent room reports in `BX`.
    fn largest_free(&self) -> u16 {
        self.free.iter().map(|&(_, size)| size).max().unwrap_or(0)
    }

    /// Return `(seg, size)` to the free list, merging it into whichever
    /// neighbour(s) it now touches so two frees either side of the same gap
    /// collapse into one entry instead of surviving as two.
    fn release(&mut self, seg: u16, size: u16) {
        if size == 0 {
            return;
        }
        self.free.push((seg, size));
        self.free.sort_by_key(|&(s, _)| s);
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(self.free.len());
        for (s, sz) in self.free.drain(..) {
            match merged.last_mut() {
                Some(last) if last.0 + last.1 == s => last.1 += sz,
                _ => merged.push((s, sz)),
            }
        }
        self.free = merged;
    }

    /// `AH=48h` -- take the first free block with room for `want` paragraphs,
    /// address order low to high (first-fit; see `AH=58h`'s doc comment for
    /// why nothing here honours a program's chosen strategy beyond accepting
    /// it). `Err` carries [`Arena::largest_free`], per `48h`'s own contract.
    ///
    /// `want` is floored to [`MIN_BLOCK`] before the search -- see that
    /// constant's doc comment for why a zero-paragraph request still has to
    /// consume real space.
    pub fn alloc(&mut self, want: u16) -> Result<u16, u16> {
        let want = want.max(MIN_BLOCK);
        match self.free.iter().position(|&(_, size)| size >= want) {
            Some(i) => {
                let (seg, size) = self.free[i];
                if size == want {
                    self.free.remove(i);
                } else {
                    self.free[i] = (seg + want, size - want);
                }
                self.allocated.insert(seg, want);
                Ok(seg)
            }
            None => Err(self.largest_free()),
        }
    }

    /// `AH=49h` -- free the block at `seg`. `Err` means nothing is allocated
    /// there, `49h`'s own "invalid memory block address" case.
    pub fn dealloc(&mut self, seg: u16) -> Result<(), ()> {
        let size = self.allocated.remove(&seg).ok_or(())?;
        self.release(seg, size);
        Ok(())
    }

    /// `AH=4Ah` -- resize the block at `seg` to `new_size` paragraphs.
    /// Shrinking always succeeds and frees the tail; growing only succeeds
    /// in place, against whatever free block immediately follows the block
    /// (see [`ResizeErr::TooSmall`] for why relocation is not on offer).
    ///
    /// A shrink to zero is floored to [`MIN_BLOCK`] the same way `alloc`
    /// floors `want` -- the caller (`ES` still names `seg`) keeps owning
    /// that one paragraph instead of it going back on the free list, where
    /// the next real allocation would first-fit into the exact segment the
    /// caller still believes is theirs. Skipped when `old_size` is already
    /// zero (the degenerate block a program with no free memory behind it
    /// starts with, from [`Arena::new`]): flooring there would grow the
    /// block without taking the paragraph from anywhere, so it is left at
    /// zero and a genuine grow request has to go through the normal
    /// adjacent-free-space check below like any other.
    fn resize(&mut self, seg: u16, new_size: u16) -> Result<(), ResizeErr> {
        let &old_size = self.allocated.get(&seg).ok_or(ResizeErr::NoSuchBlock)?;
        let new_size = if new_size == 0 && old_size > 0 {
            MIN_BLOCK
        } else {
            new_size
        };
        if new_size <= old_size {
            self.allocated.insert(seg, new_size);
            self.release(seg + new_size, old_size - new_size);
            return Ok(());
        }
        let want_extra = new_size - old_size;
        let after = seg + old_size;
        let adjacent = self.free.iter().position(|&(s, _)| s == after);
        let available = adjacent.map_or(0, |i| self.free[i].1);
        if available < want_extra {
            return Err(ResizeErr::TooSmall(old_size + available));
        }
        let i = adjacent.expect("available > 0 implies an adjacent free block was found");
        let (fseg, fsize) = self.free[i];
        if fsize == want_extra {
            self.free.remove(i);
        } else {
            self.free[i] = (fseg + want_extra, fsize - want_extra);
        }
        self.allocated.insert(seg, new_size);
        Ok(())
    }
}

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
    Fault(Fault),
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
    /// The real-mode segment the loader built this program's PSP at, if a
    /// program has been loaded. `None` is a legitimate configuration too --
    /// every unit test in this file constructs a `DosState` with no program
    /// behind it at all -- and `AH=62h` below is what has to answer for that.
    pub psp_seg: Option<u16>,
    /// The Disk Transfer Address, `DS:DX` as last set by `AH=1Ah`. `None`
    /// until the program calls it; see [`dta`] for what stands in until then.
    pub dta: Option<Ptr>,
    /// Conventional memory above the loaded program, if a program has been
    /// loaded at all. `None` is the same "no program behind it" case
    /// `psp_seg` already documents -- every unit test in this file that does
    /// not need memory management constructs a `DosState` with no arena, and
    /// `AH=48h`/`49h`/`4Ah` must fail cleanly against that rather than panic.
    pub mem: Option<Arena>,
    /// The value last set by `AH=58h` (AL=1), and reported back by AL=0.
    /// Stored so the call round-trips truthfully; nothing here reads it,
    /// because nothing here allocates any way other than first-fit -- see
    /// the `AH=58h` arm in `dispatch` for why that is not the same claim as
    /// "the strategy was honoured".
    pub alloc_strategy: u16,
}

impl Default for DosState {
    fn default() -> Self {
        Self {
            drive: 2,
            drives: 26,
            version: (5, 0),
            out: Vec::new(),
            files: None,
            psp_seg: None,
            dta: None,
            mem: None,
            alloc_strategy: 0,
        }
    }
}

/// Finish a successful call: registers back, carry clear.
fn ok<G: Guest>(g: &mut G, regs: Regs) -> Outcome {
    g.set_regs(regs);
    g.set_flag(Flag::Carry, false);
    Outcome::Continue
}

/// Finish a failed call the way DOS does: CF set, code in AX.
fn fail<G: Guest>(g: &mut G, mut regs: Regs, code: u16) -> Outcome {
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
        0x02 | 0x09 | 0x0e | 0x19 | 0x1a | 0x25 | 0x2a | 0x2b | 0x2c | 0x2d | 0x30 | 0x35 | 0x3c
            | 0x3d | 0x3e | 0x3f | 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x48 | 0x49 | 0x4a | 0x4c
            | 0x4e | 0x4f | 0x56 | 0x58 | 0x5c | 0x62 | 0x67
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
fn path_at<G: Guest>(g: &G, at: Ptr) -> Result<Vec<u8>, Fault> {
    g.read_until(at, 0, 128).map(<[u8]>::to_vec)
}

/// The Disk Transfer Address a find call should use.
///
/// Real DOS defaults the DTA to `PSP:0x80` until the program's first
/// `AH=1Ah`, and a great many programs never call `1Ah` at all because that
/// default is good enough. Isolated here the same way the `AH=25h`/`35h` IVT
/// assumption is isolated above (dos.rs:167-172): a protected-mode edge for
/// this same dispatcher is being designed and has no PSP, so it must not
/// inherit this real-mode default by silently falling through this function
/// -- it will simply have no `psp_seg` to fall back to, and `dta` will
/// correctly report `None` rather than fabricate an address.
fn dta(dos: &DosState) -> Option<Ptr> {
    dos.dta
        .or_else(|| dos.psp_seg.map(|seg| Ptr::new(seg, 0x80)))
}

/// Assemble the 43-byte record `AH=4Eh`/`4Fh` write to the DTA.
///
/// Layout -- 21 bytes reserved, 1 byte attribute, 2-byte packed time, 2-byte
/// packed date, 4-byte size, 13-byte ASCIIZ name -- is the format documented
/// for `INT 21/AH=4Eh` ("FINDFIRST using ASCIIZ") in Ralf Brown's Interrupt
/// List, at DTA offsets 00h/15h/16h/18h/1Ah/1Eh respectively.
///
/// The reserved area is real DOS's own search-continuation state (drive, an
/// FCB-style template, the attribute mask, an entry count and a directory
/// cluster), which lets `4Fh` resume a search from nothing but the DTA
/// address. This project keeps that state host-side instead
/// (`files::Files`'s private search field, keyed to the `Files` rather than
/// to a DTA address -- see its doc comment), so the reserved bytes are
/// written as zero. That is a real simplification, not a cosmetic one: two
/// concurrent searches through two different DTAs would collide here, where
/// real DOS keeps them independent. Nothing in this crate does that yet.
fn find_record(entry: &files::FindEntry) -> [u8; 43] {
    let mut r = [0u8; 43];
    r[0x15] = entry.attr;
    r[0x16..0x18].copy_from_slice(&entry.dos_time.to_le_bytes());
    r[0x18..0x1a].copy_from_slice(&entry.dos_date.to_le_bytes());
    r[0x1a..0x1e].copy_from_slice(&entry.size.to_le_bytes());
    let name = entry.name.as_bytes();
    let n = name.len().min(12); // 12 bytes of name, the 13th is the NUL
    r[0x1e..0x1e + n].copy_from_slice(&name[..n]);
    r
}

/// The DOS kernel as a service.
///
/// `DosState` stays public and separate because the runtime reports on its
/// fields at exit (`out`, and the diagnostics inside `Files`).
#[derive(Default)]
pub struct Dos {
    pub state: DosState,
}

impl<G: crate::guest::Guest> crate::service::Service<G> for Dos {
    fn claims(&self) -> &[u8] {
        &[0x21]
    }

    fn service(&mut self, _vector: u8, g: &mut G) -> crate::service::Serviced {
        use crate::service::Serviced;

        let ah = g.regs().ah();
        if !is_implemented(ah) {
            return Serviced::Unclaimed { vector: 0x21, ah };
        }
        match dispatch(g, &mut self.state) {
            Outcome::Continue => Serviced::Continue,
            Outcome::Terminate(code) => Serviced::Terminate(code),
            Outcome::Fault(f) => Serviced::Fault(f),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Service one `int 21h`.
pub fn dispatch<G: Guest>(g: &mut G, dos: &mut DosState) -> Outcome {
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

        // 1Ah -- set Disk Transfer Address to DS:DX. Required before AH=4Eh
        // is meaningful; see `dta` for what stands in for it until called.
        0x1a => {
            dos.dta = Some(regs.ds_dx());
            ok(g, regs)
        }

        // 25h -- set interrupt vector AL to DS:DX.
        //
        // In a real-mode guest the IVT *is* guest memory, so this is a plain
        // four-byte store through the seam rather than anything KVM-specific.
        // (A protected-mode edge has no IVT and would have to model one; not
        // every DOS call is as mode-agnostic as the file services.)
        0x25 => {
            let at = Ptr::new(0, u16::from(regs.al()) * 4);
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
            let at = Ptr::new(0, u16::from(regs.al()) * 4);
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

        // 43h -- get (AL=0) or set (AL=1) file attributes for DS:DX.
        //
        // This sandbox tracks no attribute bits of its own beyond what
        // `Files::stat_entry` already derives from the host file for a
        // search (`find_first`'s doc comment). AL=1 therefore stores nothing
        // and just succeeds -- the same "accepted, no effect" shape `AH=67h`
        // below has, for the same reason: a program that sets attributes
        // only to keep going must not see the call itself fail. AL=0 reuses
        // `find_first` rather than a second name-resolution path: a plain
        // (unwildcarded) name resolves to exactly the one entry a real
        // `43h` would report on, at the cost of clobbering whatever `4Eh`
        // search happens to be open -- the same shared-search simplification
        // `find_record`'s doc comment already accepts, and nothing measured
        // interleaves the two calls.
        0x43 => {
            // AL=1 (set) stores nothing and just succeeds -- see the doc
            // comment above -- so it needs neither the path nor `dos.files`,
            // and checking AL first means it can't fault on a pointer it
            // never had to read.
            if regs.al() == 1 {
                return ok(g, regs);
            }
            let path = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.find_first(&path, files::ATTR_DIRECTORY) {
                Ok(entry) => {
                    regs.cx = u16::from(entry.attr);
                    ok(g, regs)
                }
                Err(_) => fail(g, regs, files::ERR_FILE_NOT_FOUND),
            }
        }

        // 48h -- allocate BX paragraphs, answered as a segment in AX.
        0x48 => {
            let result = match dos.mem.as_mut() {
                Some(arena) => arena.alloc(regs.bx),
                // No program means no arena at all: every request is over
                // an empty pool, so the largest available is truthfully 0.
                None => Err(0),
            };
            match result {
                Ok(seg) => {
                    regs.ax = seg;
                    ok(g, regs)
                }
                Err(largest) => {
                    regs.bx = largest;
                    fail(g, regs, ERR_INSUFFICIENT_MEMORY)
                }
            }
        }

        // 49h -- free the block at ES.
        0x49 => {
            let result = match dos.mem.as_mut() {
                Some(arena) => arena.dealloc(regs.es),
                // No arena means nothing was ever handed out, so ES cannot
                // name a real block either -- the same failure `dealloc`
                // itself gives a segment it does not recognise.
                None => Err(()),
            };
            match result {
                Ok(()) => ok(g, regs),
                Err(()) => fail(g, regs, ERR_INVALID_MEMORY_BLOCK),
            }
        }

        // 4Ah -- resize the block at ES to BX paragraphs. The call a
        // Borland C startup depends on: it shrinks its own PSP-anchored
        // block before building a heap in what that shrink freed.
        0x4a => {
            let result = match dos.mem.as_mut() {
                Some(arena) => arena.resize(regs.es, regs.bx),
                None => Err(ResizeErr::NoSuchBlock),
            };
            match result {
                Ok(()) => ok(g, regs),
                Err(ResizeErr::TooSmall(largest)) => {
                    regs.bx = largest;
                    fail(g, regs, ERR_INSUFFICIENT_MEMORY)
                }
                Err(ResizeErr::NoSuchBlock) => fail(g, regs, ERR_INVALID_MEMORY_BLOCK),
            }
        }

        // 58h -- get (AL=0) or set (AL=1) the memory allocation strategy.
        //
        // Real DOS's strategy (first fit / best fit / last fit) picks which
        // free block a `48h` prefers when more than one would fit. This
        // arena has exactly one allocation policy -- `Arena::alloc`'s
        // first-fit scan -- so a program that sets a strategy is answered
        // truthfully on the round trip (AL=0 reports back whatever AL=1
        // last stored) without that value ever steering `alloc`. That is a
        // real gap, not a deliberate choice to honour first-fit specifically:
        // nothing measured so far sets anything but the default, so there is
        // no evidence yet that a second policy is worth building.
        0x58 => {
            if regs.al() == 1 {
                dos.alloc_strategy = regs.bx;
            } else {
                regs.ax = dos.alloc_strategy;
            }
            ok(g, regs)
        }

        // 67h -- set the handle count to BX. `Files` is a fixed-capacity
        // table (`MAX_HANDLES`, `files.rs`) with no per-process limit a
        // program can raise or lower, so there is nothing to store; this
        // just keeps a program that calls it from seeing a call fail that
        // real DOS would not have failed either.
        0x67 => ok(g, regs),

        // 56h -- rename DS:DX to ES:DI.
        0x56 => {
            let from = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let to = match path_at(g, Ptr::new(regs.es, regs.di)) {
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

        // 4Eh -- find first matching DS:DX, which may end in a wildcarded
        // NAME.EXT; CX is the search attribute mask. Writes the 43-byte find
        // record described at `find_record` into the DTA.
        0x4e => {
            let Some(at) = dta(dos) else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            let path = match path_at(g, regs.ds_dx()) {
                Ok(p) => p,
                Err(f) => return Outcome::Fault(f),
            };
            let attr = regs.cx as u8;
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.find_first(&path, attr) {
                Ok(entry) => {
                    let record = find_record(&entry);
                    if let Err(f) = g.write(at, &record) {
                        return Outcome::Fault(f);
                    }
                    regs.ax = 0;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 4Fh -- find next, continuing the search the last 4Eh started.
        0x4f => {
            let Some(at) = dta(dos) else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            let Some(files) = dos.files.as_mut() else {
                return fail(g, regs, ERR_INVALID_FUNCTION);
            };
            match files.find_next() {
                Ok(entry) => {
                    let record = find_record(&entry);
                    if let Err(f) = g.write(at, &record) {
                        return Outcome::Fault(f);
                    }
                    regs.ax = 0;
                    ok(g, regs)
                }
                Err(code) => fail(g, regs, code),
            }
        }

        // 62h -- get this program's PSP segment, in BX.
        //
        // Real DOS can never fail this call: some program is always running
        // when int 21h executes. This harness can construct a DosState with
        // no program loaded at all -- every other test in this file does --
        // so there is no genuine segment to report. Rather than invent one,
        // which is the exact trap this project keeps refusing to fall into,
        // this follows the precedent set throughout this file for missing
        // state (`dos.files` being `None` above) and fails the call outright.
        0x62 => match dos.psp_seg {
            Some(seg) => {
                regs.bx = seg;
                ok(g, regs)
            }
            None => fail(g, regs, ERR_INVALID_FUNCTION),
        },

        _ => fail(g, regs, ERR_INVALID_FUNCTION),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::Ptr;
    use crate::testguest::TestGuest;

    /// A guest with `text` placed at a known address, and DS:DX pointing at it.
    fn with_string(text: &[u8]) -> (TestGuest, DosState) {
        let mut g = TestGuest::new(64 * 1024);
        let at = Ptr::new(0x100, 0x20);
        g.poke(at, text);
        let mut regs = Regs::default();
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
            Outcome::Fault(Fault::Unterminated { term, .. }) => assert_eq!(term, b'$'),
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
        let mut regs = Regs::default();
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
        let mut regs = Regs::default();
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
        let mut regs = Regs::default();
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
        let mut regs = Regs::default();
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
        let mut regs = Regs::default();
        regs.ax = 0x4c00 | 3;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Terminate(3));
    }

    #[test]
    fn a_pointer_past_the_end_of_memory_faults() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = Regs::default();
        regs.set_ah(0x40);
        regs.bx = 1;
        regs.cx = 16;
        regs.ds = 0xf000;
        regs.dx = 0xfff0;
        g.call_with(regs);

        match dispatch(&mut g, &mut dos) {
            Outcome::Fault(Fault::OutOfBounds { .. }) => {}
            other => panic!("expected OutOfBounds, got {other:?}"),
        }
    }

    // -- AH=62h: get PSP address --

    #[test]
    fn get_psp_reports_the_loaded_segment_not_a_constant() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState {
            psp_seg: Some(0x1234),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x62);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(g.regs().bx, 0x1234);
    }

    #[test]
    fn get_psp_without_a_loaded_program_fails_rather_than_inventing_a_segment() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = Regs::default();
        regs.set_ah(0x62);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry(), "no program means no real segment to report");
        assert_eq!(g.regs().ax, ERR_INVALID_FUNCTION);
    }

    // -- AH=1Ah: set DTA, and the AH=25h/35h-style default it feeds --

    #[test]
    fn set_dta_stores_the_far_pointer_from_ds_dx() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();
        let mut regs = Regs::default();
        regs.set_ah(0x1a);
        regs.ds = 0x2000;
        regs.dx = 0x0080;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(dos.dta, Some(Ptr::new(0x2000, 0x0080)));
    }

    #[test]
    fn dta_defaults_to_psp_plus_0x80_before_ah_1a_is_ever_called() {
        let dos = DosState {
            psp_seg: Some(0x1000),
            ..DosState::default()
        };
        assert_eq!(dta(&dos), Some(Ptr::new(0x1000, 0x80)));
    }

    #[test]
    fn dta_is_none_with_neither_an_explicit_set_nor_a_psp() {
        assert_eq!(dta(&DosState::default()), None);
    }

    #[test]
    fn an_explicit_dta_wins_over_the_psp_default() {
        let dos = DosState {
            psp_seg: Some(0x1000),
            dta: Some(Ptr::new(0x9999, 0x0001)),
            ..DosState::default()
        };
        assert_eq!(dta(&dos), Some(Ptr::new(0x9999, 0x0001)));
    }

    // -- AH=4Eh/4Fh: find first/next, driven through dispatch end to end --

    /// A `Files` sandboxed at a scratch directory under the repo's gitignored
    /// `tmp/`, mirroring `files.rs`'s own test helper.
    fn with_files(name: &str) -> (std::path::PathBuf, Files) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/dos-poc-tests")
            .join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch dir");
        let fd = std::fs::File::open(&root).expect("open root");
        let files = Files::new(fd.into(), root.clone());
        (root, files)
    }

    #[test]
    fn find_first_writes_the_43_byte_record_with_the_documented_layout() {
        let (root, fs) = with_files("dos_find_layout");
        std::fs::write(root.join("LORD.DAT"), vec![0u8; 10]).expect("seed");

        let mut g = TestGuest::new(64 * 1024);
        let path_at = Ptr::new(0x100, 0x20);
        g.poke(path_at, b"LORD.DAT\0");
        let dta_at = Ptr::new(0x100, 0x200);
        // A guard byte just past the record, so a write one byte too long
        // would be caught rather than silently landing in unused memory.
        g.poke(Ptr::new(0x100, 0x200 + 43), &[0xaa]);

        let mut dos = DosState {
            files: Some(fs),
            dta: Some(dta_at),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x4e);
        regs.ds = path_at.seg;
        regs.dx = path_at.off;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());

        let record = g.peek(dta_at, 43);
        assert_eq!(&record[0..0x15], &[0u8; 21], "the reserved area is left zero");
        assert_eq!(record[0x15], files::ATTR_ARCHIVE, "attribute at offset 0x15");
        let size = u32::from_le_bytes(record[0x1a..0x1e].try_into().unwrap());
        assert_eq!(size, 10, "size at offset 0x1a");
        let name_end = record[0x1e..].iter().position(|&b| b == 0).expect("ASCIIZ");
        assert_eq!(&record[0x1e..0x1e + name_end], b"LORD.DAT", "name at offset 0x1e");

        assert_eq!(
            g.peek(Ptr::new(0x100, 0x200 + 43), 1),
            &[0xaa],
            "the record is exactly 43 bytes, not one more"
        );
    }

    #[test]
    fn find_next_via_dispatch_continues_the_same_search_in_order() {
        let (root, fs) = with_files("dos_find_next");
        std::fs::write(root.join("A.DAT"), vec![0u8; 1]).expect("seed");
        std::fs::write(root.join("B.DAT"), vec![0u8; 2]).expect("seed");

        let mut g = TestGuest::new(64 * 1024);
        let path_at = Ptr::new(0x100, 0x20);
        g.poke(path_at, b"*.DAT\0");
        let dta_at = Ptr::new(0x100, 0x200);

        let mut dos = DosState {
            files: Some(fs),
            dta: Some(dta_at),
            ..DosState::default()
        };

        let mut first_call = Regs::default();
        first_call.set_ah(0x4e);
        first_call.ds = path_at.seg;
        first_call.dx = path_at.off;
        g.call_with(first_call);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        let name_of = |g: &TestGuest| {
            let record = g.peek(dta_at, 43);
            let end = record[0x1e..].iter().position(|&b| b == 0).expect("ASCIIZ");
            record[0x1e..0x1e + end].to_vec()
        };
        let first = name_of(&g);

        let mut next_call = Regs::default();
        next_call.set_ah(0x4f);
        g.call_with(next_call);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        let second = name_of(&g);

        assert_eq!(first, b"A.DAT");
        assert_eq!(second, b"B.DAT");

        let mut third_call = Regs::default();
        third_call.set_ah(0x4f);
        g.call_with(third_call);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry(), "a third find-next has nothing left to report");
        assert_eq!(g.regs().ax, files::ERR_NO_MORE_FILES);
    }

    #[test]
    fn find_first_without_a_dta_fails_rather_than_guessing_one() {
        let (_root, fs) = with_files("dos_find_no_dta");
        let mut g = TestGuest::new(4096);
        let mut dos = DosState {
            files: Some(fs),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x4e);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INVALID_FUNCTION);
    }

    #[test]
    fn find_first_without_a_filesystem_fails() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState {
            psp_seg: Some(0x1000), // so the DTA default resolves
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x4e);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INVALID_FUNCTION);
    }

    // -- AH=48h/49h/4Ah: memory management, the reason WCCMMUTL.EXE stalls
    // before this task and gets past its own startup after it. --

    /// A fresh arena, matching what the loader builds for a program 16
    /// paragraphs long (`Arena::new`'s own PSP-plus-image accounting):
    /// owner block `[0x1000, 0x1010)`, everything else up to `CONV_TOP`
    /// free. Distinct owner/free boundaries, rather than round numbers, so a
    /// test asserting on an exact address cannot pass by coincidentally
    /// matching a boundary that happens to be zero.
    fn with_arena() -> DosState {
        DosState {
            psp_seg: Some(0x1000),
            mem: Some(Arena::new(0x1000, 0x1010)),
            ..DosState::default()
        }
    }

    fn call_ah(g: &mut TestGuest, ah: u8, es: u16, bx: u16, al: u8) {
        let mut regs = Regs::default();
        regs.set_ah(ah);
        regs.set_al(al);
        regs.es = es;
        regs.bx = bx;
        g.call_with(regs);
    }

    #[test]
    fn allocate_returns_a_usable_segment_and_two_allocations_do_not_overlap() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x48, 0, 4, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        let first = g.regs().ax;
        assert_eq!(first, 0x1010, "the first block comes from the arena's own start");

        call_ah(&mut g, 0x48, 0, 6, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        let second = g.regs().ax;
        assert!(
            second >= first + 4,
            "second allocation ({second:#06x}) must start at or past the first's end ({:#06x})",
            first + 4
        );
    }

    #[test]
    fn allocate_more_than_the_arena_holds_fails_with_the_exact_largest_size() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x48, 0, 0x9000, 0); // far more than the ~0x8ff0 free
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INSUFFICIENT_MEMORY);
        assert_eq!(
            g.regs().bx,
            0xa000 - 0x1010,
            "BX must be the exact largest block, not merely non-zero"
        );
    }

    #[test]
    fn free_then_allocate_the_same_size_reuses_the_space() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x48, 0, 10, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        let seg = g.regs().ax;

        call_ah(&mut g, 0x49, seg, 0, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry(), "freeing a block this arena owns must succeed");

        call_ah(&mut g, 0x48, 0, 10, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(g.regs().ax, seg, "a leaking free would hand out different memory instead");
    }

    #[test]
    fn free_of_a_segment_never_allocated_fails() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x49, 0x2000, 0, 0); // never returned by any 48h
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INVALID_MEMORY_BLOCK);
    }

    #[test]
    fn resize_down_then_allocate_succeeds_in_the_freed_tail() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        // Shrink the owner's own block from 0x10 paragraphs to 4 -- the
        // Borland startup's own move, freeing 0x1004..0x1010.
        call_ah(&mut g, 0x4a, 0x1000, 4, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());

        call_ah(&mut g, 0x48, 0, 8, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(
            g.regs().ax,
            0x1004,
            "must land in the tail the resize just freed, not the untouched arena beyond it"
        );
    }

    #[test]
    fn resize_up_beyond_the_arena_fails_with_a_truthful_largest_size() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x4a, 0x1000, 0xffff, 0); // far more than conventional memory holds
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INSUFFICIENT_MEMORY);
        assert_eq!(
            g.regs().bx,
            0xa000 - 0x1000,
            "the largest this block could grow to in place is the whole span up to CONV_TOP"
        );
    }

    #[test]
    fn resize_of_a_segment_never_allocated_fails_with_invalid_memory_block() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x4a, 0x2000, 4, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INVALID_MEMORY_BLOCK);
    }

    #[test]
    fn allocate_with_no_program_loaded_fails_cleanly_rather_than_panicking() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default(); // mem: None, exactly like every other test in this file

        call_ah(&mut g, 0x48, 0, 10, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, ERR_INSUFFICIENT_MEMORY);
        assert_eq!(g.regs().bx, 0, "an empty arena has nothing to offer as a retry size");
    }

    #[test]
    fn zero_size_allocation_does_not_alias_a_later_real_allocation() {
        // Reproduces the review finding verbatim: alloc(0) then alloc(0x20)
        // both returning the identical segment, so freeing the phantom
        // block frees memory a third caller still legitimately owns.
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x48, 0, 0, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry(), "a zero-paragraph request is a real, if minimal, allocation");
        let phantom = g.regs().ax;

        call_ah(&mut g, 0x48, 0, 0x20, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        let real = g.regs().ax;
        assert_ne!(
            phantom, real,
            "a zero-size allocation must not alias the segment a later real one returns"
        );

        // Freeing the zero-size block must free only its own paragraph, not
        // reach into the real block a different caller still owns.
        call_ah(&mut g, 0x49, phantom, 0, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());

        call_ah(&mut g, 0x48, 0, 0x10, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        let third = g.regs().ax;
        assert!(
            third >= real + 0x20 || third + 0x10 <= real,
            "third allocation ({third:#06x}) must not overlap the still-live \
             real block at {real:#06x}..+0x20"
        );
    }

    #[test]
    fn resize_down_to_zero_keeps_the_segment_from_aliasing_a_later_allocation() {
        let mut g = TestGuest::new(4096);
        let mut dos = with_arena();

        call_ah(&mut g, 0x48, 0, 8, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        let seg = g.regs().ax;

        call_ah(&mut g, 0x4a, seg, 0, 0); // shrink to zero paragraphs
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());

        call_ah(&mut g, 0x48, 0, 8, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        let other = g.regs().ax;
        assert_ne!(
            seg, other,
            "the block shrunk to zero still owns `seg` (ES still names it); \
             a new allocation must not reuse the identical segment"
        );
    }

    // -- AH=58h/67h: allocation strategy and handle count, both no-ops that
    // must simply not fail. --

    #[test]
    fn get_set_allocation_strategy_round_trips_through_state() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();

        call_ah(&mut g, 0x58, 0, 2, 1); // AL=1 set, BX=2 (DOS's own "last fit" code)
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(dos.alloc_strategy, 2);

        call_ah(&mut g, 0x58, 0, 0, 0); // AL=0 get
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(g.regs().ax, 2, "must report what was actually set, not a constant");
    }

    #[test]
    fn set_handle_count_always_succeeds() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState::default();

        call_ah(&mut g, 0x67, 0, 40, 0);
        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
    }

    // -- AH=43h: get/set file attributes --

    #[test]
    fn get_file_attributes_reports_the_real_entry() {
        let (root, fs) = with_files("dos_attr_get");
        std::fs::write(root.join("LORD.DAT"), vec![0u8; 1]).expect("seed");

        let mut g = TestGuest::new(64 * 1024);
        let path_at = Ptr::new(0x100, 0x20);
        g.poke(path_at, b"LORD.DAT\0");
        let mut dos = DosState {
            files: Some(fs),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x43);
        regs.set_al(0);
        regs.ds = path_at.seg;
        regs.dx = path_at.off;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
        assert_eq!(g.regs().cx, u16::from(files::ATTR_ARCHIVE));
    }

    #[test]
    fn get_file_attributes_of_a_missing_file_fails_with_file_not_found() {
        let (_root, fs) = with_files("dos_attr_missing");

        let mut g = TestGuest::new(64 * 1024);
        let path_at = Ptr::new(0x100, 0x20);
        g.poke(path_at, b"NOPE.DAT\0");
        let mut dos = DosState {
            files: Some(fs),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x43);
        regs.set_al(0);
        regs.ds = path_at.seg;
        regs.dx = path_at.off;
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(g.carry());
        assert_eq!(g.regs().ax, files::ERR_FILE_NOT_FOUND);
    }

    #[test]
    fn set_file_attributes_is_accepted_without_a_filesystem_read() {
        let mut g = TestGuest::new(4096);
        let mut dos = DosState {
            files: Some(with_files("dos_attr_set").1),
            ..DosState::default()
        };
        let mut regs = Regs::default();
        regs.set_ah(0x43);
        regs.set_al(1);
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
    }

    #[test]
    fn set_file_attributes_needs_neither_a_filesystem_nor_a_valid_pointer() {
        // AL=1 stores nothing (see the arm's own doc comment), so it must
        // succeed even with no filesystem behind `dos` and a DS:DX that
        // resolves outside the guest's memory -- proof that AL is checked
        // before the path is ever read, not after.
        let mut g = TestGuest::new(64);
        let mut dos = DosState::default(); // files: None
        let mut regs = Regs::default();
        regs.set_ah(0x43);
        regs.set_al(1);
        regs.ds = 0xffff;
        regs.dx = 0xffff; // linear address far past the 64-byte guest
        g.call_with(regs);

        assert_eq!(dispatch(&mut g, &mut dos), Outcome::Continue);
        assert!(!g.carry());
    }
}
