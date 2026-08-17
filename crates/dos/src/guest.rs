//! The seam: everything a DOS call needs from whatever is executing the program.
//!
//! The whole point of this module is what it does *not* mention. There is no
//! `ucontext`, no vCPU, no LDT and no signal here. A DOS service reads some
//! registers, follows a far pointer into memory, writes some registers back,
//! and reports success or failure. Those four things are the entire contract,
//! and both trap edges can satisfy them -- see `docs/2026-08-16-dos-trap-edges.md`.

/// A DOS far pointer, which is how every INT 21h argument that is not a scalar
/// arrives.
///
/// Deliberately *not* a linear address: resolving `seg` is the one thing the
/// two edges genuinely disagree about (an LDT descriptor base under a signal,
/// `seg << 4` under real mode), so the disagreement stays on their side of the
/// trait rather than leaking into every call that takes a pointer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ptr {
    pub seg: u16,
    pub off: u16,
}

impl Ptr {
    pub fn new(seg: u16, off: u16) -> Self {
        Self { seg, off }
    }
}

/// The register file as a DOS call sees it.
///
/// `ds` and `es` are members because DOS argument conventions are built on
/// them (`DS:DX` for paths and strings, `ES:BX` for buffers). That they are
/// awkward to obtain on one of the two edges is that edge's problem: on
/// x86-64 `struct sigcontext_64` carries no `ds`/`es` at all, and a handler
/// has to recover them by reading its own live registers.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Regs {
    pub ax: u16,
    pub bx: u16,
    pub cx: u16,
    pub dx: u16,
    pub si: u16,
    pub di: u16,
    pub ds: u16,
    pub es: u16,
}

impl Regs {
    /// The function number. Every dispatch decision starts here.
    pub fn ah(&self) -> u8 {
        (self.ax >> 8) as u8
    }

    pub fn al(&self) -> u8 {
        (self.ax & 0xff) as u8
    }

    pub fn set_ah(&mut self, v: u8) {
        self.ax = (self.ax & 0x00ff) | ((v as u16) << 8);
    }

    pub fn set_al(&mut self, v: u8) {
        self.ax = (self.ax & 0xff00) | v as u16;
    }

    pub fn dl(&self) -> u8 {
        (self.dx & 0xff) as u8
    }

    /// `DS:DX` -- the argument convention of nearly every pointer-taking call.
    pub fn ds_dx(&self) -> Ptr {
        Ptr::new(self.ds, self.dx)
    }
}

/// Why a guest memory access could not be served.
///
/// A fault is *not* a DOS error code. It means the program handed over a
/// pointer that does not name memory, which under real DOS would have silently
/// read something else. Surfacing it is the point: a runtime crash beats
/// undefined behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The span starting at `at` leaves the address space.
    OutOfBounds { at: Ptr, len: usize },
    /// A terminated string ran `max` bytes without its terminator.
    Unterminated { at: Ptr, term: u8, max: usize },
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::OutOfBounds { at, len } => {
                write!(f, "{:04x}:{:04x}+{len} leaves the address space", at.seg, at.off)
            }
            Fault::Unterminated { at, term, max } => write!(
                f,
                "{:04x}:{:04x}: no {term:#04x} terminator within {max} bytes",
                at.seg, at.off
            ),
        }
    }
}

/// So `Fault` can be `btrieve::mem::Mem::Error` -- a `Mem` implementor over
/// guest memory has nothing to report a bad pointer with *except* the fault
/// this trait already defines, and the engine only ever renders it with
/// `to_string`.
impl std::error::Error for Fault {}

/// What a DOS call needs from whatever is executing the program.
pub trait Guest {
    /// `len` bytes at `at`.
    fn read(&self, at: Ptr, len: usize) -> Result<&[u8], Fault>;

    /// Bytes from `at` up to but excluding the first `term`.
    ///
    /// One method rather than two because DOS terminates strings two different
    /// ways -- NUL for ASCIIZ paths, `$` for `AH=09` -- and the only thing that
    /// differs is the byte.
    fn read_until(&self, at: Ptr, term: u8, max: usize) -> Result<&[u8], Fault>;

    fn write(&mut self, at: Ptr, bytes: &[u8]) -> Result<(), Fault>;

    fn regs(&self) -> Regs;

    fn set_regs(&mut self, regs: Regs);

    /// Set a status flag the caller will read.
    ///
    /// Separate from [`Guest::set_regs`] precisely because the two edges
    /// write flags to different places: the live `EFLAGS` in a signal context,
    /// which `sigreturn` restores, versus the `FLAGS` image already pushed on
    /// the guest stack, which `iret` will pop. Writing to the live flags under
    /// `iret` is the classic bug -- every error return evaporates silently.
    fn set_flag(&mut self, flag: Flag, on: bool);
}

/// A status bit a call answers through rather than through a register.
///
/// This began as `set_carry` alone, which was wrong: `int 16h AH=01` reports
/// "no key waiting" in ZF, and with only carry available the service had to
/// claim a key was always ready -- which livelocks any program that polls the
/// keyboard. One call needing a second flag is the argument for naming the
/// flag rather than the operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flag {
    Carry,
    Zero,
}

impl Flag {
    /// Bit position in the x86 FLAGS word.
    pub fn bit(self) -> u16 {
        match self {
            Flag::Carry => 1 << 0,
            Flag::Zero => 1 << 6,
        }
    }
}
