//! The third implementor: a guest made of a byte array and a register struct.
//!
//! This is the argument for the seam that does not depend on KVM existing.
//! With it, every DOS service is ordinary unit-testable Rust -- no machine, no
//! signal, no vCPU, no fixture. Written inline against `gregs` instead, the
//! same logic is testable only by faulting a real module, which in practice
//! means it is not tested at all.

use crate::guest::{DosFault, DosGuest, DosPtr, DosRegs};

/// A flat address space and a register file, and nothing else.
pub struct TestGuest {
    mem: Vec<u8>,
    regs: DosRegs,
    carry: bool,
}

impl TestGuest {
    /// A guest with `size` bytes of memory, all zero.
    pub fn new(size: usize) -> Self {
        Self {
            mem: vec![0; size],
            regs: DosRegs::default(),
            carry: false,
        }
    }

    /// Real-mode resolution, which is also the simplest thing that can work.
    fn linear(&self, at: DosPtr) -> usize {
        at.seg as usize * 16 + at.off as usize
    }

    /// Place `bytes` at `at`, so a test can set up an argument.
    pub fn poke(&mut self, at: DosPtr, bytes: &[u8]) {
        let base = self.linear(at);
        self.mem[base..base + bytes.len()].copy_from_slice(bytes);
    }

    /// Read back, so a test can check an output buffer.
    pub fn peek(&self, at: DosPtr, len: usize) -> &[u8] {
        let base = self.linear(at);
        &self.mem[base..base + len]
    }

    /// Set up the call: this is what the program would have had in registers
    /// at the moment it executed `int 21h`.
    pub fn call_with(&mut self, regs: DosRegs) {
        self.regs = regs;
        self.carry = false;
    }

    /// Did the service report failure?
    pub fn carry(&self) -> bool {
        self.carry
    }
}

impl DosGuest for TestGuest {
    fn read(&self, at: DosPtr, len: usize) -> Result<&[u8], DosFault> {
        let base = self.linear(at);
        self.mem
            .get(base..base.saturating_add(len))
            .ok_or(DosFault::OutOfBounds { at, len })
    }

    fn read_until(&self, at: DosPtr, term: u8, max: usize) -> Result<&[u8], DosFault> {
        let base = self.linear(at);
        let tail = self
            .mem
            .get(base..)
            .ok_or(DosFault::OutOfBounds { at, len: 0 })?;
        let limit = max.min(tail.len());
        match tail[..limit].iter().position(|&b| b == term) {
            Some(n) => Ok(&tail[..n]),
            None => Err(DosFault::Unterminated { at, term, max }),
        }
    }

    fn write(&mut self, at: DosPtr, bytes: &[u8]) -> Result<(), DosFault> {
        let base = self.linear(at);
        let end = base.saturating_add(bytes.len());
        let slot = self
            .mem
            .get_mut(base..end)
            .ok_or(DosFault::OutOfBounds {
                at,
                len: bytes.len(),
            })?;
        slot.copy_from_slice(bytes);
        Ok(())
    }

    fn regs(&self) -> DosRegs {
        self.regs
    }

    fn set_regs(&mut self, regs: DosRegs) {
        self.regs = regs;
    }

    fn set_carry(&mut self, on: bool) {
        self.carry = on;
    }
}
