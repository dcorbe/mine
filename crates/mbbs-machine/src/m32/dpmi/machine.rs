//! The DPMI execution machine: run a flat 32-bit guest until it asks the host
//! for something.
//!
//! Reuses m32's crossing wholesale -- `Mapping`, `asm::enter`, the shared
//! fault arbiter -- and adds nothing to the entry path. A DPMI guest needs no
//! trampoline and no thunk table: it runs until a privileged instruction
//! faults, and the fault arm (`super::fault`) turns that into a structured
//! [`Exit`] (or resumes it in place, for `cli`/`sti`). That is the whole
//! machine.

use std::io;

use crate::m32::Mapping;
use crate::m32::asm::{self, Ctx, USER32_CS, current_cs};

/// Why a [`Machine::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The guest executed `int vector`. `eip` is the address of the `int`
    /// instruction; the guest resumes at `eip + 2` once the host has serviced
    /// it (advance with [`Machine::set_eip`], optionally after
    /// [`Machine::set_eax`]).
    Service { vector: u8, eip: u32 },

    /// The guest faulted for real -- a wild jump, a bad access, an instruction
    /// this ABI does not service. Nothing is resumable. `eip` is linear.
    Fault { signo: i32, eip: u32 },
}

/// The guest register file as a serviced trap sees it -- captured at the
/// faulting instruction. `ecx` is present here (unlike `crate::m32::Regs`)
/// because a DOS `int 21h` carries its byte count in `ECX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Regs32 {
    pub eip: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
}

/// A flat 32-bit guest and the crossing state it is entered through.
pub struct Machine {
    mapping: Mapping,
    ctx: Ctx,
}

impl Machine {
    /// A guest with a `len`-byte flat mapping, its fault recovery armed on
    /// this thread. `int` faults become [`Exit::Service`]; interrupts start
    /// enabled (`vif = 1`), as a DOS/4GW guest expects once the extender's
    /// startup `sti` has run.
    pub fn new(len: usize) -> io::Result<Self> {
        let mapping = Mapping::new(len)?;
        crate::m32::fault::arm(current_cs())?;
        let base = mapping.base() as usize as u64;
        let ctx = Ctx {
            target_selector: USER32_CS,
            dpmi: 1,
            vif: 1,
            code_lo: base,
            code_hi: base + len as u64,
            ..Default::default()
        };
        Ok(Self { mapping, ctx })
    }

    /// Wrap a mapping the LE loader has already populated, entering at the
    /// image's own entry point. `code_lo`/`code_hi` span the whole mapping, so
    /// the fault arm can read instruction bytes anywhere in it.
    pub fn adopt(mapping: Mapping, entry_eip: u32, entry_esp: u32) -> io::Result<Self> {
        crate::m32::fault::arm(current_cs())?;
        let base = mapping.base() as usize as u64;
        let len = mapping.len() as u64;
        let ctx = Ctx {
            target_offset: entry_eip,
            target_selector: USER32_CS,
            esp: entry_esp,
            dpmi: 1,
            vif: 1,
            code_lo: base,
            code_hi: base + len,
            ..Default::default()
        };
        Ok(Self { mapping, ctx })
    }

    /// The linear base of the guest mapping -- where to write code and the
    /// address to enter at.
    pub fn base(&self) -> u32 {
        self.mapping.base() as usize as u32
    }

    /// The guest mapping, to load code and data into.
    pub fn mem(&mut self) -> &mut [u8] {
        self.mapping.as_mut_slice()
    }

    /// Set both the entry `EIP` and the stack pointer (linear addresses).
    pub fn set_entry(&mut self, eip: u32, esp: u32) {
        self.ctx.target_offset = eip;
        self.ctx.esp = esp;
    }

    /// Point the next [`Machine::run`] at `eip` -- the usual way to step past a
    /// serviced `int` is `set_eip(service_eip + 2)`.
    pub fn set_eip(&mut self, eip: u32) {
        self.ctx.target_offset = eip;
    }

    /// Set `EAX` for the next entry -- how a serviced `int 21h` hands its
    /// result back to the guest.
    pub fn set_eax(&mut self, eax: u32) {
        self.ctx.eax = eax;
    }

    /// The guest's virtual interrupt-enable flag, as `cli`/`sti` have left it.
    pub fn interrupts_enabled(&self) -> bool {
        self.ctx.vif != 0
    }

    /// The guest register file captured at the last service/port trap.
    /// `ECX`/`EDX` carry `int 21h` counts and flat buffer pointers.
    pub fn regs32(&self) -> Regs32 {
        Regs32 {
            eip: self.ctx.out_eip,
            eax: self.ctx.out_eax,
            ebx: self.ctx.out_ebx,
            ecx: self.ctx.out_ecx,
            edx: self.ctx.out_edx,
            esi: self.ctx.out_esi,
            edi: self.ctx.out_edi,
        }
    }

    /// Read `len` bytes of guest memory at flat linear address `at`, or `None`
    /// if the range is not entirely within the mapping. Guest pointers are
    /// host linear addresses in the flat model, but a service must never
    /// dereference one unchecked.
    pub fn read_mem(&self, at: u32, len: usize) -> Option<&[u8]> {
        let base = self.base();
        let off = at.checked_sub(base)? as usize;
        self.mapping.as_slice().get(off..off.checked_add(len)?)
    }

    /// Write `src` into guest memory at flat linear address `at`; `false` if
    /// the range is not entirely within the mapping.
    pub fn write_mem(&mut self, at: u32, src: &[u8]) -> bool {
        let base = self.base();
        let Some(off) = at.checked_sub(base).map(|o| o as usize) else {
            return false;
        };
        let Some(end) = off.checked_add(src.len()) else {
            return false;
        };
        match self.mapping.as_mut_slice().get_mut(off..end) {
            Some(dst) => {
                dst.copy_from_slice(src);
                true
            }
            None => false,
        }
    }

    /// Enter the guest and run until it faults. On a [`Exit::Service`] the
    /// guest's registers are folded forward so a resume continues where it
    /// left off; the caller advances `EIP` (and may [`Machine::set_eax`])
    /// before calling `run` again.
    pub fn run(&mut self) -> io::Result<Exit> {
        self.ctx.out_kind = 0;
        self.ctx.out_signo = 0;
        // SAFETY: `target_offset`/`esp` address the guest `mapping`, which is
        // read/write/execute and lives (owned by `self`) across the call.
        unsafe { asm::enter(&mut self.ctx) };

        // Carry the guest's register file forward. On a fault these were
        // captured too, and folding them is harmless (the machine is spent).
        self.ctx.eax = self.ctx.out_eax;
        self.ctx.edx = self.ctx.out_edx;
        self.ctx.ebx = self.ctx.out_ebx;
        self.ctx.esi = self.ctx.out_esi;
        self.ctx.edi = self.ctx.out_edi;
        self.ctx.ebp = self.ctx.out_ebp;
        self.ctx.esp = self.ctx.out_esp;

        Ok(match self.ctx.out_kind {
            1 => Exit::Service {
                vector: self.ctx.out_vector as u8,
                eip: self.ctx.out_eip,
            },
            _ => Exit::Fault {
                signo: self.ctx.out_signo as i32,
                eip: self.ctx.out_eip,
            },
        })
    }
}
