//! The `dos` kernel's view of a 16-bit machine.
//!
//! A `dos_kernel::guest::Ptr` here is a **selector**:offset -- the module runs
//! in protected mode and its far pointers name LDT entries -- never
//! `seg << 4`. Every access goes through the machine's own selector check.

use dos_kernel::guest::{Fault, Flag, Guest, Ptr, Regs};
use mbbs_machine::m16::{FarPtr, Machine};

pub struct Guest16<'a> {
    cpu: &'a mut Machine,
    regs: Regs,
}

impl<'a> Guest16<'a> {
    /// A guest whose register file is the machine's at this moment.
    pub fn new(cpu: &'a mut Machine) -> Self {
        let r = cpu.regs();
        let regs = Regs {
            ax: r.ax,
            bx: r.bx,
            cx: r.cx,
            dx: r.dx,
            si: r.si,
            di: r.di,
            ds: r.ds,
            es: 0,
        };
        Self { cpu, regs }
    }
}

fn far(at: Ptr) -> FarPtr {
    FarPtr { selector: at.seg, offset: at.off }
}

fn out_of_bounds(at: Ptr, len: usize) -> Fault {
    Fault::OutOfBounds { at, len }
}

impl Guest for Guest16<'_> {
    fn read(&self, at: Ptr, len: usize) -> Result<&[u8], Fault> {
        self.cpu.read(far(at), len).map_err(|_| out_of_bounds(at, len))
    }

    fn read_until(&self, at: Ptr, term: u8, max: usize) -> Result<&[u8], Fault> {
        // `read_cstr` is NUL-only and unbounded; DOS also terminates with `$`.
        // Read the largest span the segment allows, then scan.
        let mut len = max;
        let tail = loop {
            match self.cpu.read(far(at), len) {
                Ok(t) => break t,
                Err(_) if len > 1 => len /= 2,
                Err(_) => return Err(out_of_bounds(at, 1)),
            }
        };
        match tail.iter().position(|&b| b == term) {
            Some(n) => Ok(&tail[..n]),
            None if len < max => Err(out_of_bounds(at, len + 1)),
            None => Err(Fault::Unterminated { at, term, max }),
        }
    }

    fn write(&mut self, at: Ptr, bytes: &[u8]) -> Result<(), Fault> {
        self.cpu.write(far(at), bytes).map_err(|_| out_of_bounds(at, bytes.len()))
    }

    fn regs(&self) -> Regs {
        self.regs
    }

    fn set_regs(&mut self, regs: Regs) {
        self.regs = regs;
        self.cpu.set_ax(regs.ax);
        self.cpu.set_bx(regs.bx);
        self.cpu.set_cx(regs.cx);
        self.cpu.set_dx(regs.dx);
        self.cpu.set_si(regs.si);
        self.cpu.set_di(regs.di);
        self.cpu.set_ds(regs.ds);
        // `ES` is not part of the 16-bit crossing (`m16::Regs` has none):
        // `2Fh` answers through it and that answer is lost here. Acceptable
        // for the callers this edge exists for; a module that reads `ES`
        // after `2Fh` gets whatever it had, which is what `m16::Regs`
        // documents.
    }

    fn set_flag(&mut self, flag: Flag, on: bool) {
        match flag {
            Flag::Carry => self.cpu.set_carry(on),
            Flag::Zero => panic!("no int 21h service answers through ZF; a guest asked for it"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine::new().expect("16-bit machine")
    }

    fn far(ptr: FarPtr) -> Ptr {
        Ptr::new(ptr.selector, ptr.offset)
    }

    #[test]
    fn reads_and_writes_go_through_the_selector() {
        let mut cpu = machine();
        let at = FarPtr { selector: cpu.data_selector(), offset: 0x20 };
        cpu.write(at, b"abc\0").expect("fits");
        let mut g = Guest16::new(&mut cpu);
        assert_eq!(g.read(far(at), 3).expect("in bounds"), b"abc");
        assert_eq!(g.read_until(far(at), 0, 16).expect("terminated"), b"abc");
        g.write(far(at), b"xyz").expect("fits");
        assert_eq!(g.read(far(at), 4).expect("in bounds"), b"xyz\0");
        let bad = Ptr::new(0x0003, 0); // no LDT entry
        assert!(matches!(g.read(bad, 1), Err(Fault::OutOfBounds { .. })));
    }

    #[test]
    fn registers_round_trip_and_the_carry_reaches_the_machine() {
        let mut cpu = machine();
        cpu.set_ax(0x1900);
        cpu.set_dx(0x0005);
        let mut g = Guest16::new(&mut cpu);
        assert_eq!(g.regs().ah(), 0x19);
        assert_eq!(g.regs().dl(), 5);
        let mut regs = g.regs();
        regs.set_al(2);
        regs.bx = 0x1234;
        g.set_regs(regs);
        g.set_flag(Flag::Carry, true);
        assert_eq!(cpu.regs().ax, 0x1902);
        assert_eq!(cpu.regs().bx, 0x1234);
        assert!(cpu.carry());
    }
}

