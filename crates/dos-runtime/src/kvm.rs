//! Edge B: a real-mode guest on a KVM vCPU.
//!
//! Not a trampoline and not a mode switch. This process stays in 64-bit long
//! mode from start to finish; the guest is a *separate* CPU that is in real
//! mode permanently. `KVM_RUN` is an ordinary blocking syscall that runs guest
//! instructions natively on the core and returns when the guest asks a
//! question. The two machines meet only through an `mmap` (the guest's
//! physical memory) and a register file.
//!
//! Measured cost of one round trip on this box: 3.33 us -- see
//! `re/spikes/kvm_realmode.c`, from which this is grown.

use std::collections::BTreeMap;
use std::io;

use crate::guest::{Fault, Guest, Ptr, Regs, Flag};

/// The port our trap stubs write to. Any unclaimed port works; the value is
/// arbitrary and only has to agree with the stub bytes.
pub const TRAP_PORT: u16 = 0xe6;

/// `out TRAP_PORT, al` then `iret`.
///
/// `out` rather than `hlt` because `hlt` is only guaranteed to exit to
/// userspace when there is no in-kernel irqchip, whereas an unclaimed port is
/// unconditional. `al` is written to a port whose data we discard, so the stub
/// clobbers no guest register at all.
/// Four bytes per vector, not three, so that the vector a trap came from is
/// `(rip - 2) / STUB_STRIDE` -- the disambiguation-by-address the design note
/// describes, made into arithmetic instead of a lookup.
const STUB: [u8; 4] = [0xe6, TRAP_PORT as u8, 0xcf, 0x90];
const STUB_STRIDE: u16 = 4;

const KVM_GET_API_VERSION: libc::c_ulong = 0xae00;
const KVM_CREATE_VM: libc::c_ulong = 0xae01;
const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0xae04;
const KVM_CREATE_VCPU: libc::c_ulong = 0xae41;
const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x4020_ae46;
const KVM_RUN: libc::c_ulong = 0xae80;
const KVM_GET_REGS: libc::c_ulong = 0x8090_ae81;
const KVM_SET_REGS: libc::c_ulong = 0x4090_ae82;
const KVM_GET_SREGS: libc::c_ulong = 0x8138_ae83;
const KVM_SET_SREGS: libc::c_ulong = 0x4138_ae84;

const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_HLT: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmRegs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmSegment {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmDtable {
    base: u64,
    limit: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmSregs {
    cs: KvmSegment,
    ds: KvmSegment,
    es: KvmSegment,
    fs: KvmSegment,
    gs: KvmSegment,
    ss: KvmSegment,
    tr: KvmSegment,
    ldt: KvmSegment,
    gdt: KvmDtable,
    idt: KvmDtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

/// The head of `struct kvm_run`, up to and including the `io` arm of its union.
/// Only the fields this needs are named; the mapping is larger.
///
/// The unread fields are transcribed rather than padded so that the offsets of
/// the ones that matter are checkable against `linux/kvm.h` by eye.
#[repr(C)]
#[allow(dead_code)]
struct KvmRun {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [u8; 6],
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    io_direction: u8,
    io_size: u8,
    io_port: u16,
    io_count: u32,
    io_data_offset: u64,
}

const KVM_INTERRUPT: libc::c_ulong = 0x4004_ae86;
const KVM_SET_GUEST_DEBUG: libc::c_ulong = 0x4048_ae9b;
const KVM_GUESTDBG_ENABLE: u32 = 0x0000_0001;
const KVM_GUESTDBG_SINGLESTEP: u32 = 0x0000_0002;
const KVM_GUESTDBG_USE_HW_BP: u32 = 0x0002_0000;
const KVM_EXIT_DEBUG: u32 = 4;

/// `struct kvm_guest_debug` with x86's `debugreg[8]` arch payload.
#[repr(C)]
struct KvmGuestDebug {
    control: u32,
    pad: u32,
    debugreg: [u64; 8],
}
const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
const KVM_EXIT_INTR: u32 = 10;

#[repr(C)]
struct KvmInterrupt {
    irq: u32,
}

/// Physical address of the BIOS tick count at `0040:006C`, which every DOS-era
/// runtime treats as the clock.
const BIOS_TICKS: usize = 0x46c;
/// 18.2 Hz, the rate the 8253 was divided down to and the rate every program
/// written before 1995 assumes.
const TICK_NANOS: u64 = 54_925_400;

/// Why the guest stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// The guest executed this interrupt vector and is waiting to be serviced.
    Trap(u8),
    /// The guest wrote to a hardware port we do not claim.
    PortWrite { port: u16, value: u8 },
    /// The guest read a port we do not claim. The caller must answer with
    /// [`VmGuest::complete_port_read`] before the next [`VmGuest::run`].
    PortRead { port: u16 },
    /// The guest is now able to take an interrupt.
    IrqWindow,
    /// A watchpoint fired, or a single step completed.
    Debug,
    /// The guest halted.
    Halted,
    /// The watchdog cut in: the guest is running but not asking for anything.
    Interrupted,
    /// Something this proof of concept does not model.
    Unexpected(u32),
}

/// Stops the helper threads when dropped, and *waits* for them.
///
/// Joining is not tidiness: the clock thread writes into the guest mapping, so
/// a thread still sleeping when `VmGuest` unmaps it wakes to a use-after-free.
pub struct Helpers {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Ticks actually delivered. A program that times itself against the BIOS
    /// clock is only as accurate as this is, so it is worth being able to say
    /// what rate the guest really saw rather than what was intended.
    pub ticks: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl Drop for Helpers {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn last_err<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

/// A real-mode guest, and the window onto its memory.
pub struct VmGuest {
    kvm: libc::c_int,
    vm: libc::c_int,
    vcpu: libc::c_int,
    run: *mut KvmRun,
    run_size: usize,
    mem: *mut u8,
    mem_len: usize,
    regs: KvmRegs,
    sregs: KvmSregs,
    regs_dirty: bool,
    sregs_dirty: bool,
    stub_seg: u16,
    /// Every hardware port the guest touched that is not our trap, and how
    /// often. A real DOS box has hardware; a 1994 Borland startup will poke at
    /// it, and refusing to answer stops the program dead. Answering `0xff` and
    /// counting is how we find out what actually needs modelling.
    pub port_log: BTreeMap<u16, u32>,
}

impl VmGuest {
    /// Create a VM with `mem_len` bytes of guest physical memory, starting at
    /// guest physical zero so that the IVT lands where the CPU expects it.
    pub fn new(mem_len: usize) -> io::Result<Self> {
        // SAFETY: a plain open of a character device.
        let kvm = unsafe { libc::open(c"/dev/kvm".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if kvm < 0 {
            return last_err();
        }

        // SAFETY: KVM_GET_API_VERSION takes no argument.
        let version = unsafe { libc::ioctl(kvm, KVM_GET_API_VERSION, 0) };
        if version != 12 {
            unsafe { libc::close(kvm) };
            return Err(io::Error::other(format!(
                "unexpected KVM API version {version}, expected 12"
            )));
        }

        // SAFETY: KVM_CREATE_VM's argument is a machine type; 0 is the default.
        let vm = unsafe { libc::ioctl(kvm, KVM_CREATE_VM, 0) };
        if vm < 0 {
            unsafe { libc::close(kvm) };
            return last_err();
        }

        // SAFETY: an anonymous shared mapping; KVM requires a stable address,
        // which is why this is not a `Vec`.
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mem_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mem == libc::MAP_FAILED {
            return last_err();
        }

        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: mem_len as u64,
            userspace_addr: mem as u64,
        };
        // SAFETY: `region` outlives the call, which copies it.
        if unsafe { libc::ioctl(vm, KVM_SET_USER_MEMORY_REGION, std::ptr::from_ref(&region)) } < 0 {
            return last_err();
        }

        // SAFETY: vcpu index 0.
        let vcpu = unsafe { libc::ioctl(vm, KVM_CREATE_VCPU, 0) };
        if vcpu < 0 {
            return last_err();
        }

        // SAFETY: no argument.
        let run_size = unsafe { libc::ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0) };
        if run_size < 0 {
            return last_err();
        }
        let run_size = run_size as usize;

        // SAFETY: the kernel defines this mapping for the vcpu fd.
        let run = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                run_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu,
                0,
            )
        };
        if run == libc::MAP_FAILED {
            return last_err();
        }

        Ok(Self {
            kvm,
            vm,
            vcpu,
            run: run.cast::<KvmRun>(),
            run_size,
            mem: mem.cast::<u8>(),
            mem_len,
            regs: KvmRegs::default(),
            sregs: KvmSregs::default(),
            regs_dirty: false,
            sregs_dirty: false,
            stub_seg: 0,
            port_log: BTreeMap::new(),
        })
    }

    fn mem_ref(&self) -> &[u8] {
        // SAFETY: `mem` is a live mapping of `mem_len` bytes for our lifetime.
        unsafe { std::slice::from_raw_parts(self.mem, self.mem_len) }
    }

    fn mem_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` excludes any other reference.
        unsafe { std::slice::from_raw_parts_mut(self.mem, self.mem_len) }
    }

    /// Copy `bytes` to guest physical `phys`.
    pub fn load(&mut self, phys: usize, bytes: &[u8]) -> io::Result<()> {
        let end = phys
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("load overflows the address space"))?;
        let len = self.mem_len;
        let slot = self
            .mem_mut()
            .get_mut(phys..end)
            .ok_or_else(|| io::Error::other(format!("load {phys}..{end} exceeds {len}")))?;
        slot.copy_from_slice(bytes);
        Ok(())
    }

    /// Point real-mode interrupt `vector` at `seg:off`.
    ///
    /// The IVT is guest memory like any other -- four bytes per vector, offset
    /// first -- so this is a plain store, not a KVM operation.
    pub fn set_ivt(&mut self, vector: u8, seg: u16, off: u16) -> io::Result<()> {
        let at = vector as usize * 4;
        let mut entry = [0u8; 4];
        entry[0..2].copy_from_slice(&off.to_le_bytes());
        entry[2..4].copy_from_slice(&seg.to_le_bytes());
        self.load(at, &entry)
    }

    /// Install the trap stub for `vector` and point the IVT at it.
    pub fn hook(&mut self, vector: u8, stub_seg: u16) -> io::Result<()> {
        let off = u16::from(vector) * STUB_STRIDE;
        self.load(stub_seg as usize * 16 + off as usize, &STUB)?;
        self.stub_seg = stub_seg;
        self.set_ivt(vector, stub_seg, off)
    }

    /// Hook every interrupt.
    ///
    /// An unhooked vector is four zero bytes, so a program calling an
    /// interrupt we have not modelled jumps to `0000:0000` and executes the
    /// vector table as code -- which presents as an unexplained hang rather
    /// than as "you are missing int 10h". Hooking all 256 turns every such
    /// gap into a named report.
    pub fn hook_all(&mut self, stub_seg: u16) -> io::Result<()> {
        for vector in 0..=u8::MAX {
            self.hook(vector, stub_seg)?;
        }
        Ok(())
    }

    /// Put the vCPU in real mode at `cs:ip` with a stack at `ss:sp`, and
    /// `DS`/`ES` pointing at the same place -- the `.COM` convention.
    pub fn start(&mut self, cs: u16, ip: u16, ss: u16, sp: u16) -> io::Result<()> {
        self.enter(cs, ip, ss, sp, ss, ss)
    }

    /// Enter with every segment stated. DOS hands an `.EXE` its PSP in
    /// `DS` and `ES` while `SS` is the program's own stack, so the `.COM`
    /// shorthand above cannot express it.
    pub fn enter(
        &mut self,
        cs: u16,
        ip: u16,
        ss: u16,
        sp: u16,
        ds: u16,
        es: u16,
    ) -> io::Result<()> {
        let mut sregs = KvmSregs::default();
        // SAFETY: fills `sregs` with the vcpu's reset state, which is already
        // real-mode shaped -- we only retarget the segments we care about.
        if unsafe { libc::ioctl(self.vcpu, KVM_GET_SREGS, std::ptr::from_mut(&mut sregs)) } < 0 {
            return last_err();
        }

        sregs.cs.selector = cs;
        sregs.cs.base = (cs as u64) << 4;
        sregs.cs.limit = 0xffff;

        sregs.ds.selector = ds;
        sregs.ds.base = (ds as u64) << 4;
        sregs.ds.limit = 0xffff;

        sregs.es = sregs.ds;
        sregs.es.selector = es;
        sregs.es.base = (es as u64) << 4;

        sregs.ss = sregs.ds;
        sregs.ss.selector = ss;
        sregs.ss.base = (ss as u64) << 4;

        sregs.cr0 &= !1u64; // clear PE: this is real mode, not a switch into it

        // SAFETY: `sregs` outlives the call.
        if unsafe { libc::ioctl(self.vcpu, KVM_SET_SREGS, std::ptr::from_ref(&sregs)) } < 0 {
            return last_err();
        }
        self.sregs = sregs;

        let regs = KvmRegs {
            rip: ip as u64,
            rsp: sp as u64,
            rflags: 0x2, // bit 1 is reserved and must be set
            ..KvmRegs::default()
        };
        // SAFETY: `regs` outlives the call.
        if unsafe { libc::ioctl(self.vcpu, KVM_SET_REGS, std::ptr::from_ref(&regs)) } < 0 {
            return last_err();
        }
        self.regs = regs;
        self.regs_dirty = false;
        self.sregs_dirty = false;
        Ok(())
    }

    fn exit_reason(&self) -> u32 {
        // SAFETY: `run` is a live mapping of at least `size_of::<KvmRun>()`.
        unsafe { (*self.run).exit_reason }
    }

    fn io_port(&self) -> u16 {
        // SAFETY: as above.
        unsafe { (*self.run).io_port }
    }

    /// Run until the guest asks a question.
    pub fn run(&mut self) -> io::Result<Stop> {
        if self.regs_dirty {
            // SAFETY: `regs` outlives the call.
            if unsafe { libc::ioctl(self.vcpu, KVM_SET_REGS, std::ptr::from_ref(&self.regs)) } < 0 {
                return last_err();
            }
            self.regs_dirty = false;
        }
        if self.sregs_dirty {
            let sregs = std::ptr::from_ref(&self.sregs);
            // SAFETY: `sregs` outlives the call.
            if unsafe { libc::ioctl(self.vcpu, KVM_SET_SREGS, sregs) } < 0 {
                return last_err();
            }
            self.sregs_dirty = false;
        }

        loop {
            // SAFETY: KVM_RUN takes no argument.
            let rc = unsafe { libc::ioctl(self.vcpu, KVM_RUN, 0) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // The watchdog took the CPU back. The vCPU is stopped, so
                    // its registers can be read to say where the guest is.
                    let regs = std::ptr::from_mut(&mut self.regs);
                    // SAFETY: both outlive their calls.
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_REGS, regs) } < 0 {
                        return last_err();
                    }
                    let sregs = std::ptr::from_mut(&mut self.sregs);
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_SREGS, sregs) } < 0 {
                        return last_err();
                    }
                    return Ok(Stop::Interrupted);
                }
                return Err(err);
            }

            return match self.exit_reason() {
                KVM_EXIT_IO if self.io_port() == TRAP_PORT => {
                    // SAFETY: both outlive their calls.
                    let regs = std::ptr::from_mut(&mut self.regs);
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_REGS, regs) } < 0 {
                        return last_err();
                    }
                    let sregs = std::ptr::from_mut(&mut self.sregs);
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_SREGS, sregs) } < 0 {
                        return last_err();
                    }
                    // KVM leaves `rip` at the `out` on an I/O exit rather
                    // than past it, so do not "correct" for the instruction
                    // length: with a 4-byte stride, integer division lands on
                    // the right vector whether rip is at the `out` or after it.
                    Ok(Stop::Trap((self.regs.rip as u16 / STUB_STRIDE) as u8))
                }
                KVM_EXIT_IO => {
                    // SAFETY: `run` is a live mapping of at least `run_size`.
                    let (port, direction, offset) = unsafe {
                        let r = &*self.run;
                        (r.io_port, r.io_direction, r.io_data_offset as usize)
                    };
                    *self.port_log.entry(port).or_insert(0) += 1;
                    const KVM_EXIT_IO_IN: u8 = 0;
                    if direction == KVM_EXIT_IO_IN {
                        Ok(Stop::PortRead { port })
                    } else {
                        let value = if offset < self.run_size {
                            // SAFETY: bounds checked against the mapping.
                            unsafe { self.run.cast::<u8>().add(offset).read() }
                        } else {
                            0
                        };
                        Ok(Stop::PortWrite { port, value })
                    }
                }
                KVM_EXIT_DEBUG => {
                    let regs = std::ptr::from_mut(&mut self.regs);
                    // SAFETY: both outlive their calls.
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_REGS, regs) } < 0 {
                        return last_err();
                    }
                    let sregs = std::ptr::from_mut(&mut self.sregs);
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_SREGS, sregs) } < 0 {
                        return last_err();
                    }
                    Ok(Stop::Debug)
                }
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(Stop::IrqWindow),
                KVM_EXIT_HLT => Ok(Stop::Halted),
                KVM_EXIT_INTR => {
                    let regs = std::ptr::from_mut(&mut self.regs);
                    // SAFETY: both outlive their calls.
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_REGS, regs) } < 0 {
                        return last_err();
                    }
                    let sregs = std::ptr::from_mut(&mut self.sregs);
                    if unsafe { libc::ioctl(self.vcpu, KVM_GET_SREGS, sregs) } < 0 {
                        return last_err();
                    }
                    Ok(Stop::Interrupted)
                }
                other => Ok(Stop::Unexpected(other)),
            };
        }
    }

    /// Answer the port read the guest is waiting on.
    ///
    /// `0xff` is what an absent device reads as on a real bus, and is the right
    /// answer for anything not modelled -- but it has to be an explicit choice
    /// by whoever knows the hardware, not a default buried in the CPU edge.
    /// Swallowing port I/O here is what hid LORDCFG's cursor writes: it moves
    /// the cursor through the CRTC registers, thousands of times, and none of
    /// it ever reached the video model.
    pub fn complete_port_read(&mut self, value: u8) {
        // SAFETY: `run` is a live mapping of at least `run_size` bytes.
        let (size, count, offset) = unsafe {
            let r = &*self.run;
            (r.io_size as usize, r.io_count as usize, r.io_data_offset as usize)
        };
        let Some(bytes) = size.checked_mul(count) else {
            return;
        };
        if offset.saturating_add(bytes) > self.run_size {
            return;
        }
        // SAFETY: bounds checked against the mapping just above.
        unsafe {
            std::ptr::write_bytes(self.run.cast::<u8>().add(offset), value, bytes);
        }
    }

    /// Ask to be told the moment the guest can take an interrupt.
    ///
    /// Only worth setting while one is actually pending. Requesting it
    /// unconditionally exits every time the guest is interruptible, which is
    /// most of the time -- measured at 2,000 deliveries a second against
    /// 119,000 once gated (`re/spikes/kvm_irq_inject.c`).
    pub fn set_interrupt_window(&mut self, want: bool) {
        // SAFETY: `run` is a live mapping; this is its first byte pair.
        unsafe { (*self.run).request_interrupt_window = u8::from(want) };
    }

    /// Is the guest interruptible right now?
    pub fn ready_for_interrupt(&self) -> bool {
        // SAFETY: as above.
        unsafe { (*self.run).ready_for_interrupt_injection != 0 }
    }

    /// Deliver a hardware interrupt by vector.
    ///
    /// With no in-kernel irqchip this takes the vector directly rather than an
    /// IRQ line, so the caller does the 8259's mapping.
    pub fn inject(&mut self, vector: u8) -> io::Result<()> {
        let irq = KvmInterrupt {
            irq: u32::from(vector),
        };
        // SAFETY: `irq` outlives the call, which copies it.
        if unsafe { libc::ioctl(self.vcpu, KVM_INTERRUPT, std::ptr::from_ref(&irq)) } < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Stop when the guest touches `linear`, and/or after every instruction.
    ///
    /// A watchpoint is how a trace gets armed without tracing everything.
    /// Stepping costs four to six microseconds an instruction, so a two-second
    /// native run would take about a hundred minutes to step -- but a hardware
    /// breakpoint runs at full speed and stops on the one access that matters
    /// (`re/spikes/kvm_singlestep.c`).
    ///
    /// The stop is reported *after* the access completes, because data
    /// breakpoints are trap-type. The instruction named is the one following
    /// the access, which is easy to mistake for an off-by-one.
    pub fn debug(&mut self, watch: Option<u32>, step: bool) -> io::Result<()> {
        let mut dbg = KvmGuestDebug {
            control: KVM_GUESTDBG_ENABLE,
            pad: 0,
            debugreg: [0; 8],
        };
        if step {
            dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        }
        if let Some(addr) = watch {
            dbg.control |= KVM_GUESTDBG_USE_HW_BP;
            dbg.debugreg[0] = u64::from(addr);
            // L0 enables DR0; R/W0 = 11 breaks on data read or write; LEN0 = 00
            // watches one byte.
            dbg.debugreg[7] = 0x1 | (0x3 << 16);
        }
        if dbg.control == KVM_GUESTDBG_ENABLE {
            dbg.control = 0; // nothing asked for: turn debugging off entirely
        }
        // SAFETY: `dbg` outlives the call, which copies it.
        if unsafe { libc::ioctl(self.vcpu, KVM_SET_GUEST_DEBUG, std::ptr::from_ref(&dbg)) } < 0 {
            return last_err();
        }
        Ok(())
    }

    /// The bytes at the current `CS:IP`, for disassembling a trace afterwards.
    pub fn code_here(&self, len: usize) -> Vec<u8> {
        let at = (self.sregs.cs.base as usize) + (self.regs.rip as u16 as usize);
        let mem = self.mem_ref();
        mem.get(at..at.saturating_add(len)).unwrap_or(&[]).to_vec()
    }

    /// Registers as a trace line wants them.
    pub fn trace_line(&self) -> String {
        let r = &self.regs;
        format!(
            "{:04x}:{:04x}  ax={:04x} bx={:04x} cx={:04x} dx={:04x} si={:04x} di={:04x}              ds={:04x} es={:04x} fl={:04x}  {}",
            self.sregs.cs.selector,
            r.rip as u16,
            r.rax as u16, r.rbx as u16, r.rcx as u16, r.rdx as u16,
            r.rsi as u16, r.rdi as u16,
            self.sregs.ds.selector, self.sregs.es.selector,
            r.rflags as u16,
            self.code_here(8).iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
        )
    }

    /// Linear addresses where `value` appears as a little-endian word.
    ///
    /// How you find out where a program put something you typed. Cheap, and
    /// far more direct than reasoning about a Turbo Pascal stack frame.
    pub fn scan_u16(&self, value: u16, limit: usize) -> Vec<usize> {
        let want = value.to_le_bytes();
        let mem = self.mem_ref();
        let mut hits = Vec::new();
        for at in 0..mem.len().saturating_sub(1) {
            if mem[at] == want[0] && mem[at + 1] == want[1] {
                hits.push(at);
                if hits.len() >= limit {
                    break;
                }
            }
        }
        hits
    }

    /// The current instruction's linear address, for collapsing a `rep`.
    pub fn code_addr(&self) -> usize {
        (self.sregs.cs.base as usize) + (self.regs.rip as u16 as usize)
    }

    /// Where the guest is now, for diagnostics.
    pub fn cs_ip(&self) -> (u16, u16) {
        (self.sregs.cs.selector, self.regs.rip as u16)
    }

    /// Start the BIOS clock, and a watchdog that interrupts `KVM_RUN` after
    /// `watchdog_ms` of the guest not asking for anything.
    ///
    /// The clock is the clearest demonstration of what this architecture is:
    /// guest physical memory is an ordinary shared mapping, so a *host thread*
    /// bumps the tick count at `0040:006C` while the guest is running natively
    /// on another core. No trap, no exit, no coordination. A Turbo Pascal
    /// runtime calibrating its delay loop spins forever without it.
    pub fn helpers(&mut self, watchdog_ms: u64) -> Helpers {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let mem = self.mem as usize;
        let run = self.run as usize;

        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let clock_counter = Arc::clone(&counter);
        let clock_stop = Arc::clone(&stop);
        let clock = std::thread::spawn(move || {
            let ticks = (mem + BIOS_TICKS) as *mut u32;
            let mut n: u32 = 0;
            while !clock_stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_nanos(TICK_NANOS));
                if clock_stop.load(Ordering::Relaxed) {
                    return;
                }
                n = n.wrapping_add(1);
                // SAFETY: the mapping outlives these threads, which the
                // `Helpers` guard stops before `VmGuest` is dropped.
                unsafe { ticks.write_volatile(n) };
                clock_counter.store(n, Ordering::Relaxed);
            }
        });

        // A spinning guest never re-enters KVM_RUN, so `immediate_exit` alone
        // cannot reach it -- the kernel only reads that on entry. The only way
        // to take the CPU back from a guest that is asking for nothing is to
        // signal the thread blocked in the ioctl.
        extern "C" fn nudge(_: libc::c_int) {}
        // SAFETY: installing a no-op handler with no SA_RESTART, so that the
        // interrupted `ioctl` reports EINTR rather than being resumed.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = nudge as *const () as usize;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        }
        // SAFETY: both are plain queries about the calling thread.
        let (pid, tid) = unsafe {
            (
                libc::getpid(),
                libc::syscall(libc::SYS_gettid) as libc::pid_t,
            )
        };
        let _ = run;

        let dog_stop = Arc::clone(&stop);
        let dog = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(watchdog_ms);
            while !dog_stop.load(Ordering::Relaxed) {
                if std::time::Instant::now() >= deadline {
                    // Keep signalling rather than firing once. A single signal
                    // that arrives while the main thread is in userspace -- not
                    // blocked in KVM_RUN -- is swallowed by the no-op handler
                    // and the watchdog silently never fires again, which is how
                    // a guest spinning on port I/O hung past its deadline
                    // forever.
                    // SAFETY: signalling a thread of our own process.
                    unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) };
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        Helpers {
            stop,
            threads: vec![clock, dog],
            ticks: counter,
        }
    }

    /// Resolve a far pointer the way real mode does.
    fn linear(&self, at: Ptr) -> usize {
        at.seg as usize * 16 + at.off as usize
    }

    fn span(&self, at: Ptr, len: usize) -> Result<(usize, usize), Fault> {
        let base = self.linear(at);
        let end = base
            .checked_add(len)
            .ok_or(Fault::OutOfBounds { at, len })?;
        if end > self.mem_len {
            return Err(Fault::OutOfBounds { at, len });
        }
        Ok((base, end))
    }
}

impl Guest for VmGuest {
    fn read(&self, at: Ptr, len: usize) -> Result<&[u8], Fault> {
        let (base, end) = self.span(at, len)?;
        Ok(&self.mem_ref()[base..end])
    }

    fn read_until(&self, at: Ptr, term: u8, max: usize) -> Result<&[u8], Fault> {
        let base = self.linear(at);
        let mem = self.mem_ref();
        let tail = mem
            .get(base..)
            .ok_or(Fault::OutOfBounds { at, len: 0 })?;
        let limit = max.min(tail.len());
        match tail[..limit].iter().position(|&b| b == term) {
            Some(n) => Ok(&tail[..n]),
            None => Err(Fault::Unterminated { at, term, max }),
        }
    }

    fn write(&mut self, at: Ptr, bytes: &[u8]) -> Result<(), Fault> {
        let (base, end) = self.span(at, bytes.len())?;
        self.mem_mut()[base..end].copy_from_slice(bytes);
        Ok(())
    }

    fn regs(&self) -> Regs {
        Regs {
            ax: self.regs.rax as u16,
            bx: self.regs.rbx as u16,
            cx: self.regs.rcx as u16,
            dx: self.regs.rdx as u16,
            si: self.regs.rsi as u16,
            di: self.regs.rdi as u16,
            ds: self.sregs.ds.selector,
            es: self.sregs.es.selector,
        }
    }

    fn set_regs(&mut self, regs: Regs) {
        // Only the low 16 bits are the guest's; leave the rest of each 64-bit
        // register as the CPU left it.
        self.regs.rax = (self.regs.rax & !0xffff) | regs.ax as u64;
        self.regs.rbx = (self.regs.rbx & !0xffff) | regs.bx as u64;
        self.regs.rcx = (self.regs.rcx & !0xffff) | regs.cx as u64;
        self.regs.rdx = (self.regs.rdx & !0xffff) | regs.dx as u64;
        self.regs.rsi = (self.regs.rsi & !0xffff) | regs.si as u64;
        self.regs.rdi = (self.regs.rdi & !0xffff) | regs.di as u64;
        self.regs_dirty = true;

        // Some calls answer in a segment register -- `35h` returns the vector
        // in ES:BX, `2Fh` the DTA in ES:BX, `62h` the PSP in BX. Dropping the
        // segment half silently hands the program a pointer into whatever it
        // happened to have in ES, so this is not optional.
        if regs.ds != self.sregs.ds.selector {
            self.sregs.ds.selector = regs.ds;
            self.sregs.ds.base = (regs.ds as u64) << 4;
            self.sregs_dirty = true;
        }
        if regs.es != self.sregs.es.selector {
            self.sregs.es.selector = regs.es;
            self.sregs.es.base = (regs.es as u64) << 4;
            self.sregs_dirty = true;
        }
    }

    /// Write a flag into the `FLAGS` image the stub's `iret` will pop.
    ///
    /// After `int n` the stack holds IP, CS, then FLAGS, so the word lives at
    /// `SS:SP+4`. Setting the *live* flags instead would be undone by `iret`
    /// the moment the guest resumes, and every DOS error return would vanish.
    fn set_flag(&mut self, flag: Flag, on: bool) {
        let base = (self.sregs.ss.base as usize) + (self.regs.rsp as u16 as usize) + 4;
        // Losing the carry here is the exact failure this convention exists to
        // avoid, so an unreachable stack address stops rather than quietly
        // discarding the program's error return.
        let slot = self
            .mem_mut()
            .get_mut(base..base + 2)
            .expect("stacked FLAGS word is outside guest memory");
        let mut flags = u16::from_le_bytes([slot[0], slot[1]]);
        if on {
            flags |= flag.bit();
        } else {
            flags &= !flag.bit();
        }
        slot.copy_from_slice(&flags.to_le_bytes());
    }
}

impl Drop for VmGuest {
    fn drop(&mut self) {
        // SAFETY: each of these was produced by the matching call in `new`.
        unsafe {
            libc::munmap(self.run.cast::<libc::c_void>(), self.run_size);
            libc::munmap(self.mem.cast::<libc::c_void>(), self.mem_len);
            libc::close(self.vcpu);
            libc::close(self.vm);
            libc::close(self.kvm);
        }
    }
}
