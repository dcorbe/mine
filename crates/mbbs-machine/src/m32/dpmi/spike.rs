//! The go/no-go gate: prove an asynchronous signal can be turned into an
//! interrupt into running 32-bit compat-mode guest code and returned from
//! cleanly, N times, with no loss and no duplication.
//!
//! This is a proof harness, not shipped API -- `#[cfg(test)]` only. It builds
//! a bespoke excursion (no `Machine`) so it can inject into a guest that is
//! *running*, which `Machine::run` deliberately never exposes.
//!
//! Mechanism, and why it cannot nest or corrupt:
//!
//! * The guest spins in a tight loop reading a host-written `done` flag. Its
//!   interrupt service routine is `inc dword [counter] ; iret` -- it counts by
//!   writing memory the host reads back, so counting needs no host round-trip.
//! * A driver thread sends the injection signal to the guest thread. The
//!   handler, running on the guest thread's alternate stack, pushes a real
//!   32-bit `iret` frame (`EFLAGS`, `CS`, `EIP`) onto the guest stack and
//!   points `EIP` at the ISR. The ISR's own `iret` pops that frame and resumes
//!   exactly where the guest was interrupted -- the CPU does the return, not us.
//! * The handler injects only when the interrupted `CS` is the guest's, the
//!   virtual IF is set, and `EIP` is **not already inside the ISR**. That last
//!   guard is what makes nesting impossible without any software IF juggling:
//!   a tick that lands mid-ISR is skipped, so every accepted injection is
//!   exactly one ISR run is exactly one increment.
//! * The driver runs lockstep -- it resends until each tick lands -- so a
//!   skipped tick is retried rather than lost. Accepted injections == counter
//!   increments == N.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

use crate::m32::Mapping;
use crate::m32::asm::{Ctx, USER32_CS, current_cs, enter};

/// The spike drives a bespoke excursion through process-global statics
/// (`INJ`, `GUEST_TID`, `ACCEPTED`); two spike runs must never overlap, and
/// cargo runs tests in parallel by default. Every entry point takes this
/// first.
static SPIKE_LOCK: Mutex<()> = Mutex::new(());

const MAP_LEN: usize = 0x10000;
const COUNTER_OFF: usize = 0x100;
const DONE_OFF: usize = 0x104;
const ISR_OFF: usize = 0x200;
const LOOP_OFF: usize = 0x300;
const STACK_OFF: usize = 0xF000;

/// Everything the injection handler needs, published before the excursion and
/// read (never written) inside the signal handler.
struct Inj {
    ctx: *mut Ctx,
    isr_lo: u32,
    isr_hi: u32,
    isr_addr: u32,
}

// The live `Inj` for the running excursion. Raw pointer because the handler
// reads it in signal context; set once before entering, cleared after.
static INJ: AtomicPtr<Inj> = AtomicPtr::new(std::ptr::null_mut());
// The guest thread's tid, for the driver to target.
static GUEST_TID: AtomicI32 = AtomicI32::new(0);
// How many injections the handler has actually performed (accepted), for the
// test to cross-check against the guest's own counter.
static ACCEPTED: AtomicU32 = AtomicU32::new(0);

/// `SIGUSR1` is not touched by the fault arbiter (which owns SIGSEGV/… and the
/// watchdog's SIGRTMIN), so the injection path cannot collide with it.
const INJECT_SIGNO: i32 = libc::SIGUSR1;

/// The injection handler. Async-signal-safe: atomic loads, greg reads/writes,
/// and raw writes into the guest's own stack. No allocation, no locks, no libc.
extern "C" fn on_inject(_sig: i32, _info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    let inj = INJ.load(Ordering::Acquire);
    if inj.is_null() {
        return;
    }
    // SAFETY: `INJ` points at a live `Inj` for as long as it is non-null (the
    // excursion owns it and clears the pointer before dropping it).
    let inj = unsafe { &*inj };

    // SAFETY: an SA_SIGINFO handler is handed a real `ucontext_t`.
    let uc = unsafe { &mut *uc.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;

    let cs = (gregs[libc::REG_CSGSFS as usize] as u64 & 0xffff) as u16;
    if cs != USER32_CS {
        return; // not in guest code (host, or the guest has exited)
    }
    // SAFETY: `inj.ctx` is the live excursion context.
    if unsafe { (*inj.ctx).vif } == 0 {
        return; // interrupts disabled: hold (the driver will retry)
    }
    let eip = gregs[libc::REG_RIP as usize] as u32;
    if eip >= inj.isr_lo && eip < inj.isr_hi {
        return; // already inside the ISR: never nest
    }

    // Push a 32-bit iret frame (EFLAGS, CS, EIP) so the ISR's own `iret`
    // returns to exactly here. Stack grows down; iret will pop EIP first.
    let esp = gregs[libc::REG_RSP as usize] as u32;
    let eflags = gregs[libc::REG_EFL as usize] as u32;
    let new_esp = esp - 12;
    // SAFETY: `new_esp .. esp` is within the guest stack region of the live
    // mapping (the excursion sizes the stack with headroom for this frame).
    unsafe {
        let p = new_esp as *mut u32;
        *p.add(0) = eip; // popped into EIP
        *p.add(1) = u32::from(USER32_CS); // popped into CS
        *p.add(2) = eflags; // popped into EFLAGS
    }
    gregs[libc::REG_RSP as usize] = u64::from(new_esp) as libc::greg_t;
    gregs[libc::REG_RIP as usize] = u64::from(inj.isr_addr) as libc::greg_t;

    ACCEPTED.fetch_add(1, Ordering::Release);
}

/// Install [`on_inject`] for [`INJECT_SIGNO`], on the alternate stack the fault
/// arbiter already set up for this thread.
fn install_injection_handler() {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_inject as usize;
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
        let rc = libc::sigaction(INJECT_SIGNO, &sa, std::ptr::null_mut());
        assert_eq!(rc, 0, "installing the injection handler");
    }
}

fn gettid() -> i32 {
    // SAFETY: `gettid` takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

/// `je rel8` / `jmp` helpers keep the hand-assembly readable.
fn build_guest(base: u32) -> Vec<u8> {
    let mut m = vec![0u8; MAP_LEN];

    let counter_addr = base + COUNTER_OFF as u32;
    let done_addr = base + DONE_OFF as u32;

    // ISR: inc dword [counter] ; iret
    let mut isr = vec![0xFF, 0x05];
    isr.extend_from_slice(&counter_addr.to_le_bytes());
    isr.push(0xCF); // iret
    m[ISR_OFF..ISR_OFF + isr.len()].copy_from_slice(&isr);

    // Loop:
    //   L: cmp dword [done], 0    ; 83 3D <done32> 00   (7 bytes)
    //      je L                   ; 74 F7               (2 bytes, rel8 = -9)
    //      int 0x21               ; CD 21               (fall through -> exit)
    let mut lp = vec![0x83, 0x3D];
    lp.extend_from_slice(&done_addr.to_le_bytes());
    lp.push(0x00);
    lp.push(0x74);
    lp.push(0xF7); // -9: back to L
    lp.push(0xCD);
    lp.push(0x21);
    m[LOOP_OFF..LOOP_OFF + lp.len()].copy_from_slice(&lp);

    m
}

/// Build a guest that first executes `cli` each loop iteration, so the virtual
/// IF is clear and injections must be refused. `int 0x21` still exits.
fn build_cli_guest(base: u32) -> Vec<u8> {
    let mut m = vec![0u8; MAP_LEN];
    let done_addr = base + DONE_OFF as u32;

    //   L: cli                    ; FA                  (1 byte)
    //      cmp dword [done], 0    ; 83 3D <done32> 00   (7 bytes)
    //      je L                   ; 74 <rel8 = -10>     (2 bytes)
    //      int 0x21               ; CD 21
    let mut lp = vec![0xFA, 0x83, 0x3D];
    lp.extend_from_slice(&done_addr.to_le_bytes());
    lp.push(0x00);
    lp.push(0x74);
    lp.push(0xF6); // -10: back to L (the cli)
    lp.push(0xCD);
    lp.push(0x21);
    m[LOOP_OFF..LOOP_OFF + lp.len()].copy_from_slice(&lp);
    m
}

/// Prove `cli` masks injection: with the virtual IF clear, a burst of
/// injection signals must all be refused. Returns `(counter, accepted)`, both
/// of which must be zero.
fn run_cli_masks_injection(bursts: u32) -> (u32, u32) {
    let _guard = SPIKE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    crate::m32::fault::arm(current_cs()).expect("arm fault recovery");
    install_injection_handler();

    let mut mapping = Mapping::new(MAP_LEN).expect("guest mapping");
    let base = mapping.base() as usize as u32;
    mapping.as_mut_slice().copy_from_slice(&build_cli_guest(base));

    let isr_addr = base + ISR_OFF as u32;
    let counter_ptr = (base as usize + COUNTER_OFF) as *mut u32;
    let done_ptr = (base as usize + DONE_OFF) as *mut u32;

    let mut ctx = Ctx {
        target_offset: base + LOOP_OFF as u32,
        target_selector: USER32_CS,
        esp: base + STACK_OFF as u32,
        dpmi: 1,
        vif: 1, // the guest's own `cli` clears it
        code_lo: u64::from(base),
        code_hi: u64::from(base) + MAP_LEN as u64,
        ..Default::default()
    };

    let inj = Box::new(Inj {
        ctx: &mut ctx,
        isr_lo: isr_addr,
        isr_hi: isr_addr + 8,
        isr_addr,
    });
    let inj_ptr = Box::into_raw(inj);
    INJ.store(inj_ptr, Ordering::Release);
    ACCEPTED.store(0, Ordering::Release);
    GUEST_TID.store(gettid(), Ordering::Release);

    let done_addr = done_ptr as usize;
    let driver = std::thread::spawn(move || {
        let tid = loop {
            let t = GUEST_TID.load(Ordering::Acquire);
            if t != 0 {
                break t;
            }
            std::hint::spin_loop();
        };
        let pid = unsafe { libc::getpid() };
        for _ in 0..bursts {
            unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, INJECT_SIGNO) };
            for _ in 0..4000 {
                std::hint::spin_loop();
            }
        }
        unsafe { std::ptr::write_volatile(done_addr as *mut u32, 1) };
    });

    // SAFETY: `ctx` addresses the live `mapping`, RWX for the call's duration.
    unsafe { enter(&mut ctx) };
    driver.join().expect("driver thread");

    INJ.store(std::ptr::null_mut(), Ordering::Release);
    GUEST_TID.store(0, Ordering::Release);
    let accepted = ACCEPTED.load(Ordering::Acquire);
    // SAFETY: `inj_ptr` came from `Box::into_raw` and is no longer published.
    drop(unsafe { Box::from_raw(inj_ptr) });

    assert_eq!(ctx.out_kind, 1, "guest exited via int 21h service");
    // SAFETY: single-threaded now (driver joined).
    let counter = unsafe { std::ptr::read_volatile(counter_ptr) };
    (counter, accepted)
}

/// Run the guest with `deliveries` lockstep injections, returning the guest's
/// own counter after it exits. `ACCEPTED` is cross-checked against it.
fn run_spike(deliveries: u32) -> u32 {
    let _guard = SPIKE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Arm the shared fault handler (for the guest's exit `int 0x21`, and any
    // real fault), then our own injection handler on top.
    crate::m32::fault::arm(current_cs()).expect("arm fault recovery");
    install_injection_handler();

    let mut mapping = Mapping::new(MAP_LEN).expect("guest mapping");
    let base = mapping.base() as usize as u32;
    let bytes = build_guest(base);
    mapping.as_mut_slice().copy_from_slice(&bytes);

    let isr_addr = base + ISR_OFF as u32;
    let loop_addr = base + LOOP_OFF as u32;
    let counter_ptr = (base as usize + COUNTER_OFF) as *mut u32;
    let done_ptr = (base as usize + DONE_OFF) as *mut u32;

    let mut ctx = Ctx {
        target_offset: loop_addr,
        target_selector: USER32_CS,
        esp: base + STACK_OFF as u32,
        dpmi: 1,
        vif: 1,
        code_lo: u64::from(base),
        code_hi: u64::from(base) + MAP_LEN as u64,
        ..Default::default()
    };

    let inj = Box::new(Inj {
        ctx: &mut ctx,
        isr_lo: isr_addr,
        isr_hi: isr_addr + 8, // `inc [m32]` (6) + `iret` (1), rounded up
        isr_addr,
    });
    let inj_ptr = Box::into_raw(inj);
    INJ.store(inj_ptr, Ordering::Release);
    ACCEPTED.store(0, Ordering::Release);
    GUEST_TID.store(gettid(), Ordering::Release);

    // Driver thread: send lockstep injections, then raise `done`.
    let counter_addr = counter_ptr as usize;
    let done_addr = done_ptr as usize;
    let driver = std::thread::spawn(move || {
        let tid = loop {
            let t = GUEST_TID.load(Ordering::Acquire);
            if t != 0 {
                break t;
            }
            std::hint::spin_loop();
        };
        let pid = unsafe { libc::getpid() };
        let counter = counter_addr as *const u32;
        for i in 1..=deliveries {
            loop {
                unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, INJECT_SIGNO) };
                // Give the target a moment to take the signal and run the ISR.
                for _ in 0..2000 {
                    std::hint::spin_loop();
                }
                let seen = unsafe { std::ptr::read_volatile(counter) };
                if seen >= i {
                    break;
                }
            }
        }
        // Tell the guest to fall out of its loop and exit.
        unsafe { std::ptr::write_volatile(done_addr as *mut u32, 1) };
    });

    // Enter the guest; it spins (taking injections) until `done`, then exits
    // through `int 0x21`, which the DPMI fault arm turns into a service exit.
    // SAFETY: `ctx` addresses the live `mapping`, RWX for the call's duration.
    unsafe { enter(&mut ctx) };

    driver.join().expect("driver thread");

    // Tear down before dropping the boxed `Inj`.
    INJ.store(std::ptr::null_mut(), Ordering::Release);
    GUEST_TID.store(0, Ordering::Release);
    // SAFETY: `inj_ptr` came from `Box::into_raw` and is no longer published.
    drop(unsafe { Box::from_raw(inj_ptr) });

    assert_eq!(ctx.out_kind, 1, "guest exited via int 21h service");
    assert_eq!(ctx.out_vector, 0x21, "the exit vector");

    // SAFETY: single-threaded now (driver joined); the counter is live.
    unsafe { std::ptr::read_volatile(counter_ptr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_n_deliveries_no_loss_no_dup() {
        let n = 200;
        let counter = run_spike(n);
        assert_eq!(counter, n, "every injected tick entered the ISR exactly once");
        assert_eq!(
            ACCEPTED.load(Ordering::Acquire),
            n,
            "accepted injections match the guest's own count"
        );
    }

    #[test]
    fn cli_masks_injection_entirely() {
        let (counter, accepted) = run_cli_masks_injection(30);
        assert_eq!(counter, 0, "a cli'd guest ran its ISR zero times");
        assert_eq!(accepted, 0, "every injection was refused while IF was clear");
    }
}
