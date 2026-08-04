//! Surviving a module that faults.
//!
//! A 16-bit module can divide by zero, execute a privileged instruction, or
//! dereference a pointer to nowhere, and none of that should take the host down
//! with it. Recovery works by editing the interrupted context so that
//! `sigreturn` lands back in host code, which is the same manoeuvre
//! `<asm/ucontext.h>` describes DOSEMU using:
//!
//! > These DOSEMU versions expect sigreturn to send them back to 64-bit mode
//! > without killing them, despite the fact that the SS selector when the
//! > signal was raised is no longer valid.
//!
//! The edit is not invented. It reproduces exactly what the trampoline would
//! have done had the module reached it: `RIP` from `R11`, `RSP` from `R15`,
//! `SS` from `R13`, `CS` back to the host's. Those four registers are set
//! before every entry and compatibility mode has no encoding that can disturb
//! them, so they are still intact at the moment of the fault.
//!
//! # The alternate stack is not optional -- but its address is
//!
//! Without `SA_ONSTACK`, a signal taken in compatibility mode kills the
//! process: the kernel cannot build a frame, calls `force_sigsegv()`, fails the
//! same way again, and dies with a handler installed. That much was measured in
//! <https://github.com/dcorbe/x86-compat16>.
//!
//! That project also concluded the alternate stack had to be **below 4 GiB**,
//! which was wrong: its fix added an alternate stack *and* mapped it low, and
//! the low mapping was credited with both. Dropping `MAP_32BIT` here changed
//! nothing, and compat16 now carries a three-arm test that settles it --
//! killed with no alternate stack, fine with one at any address.
//!
//! So the rule is `SA_ONSTACK`, not the address. That makes sense: with an
//! alternate stack the frame goes at a location the kernel already knows,
//! instead of one derived from an `RSP` that compatibility mode has truncated
//! and a 16-bit `SS` has re-based.
//!
//! `MAP_32BIT` is kept below anyway. It costs nothing and rules out a whole
//! class of surprise for free.

use std::cell::Cell;
use std::io;
use std::sync::Once;
use std::sync::atomic::{AtomicU16, Ordering};

use crate::asm::Ctx;

/// Signals a module can raise by misbehaving. `SIGTRAP` is deliberately absent:
/// it belongs to debuggers, and a module executing `int3` is pathological
/// rather than routine.
const FAULT_SIGNALS: [i32; 4] = [libc::SIGSEGV, libc::SIGILL, libc::SIGBUS, libc::SIGFPE];

/// `UC_STRICT_RESTORE_SS` from `<asm/ucontext.h>`, which libc does not re-export.
/// Setting it tells `sigreturn` to restore `SS` from the frame unconditionally,
/// which is what we want given we have just written a new one into it.
const UC_STRICT_RESTORE_SS: libc::c_ulong = 0x4;

/// Size of the alternate signal stack. A handler that only edits registers
/// needs very little, but `SIGSTKSZ` worth costs nothing.
const ALTSTACK_BYTES: usize = 64 * 1024;

/// The 64-bit code selector host code runs under, recorded when the handlers go
/// in. The handler compares against it to decide whether a fault is a module's
/// or someone else's, so it must be a plain value readable without allocation.
static HOST_CS: AtomicU16 = AtomicU16::new(0);

static INSTALL: Once = Once::new();

thread_local! {
    /// This thread's alternate signal stack, mapped once and kept.
    static ALTSTACK: Cell<*mut libc::c_void> = const { Cell::new(std::ptr::null_mut()) };
}

/// Make module faults survivable on this thread.
///
/// Installs the process-wide handlers on first call, and this thread's
/// alternate signal stack every time -- the handlers are shared, the stack is
/// not.
pub(crate) fn arm(host_cs: u16) -> io::Result<()> {
    install_altstack()?;

    let mut result = Ok(());
    INSTALL.call_once(|| {
        HOST_CS.store(host_cs, Ordering::Relaxed);
        result = install_handlers();
    });
    result
}

fn install_altstack() -> io::Result<()> {
    ALTSTACK.with(|slot| {
        if slot.get().is_null() {
            // SAFETY: an ordinary anonymous mapping. MAP_32BIT is the whole
            // point -- see the module comment.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ALTSTACK_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            slot.set(base);
        }

        let stack = libc::stack_t {
            ss_sp: slot.get(),
            ss_size: ALTSTACK_BYTES,
            ss_flags: 0,
        };
        // SAFETY: `stack` describes a live mapping owned by this thread for the
        // rest of its life.
        if unsafe { libc::sigaltstack(&stack, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

fn install_handlers() -> io::Result<()> {
    // SAFETY: zeroed sigaction is a valid starting point; every field used is
    // set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
    // SAFETY: emptying a freshly zeroed set.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };

    for signo in FAULT_SIGNALS {
        // SAFETY: `action` is fully initialised and outlives the call.
        if unsafe { libc::sigaction(signo, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Bit positions inside the packed segment-register `greg`.
const CS_SHIFT: u32 = 0;
const SS_SHIFT: u32 = 48;
/// Everything between `CS` and `SS`: `GS` and `FS`, which we leave alone.
const KEEP_GS_FS: u64 = 0x0000_ffff_ffff_0000;

/// Turn a module's fault into an ordinary return from [`crate::Machine::enter`].
///
/// Async-signal-safe: it reads one atomic, edits the context in place, and
/// returns. No allocation, no locks, no library calls.
extern "C" fn handler(signo: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;

    let packed = gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;
    let host_cs = HOST_CS.load(Ordering::Relaxed);

    if faulting_cs == host_cs {
        // Not a module fault -- host code, or something else entirely. Put the
        // default disposition back and return, so the faulting instruction runs
        // again and kills us the way it would have without us here. Quietly
        // swallowing another subsystem's SIGSEGV would be much worse than
        // dying.
        //
        // This is correct for every signal in FAULT_SIGNALS and ONLY because
        // they are synchronous: returning re-executes the faulting instruction.
        // An asynchronous signal does not re-raise, so this branch would let it
        // through *and* leave SIG_DFL installed, and the next one would
        // terminate the process. If a watchdog timer is added here it needs its
        // own branch that simply ignores a signal arriving in host code -- see
        // "Revisit early: the watchdog" in
        // docs/plans/2026-08-03-16bit-module-execution.md.
        //
        // SAFETY: restoring the default disposition of a signal.
        unsafe {
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(signo, &dfl, std::ptr::null_mut());
        }
        return;
    }

    // The fault happened in 16-bit code, so the excursion registers are still
    // exactly as `mbbs16_enter` left them: compatibility mode cannot name
    // r8-r15, which is what makes this recovery possible at all.
    let ctx16 = gregs[libc::REG_R14 as usize] as *mut Ctx;
    let host_ss = (gregs[libc::REG_R13 as usize] as u64) as u16;

    // SAFETY: R14 holds the `Ctx` passed to `mbbs16_enter`, which the caller
    // keeps alive across the excursion, and 16-bit code cannot have altered it.
    unsafe { (*ctx16).out_signo = signo as u64 };

    // DS is not part of the x86-64 signal frame, so `sigreturn` will not put it
    // back. Set it here instead -- the change outlives the handler precisely
    // because nothing will overwrite it. R12 holds the host's, put there by
    // `mbbs16_enter` for the trampoline that this is standing in for.
    let host_ds = gregs[libc::REG_R12 as usize] as u16;
    // SAFETY: loading a selector the host was already running under.
    unsafe { std::arch::asm!("mov ds, {0:x}", in(reg) host_ds, options(nostack, preserves_flags)) };

    gregs[libc::REG_RIP as usize] = gregs[libc::REG_R11 as usize];
    gregs[libc::REG_RSP as usize] = gregs[libc::REG_R15 as usize];
    gregs[libc::REG_CSGSFS as usize] = ((packed & KEEP_GS_FS)
        | u64::from(host_cs) << CS_SHIFT
        | u64::from(host_ss) << SS_SHIFT) as libc::greg_t;

    // We have just replaced the saved SS. Say so, rather than relying on the
    // kernel deciding the old one was still valid.
    uc.uc_flags |= UC_STRICT_RESTORE_SS;
}
