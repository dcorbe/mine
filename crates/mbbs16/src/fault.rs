//! Surviving a module that faults, or one that never returns.
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
//!
//! # Synchronous and asynchronous are not the same signal
//!
//! Everything above is about faults, which are **synchronous**: they arrive at
//! the instruction that caused them, and returning from the handler re-executes
//! it. That is what makes the "not ours" branch below safe -- restoring the
//! default disposition and returning kills the process exactly as it would have
//! died without us there.
//!
//! The watchdog's timer is **asynchronous**. It arrives anywhere, and it does
//! not re-raise. Passed through the same branch, the handler would return, the
//! host would carry on, and the disposition would now be `SIG_DFL` -- so the
//! *next* tick would terminate the process. Delayed, silent, and miserable to
//! debug. The window is not small either: the timer is armed across an entire
//! entry point, which includes all the time Rust spends servicing the module's
//! imports.
//!
//! So a tick arriving in host code is **ignored**, never passed through. See
//! [`crate::watchdog`] for the timer half.

use std::cell::Cell;
use std::io;
use std::sync::Once;
use std::sync::atomic::{AtomicU16, Ordering};

use crate::asm::Ctx;
use crate::watchdog;

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
    // SAFETY: emptying a freshly zeroed set, then blocking one signal in it.
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        // The one signal worth masking during a handler. A tick landing partway
        // through the context rewrite would be harmless -- it would see the
        // handler's own 64-bit CS and take the ignore branch -- but a timer that
        // cannot interrupt this handler at all is one fewer thing to reason
        // about, and it costs nothing. Faults are left unmasked: a handler that
        // faults should die, not deadlock.
        libc::sigaddset(&mut action.sa_mask, watchdog::signo());
    }

    // The watchdog's timer rides the same handler. Its recovery path is
    // identical to a fault's -- the context rewrite below is exactly what a
    // timeout needs -- and only the branch deciding whether to act on it
    // differs.
    for signo in FAULT_SIGNALS.into_iter().chain([watchdog::signo()]) {
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

/// Turn a module's fault, or its overrun, into an ordinary return from
/// [`crate::Machine::run`].
///
/// Async-signal-safe: it reads one atomic, edits the context in place, and
/// returns. No allocation, no locks, no library calls.
extern "C" fn handler(signo: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;

    let packed = gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;
    let host_cs = HOST_CS.load(Ordering::Relaxed);

    // R14 holds the `Ctx` passed to `mbbs16_enter`, which the caller keeps alive
    // across the excursion. Compatibility mode cannot name r8-r15, so 16-bit
    // code cannot have altered it -- which is what makes any of this recovery
    // possible. Only meaningful once we know we interrupted 16-bit code.
    let ctx16 = gregs[libc::REG_R14 as usize] as *mut Ctx;

    if signo == watchdog::signo() {
        // A watchdog tick. Asynchronous, so it must never reach the SIG_DFL
        // branch below -- see the module comment.
        //
        // The timer carries the address of the context it watches, which is the
        // only thing here that is meaningful no matter where the tick landed.
        // `R14` is not: it names an excursion, and there may not be one.
        //
        // SAFETY: `info` is non-null for an SA_SIGINFO handler, and a
        // POSIX-timer signal carries the `sigev_value` given to `timer_create`,
        // which is a `Ctx` the owning `Watched` keeps alive for as long as the
        // timer exists.
        let watched = unsafe { (*info).si_value().sival_ptr }.cast::<Ctx>();

        // Whose module is executing right now -- if anyone's -- decides only
        // *how* to stop it, not whether the budget is gone. It is gone either
        // way, so record that first and unconditionally.
        //
        // SAFETY: as above. Volatile because the host reads this field outside
        // any excursion and must not have the read optimised away.
        unsafe { std::ptr::write_volatile(&raw mut (*watched).expired, 1) };

        if faulting_cs == host_cs || !std::ptr::eq(ctx16, watched) {
            // Either nothing is in 16-bit mode, or someone else is. There is no
            // context here belonging to the overrunning module that could be
            // rewritten, so leave it to the host: it checks the flag just set
            // before it resumes the module, and refuses.
            //
            // Ignoring the tick is the *only* correct thing to do with it.
            // Passing it to the default disposition would leave SIG_DFL
            // installed on a signal that does not re-raise, and the next tick
            // would then terminate the process.
            return;
        }
    } else if faulting_cs == host_cs {
        // Not a module fault -- host code, or something else entirely. Put the
        // default disposition back and return, so the faulting instruction runs
        // again and kills us the way it would have without us here. Quietly
        // swallowing another subsystem's SIGSEGV would be much worse than
        // dying.
        //
        // Correct for every signal in FAULT_SIGNALS and ONLY because they are
        // synchronous: returning re-executes the faulting instruction. Nothing
        // asynchronous may be routed here.
        //
        // SAFETY: restoring the default disposition of a signal.
        unsafe {
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(signo, &dfl, std::ptr::null_mut());
        }
        return;
    }

    // 16-bit code was interrupted, and it is ours to stop.
    let host_ss = (gregs[libc::REG_R13 as usize] as u64) as u16;

    // SAFETY: as `ctx16` above.
    unsafe {
        (*ctx16).out_signo = signo as u64;
        // Where it stopped, taken before the rewrite below destroys it. The CPU
        // pushed CS:IP, so this is an offset within the module's code segment
        // and not a linear address -- which is exactly the number a disassembly
        // of the module image is annotated with.
        (*ctx16).out_cs = u64::from(faulting_cs);
        (*ctx16).out_ip = gregs[libc::REG_RIP as usize] as u64;
    }

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
