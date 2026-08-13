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
//! # Sharing the disposition with other ABIs
//!
//! There is exactly one SIGSEGV/SIGILL/SIGBUS/SIGFPE disposition per process,
//! so a host running both a 16-bit and a 32-bit module in one process cannot
//! have each crate install its own handler -- the second `Machine::new` would
//! silently take the first ABI's handler away, and worse: `mbbs32`'s old
//! handler decided a fault was "ours" by checking `CS != host_cs`, which is
//! true for a 16-bit fault too, so it would have read `R14` as the wrong
//! `Ctx` type and corrupted the process. See [`crate::fault`] for the
//! shared arbiter this module now registers with instead of installing its
//! own handler: it claims a fault only when [`is_ldt_selector`] answers yes,
//! never by ruling out the host.
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
//! So the rule is `SA_ONSTACK`, not the address. [`crate::fault`]'s shared
//! `install_altstack` keeps `MAP_32BIT` anyway, for the same reason this
//! module always did: it costs nothing and rules out a whole class of
//! surprise for free.
//!
//! # Synchronous and asynchronous are not the same signal
//!
//! Everything above is about faults, which are **synchronous**: they arrive at
//! the instruction that caused them, and returning from the handler re-executes
//! it. That is what makes "nobody claims it" safe -- `crate::fault::register`'s
//! shared handler restoring the default disposition and returning kills the
//! process exactly as it would have died without us there.
//!
//! The watchdog's timer is **asynchronous**. It arrives anywhere, and it does
//! not re-raise. Dispatched the way a fault is -- by asking every ABI's claim
//! predicate whether it owns the interrupted `CS` -- a tick that lands in host
//! code would find no claimant, hit the "nobody claims it" branch, and leave
//! the disposition at `SIG_DFL` -- so the *next* tick would terminate the
//! process. Delayed, silent, and miserable to debug. The window is not small
//! either: the timer is armed across an entire entry point, which includes
//! all the time Rust spends servicing the module's imports.
//!
//! So the watchdog signal is registered with the arbiter as its own
//! [`crate::fault::AsyncClaim`], not folded into the CS-claim dispatch: every
//! delivery reaches [`recover_watchdog`] unconditionally, `CS` never enters
//! into whether it is "ours" to look at. See [`crate::m16::watchdog`] for the
//! timer half.

use std::io;

use crate::m16::asm::Ctx;
use crate::m16::watchdog;

/// `UC_STRICT_RESTORE_SS` from `<asm/ucontext.h>`, which libc does not re-export.
/// Setting it tells `sigreturn` to restore `SS` from the frame unconditionally,
/// which is what we want given we have just written a new one into it.
const UC_STRICT_RESTORE_SS: libc::c_ulong = 0x4;

static INSTALL: std::sync::Once = std::sync::Once::new();

/// Make module faults survivable on this thread, and register this ABI's
/// claim with the shared arbiter.
///
/// Registers the process-wide claim on first call only -- see
/// [`crate::fault::register`]'s doc comment for why that guard has to live
/// here rather than inside the arbiter -- and arms this thread's alternate
/// signal stack every time, since that part is per-thread, not per-ABI.
pub(crate) fn arm(host_cs: u16) -> io::Result<()> {
    crate::fault::install_altstack()?;

    let mut result = Ok(());
    INSTALL.call_once(|| {
        result = crate::fault::register(
            host_cs,
            crate::fault::FaultClaim {
                claims: is_ldt_selector,
                recover: recover_fault,
            },
            Some(crate::fault::AsyncClaim {
                signo: watchdog::signo(),
                recover: recover_watchdog,
            }),
        );
    });
    result
}

/// This ABI's positive claim: 16-bit module code runs in the LDT, never the
/// GDT. [`crate::m16::seg::Segment::selector`] always sets the table-indicator bit
/// (`| 0x7`, TI and RPL 3 together), so any faulting selector with that bit
/// set names one of this module's own segments and nothing else in the
/// process ever runs under one. Measured, not assumed: instrumenting the
/// handler and driving `crates/mbbs-machine/tests/fault.rs`'s fixture recorded
/// `0x07`/`0x0f`/`0x47`/`0x4f` -- always TI set -- against a host `CS` of
/// `0x33`, which never has it.
fn is_ldt_selector(cs: u16) -> bool {
    cs & 0x4 != 0
}

/// Bit positions inside the packed segment-register `greg`.
const CS_SHIFT: u32 = 0;
const SS_SHIFT: u32 = 48;
/// Everything between `CS` and `SS`: `GS` and `FS`, which we leave alone.
const KEEP_GS_FS: u64 = 0x0000_ffff_ffff_0000;

/// Turn a module's fault, or its overrun, into an ordinary return from
/// [`crate::m16::Machine::run`].
///
/// Async-signal-safe: it reads the interrupted context, edits it in place,
/// and returns. No allocation, no locks, no library calls.
///
/// # Safety
///
/// See [`crate::fault::RecoverFn`]. Called only after [`is_ldt_selector`] has
/// claimed the faulting `CS`, which is what makes reading `R14` as a
/// `*mut Ctx` sound -- see the field below.
unsafe fn recover_fault(signo: libc::c_int, ctx: *mut libc::c_void, host_cs: u16) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;
    let packed = gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;

    // R14 holds the `Ctx` passed to `mbbs16_enter`, which the caller keeps
    // alive across the excursion. Compatibility mode cannot name r8-r15, so
    // 16-bit code cannot have altered it -- which is what makes any of this
    // recovery possible.
    let ctx16 = gregs[libc::REG_R14 as usize] as *mut Ctx;

    // SAFETY: `ctx16`, `gregs` and `packed` all come from this same fault;
    // `ctx16` is the live `Ctx` this excursion was entered with.
    unsafe { rewrite(uc, packed, ctx16, signo, faulting_cs, host_cs) };
}

/// Handle one delivery of the watchdog's timer, whether or not it concerns
/// this excursion.
///
/// # Safety
///
/// See [`crate::fault::AsyncRecoverFn`]. Reached for *every* delivery of
/// [`watchdog::signo`], regardless of what was executing -- unlike
/// [`recover_fault`], no CS claim has been checked yet.
unsafe fn recover_watchdog(
    signo: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
    host_cs: u16,
) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;
    let packed = gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;

    // R14 holds the `Ctx` passed to `mbbs16_enter`. Meaningful only once we
    // know 16-bit code was actually interrupted -- see below.
    let ctx16 = gregs[libc::REG_R14 as usize] as *mut Ctx;

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
        // Either nothing is in 16-bit mode, or someone else is (possibly
        // another ABI's module entirely, or this ABI's own module on a
        // different excursion). There is no context here belonging to the
        // overrunning module that could be rewritten, so leave it to the
        // host: it checks the flag just set before it resumes the module,
        // and refuses.
        //
        // Ignoring the tick is the *only* correct thing to do with it. See
        // the module doc comment for why it must never fall through to the
        // arbiter's "nobody claims it" branch.
        return;
    }

    // SAFETY: `ctx16`, `gregs` and `packed` all come from this same
    // delivery; `ctx16 == watched`, just proven above, and `watched` is a
    // live `Ctx` for as long as its `Watched` exists.
    unsafe { rewrite(uc, packed, ctx16, signo, faulting_cs, host_cs) };
}

/// The context rewrite shared by a synchronous fault and a watchdog tick
/// that has decided to act: point `sigreturn` back at host code, exactly as
/// the trampoline would have on an ordinary return.
///
/// # Safety
///
/// `ctx16` must be a live, dereferenceable `*mut Ctx` -- the excursion's own
/// context, still owned by its caller's stack frame (or, for the watchdog,
/// by the `Watched` that armed the timer).
unsafe fn rewrite(
    uc: &mut libc::ucontext_t,
    packed: u64,
    ctx16: *mut Ctx,
    signo: libc::c_int,
    faulting_cs: u16,
    host_cs: u16,
) {
    let gregs = &mut uc.uc_mcontext.gregs;
    let host_ss = (gregs[libc::REG_R13 as usize] as u64) as u16;

    // SAFETY: as this function's own safety section.
    unsafe {
        (*ctx16).out_signo = signo as u64;
        // Where it stopped, taken before the rewrite below destroys it. The
        // CPU pushed CS:IP, so this is an offset within the module's code
        // segment and not a linear address -- which is exactly the number a
        // disassembly of the module image is annotated with.
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
