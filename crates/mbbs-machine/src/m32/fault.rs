//! Surviving a module that faults.
//!
//! # Sharing the disposition with other ABIs
//!
//! There is exactly one SIGSEGV/SIGILL/SIGBUS/SIGFPE disposition per process.
//! This crate used to install its own handler, deciding a fault was "ours"
//! whenever the faulting `CS` was not the host's -- which is also true of a
//! 16-bit fault, so a process running both ABIs would have had this handler
//! read a 16-bit excursion's `R14` as an `crate::m32::asm::Ctx*`, rewrite `SS`
//! from an `R13` nothing on this path ever sets, and corrupt the process.
//! Installing `mbbs16`'s old handler instead broke the same thing in
//! reverse.
//!
//! [`crate::fault`] is the fix this module now registers with instead of
//! installing its own handler: every ABI gets a *positive* claim over the
//! faulting `CS` -- [`is_user32_cs`] here -- rather than deciding by ruling
//! the host out, and the shared handler tries each ABI's claim in turn.
//!
//! # The recovery protocol, and why it is one register lighter than mbbs16's
//!
//! `mbbs16` recovers by editing the interrupted context so `sigreturn` lands
//! back in host code: `RIP` from `R11`, `RSP` from `R15`, `SS` from `R13`, `CS`
//! back to the host's. `docs/plans/mbbs32/compat32_fault.c` measured the same
//! manoeuvre for 32-bit compatibility mode and found `SS` **never disturbed** --
//! 32-bit flat code runs on the host's own stack segment, so there is nothing
//! `R13` would need to carry. The protocol here is `RIP <- R11`, `RSP <- R15`,
//! `CS <- host`, and nothing else.
//!
//! `EIP` is reported as a **linear address**, unlike `crate::m16::Exit::Fault`'s
//! `cs:ip`: a flat segment has base zero, so the value the CPU pushed already
//! is the number a disassembly of the mapped image is annotated with.
//!
//! # The alternate stack is not optional
//!
//! Without `SA_ONSTACK`, a signal taken in compatibility mode kills the
//! process outright: the kernel cannot build a frame on a `RSP` that
//! compatibility mode has truncated, calls `force_sigsegv()`, fails the same
//! way again, and dies with a handler installed. Measured in
//! <https://github.com/dcorbe/x86-compat16> and inherited here unchanged --
//! see `crates/mbbs-machine/src/m16/fault.rs`'s module comment for the fuller account,
//! including why the stack's *address* (as opposed to `SA_ONSTACK` itself)
//! turned out not to matter. [`crate::fault`] owns the one alternate
//! stack this thread gets; both ABIs share it.
//!
//! # The FS_BASE hazard, and why this file does not need to fix it
//!
//! Task 15's `Tib` gives a module's `FS` a real LDT descriptor, which means
//! `FS_BASE` -- the MSR long-mode addressing actually uses for `%fs`-relative
//! access, including glibc's own thread-local storage -- is the **module's**
//! TIB address at the instant a fault is taken, not the host's. [`recover`]
//! touches no `thread_local`, does no allocation, and calls no library
//! function at all -- not even `libc::sigaction`, unlike the standalone
//! handler this module used to install, because giving up a claimed fault
//! back to `SIG_DFL` is now [`crate::fault`]'s job, reached only once
//! nobody's claim matched, which never happens while `FS_BASE` is wrong --
//! so nothing here depends on `FS_BASE` being correct while it runs.
//!
//! Measured the hard way while instrumenting this file to print the faulting
//! `CS`: a single `libc::write` call inserted into this path was enough to
//! crash the test process, because glibc's wrapper touches `%fs`-relative
//! TLS to set `errno`, and `%fs` at that instant names the module's TIB, not
//! the host's. A raw `syscall` instruction has no such problem. That
//! instrumentation is gone; the failure it produced is recorded here because
//! it is exactly the class of mistake this section warns against, caught in
//! the act rather than merely asserted.
//!
//! The restoration itself already happens regardless: [`crate::m32::asm::enter`]
//! wraps every crossing in an unconditional `arch_prctl(ARCH_GET_FS)` /
//! `arch_prctl(ARCH_SET_FS)` pair, and that wrapper's shape does not care
//! *how* [`crate::m32::asm::mbbs32_enter_raw`][raw] returns to it -- by the
//! trampoline's cooperative `jmp *%r11`, or by this handler rewriting `RIP`
//! to the same address `R11` already names. Either way control lands back at
//! the same instruction inside `enter`, and `set_fs_base` runs next. That is
//! exactly why the recovery protocol above targets `R11`/`R15` rather than
//! the trampoline itself: it reproduces the trampoline's *landing site*, not
//! its body, and the landing site is where `enter`'s own safety net already
//! lives. `a_faulting_module_leaves_the_hosts_thread_locals_working` below is
//! the test that checks this rather than trusts it.
//!
//! # The watchdog rides the same arbiter, asynchronously
//!
//! Task 16 lands `crate::m32::watchdog`: a per-machine CPU-time timer, the
//! flat-ABI mirror of `crate::m16::watchdog`. Its signal is asynchronous --
//! it can land anywhere, not only at the instruction that provoked it -- so
//! it cannot be dispatched by a `CS` claim the way [`is_user32_cs`] decides
//! a fault. It rides `crate::fault`'s registry as its own
//! [`crate::fault::AsyncClaim`] instead, and shares the exact real-time
//! signal `crate::m16::watchdog` already claims (`crate::fault`'s module doc
//! comment, "Two signal classes"), so [`recover_watchdog`] cannot assume
//! every delivery is this ABI's: it untags the payload against [`owner`],
//! this ABI's own registered slot, before treating anything as an
//! `m32::asm::Ctx`. See `crate::m32::watchdog`'s own module doc comment for
//! the timer half.
//!
//! [raw]: crate::m32::asm

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::m32::asm::Ctx;
use crate::m32::watchdog;

/// `UC_STRICT_RESTORE_SS` from `<asm/ucontext.h>`, which libc does not
/// re-export. `compat32_fault.c` set this unconditionally even though it
/// deliberately left `SS` untouched, and recovery still worked -- so it is
/// carried over here for the same reason `mbbs16` sets it: telling
/// `sigreturn` to trust the frame's `SS` rather than second-guess it costs
/// nothing when `SS` is correct, which it always is here (never rewritten).
const UC_STRICT_RESTORE_SS: libc::c_ulong = 0x4;

static INSTALL: std::sync::Once = std::sync::Once::new();

/// This ABI's slot index in the shared arbiter's registry -- see
/// `crate::m16::fault::OWNER`'s own doc comment, which this mirrors
/// exactly.
static OWNER: AtomicUsize = AtomicUsize::new(usize::MAX);

/// This ABI's registered slot in the shared arbiter, for tagging a new
/// watchdog's `sigval` -- see [`crate::fault::tag`].
///
/// # Panics
///
/// If called before [`arm`] has run at least once in this process. Every
/// [`crate::m32::Machine::new`] calls `arm` before building a
/// [`watchdog::Watched`], so this only fires if that ordering is broken.
pub(crate) fn owner() -> usize {
    let owner = OWNER.load(Ordering::Relaxed);
    assert_ne!(owner, usize::MAX, "m32::fault::owner() read before arm() registered");
    owner
}

/// Make module faults survivable on this thread, and register this ABI's
/// claim -- and its watchdog's -- with the shared arbiter.
///
/// Registers the process-wide claim on first call only, and arms this
/// thread's alternate signal stack every time -- the claim is shared across
/// every thread once registered, the stack is not.
pub(crate) fn arm(host_cs: u16) -> io::Result<()> {
    crate::fault::install_altstack()?;

    let mut result = Ok(());
    INSTALL.call_once(|| {
        result = crate::fault::register(
            host_cs,
            crate::fault::FaultClaim {
                claims: is_user32_cs,
                recover,
            },
            Some(crate::fault::AsyncClaim {
                signo: watchdog::signo(),
                recover: recover_watchdog,
            }),
        )
        .map(|i| OWNER.store(i, Ordering::Relaxed));
    });
    result
}

/// This ABI's positive claim: 32-bit module code always runs under Linux's
/// fixed `__USER32_CS` GDT selector, `0x23` -- there is no `modify_ldt` call
/// for it, unlike `mbbs16`'s per-module LDT segments, so one constant is the
/// whole test. Measured, not assumed: instrumenting the handler and driving
/// this file's own tests below recorded `0x23` on every delivery, against a
/// host `CS` of `0x33`.
fn is_user32_cs(cs: u16) -> bool {
    cs == crate::m32::asm::USER32_CS
}

/// Bit position of `CS` inside the packed segment-register `greg`. `SS`'s
/// counterpart (`crate::m16::fault`'s `SS_SHIFT`) has no analogue here: `SS` is
/// never rewritten, so nothing in this file ever shifts anything into it.
const CS_SHIFT: u32 = 0;

/// Everything except `CS`: `GS`, `FS` and -- unlike `crate::m16::fault`'s mask --
/// `SS` too, which this file leaves exactly as the CPU already has it.
const KEEP_EVERYTHING_BUT_CS: u64 = 0xffff_ffff_ffff_0000;

/// Turn a module's fault into an ordinary return from [`crate::m32::asm::enter`].
///
/// Async-signal-safe: it edits the interrupted context in place and returns.
/// No allocation, no locks, and -- on this path, always, now that giving a
/// fault back up to `SIG_DFL` belongs to [`crate::fault`] -- no library
/// call either; see the module doc comment's "FS_BASE hazard" section for
/// why that specifically matters here.
///
/// # Safety
///
/// See [`crate::fault::RecoverFn`]. Called only after [`is_user32_cs`] has
/// claimed the faulting `CS`, which is what makes reading `R14` as a
/// `*mut Ctx` sound -- see the field below.
unsafe fn recover(signo: libc::c_int, ctx: *mut libc::c_void, host_cs: u16) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;
    let packed = gregs[libc::REG_CSGSFS as usize] as u64;

    // 32-bit module code was interrupted, and it is ours to stop. R14 holds
    // the Ctx passed to mbbs32_enter_raw, which the caller keeps alive across
    // the excursion. Compatibility mode cannot name r8-r15, so 32-bit code
    // cannot have altered it -- which is what makes any of this recovery
    // possible.
    let ctx32 = gregs[libc::REG_R14 as usize] as *mut Ctx;

    // SAFETY: `ctx32`, `gregs` and `packed` all come from this same fault;
    // `ctx32` is the live `Ctx` this excursion was entered with.
    unsafe { rewrite(uc, packed, ctx32, signo, host_cs) };
}

/// Handle one delivery of the watchdog's timer, whether or not it concerns
/// this excursion. The 32-bit mirror of `crate::m16::fault::recover_watchdog`
/// -- see that function's own doc comment for the shape; the only
/// substantive difference is `crate::m32::fault`'s one-register-lighter
/// rewrite (no `SS`, no `DS` reload -- see this module's doc comment).
///
/// # Safety
///
/// See [`crate::fault::AsyncRecoverFn`]. Reached for *every* delivery of
/// [`watchdog::signo`], regardless of what was executing -- unlike
/// [`recover`], no CS claim has been checked yet, and (now that `m16`'s
/// watchdog shares this same signal number) not even the ABI is known
/// until [`owner`] says so.
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

    // R14 holds the `Ctx` passed to `mbbs32_enter_raw`. Meaningful only once
    // we know 32-bit code was actually interrupted -- see below.
    let ctx32 = gregs[libc::REG_R14 as usize] as *mut Ctx;

    // The timer carries the (tagged) address of the context it watches --
    // see this module's own doc comment, "The watchdog rides the same
    // arbiter, asynchronously".
    //
    // SAFETY: `info` is non-null for an SA_SIGINFO handler, and a
    // POSIX-timer signal carries the `sigev_value` given to `timer_create`,
    // which is `crate::fault::tag`'s output over a `Ctx` the owning
    // `Watched` keeps alive for as long as the timer exists.
    let sival_ptr = unsafe { (*info).si_value().sival_ptr };
    // SAFETY: `Watched::new` built this `sigval` with `crate::fault::tag`
    // over a `Ctx`, which is the same `T` named here.
    let Some(watched) = (unsafe { crate::fault::untag::<Ctx>(sival_ptr, owner()) }) else {
        // Tagged for a different ABI's slot -- not an error, just not ours.
        return;
    };

    // Whose module is executing right now -- if anyone's -- decides only
    // *how* to stop it, not whether the budget is gone. It is gone either
    // way, so record that first and unconditionally.
    //
    // SAFETY: as above. Volatile because the host reads this field outside
    // any excursion and must not have the read optimised away.
    unsafe { std::ptr::write_volatile(&raw mut (*watched).expired, 1) };

    if faulting_cs == host_cs || !std::ptr::eq(ctx32, watched) {
        // Either nothing is in 32-bit mode, or someone else is. Leave it to
        // the host, which checks the flag just set before it resumes the
        // module and refuses. See `crate::m16::fault::recover_watchdog`'s
        // own comment on this branch -- identical reasoning.
        return;
    }

    // SAFETY: `ctx32`, `gregs` and `packed` all come from this same
    // delivery; `ctx32 == watched`, just proven above, and `watched` is a
    // live `Ctx` for as long as its `Watched` exists.
    unsafe { rewrite(uc, packed, ctx32, signo, host_cs) };
}

/// The context rewrite shared by a synchronous fault and a watchdog tick
/// that has decided to act: point `sigreturn` back at host code, exactly as
/// the trampoline would have on an ordinary return. Mirrors
/// `crate::m16::fault::rewrite`, minus the `SS`/`DS` handling this ABI
/// never needs (see the module doc comment).
///
/// # Safety
///
/// `ctx32` must be a live, dereferenceable `*mut Ctx` -- the excursion's own
/// context, still owned by its caller's stack frame (or, for the watchdog,
/// by the `Watched` that armed the timer).
unsafe fn rewrite(
    uc: &mut libc::ucontext_t,
    packed: u64,
    ctx32: *mut Ctx,
    signo: libc::c_int,
    host_cs: u16,
) {
    let gregs = &mut uc.uc_mcontext.gregs;

    // SAFETY: `ctx32` is the live `Ctx` this excursion was entered with, and
    // it outlives the call (owned by the caller's stack frame for the
    // duration of `enter`, or by the `Watched` that armed the timer).
    unsafe {
        (*ctx32).out_signo = signo as u64;
        // Where it stopped, taken before the rewrite below destroys it. A
        // linear address, not an offset -- see the module doc comment.
        (*ctx32).out_eip = gregs[libc::REG_RIP as usize] as u32;
    }

    gregs[libc::REG_RIP as usize] = gregs[libc::REG_R11 as usize];
    gregs[libc::REG_RSP as usize] = gregs[libc::REG_R15 as usize];
    gregs[libc::REG_CSGSFS as usize] =
        ((packed & KEEP_EVERYTHING_BUT_CS) | u64::from(host_cs) << CS_SHIFT) as libc::greg_t;

    // SS was never touched above, so this is not strictly required the way
    // it is in mbbs16 (which just wrote a new one) -- but it is exactly what
    // the measured recovery in `compat32_fault.c` did, and asserting it costs
    // nothing.
    uc.uc_flags |= UC_STRICT_RESTORE_SS;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m32::asm::{USER32_CS, current_cs, enter, trampoline};
    use crate::m32::map::Mapping;

    /// Bytes for `ljmp $USER_CS, $target` (`ljmp ptr16:32`, opcode `0xea`).
    fn ljmp_back(target: u32) -> [u8; 7] {
        let mut b = [0u8; 7];
        b[0] = 0xea;
        b[1..5].copy_from_slice(&target.to_le_bytes());
        b[5..7].copy_from_slice(&current_cs().to_le_bytes());
        b
    }

    /// A fresh low mapping with the trampoline at its base and `build`'s
    /// bytes right after it. Same layout `asm.rs`'s own `low_mapping_with`
    /// uses; duplicated rather than shared because that helper is private to
    /// `asm::tests`.
    fn low_mapping_with(build: impl FnOnce(u32) -> Vec<u8>) -> (Mapping, u32) {
        let mut mapping = Mapping::new(4096).expect("a low mapping");
        let tramp_addr = mapping.base() as usize as u32;
        let tramp = trampoline();
        let tramp_len = tramp.len();
        let code_off = tramp_len.div_ceil(16) * 16;

        let code = build(tramp_addr);
        assert!(code_off + code.len() <= mapping.len());

        let dst = mapping.as_mut_slice();
        dst[..tramp_len].copy_from_slice(tramp);
        dst[code_off..code_off + code.len()].copy_from_slice(&code);

        (mapping, tramp_addr + code_off as u32)
    }

    /// `mov eax, [0]` -- an ordinary, unprefixed dereference of address zero.
    /// `docs/plans/mbbs32/compat32_fault.c` uses the identical instruction:
    /// it faults on the null *segment* (`DS`) in that experiment, but
    /// `mbbs32_enter_raw` loads a real flat `DS` before every jump (see
    /// `asm.rs`), so here it faults on the null *address* instead -- either
    /// way, a SIGSEGV taken squarely inside 32-bit compatibility mode.
    fn null_deref_code(tramp_addr: u32) -> Vec<u8> {
        let mut code = vec![0xa1u8, 0x00, 0x00, 0x00, 0x00]; // mov eax, moffs32(0)
        code.extend_from_slice(&ljmp_back(tramp_addr));
        code
    }

    #[test]
    fn a_module_that_dereferences_null_recovers_rather_than_killing_the_process() {
        arm(current_cs()).expect("install the fault handler");

        let (_mapping, code_addr) = low_mapping_with(null_deref_code);

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            ..Default::default()
        };
        // SAFETY: `code_addr` names the freshly written instructions above,
        // mapped read/write/execute below 4 GiB; `_mapping` outlives the
        // call. A signal handler is installed, so the fault this code takes
        // is recoverable rather than fatal.
        unsafe { enter(&mut ctx) };

        assert_eq!(
            ctx.out_signo,
            i64::from(libc::SIGSEGV) as u64,
            "the module's fault was not recorded"
        );
        assert_eq!(
            ctx.out_eip, code_addr,
            "EIP did not name the faulting instruction"
        );
    }

    #[test]
    fn a_fault_from_the_wrong_selector_is_not_mistaken_for_the_hosts_own() {
        // A regression guard for the dispatch condition itself: a module
        // fault must never be routed to the "not ours" branch, which would
        // restore SIG_DFL on a signal a *later* test in this same process
        // still needs handled -- corrupting every test that runs after it,
        // not just this one.
        arm(current_cs()).expect("install the fault handler");

        let (_mapping, code_addr) = low_mapping_with(null_deref_code);
        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            ..Default::default()
        };
        // SAFETY: as above.
        unsafe { enter(&mut ctx) };
        assert_ne!(ctx.out_signo, 0, "the fault was not recovered at all");

        // Prove the handler is still live and still ours: fault again.
        let (_mapping2, code_addr2) = low_mapping_with(null_deref_code);
        let mut ctx2 = Ctx {
            target_offset: code_addr2,
            target_selector: USER32_CS,
            ..Default::default()
        };
        // SAFETY: as above.
        unsafe { enter(&mut ctx2) };
        assert_eq!(
            ctx2.out_signo,
            i64::from(libc::SIGSEGV) as u64,
            "SIGSEGV's disposition was not still ours after the first recovery -- \
             the \"not ours\" branch must have fired and restored SIG_DFL"
        );
    }

    /// The FS_BASE hazard the module doc comment describes: a module's own
    /// `FS` names its TIB while it runs, so `FS_BASE` is the *module's*
    /// address, not the host's, at the instant a fault is taken. This test is
    /// what proves `crate::m32::asm::enter`'s unconditional restore covers the
    /// fault path too, rather than merely asserting that it should -- with a
    /// real [`crate::m32::tib::Tib`], exactly what `wccmmud.dll` gets, rather than
    /// a stand-in selector.
    #[test]
    fn a_faulting_module_leaves_the_hosts_thread_locals_working() {
        use std::cell::Cell;
        thread_local! {
            static PROBE: Cell<u32> = const { Cell::new(0) };
        }

        arm(current_cs()).expect("install the fault handler");

        let tib = crate::m32::tib::Tib::new(crate::m32::tib::DEFAULT_STACK_LEN).expect("a Tib");

        let (_mapping, code_addr) = low_mapping_with(null_deref_code);

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            fs: tib.fs_selector(),
            esp: tib.stack_base() - 0x100, // never touched by this code
            ..Default::default()
        };
        // SAFETY: `code_addr` is mapped read/write/execute below 4 GiB and
        // outlives the call; `tib.fs_selector()` names a live LDT descriptor
        // over `tib`'s own mapping, which also outlives the call.
        unsafe { enter(&mut ctx) };
        assert_ne!(ctx.out_signo, 0, "the module did not fault as expected");

        // If FS_BASE were still the module's, this would write through the
        // wrong base -- either corrupting unrelated memory or faulting the
        // test process itself, not merely reading back the wrong value.
        PROBE.with(|p| p.set(0xdead_beef));
        assert_eq!(
            PROBE.with(|p| p.get()),
            0xdead_beef,
            "the host's own thread_local storage did not survive a module fault"
        );
    }
}
