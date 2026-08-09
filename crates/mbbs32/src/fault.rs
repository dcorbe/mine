//! Surviving a module that faults.
//!
//! # This handler and mbbs16's cannot both be installed
//!
//! There is exactly one SIGSEGV disposition per process. mbbs16's handler
//! dispatches on two cases -- host CS, or "ours" -- so a 32-bit fault (CS 0x23)
//! lands in its 16-bit branch and has SS rewritten from R13, which nothing on
//! this path sets. Installing this one instead breaks the same thing in reverse.
//!
//! Running both ABIs in one process needs a single arbiter dispatching three
//! ways on the faulting CS. That is designed in
//! `docs/plans/2026-08-08-mbbs32-design.md` and deliberately NOT built here:
//! this increment runs 32-bit modules alone. Do not "fix" the duplication by
//! making one crate call the other.
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
//! `EIP` is reported as a **linear address**, unlike `mbbs16::Exit::Fault`'s
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
//! see `crates/mbbs16/src/fault.rs`'s module comment for the fuller account,
//! including why the stack's *address* (as opposed to `SA_ONSTACK` itself)
//! turned out not to matter.
//!
//! # The FS_BASE hazard, and why this file does not need to fix it
//!
//! Task 15's `Tib` gives a module's `FS` a real LDT descriptor, which means
//! `FS_BASE` -- the MSR long-mode addressing actually uses for `%fs`-relative
//! access, including glibc's own thread-local storage -- is the **module's**
//! TIB address at the instant a fault is taken, not the host's. This handler
//! touches no `thread_local`, does no allocation, and calls `libc::sigaction`
//! only on the branch that hands a *foreign* fault back to `SIG_DFL` (never
//! reached by a module fault, so never reached while `FS_BASE` is wrong) --
//! so nothing here depends on `FS_BASE` being correct while it runs.
//!
//! The restoration itself already happens regardless: [`crate::asm::enter`]
//! wraps every crossing in an unconditional `arch_prctl(ARCH_GET_FS)` /
//! `arch_prctl(ARCH_SET_FS)` pair, and that wrapper's shape does not care
//! *how* [`crate::asm::mbbs32_enter_raw`][raw] returns to it -- by the
//! trampoline's cooperative `jmp *%r11`, or by this handler rewriting `RIP`
//! to the same address `R11` already names. Either way control lands back at
//! the same instruction inside `enter`, and `set_fs_base` runs next. That is
//! exactly why the recovery protocol above targets `R11`/`R15` rather than
//! the trampoline itself: it reproduces the trampoline's *landing site*, not
//! its body, and the landing site is where `enter`'s own safety net already
//! lives. `a_faulting_module_leaves_the_hosts_thread_locals_working` below is
//! the test that checks this rather than trusts it.
//!
//! [raw]: crate::asm

use std::cell::Cell;
use std::io;
use std::sync::Once;
use std::sync::atomic::{AtomicU16, Ordering};

use crate::asm::Ctx;

/// Signals a module can raise by misbehaving. `SIGTRAP` is deliberately
/// absent -- it belongs to debuggers, and a module executing `int3` is
/// pathological rather than routine. Same list as `mbbs16::fault`; there is
/// no watchdog signal to add to it here, because this crate has no watchdog
/// yet (see `docs/plans/2026-08-08-mbbs32-design.md`, "The fault arbiter,
/// and why it is shared" -- that is where one eventually lands, moved
/// unchanged from `mbbs16`, not reimplemented per-crate).
const FAULT_SIGNALS: [i32; 4] = [libc::SIGSEGV, libc::SIGILL, libc::SIGBUS, libc::SIGFPE];

/// `UC_STRICT_RESTORE_SS` from `<asm/ucontext.h>`, which libc does not
/// re-export. `compat32_fault.c` set this unconditionally even though it
/// deliberately left `SS` untouched, and recovery still worked -- so it is
/// carried over here for the same reason `mbbs16` sets it: telling
/// `sigreturn` to trust the frame's `SS` rather than second-guess it costs
/// nothing when `SS` is correct, which it always is here (never rewritten).
const UC_STRICT_RESTORE_SS: libc::c_ulong = 0x4;

/// Size of the alternate signal stack. A handler that only edits registers
/// needs very little, but `SIGSTKSZ` worth costs nothing.
const ALTSTACK_BYTES: usize = 64 * 1024;

/// The 64-bit code selector host code runs under, recorded when the handlers
/// go in. The handler compares against it to decide whether a fault is a
/// module's or someone else's, so it must be a plain value readable without
/// allocation.
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
            // SAFETY: an ordinary anonymous mapping. MAP_32BIT is not needed
            // here -- unlike a module's own memory, nothing about this stack
            // has to be a 32-bit-addressable quantity -- but it costs nothing
            // and mbbs16 carries it for the same reason, so it is kept for
            // consistency rather than dropped.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ALTSTACK_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
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
        // SAFETY: `stack` describes a live mapping owned by this thread for
        // the rest of its life.
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

/// Bit position of `CS` inside the packed segment-register `greg`. `SS`'s
/// counterpart (`mbbs16::fault::SS_SHIFT`) has no analogue here: `SS` is
/// never rewritten, so nothing in this file ever shifts anything into it.
const CS_SHIFT: u32 = 0;

/// Everything except `CS`: `GS`, `FS` and -- unlike `mbbs16::fault`'s mask --
/// `SS` too, which this file leaves exactly as the CPU already has it.
const KEEP_EVERYTHING_BUT_CS: u64 = 0xffff_ffff_ffff_0000;

/// Turn a module's fault into an ordinary return from [`crate::asm::enter`].
///
/// Async-signal-safe: it reads one atomic, edits the context in place, and
/// returns. No allocation, no locks, and -- on the path a module fault
/// actually takes -- no library call either; see the module doc comment's
/// "FS_BASE hazard" section for why that specifically matters here.
extern "C" fn handler(signo: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler.
    let uc = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let gregs = &mut uc.uc_mcontext.gregs;

    let packed = gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;
    let host_cs = HOST_CS.load(Ordering::Relaxed);

    if faulting_cs == host_cs {
        // Not a module fault -- host code, or something else entirely. Put
        // the default disposition back and return, so the faulting
        // instruction runs again and kills us the way it would have without
        // us here. Quietly swallowing another subsystem's SIGSEGV would be
        // much worse than dying.
        //
        // SAFETY: restoring the default disposition of a signal.
        unsafe {
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(signo, &dfl, std::ptr::null_mut());
        }
        return;
    }

    // 32-bit module code was interrupted, and it is ours to stop. R14 holds
    // the Ctx passed to mbbs32_enter_raw, which the caller keeps alive across
    // the excursion. Compatibility mode cannot name r8-r15, so 32-bit code
    // cannot have altered it -- which is what makes any of this recovery
    // possible.
    let ctx32 = gregs[libc::REG_R14 as usize] as *mut Ctx;

    // SAFETY: `ctx32` is the live `Ctx` this excursion was entered with, and
    // it outlives the call (owned by the caller's stack frame for the
    // duration of `enter`).
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
    use crate::asm::{USER32_CS, current_cs, enter, trampoline};
    use crate::map::Mapping;

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
    /// what proves `crate::asm::enter`'s unconditional restore covers the
    /// fault path too, rather than merely asserting that it should -- with a
    /// real [`crate::tib::Tib`], exactly what `wccmmud.dll` gets, rather than
    /// a stand-in selector.
    #[test]
    fn a_faulting_module_leaves_the_hosts_thread_locals_working() {
        thread_local! {
            static PROBE: Cell<u32> = const { Cell::new(0) };
        }

        arm(current_cs()).expect("install the fault handler");

        let tib = crate::tib::Tib::new(crate::tib::DEFAULT_STACK_LEN).expect("a Tib");

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
