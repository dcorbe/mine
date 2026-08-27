//! The DPMI excursion's fault-recovery arm.
//!
//! `crate::m32::fault::recover` calls [`recover_trap`] for any fault taken
//! while `Ctx::dpmi` is set, before it would otherwise poison the machine. A
//! DOS-extender guest runs in ring 3, so its privileged `int`/`in`/`out`/
//! `cli`/`sti` instructions all raise `#GP` -- delivered as `SIGSEGV` -- and
//! this arm decodes the faulting bytes and turns each into either an in-place
//! resume (`cli`/`sti`) or a structured, resumable exit (`int`).
//!
//! Async-signal-safe: the only work here is pointer reads/writes into the
//! guest's own live mapping and `ucontext_t`, plus [`super::decode::decode`],
//! which is pure computation. No allocation, no locks, no libc.

use super::decode::{Trap, decode};
use crate::m32::asm::Ctx;

/// The most bytes any instruction [`decode`] recognises can occupy
/// (`0x66` prefix + opcode + imm8). Reading this many at the faulting `EIP`
/// is always enough, and never fewer than the real instruction.
const MAX_TRAP_LEN: u64 = 3;

/// Decode the instruction at the faulting `EIP` and act on it. Returns `true`
/// if it was a trap this ABI handles (the guest was resumed in place, or a
/// service landing-pad was set up), `false` to let the caller poison -- which
/// is the right outcome for a genuine fault inside a DPMI guest, or for a
/// privileged instruction this ABI does not yet service (port I/O).
///
/// # Safety
///
/// Called only from `crate::m32::fault::recover`, on the signal's alternate
/// stack, with `uc` the live `ucontext_t` and `ctx` the live `Ctx` this
/// excursion was entered with (`dpmi != 0` already checked). Must stay
/// async-signal-safe.
pub(crate) unsafe fn recover_trap(
    uc: &mut libc::ucontext_t,
    ctx: *mut Ctx,
    host_cs: u16,
) -> bool {
    let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;

    // Never read instruction bytes outside the guest's own mapping: a fault
    // whose EIP has left it is a real fault (a wild jump), not a trap.
    let lo = unsafe { (*ctx).code_lo };
    let hi = unsafe { (*ctx).code_hi };
    if rip < lo || rip >= hi {
        return false;
    }
    let avail = (hi - rip).min(MAX_TRAP_LEN) as usize;
    // SAFETY: `[rip, rip + avail)` lies within `[lo, hi)`, the guest's live
    // mapping, so these bytes are mapped and readable.
    let bytes = unsafe { std::slice::from_raw_parts(rip as *const u8, avail) };

    let Some(dec) = decode(bytes) else {
        return false;
    };

    match dec.trap {
        Trap::Cli => {
            // SAFETY: `ctx` is the live excursion context; `uc` is the live
            // signal context, and `advance` only edits its `RIP` greg.
            unsafe {
                (*ctx).vif = 0;
                advance(uc, dec.len);
            }
            true
        }
        Trap::Sti => {
            // SAFETY: as the `Cli` arm above.
            unsafe {
                (*ctx).vif = 1;
                advance(uc, dec.len);
            }
            true
        }
        Trap::Int(vector) => {
            let packed = uc.uc_mcontext.gregs[libc::REG_CSGSFS as usize] as u64;
            // Reuse m32's exact register capture + landing-pad rewrite, with
            // `signo == 0` because a serviced trap is not a fault. It records
            // `out_eip` (the `int` address) before redirecting to the host.
            // SAFETY: `ctx` is the live excursion context; forwarded contract.
            unsafe { crate::m32::fault::rewrite(uc, packed, ctx, 0, host_cs) };
            unsafe {
                (*ctx).out_kind = 1;
                (*ctx).out_vector = u64::from(vector);
                (*ctx).out_len = u64::from(dec.len);
            }
            true
        }
        // Port I/O reaches the host through the device layer, which resolves
        // the `DX`-form port and the outbound value from the register file.
        // Not built yet: let it poison as an unsupported instruction rather
        // than silently swallow it.
        Trap::In { .. } | Trap::Out { .. } => false,
    }
}

/// Skip the just-handled instruction and let `sigreturn` resume the guest in
/// place -- the `cli`/`sti` path, which never returns to the host.
unsafe fn advance(uc: &mut libc::ucontext_t, len: u8) {
    uc.uc_mcontext.gregs[libc::REG_RIP as usize] += libc::greg_t::from(len);
}
