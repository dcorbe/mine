//! A 32-bit module that will not stop must not be able to stop the host.
//!
//! The mirror of `watchdog.rs` (m16's own suite), for the flat 32-bit ABI --
//! see `src/m32/watchdog.rs` and `src/fault.rs`'s "Two signal classes"
//! section for the mechanism. Both watchdogs now share the same real-time
//! signal, so it is the arbiter's tagged-payload registry, not the signal
//! number, that keeps a delivery from landing on the wrong ABI; the
//! cross-ABI proof of that lives in `crates/mbbs/tests/timeout_16_after_32.rs`
//! and `timeout_32_after_16.rs`, not here -- this file stays single-ABI, the
//! same way `watchdog.rs` does.
//!
//! **A failure here can hang rather than fail.** The only thing that can end
//! a wedged excursion is the mechanism under test, so if it is broken there
//! is nothing left to notice. That is unavoidable and is why the loops that
//! *can* be bounded are bounded -- byte-for-byte the same caveat
//! `watchdog.rs`'s own module comment states.

use std::time::Duration;

use mbbs_machine::m32::{Exit, Machine, Mapping, Poison};

/// Small enough to keep the suite quick, large enough that a scheduling
/// hiccup cannot make a well-behaved module look wedged. Byte-for-byte
/// `watchdog.rs`'s own `BUDGET`.
const BUDGET: Duration = Duration::from_millis(50);

/// `jmp $` -- two bytes, no memory access, no host calls. The purest form
/// of the problem, same fixture `watchdog.rs` uses for m16 (opcode 0xEB is a
/// relative short jump regardless of operand-size mode).
fn wedged_code() -> [u8; 2] {
    [0xeb, 0xfe]
}

/// A module that behaves: near `ret`, cdecl's own return.
fn polite_code() -> [u8; 1] {
    [0xc3]
}

/// Burn `d` of **this thread's CPU time** -- byte-for-byte `watchdog.rs`'s
/// own `burn`/`cpu_time`; see that file's comment for why CPU time, not wall
/// clock, is what makes the wait exact.
fn burn(d: Duration) {
    let start = cpu_time();
    while cpu_time() - start < d {
        std::hint::black_box(0u64);
    }
}

fn cpu_time() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes the `timespec` and nothing else.
    let ok = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert_eq!(ok, 0, "the thread CPU clock is not readable");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// A fresh low mapping holding `bytes` at its base, and that base as a
/// linear entry address. The mapping must outlive every call made against
/// the returned address -- `m32::Machine` does not own a module's code, only
/// its stack (`Machine::call`'s own doc comment).
fn low_code(bytes: &[u8]) -> (Mapping, u32) {
    let mut mapping = Mapping::new(4096).expect("a low mapping");
    let addr = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
    (mapping, addr)
}

/// `call thunk_addr ; ret` -- a module that calls one host thunk and, once
/// resumed, returns immediately. Returns the mapping (which must outlive
/// every call against `entry`), `entry`, and `next_ip` -- the linear address
/// right after the 5-byte `call`, which is where a resumed module continues
/// (or, if its budget is gone, where [`Exit::Timeout`] reports it as never
/// having reached).
///
/// The `call rel32` displacement is computed against the mapping's own
/// address, not hand-worked-out -- `asm.rs`'s own module doc comment names
/// exactly this class of mistake as the one this project keeps making.
fn call_thunk_then_ret(thunk_addr: u32) -> (Mapping, u32, u32) {
    let mut mapping = Mapping::new(4096).expect("a low mapping");
    let entry = mapping.base() as usize as u32;
    let next_ip = entry + 5; // address right after the 5-byte call
    let rel = thunk_addr.wrapping_sub(next_ip);

    let mut bytes = vec![0xe8]; // call rel32
    bytes.extend_from_slice(&rel.to_le_bytes());
    bytes.push(0xc3); // ret, once the host answers
    mapping.as_mut_slice()[..bytes.len()].copy_from_slice(&bytes);

    (mapping, entry, next_ip)
}

fn wedged_machine() -> (Machine, Mapping, u32) {
    let mut machine = Machine::new().expect("32-bit machine");
    machine.set_budget(BUDGET);
    let (mapping, entry) = low_code(&wedged_code());
    (machine, mapping, entry)
}

#[test]
fn a_module_that_never_returns_is_interrupted() {
    let (mut machine, _mapping, entry) = wedged_machine();

    let exit = machine.call(entry, &[]).expect("called the module");

    match exit {
        Exit::Timeout { eip } => {
            assert_eq!(eip, entry, "the two-byte loop jumps back to its own start");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[test]
fn an_overrun_spent_in_host_code_still_counts() {
    // A module parked at an import call while the host burns its whole
    // budget servicing it. Nothing is executing in 32-bit mode, so no tick
    // can ever interrupt the module -- and yet the budget is just as gone.
    // Mirrors `watchdog.rs`'s own test of the same name.
    let mut machine = Machine::new().expect("32-bit machine");
    machine.set_budget(BUDGET);

    const THUNK: u16 = 1;
    let thunk_addr = machine.thunk_addr(THUNK);
    let (_mapping, entry, next_ip) = call_thunk_then_ret(thunk_addr);

    let exit = machine.call(entry, &[]).expect("called the module");
    assert!(matches!(exit, Exit::Call { index: THUNK }), "{exit:?}");

    burn(BUDGET * 3);

    let exit = machine.resume(mbbs_machine::m32::Ret::Void).expect("resumed");
    match exit {
        Exit::Timeout { eip } => {
            // Where it would have continued: the `ret` right after the call.
            assert_eq!(eip, next_ip, "the ret follows the five-byte call");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[test]
fn the_host_still_works_after_a_timeout() {
    let (mut wedged, _mapping, entry) = wedged_machine();
    assert!(matches!(
        wedged.call(entry, &[]).expect("called"),
        Exit::Timeout { .. }
    ));

    // The whole point: one module that will not stop must not end the
    // process serving everyone else.
    let mut fresh = Machine::new().expect("second 32-bit machine");
    let (_polite_mapping, polite_entry) = low_code(&polite_code());
    assert!(matches!(
        fresh.call(polite_entry, &[]).expect("called"),
        Exit::Returned { .. }
    ));
}

#[test]
fn a_timed_out_machine_refuses_to_be_entered_again() {
    let (mut machine, _mapping, entry) = wedged_machine();
    assert!(matches!(
        machine.call(entry, &[]).expect("called"),
        Exit::Timeout { .. }
    ));

    assert!(
        matches!(machine.poisoned(), Some(Poison::Timeout { .. })),
        "a timed-out machine is poisoned"
    );
    assert!(
        machine.call(entry, &[]).is_err(),
        "a poisoned machine must refuse a second call"
    );
}

#[test]
fn a_well_behaved_module_is_never_interrupted() {
    // The false-positive guard, and the mutation target for "disarm the
    // timer but leave the registration" -- see the plan's mutation table.
    // A watchdog that fires on correct behaviour is worse than none, so run
    // many short calls under a budget a single one comes nowhere near --
    // which also checks that the timer is disarmed on return rather than
    // carrying its remainder into the next call.
    let mut machine = Machine::new().expect("32-bit machine");
    machine.set_budget(BUDGET);
    let (_mapping, entry) = low_code(&polite_code());

    for _ in 0..10_000 {
        assert!(matches!(
            machine.call(entry, &[]).expect("called"),
            Exit::Returned { .. }
        ));
    }
    assert!(machine.poisoned().is_none());
}

#[test]
fn a_ticking_machine_does_not_kill_a_different_one() {
    // Two 32-bit machines armed on the same thread. Proves the async
    // registry's payload tag disambiguates not only between ABIs (the
    // cross-ABI coexistence tests do that) but between two machines of the
    // SAME ABI sharing the same registered slot -- mirrors `watchdog.rs`'s
    // own test of the same name.
    let mut parked = Machine::new().expect("first 32-bit machine");
    parked.set_budget(BUDGET);

    const THUNK: u16 = 2;
    let thunk_addr = parked.thunk_addr(THUNK);
    let (_mapping, entry, _next_ip) = call_thunk_then_ret(thunk_addr);

    assert!(matches!(
        parked.call(entry, &[]).expect("called"),
        Exit::Call { index: THUNK }
    ));

    // Let the parked machine's budget expire while nothing of its own is
    // running.
    burn(BUDGET * 2);

    // Now a second module runs, well within its own generous budget, while
    // the first machine's timer keeps ticking.
    let mut busy = Machine::new().expect("second 32-bit machine");
    busy.set_budget(Duration::from_secs(30));

    // A long but perfectly legal spin: `mov ecx, 0xffffff; dec ecx; jnz -5;
    // ret`.
    let mut spin = vec![0xb9]; // mov ecx, imm32
    spin.extend_from_slice(&0x00ff_ffffu32.to_le_bytes());
    spin.extend_from_slice(&[0x49]); // dec ecx
    spin.extend_from_slice(&[0x75, 0xfd]); // jnz -3 (back to dec ecx)
    spin.push(0xc3); // ret
    let (_spin_mapping, spin_entry) = low_code(&spin);

    let exit = busy.call(spin_entry, &[]).expect("called");
    assert!(
        matches!(exit, Exit::Returned { .. }),
        "a tick meant for another machine stopped this one: {exit:?}"
    );
    assert!(busy.poisoned().is_none());

    // And the ticks were not merely discarded -- they landed on the machine
    // they were about, which refuses to go any further.
    let exit = parked.resume(mbbs_machine::m32::Ret::Void).expect("resumed");
    assert!(
        matches!(exit, Exit::Timeout { .. }),
        "the overrunning machine was let off: {exit:?}"
    );
}
