//! A module that will not stop must not be able to stop the host.
//!
//! MajorBBS is cooperatively scheduled -- nothing takes the CPU back from a
//! module that refuses to return -- so without a watchdog a wedged module is
//! not "the module fails" or "the board fails" but *the board hangs*, which is
//! worse than either. See `src/watchdog.rs`.
//!
//! **A failure here can hang rather than fail.** The only thing that can end a
//! wedged excursion is the mechanism under test, so if it is broken there is
//! nothing left to notice. That is unavoidable and is why the loops that *can*
//! be bounded are bounded.

use std::time::{Duration, Instant};

use mbbs16::{Exit, Machine, Poison, Ret};

/// Small enough to keep the suite quick, large enough that a scheduling hiccup
/// cannot make a well-behaved module look wedged. This is CPU time, so it is
/// unaffected by how busy the machine running the tests is. Ticks arrive at a
/// quarter of this.
const BUDGET: Duration = Duration::from_millis(50);

/// A module that spins forever and touches nothing.
///
/// `jmp $` -- two bytes, no memory access, no host calls. The purest form of
/// the problem: nothing about it will ever raise a signal on its own.
fn wedged_module() -> Vec<u8> {
    vec![0xeb, 0xfe]
}

/// A module that behaves: it returns immediately.
fn polite_module() -> Vec<u8> {
    vec![0xcb] // lret
}

/// Burn `d` of CPU without sleeping, so a CPU-time timer actually advances.
fn burn(d: Duration) {
    let start = Instant::now();
    while start.elapsed() < d {
        std::hint::black_box(0u64);
    }
}

fn wedged_machine() -> Machine {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.set_budget(BUDGET);
    machine.load_code(&wedged_module()).expect("module fits");
    machine
}

#[test]
fn a_module_that_never_returns_is_interrupted() {
    let mut machine = wedged_machine();

    let exit = machine.call(0, &[]).expect("called the module");

    match exit {
        Exit::Timeout { cs, ip } => {
            assert_eq!(cs, machine.code_selector(), "stopped outside module code");
            assert_eq!(ip, 0, "the two-byte loop jumps back to offset 0");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[test]
fn a_module_looping_on_a_host_call_is_interrupted() {
    // The failure mode that arming per crossing would miss entirely. This module
    // calls a shim and jumps back to do it again; the host services every call
    // promptly, so nothing is wedged in the sense of "stuck in 16-bit code" --
    // it is wedged in the sense that matters, which is that the entry point will
    // never return. A budget re-armed on each resume would be reset faster than
    // it could ever expire.
    //
    // It is also the workload that shows why a tick landing in host code has to
    // count. Most of each iteration is spent in the host servicing the call, so
    // most ticks land there; discarding them made this take roughly three and a
    // half times the budget and several attempts, instead of the first tick.
    let mut machine = Machine::new().expect("16-bit machine");
    machine.set_budget(BUDGET);

    const THUNK: u16 = 7;
    let mut code = vec![0x9a, 0, 0, 0, 0]; // lcall $CS, $thunk
    code[1..5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.extend_from_slice(&[0xeb, 0xf9]); // jmp back to the lcall
    machine.load_code(&code).expect("module fits");

    // Bounded so that a broken watchdog fails the test instead of running until
    // someone notices. An iteration costs a few hundred nanoseconds even at
    // -O0, so this is orders of magnitude more than the budget can cover.
    let mut exit = machine.call(0, &[]).expect("called the module");
    for _ in 0..10_000_000 {
        match exit {
            Exit::Call { index } => {
                assert_eq!(index, THUNK);
                exit = machine.resume(Ret::U16(0)).expect("resumed");
            }
            Exit::Timeout { .. } => return,
            other => panic!("expected a timeout eventually, got {other:?}"),
        }
    }
    panic!("a module looping on a host call was never interrupted");
}

#[test]
fn an_overrun_spent_in_host_code_still_counts() {
    // A module parked at an import call while the host burns its whole budget
    // servicing it. Nothing is executing in 16-bit mode, so no tick can ever
    // interrupt the module -- and yet the budget is just as gone. The overrun is
    // recorded against the machine and the next re-entry is refused.
    //
    // This test also covers the trap the design had to avoid: a tick reaching
    // the fault handler's "not ours" branch would restore SIG_DFL and return,
    // which is harmless once and fatal the next time, because a timer does not
    // re-raise the way a fault does. The burn below spans several ticks. If they
    // were being passed through, the process would die partway and this test
    // would not fail so much as vanish.
    let mut machine = Machine::new().expect("16-bit machine");
    machine.set_budget(BUDGET);

    const THUNK: u16 = 1;
    let mut code = vec![0x9a, 0, 0, 0, 0]; // lcall $CS, $thunk
    code[1..5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xcb); // lret, once the host is done
    machine.load_code(&code).expect("module fits");

    let exit = machine.call(0, &[]).expect("called the module");
    assert!(matches!(exit, Exit::Call { index: THUNK }), "{exit:?}");

    burn(BUDGET * 3);

    let exit = machine.resume(Ret::U16(0)).expect("resumed");
    match exit {
        Exit::Timeout { cs, ip } => {
            // Where it would have carried on: the `lret` after the call.
            assert_eq!(cs, machine.code_selector());
            assert_eq!(ip, 5, "the lret follows the five-byte lcall");
        }
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[test]
fn the_host_still_works_after_a_timeout() {
    let mut wedged = wedged_machine();
    assert!(matches!(
        wedged.call(0, &[]).expect("called"),
        Exit::Timeout { .. }
    ));

    // The whole point: one module that will not stop must not end the process
    // serving everyone else.
    let mut fresh = Machine::new().expect("second 16-bit machine");
    fresh.load_code(&polite_module()).expect("module fits");
    assert!(matches!(
        fresh.call(0, &[]).expect("called"),
        Exit::Returned { .. }
    ));
}

#[test]
fn a_timed_out_machine_refuses_to_be_entered_again() {
    // Killing the call did not repair the globals it was halfway through
    // updating. The module is untrustworthy, not merely stopped.
    let mut machine = wedged_machine();
    assert!(matches!(
        machine.call(0, &[]).expect("called"),
        Exit::Timeout { .. }
    ));

    assert!(
        matches!(machine.poisoned(), Some(Poison::Timeout { .. })),
        "a timed-out machine is poisoned"
    );
    assert!(
        machine.call(0, &[]).is_err(),
        "a poisoned machine must refuse a second call"
    );
}

#[test]
fn a_well_behaved_module_is_never_interrupted() {
    // The false-positive guard. A watchdog that fires on correct behaviour is
    // worse than no watchdog, so run many short calls under a budget that a
    // single one comes nowhere near -- which also checks that the timer is
    // disarmed on return rather than carrying its remainder into the next call.
    let mut machine = Machine::new().expect("16-bit machine");
    machine.set_budget(BUDGET);
    machine.load_code(&polite_module()).expect("module fits");

    for _ in 0..10_000 {
        assert!(matches!(
            machine.call(0, &[]).expect("called"),
            Exit::Returned { .. }
        ));
    }
    assert!(machine.poisoned().is_none());
}

#[test]
fn a_ticking_machine_does_not_kill_a_different_one() {
    // Two machines armed on the same thread. The first is left parked at a host
    // call with its budget running out; the second then runs a long but
    // perfectly legal computation. Both timers deliver the same signal to the
    // same thread, so the only thing that can tell them apart is the context
    // address each timer carries.
    let mut parked = Machine::new().expect("first 16-bit machine");
    parked.set_budget(BUDGET);

    const THUNK: u16 = 2;
    let mut code = vec![0x9a, 0, 0, 0, 0]; // lcall $CS, $thunk
    code[1..5].copy_from_slice(&parked.thunk_address(THUNK).to_bytes());
    code.push(0xcb); // lret
    parked.load_code(&code).expect("module fits");
    assert!(matches!(
        parked.call(0, &[]).expect("called"),
        Exit::Call { index: THUNK }
    ));

    // Let the parked machine's budget expire while nothing of its own is running.
    burn(BUDGET * 2);

    // Now a second module runs, well within its own generous budget, while the
    // first machine's timer keeps ticking.
    let mut busy = Machine::new().expect("second 16-bit machine");
    busy.set_budget(Duration::from_secs(30));

    // 0xffff iterations of `loop $` -- long enough that several of the parked
    // machine's ticks land squarely inside it.
    let mut spin = vec![0xb9, 0xff, 0xff]; // mov $0xffff, %cx
    spin.extend_from_slice(&[0xe2, 0xfe]); // loop $
    spin.push(0xcb); // lret
    busy.load_code(&spin).expect("module fits");

    let exit = busy.call(0, &[]).expect("called");
    assert!(
        matches!(exit, Exit::Returned { .. }),
        "a tick meant for another machine stopped this one: {exit:?}"
    );
    assert!(busy.poisoned().is_none());

    // And the ticks were not merely discarded -- they landed on the machine
    // they were about, which refuses to go any further.
    let exit = parked.resume(Ret::U16(0)).expect("resumed");
    assert!(
        matches!(exit, Exit::Timeout { .. }),
        "the overrunning machine was let off: {exit:?}"
    );
}
