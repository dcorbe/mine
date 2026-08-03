//! A module that dies must not take the host with it.
//!
//! Recovery works by editing the interrupted context so `sigreturn` lands back
//! in host code -- the same edit the trampoline would have made had the module
//! reached it. See `src/fault.rs`.

use mbbs16::{Exit, Machine, Ret};

/// A module that executes `HLT`.
///
/// Privileged, so it raises `#GP` and arrives as `SIGSEGV`. It stands in for
/// the whole family of things a real module can do to itself: a bad opcode, a
/// pointer to nowhere, a divide by zero.
fn suicidal_module() -> Vec<u8> {
    vec![
        0xb8, 0x34, 0x12, // mov $0x1234, %ax   -- proves we got there at all
        0xf4, // hlt               -- and no further
    ]
}

/// A module that behaves: it returns immediately.
fn polite_module() -> Vec<u8> {
    vec![0xcb] // lret
}

#[test]
fn a_module_that_faults_is_reported_not_fatal() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&suicidal_module()).expect("module fits");

    let exit = machine.call(0, &[]).expect("called the module");

    match exit {
        Exit::Fault { signo } => assert_eq!(signo, libc::SIGSEGV, "HLT raises #GP"),
        other => panic!("expected a fault, got {other:?}"),
    }
}

#[test]
fn the_host_still_works_after_a_module_faults() {
    // Kill one module...
    let mut doomed = Machine::new().expect("16-bit machine");
    doomed.load_code(&suicidal_module()).expect("module fits");
    assert!(matches!(
        doomed.call(0, &[]).expect("called"),
        Exit::Fault { .. }
    ));

    // ...and the next one runs as if nothing happened. This is the whole point:
    // one bad module must not be able to end the process serving everyone else.
    let mut fresh = Machine::new().expect("second 16-bit machine");
    fresh.load_code(&polite_module()).expect("module fits");
    assert!(matches!(
        fresh.call(0, &[]).expect("called"),
        Exit::Returned { .. }
    ));
}

#[test]
fn a_faulted_module_reports_the_fault_rather_than_a_stale_call() {
    // Run a module far enough to make a real call, then fault it. The second
    // excursion must come back as a fault and not as a repeat of the first
    // call, which is what stale context would look like.
    let mut machine = Machine::new().expect("16-bit machine");

    const THUNK: u16 = 4;
    let mut code = vec![0x9a, 0, 0, 0, 0]; // lcall $CS, $thunk
    code[1..5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xf4); // hlt, on return
    machine.load_code(&code).expect("module fits");

    let first = machine.call(0, &[]).expect("called");
    assert!(matches!(first, Exit::Call { index: THUNK }), "{first:?}");

    let second = machine.resume(Ret::U16(0)).expect("resumed");
    assert!(matches!(second, Exit::Fault { .. }), "{second:?}");
}
