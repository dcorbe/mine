//! Can a 16-bit module still be recovered from a fault once a 32-bit machine
//! exists in the same process?
//!
//! This constructs the 16-bit machine FIRST, then a 32-bit machine, holds the
//! latter alive, and then faults the 16-bit module.
//!
//! # It was written red, and the arbiter turned it green
//!
//! When this test went in, `m16` and `m32` were separate crates and each
//! installed its own process-wide handler for the same four signals
//! (SIGSEGV/SIGILL/SIGBUS/SIGFPE) through its own `static INSTALL: Once`.
//! There is one disposition per process, so whichever machine constructed
//! second simply won, and nothing arbitrated between them -- the 32-bit
//! fault module said so itself, naming the problem and declining to solve
//! it: "Running both ABIs in one process needs a single arbiter...
//! deliberately NOT built here."
//!
//! `8c61335` built it. There is now one handler, in
//! `crates/mbbs-machine/src/fault.rs`, and each ABI claims a fault
//! *positively* -- `is_ldt_selector` here, `is_user32_cs` for the 32-bit
//! side -- rather than by ruling the host out, which is the only thing that
//! can work once there are two claimants. So this is no longer an open
//! question with a red test attached: it is the regression guard that the
//! arbiter keeps holding, and `fault_32_after_16.rs` is the same guard
//! pointed the other way.
//!
//! Its own binary, and hence its own process: see `fault_16_alone.rs`'s module
//! comment for why sharing one with the control makes both results
//! meaningless.

use mbbs_machine::m16::Exit;

/// Byte-for-byte the control's fixture, and `crates/mbbs-machine/tests/fault.rs`'s.
fn suicidal() -> Vec<u8> {
    vec![
        0xb8, 0x34, 0x12, // mov $0x1234, %ax
        0xf4, // hlt
    ]
}

#[test]
fn a_16_bit_fault_is_recovered_after_mbbs32_has_also_armed() {
    let mut machine = mbbs_machine::m16::Machine::new().expect("a 16-bit machine");
    machine.load_code(&suicidal()).expect("module fits");
    let entry = machine.code_ptr(0);

    // The clobber, held alive across the fault below exactly as a host serving
    // both widths from one process would hold it.
    let _thirty_two = mbbs_machine::m32::Machine::new().expect("a 32-bit machine");

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        Exit::Fault { signo, .. } => assert_eq!(signo, libc::SIGSEGV),
        other => panic!("expected a recovered fault, got {other:?}"),
    }
}
