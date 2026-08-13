//! The question `crates/mbbs32/src/fault.rs` names and declines to answer:
//! can a 16-bit module still be recovered from a fault once a 32-bit machine
//! exists in the same process?
//!
//! Both machine crates install a process-wide handler for the same four
//! signals (SIGSEGV/SIGILL/SIGBUS/SIGFPE) through their own `static INSTALL:
//! Once`. There is one disposition per process. Whichever constructs second
//! wins, and nothing arbitrates between them -- `mbbs32/src/fault.rs` says
//! "Running both ABIs in one process needs a single arbiter... deliberately
//! NOT built here."
//!
//! So this constructs the 16-bit machine FIRST, then a 32-bit machine, holds
//! the latter alive, and then faults the 16-bit module. If recovery still
//! works, the two handlers are compatible by luck or by design and the
//! arbiter is unnecessary. If it does not, this is the red test the arbiter
//! has to turn green.
//!
//! Its own binary, and hence its own process: see `fault_16_alone.rs`'s module
//! comment for why sharing one with the control makes both results
//! meaningless.

use mbbs_machine::m16::Exit;

/// Byte-for-byte the control's fixture, and `crates/mbbs16/tests/fault.rs`'s.
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
