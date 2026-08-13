//! Control: a 16-bit module fault, recovered, with no 32-bit machine in the
//! process at all.
//!
//! Its own test binary -- hence its own process, hence its own signal
//! disposition -- for the reason `crates/mbbs/tests/wg32_abi.rs` documents at
//! length: `cargo test` runs the tests within one binary as THREADS of one
//! process, and a `mbbs_machine::m32::Machine::new` anywhere in that binary rearms the
//! process's SIGSEGV handler for every thread in it, whichever test happens to
//! be faulting at the time.
//!
//! An earlier draft of this put this test and its sibling
//! (`fault_16_after_32.rs`) in one file. The whole binary died with SIGSEGV
//! and reported the CONTROL as the failing test, which is a false accusation:
//! the sibling's 32-bit machine had armed over `mbbs16`'s handler in another
//! thread. Splitting them is not tidiness -- it is what makes either result
//! mean anything.
//!
//! If this test fails, `mbbs16`'s own fault recovery is broken and the
//! sibling's result should not be read at all.

use mbbs_machine::m16::Exit;

/// A module that executes `HLT` -- privileged, so `#GP`, arriving as SIGSEGV.
/// Byte-for-byte `crates/mbbs-machine/tests/fault.rs`'s own fixture.
fn suicidal() -> Vec<u8> {
    vec![
        0xb8, 0x34, 0x12, // mov $0x1234, %ax
        0xf4, // hlt
    ]
}

#[test]
fn a_16_bit_fault_is_recovered_when_only_mbbs16_has_armed() {
    let mut machine = mbbs_machine::m16::Machine::new().expect("a 16-bit machine");
    machine.load_code(&suicidal()).expect("module fits");
    let entry = machine.code_ptr(0);

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        Exit::Fault { signo, .. } => assert_eq!(signo, libc::SIGSEGV),
        other => panic!("expected a recovered fault, got {other:?}"),
    }
}
