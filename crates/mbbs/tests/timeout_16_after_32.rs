//! Mirror of `timeout_32_after_16.rs`: this time the 16-bit machine is the
//! one that times out, with a 32-bit machine already registered -- and the
//! 32-bit machine must keep working afterward. See that file's own module
//! comment for why this pair exists and what it is the actual test for
//! (the async registry's payload tag, not the CS claim the plain fault
//! triplet already covers).
//!
//! Construction order stays fixed across this whole family (16-bit first,
//! then 32-bit) -- see `fault_16_after_32.rs`'s own module comment for why
//! that order is not what "after" in these filenames names.
//!
//! Its own binary: see `fault_16_alone.rs`'s module comment.

use mbbs_machine::m16;
use mbbs_machine::m32;

use std::time::Duration;

const BUDGET: Duration = Duration::from_millis(50);

/// `jmp $` -- byte-for-byte `crates/mbbs-machine/tests/watchdog.rs`'s own
/// `wedged_module` fixture.
fn wedged_16() -> Vec<u8> {
    vec![0xeb, 0xfe]
}

/// A near `ret` -- byte-for-byte `crates/mbbs-machine/tests/m32_watchdog.rs`'s
/// own `polite_code` fixture.
fn polite_32() -> [u8; 1] {
    [0xc3]
}

#[test]
fn a_16_bit_timeout_is_recovered_after_mbbs32_has_also_armed_and_mbbs32_still_runs() {
    let mut sixteen = m16::Machine::new().expect("a 16-bit machine");
    sixteen.set_budget(BUDGET);
    sixteen.load_code(&wedged_16()).expect("module fits");

    let mut mapping = m32::Mapping::new(4096).expect("a low mapping for a polite module");
    let entry = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..1].copy_from_slice(&polite_32());

    // Constructed second, and used again at the end -- never arms a budget
    // of its own, so any tick it sees is necessarily meant for the 16-bit
    // machine above.
    let mut thirty_two = m32::Machine::new().expect("a 32-bit machine");

    match sixteen.call(sixteen.code_ptr(0), &[]).expect("recovered, not fatal") {
        m16::Exit::Timeout { .. } => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(
        matches!(sixteen.poisoned(), Some(m16::Poison::Timeout { .. })),
        "the timed-out 16-bit machine must be poisoned"
    );

    match thirty_two.call(entry, &[]).expect("still callable") {
        m32::Exit::Returned { .. } => {}
        other => panic!("the 32-bit machine was disturbed by the 16-bit timeout: {other:?}"),
    }
}
