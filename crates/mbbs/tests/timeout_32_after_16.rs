//! A 32-bit timeout, with a 16-bit machine already registered -- and proof
//! that the 16-bit machine keeps working afterward.
//!
//! The timeout mirror of `fault_32_after_16.rs`: same construction order
//! (16-bit machine first, then 32-bit), same reason for it -- see that
//! file's own module comment. What is new here is the "keeps working
//! afterward" half: the plain fault triplet never calls back into the
//! machine it held alive as a clobber, but design §5's whole point is that
//! a timeout in one ABI must not disturb the other, so this test proves it
//! rather than merely surviving it.
//!
//! This is also the test the async registry's payload tag actually exists
//! for. `crate::fault`'s module doc comment ("Two signal classes") explains
//! why: both watchdogs now share the SAME real-time signal rather than each
//! claiming its own, so unlike the plain fault triplet (where a CS claim
//! alone tells synchronous signals apart), a broken payload tag here would
//! let a tick meant for the 32-bit machine misdeliver to the 16-bit one's
//! watchdog -- either falsely poisoning a module that behaved, or leaving
//! the wedged one running forever undetected.
//!
//! Its own binary, and hence its own process: see `fault_16_alone.rs`'s
//! module comment for why timing-sensitive and faulting tests never share a
//! process with a sibling -- doubly true here, since this file deliberately
//! burns CPU time on a budget the watchdog is meant to catch.

use mbbs_machine::m16;
use mbbs_machine::m32::{Exit, Mapping, Poison};

use std::time::Duration;

const BUDGET: Duration = Duration::from_millis(50);

/// `lret` -- byte-for-byte `crates/mbbs-machine/tests/watchdog.rs`'s own
/// `polite_module` fixture.
fn polite_16() -> Vec<u8> {
    vec![0xcb]
}

/// `jmp $` -- byte-for-byte `crates/mbbs-machine/tests/m32_watchdog.rs`'s
/// own `wedged_code` fixture.
fn wedged_32() -> [u8; 2] {
    [0xeb, 0xfe]
}

#[test]
fn a_32_bit_timeout_is_recovered_after_mbbs16_has_also_armed_and_mbbs16_still_runs() {
    // Constructed first, and used again at the end -- the machine whose
    // continued good health this test exists to prove. It never arms a
    // watchdog budget of its own here, so any tick it sees is necessarily
    // meant for someone else.
    let mut sixteen = m16::Machine::new().expect("a 16-bit machine");
    sixteen.load_code(&polite_16()).expect("module fits");

    let mut mapping = Mapping::new(4096).expect("a low mapping for the wedged code");
    let entry = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..2].copy_from_slice(&wedged_32());

    let mut thirty_two = mbbs_machine::m32::Machine::new().expect("a 32-bit machine");
    thirty_two.set_budget(BUDGET);

    match thirty_two.call(entry, &[]).expect("recovered, not fatal") {
        Exit::Timeout { eip } => assert_eq!(eip, entry, "the two-byte loop jumps back to itself"),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(
        matches!(thirty_two.poisoned(), Some(Poison::Timeout { .. })),
        "the timed-out 32-bit machine must be poisoned"
    );

    // The whole point: a tick meant for the 32-bit machine must not have
    // been misdelivered to the 16-bit one, which never armed a budget at
    // all and has been sitting idle throughout.
    match sixteen.call(sixteen.code_ptr(0), &[]).expect("still callable") {
        m16::Exit::Returned { .. } => {}
        other => panic!("the 16-bit machine was disturbed by the 32-bit timeout: {other:?}"),
    }
}
