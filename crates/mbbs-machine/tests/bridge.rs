//! The thunk table and trampoline live somewhere a module image cannot reach.
//!
//! They used to sit at fixed offsets inside the module's own code segment, which
//! works only for images small enough to stay below them. Six of `WCCMMUD.DLL`'s
//! 82 segments are larger than the old thunk table offset and three are larger
//! than the old trampoline's, so a real module could not be loaded at all.
//!
//! The bridge therefore gets its own segment. A thunk is reached by far call and
//! names its selector explicitly, so nothing about the crossing changes -- but a
//! module image may now be as large as a 16-bit segment can be.

use mbbs_machine::m16::{Exit, Machine, Ret};

/// A thunk index the test module calls. Arbitrary.
const THUNK: u16 = 3;

/// The last address a 16-bit code segment can hold an entry point at, with room
/// for the six bytes below.
const HIGH_ENTRY: usize = 0xfff0;

#[test]
fn the_bridge_is_not_in_the_module_code_segment() {
    let machine = Machine::new().expect("16-bit machine");

    assert_ne!(
        machine.thunk_address(THUNK).selector,
        machine.code_selector(),
        "the thunk table must not share a segment with the module image"
    );
}

#[test]
fn a_module_image_may_fill_its_whole_code_segment() {
    let mut machine = Machine::new().expect("16-bit machine");

    // 0xcc everywhere the module does not use, so entering at the wrong offset
    // faults loudly rather than executing whatever the allocator left behind.
    let mut image = vec![0xccu8; 64 * 1024];

    //  0: 9a <far ptr>   lcall $CS, $thunk
    //  5: cb             lret            with the host's answer still in AX
    image[HIGH_ENTRY] = 0x9a;
    image[HIGH_ENTRY + 1..HIGH_ENTRY + 5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    image[HIGH_ENTRY + 5] = 0xcb;

    machine.load_code(&image).expect("a full segment of module");

    let mut exit = machine
        .call(machine.code_ptr(HIGH_ENTRY as u16), &[])
        .expect("called it");
    let mut serviced = 0;

    loop {
        match exit {
            Exit::Call { index: THUNK } => {
                serviced += 1;
                exit = machine.resume(Ret::U16(0xd00d)).expect("resumed");
            }
            Exit::Returned { ax, .. } => {
                assert_eq!(ax, 0xd00d, "the host's answer came back out");
                break;
            }
            Exit::Call { index } => panic!("unexpected thunk {index}"),
            Exit::Fault { signo, cs, ip } => {
                panic!("module faulted with signal {signo} at {cs:#06x}:{ip:#06x}")
            }
            Exit::Timeout { cs, ip } => panic!("module timed out at {cs:#06x}:{ip:#06x}"),
            Exit::Interrupt { vector, cs, ip } => {
                panic!("module executed int {vector:#04x} at {cs:#06x}:{ip:#06x}")
            }
        }
    }

    assert_eq!(serviced, 1, "the host should have been called exactly once");
}
