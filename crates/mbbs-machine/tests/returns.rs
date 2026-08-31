//! Return values wider than a word come back in `DX:AX`.
//!
//! Borland's 16-bit C returns an `int` in `AX`, and a `long` or a far pointer
//! in `DX:AX` with the high half in `DX`. For a far pointer that means the
//! **segment** is in `DX` and the **offset** in `AX`, which is the same order a
//! 32-bit value has -- and exactly the pair a host is most likely to swap.

use mbbs_machine::m16::{Exit, FarPtr, Machine, Ret};

const THUNK: u16 = 2;

/// ```text
///  0: 9a <far ptr>    lcall $CS, $thunk
///  5: 89 c6           mov   %ax, %si     the low half, somewhere callee-saved
///  7: 89 d7           mov   %dx, %di     and the high half
///  9: cb              lret
/// ```
fn test_module() -> Vec<u8> {
    vec![
        0x9a, 0, 0, 0, 0, // lcall $CS, $thunk
        0x89, 0xc6, // mov %ax, %si
        0x89, 0xd7, // mov %dx, %di
        0xcb, // lret
    ]
}

const CALL_SITE: usize = 1;

/// Run the module, servicing its one call with `ret`, and give back what it
/// kept in `(SI, DI)` -- which is `(AX, DX)`.
fn returned(ret: Ret) -> (u16, u16) {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let thunk = machine.thunk_address(THUNK).to_bytes();
    code[CALL_SITE..CALL_SITE + 4].copy_from_slice(&thunk);
    machine.load_code(&code).expect("module fits");

    let mut exit_reason = machine
        .call(machine.code_ptr(0), &[])
        .expect("called the module");
    loop {
        match exit_reason {
            Exit::Call { index: THUNK } => {
                exit_reason = machine.resume(ret).expect("resumed");
            }
            Exit::Returned { .. } => break,
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

    (machine.si(), machine.di())
}

#[test]
fn an_int_comes_back_in_ax_alone() {
    let (ax, dx) = returned(Ret::U16(0x1234));
    assert_eq!(ax, 0x1234, "AX carries the value");
    assert_eq!(dx, 0, "DX is not part of an int return");
}

#[test]
fn a_long_comes_back_split_across_dx_and_ax() {
    let (ax, dx) = returned(Ret::U32(0xdead_beef));
    assert_eq!(ax, 0xbeef, "AX carries the low half");
    assert_eq!(dx, 0xdead, "DX carries the high half");
}

#[test]
fn a_far_pointer_comes_back_segment_in_dx_offset_in_ax() {
    // Deliberately distinguishable: swapping the halves would be obvious, which
    // is the point. A far pointer is a 32-bit value whose high half is the
    // segment, so it lands the same way a long does.
    let ptr = FarPtr {
        offset: 0x1234,
        selector: 0xabcd,
    };
    let (ax, dx) = returned(Ret::Far(ptr));
    assert_eq!(ax, 0x1234, "AX carries the offset");
    assert_eq!(dx, 0xabcd, "DX carries the segment");
}

#[test]
fn a_void_return_leaves_both_halves_clear() {
    let (ax, dx) = returned(Ret::Void);
    assert_eq!((ax, dx), (0, 0), "nothing to return, nothing left behind");
}

#[test]
fn a_far_pointer_return_round_trips_through_its_own_encoding() {
    // The register split and the in-memory layout have to agree: offset low,
    // segment high, in both.
    let ptr = FarPtr {
        offset: 0x1234,
        selector: 0xabcd,
    };
    assert_eq!(FarPtr::from_bytes(ptr.to_bytes()), ptr);
    assert_eq!(ptr.to_bytes(), [0x34, 0x12, 0xcd, 0xab]);
}
