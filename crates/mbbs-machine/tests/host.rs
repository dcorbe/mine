//! The two things a host needs from the execution core that a module does not:
//! memory of its own that a module can address, and a way to refuse a module
//! for a reason the host reached itself.
//!
//! Both exist for the same boundary. A MajorBBS module imports `usrnum` and
//! `margv` without ever calling them -- it takes their `selector:offset` and
//! reads and writes them directly -- so the host must own memory in the
//! module's own address space to point those fixups at. And when a module calls
//! an import the host has no implementation for, there is no value it can
//! honestly return, so it must be able to stop the module instead.

use mbbs_machine::m16::{Exit, FarPtr, Machine, Poison, Ret};

/// ```text
///  0: b8 ss ss     mov   $selector, %ax
///  3: 8e c0        mov   %ax, %es
///  5: 26 a1 00 00  mov   %es:0x0, %ax
///  9: cb           lret
/// ```
fn reader(selector: u16) -> Vec<u8> {
    let mut code = vec![0xb8];
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x8e, 0xc0, 0x26, 0xa1, 0x00, 0x00, 0xcb]);
    code
}

/// ```text
///  0: b8 ss ss     mov   $selector, %ax
///  3: 8e c0        mov   %ax, %es
///  5: b8 vv vv     mov   $value, %ax
///  8: 26 a3 02 00  mov   %ax, %es:0x2
///  c: cb           lret
/// ```
fn writer(selector: u16, value: u16) -> Vec<u8> {
    let mut code = vec![0xb8];
    code.extend_from_slice(&selector.to_le_bytes());
    code.extend_from_slice(&[0x8e, 0xc0, 0xb8]);
    code.extend_from_slice(&value.to_le_bytes());
    code.extend_from_slice(&[0x26, 0xa3, 0x02, 0x00, 0xcb]);
    code
}

fn run(machine: &mut Machine) -> Exit {
    let exit = machine
        .call(machine.code_ptr(0), &[])
        .expect("called the module");
    match exit {
        Exit::Returned { .. } => exit,
        other => panic!("expected a return, got {other:?}"),
    }
}

#[test]
fn a_module_reads_what_the_host_wrote_into_a_host_segment() {
    const CANARY: u16 = 0xbeef;

    let mut machine = Machine::new().expect("16-bit machine");
    let globals = machine.alloc_segment(4096).expect("host segment");
    machine
        .write(
            FarPtr {
                offset: 0,
                selector: globals,
            },
            &CANARY.to_le_bytes(),
        )
        .expect("the host can write its own memory");

    machine.load_code(&reader(globals)).expect("module fits");

    // A host global is not a Rust value with a mirror in module memory. It is
    // *in* module memory, and this is the read that proves it.
    assert_eq!(run(&mut machine), Exit::Returned { ax: CANARY, dx: 0 });
}

#[test]
fn the_host_reads_what_a_module_wrote_into_a_host_segment() {
    const VALUE: u16 = 0x1234;

    let mut machine = Machine::new().expect("16-bit machine");
    let globals = machine.alloc_segment(4096).expect("host segment");
    machine.load_code(&writer(globals, VALUE)).expect("fits");
    run(&mut machine);

    // The other direction, and the one that matters more: the module writes
    // `prfptr` and `margc` without telling anyone, so the host has to read them
    // back out of this memory rather than remember what it last put there.
    let seen = machine
        .resolve(
            FarPtr {
                offset: 2,
                selector: globals,
            },
            2,
        )
        .expect("in bounds");
    assert_eq!(u16::from_le_bytes([seen[0], seen[1]]), VALUE);
}

#[test]
fn a_host_segment_is_not_one_of_the_machines_own() {
    let mut machine = Machine::new().expect("16-bit machine");
    let first = machine.alloc_segment(256).expect("host segment");
    let second = machine.alloc_segment(256).expect("another host segment");

    for named in [
        machine.code_selector(),
        machine.stack_selector(),
        machine.data_selector(),
    ] {
        assert_ne!(first, named, "a host segment must be its own");
    }
    assert_ne!(first, second, "two host segments are two segments");
}

#[test]
fn a_host_segment_must_be_addressable_by_a_16_bit_pointer() {
    let mut machine = Machine::new().expect("16-bit machine");

    // Zero is not a length, and 64 KiB is the most an offset can name. Asking
    // for either is a host bug worth an error rather than a descriptor whose
    // limit says something other than what was asked for.
    assert!(machine.alloc_segment(0).is_err(), "zero bytes");
    assert!(machine.alloc_segment(64 * 1024 + 1).is_err(), "past 64 KiB");
    assert!(machine.alloc_segment(64 * 1024).is_ok(), "exactly 64 KiB");
}

#[test]
fn an_unimplemented_import_poisons_by_name() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&[0xcb]).expect("module fits");

    machine
        .poison(Poison::Unimplemented {
            module: "MAJORBBS".to_owned(),
            symbol: "opnmsg".to_owned(),
        })
        .expect("poisoned");

    let refused = machine
        .call(machine.code_ptr(0), &[])
        .expect_err("a poisoned machine must refuse to be entered");

    // The name is the whole value of poisoning here. A host that returned zero
    // instead would get a fault in module code many calls later, naming nothing
    // about which import was missing.
    let said = refused.to_string();
    assert!(
        said.contains("MAJORBBS.opnmsg"),
        "the refusal must name the import: {said}"
    );
}

#[test]
fn the_first_reason_a_module_was_poisoned_is_the_one_kept() {
    let mut machine = Machine::new().expect("16-bit machine");

    machine
        .poison(Poison::Unimplemented {
            module: "MAJORBBS".to_owned(),
            symbol: "alczer".to_owned(),
        })
        .expect("poisoned");
    machine
        .poison(Poison::Unimplemented {
            module: "MAJORBBS".to_owned(),
            symbol: "opnbtv".to_owned(),
        })
        .expect("poisoned again");

    // A module stopped for one thing that is then asked for another is still
    // stopped for the first. That is the one that is true.
    assert_eq!(
        machine.poisoned(),
        Some(&Poison::Unimplemented {
            module: "MAJORBBS".to_owned(),
            symbol: "alczer".to_owned(),
        })
    );
}

#[test]
fn poisoning_forgets_the_call_frame() {
    // Whatever was on the module's stack described a call that will never be
    // serviced. Leaving `arg_u16` able to report those leftovers would let a
    // host read arguments belonging to a call it already refused.
    let mut machine = Machine::new().expect("16-bit machine");

    const THUNK: u16 = 3;
    let mut code = vec![0x9a, 0, 0, 0, 0]; // lcall $CS, $thunk
    code[1..5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xcb);
    machine.load_code(&code).expect("module fits");

    assert!(matches!(
        machine.call(machine.code_ptr(0), &[]).expect("called"),
        Exit::Call { index: THUNK }
    ));
    machine
        .poison(Poison::Unimplemented {
            module: "MAJORBBS".to_owned(),
            symbol: "opnbtv".to_owned(),
        })
        .expect("poisoned");

    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| machine.sp())).is_err(),
        "a poisoned machine has no outstanding call to read"
    );
}

#[test]
fn a_long_argument_reads_back_as_one_value() {
    // Borland pushes a `long` as two words, low half nearest the frame -- the
    // same arrangement a far pointer arrives in. Which of the two an argument
    // is depends on the routine, and for a varargs routine on the format
    // string, so the core reads the words and the host decides what they mean.
    const VALUE: u32 = 0xdead_beef;

    let mut machine = Machine::new().expect("16-bit machine");
    const THUNK: u16 = 7;

    // The module pushes the argument itself, right to left, exactly as Borland
    // would: high half first, so the low half lands nearest the call frame.
    //
    //   b8 hh hh   mov   $high, %ax
    //   50         push  %ax
    //   b8 ll ll   mov   $low, %ax
    //   50         push  %ax
    //   9a ...     lcall $CS, $thunk
    //   cb         lret
    let mut code = vec![0xb8];
    code.extend_from_slice(&((VALUE >> 16) as u16).to_le_bytes());
    code.extend_from_slice(&[0x50, 0xb8]);
    code.extend_from_slice(&(VALUE as u16).to_le_bytes());
    code.extend_from_slice(&[0x50, 0x9a, 0, 0, 0, 0]);
    let at = code.len() - 4;
    code[at..at + 4].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xcb);
    machine.load_code(&code).expect("module fits");

    assert!(matches!(
        machine.call(machine.code_ptr(0), &[]).expect("called"),
        Exit::Call { index: THUNK }
    ));

    assert_eq!(machine.arg_u32(0), VALUE);
    assert_eq!(
        machine.arg_far(0),
        FarPtr {
            offset: VALUE as u16,
            selector: (VALUE >> 16) as u16,
        },
        "the same two words, read as an address instead of a number"
    );

    machine.resume(Ret::Void).expect("resumed");
}

#[test]
fn a_machine_that_is_not_in_a_call_has_no_frame() {
    // `sp()` panics here, deliberately -- a shim asking is a bug. The refusal
    // path asks about machines in any state, so it gets the honest answer.
    let machine = Machine::new().expect("16-bit machine");
    assert_eq!(machine.frame_sp(), None);
}
