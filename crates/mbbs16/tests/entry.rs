//! Calling a module entry point, the way MajorBBS does.
//!
//! 64-bit mode has no far call that could reach 16-bit code, so the frame a far
//! call would have left is built by hand and the entry point is reached by far
//! jump. From inside, a module cannot tell: it sees its arguments where cdecl
//! says they are, and its `RETF` pops the frame the host laid down.
//!
//! The module here uses the ordinary Borland far-function prologue, so the
//! frame layout is not an invention of this crate's -- it is what a compiled
//! module actually reads.

use mbbs16::{Exit, INITIAL_SP, Machine, Ret};

/// An entry point taking two `int`s and returning `a - b`.
///
/// ```text
///  0: 55              push  %bp
///  1: 89 e5           mov   %sp, %bp     the classic prologue; now
///  3: 8b 46 06        mov   0x6(%bp), %ax    bp+0 saved BP
///  6: 2b 46 08        sub   0x8(%bp), %ax    bp+2 return IP
///  9: 5d              pop   %bp              bp+4 return CS
///  a: cb              lret                   bp+6 arg 0, bp+8 arg 1
/// ```
///
/// Subtraction rather than addition on purpose: it is order-sensitive, so
/// arguments arriving the wrong way round cannot pass.
const SUBTRACT_ENTRY: &[u8] = &[
    0x55, 0x89, 0xe5, 0x8b, 0x46, 0x06, 0x2b, 0x46, 0x08, 0x5d, 0xcb,
];

/// An entry point returning a `long`: `0x5678_1234`, high half in `DX`.
///
/// ```text
///  0: b8 34 12        mov $0x1234, %ax
///  3: ba 78 56        mov $0x5678, %dx
///  6: cb              lret
/// ```
const LONG_ENTRY: &[u8] = &[0xb8, 0x34, 0x12, 0xba, 0x78, 0x56, 0xcb];

fn machine_with(code: &[u8]) -> Machine {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(code).expect("module fits");
    machine
}

#[test]
fn a_module_entry_point_receives_its_arguments_in_cdecl_order() {
    let mut machine = machine_with(SUBTRACT_ENTRY);

    let exit = machine.call(0, &[70, 28]).expect("called the module");

    match exit {
        Exit::Returned { ax, dx } => {
            assert_eq!(ax, 42, "the module computed 70 - 28");
            assert_eq!(dx, 0, "an int return does not touch DX");
        }
        other => panic!("expected a return, got {other:?}"),
    }
}

#[test]
fn arguments_are_not_silently_reversed() {
    // The mirror of the test above. If the frame were built left to right the
    // module would compute 28 - 70 and this would be the passing case.
    let mut machine = machine_with(SUBTRACT_ENTRY);

    let exit = machine.call(0, &[28, 70]).expect("called the module");

    match exit {
        Exit::Returned { ax, .. } => assert_eq!(ax, 28u16.wrapping_sub(70)),
        other => panic!("expected a return, got {other:?}"),
    }
}

#[test]
fn a_module_can_return_a_long() {
    let mut machine = machine_with(LONG_ENTRY);

    match machine.call(0, &[]).expect("called the module") {
        Exit::Returned { ax, dx } => {
            assert_eq!(ax, 0x1234, "low half");
            assert_eq!(dx, 0x5678, "high half");
        }
        other => panic!("expected a return, got {other:?}"),
    }
}

#[test]
fn each_call_starts_from_a_clean_stack() {
    // cdecl makes cleaning the arguments the caller's job, and the caller here
    // is the host. Rather than unwind, every call lays its frame down afresh --
    // so calling repeatedly must not walk the stack pointer downwards.
    let mut machine = machine_with(SUBTRACT_ENTRY);

    for _ in 0..64 {
        match machine.call(0, &[100, 1]).expect("called the module") {
            Exit::Returned { ax, .. } => assert_eq!(ax, 99),
            other => panic!("expected a return, got {other:?}"),
        }
    }
}

#[test]
fn an_entry_point_can_call_the_host_and_still_return() {
    // The two halves of the calling model in one module: the host calls in, the
    // module calls out, the host answers, the module returns.
    //
    //  0: 9a <far ptr>   lcall $CS, $thunk
    //  5: cb             lret            with the host's answer still in AX
    const THUNK: u16 = 9;
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = vec![0x9a, 0, 0, 0, 0, 0xcb];
    code[1..5].copy_from_slice(&machine.thunk_address(THUNK).to_bytes());
    machine.load_code(&code).expect("module fits");

    let mut exit = machine.call(0, &[]).expect("called the module");
    let mut serviced = 0;

    loop {
        match exit {
            Exit::Call { index: THUNK } => {
                // Only the entry frame is on the stack beneath this call.
                assert_eq!(machine.sp(), INITIAL_SP - 8, "entry frame, then this call");
                serviced += 1;
                exit = machine.resume(Ret::U16(0xbeef)).expect("resumed");
            }
            Exit::Returned { ax, .. } => {
                assert_eq!(ax, 0xbeef, "the host's answer became the return value");
                break;
            }
            Exit::Call { index } => panic!("unexpected thunk {index}"),
            Exit::Fault { signo } => panic!("module faulted with signal {signo}"),
        }
    }

    assert_eq!(serviced, 1);
}
