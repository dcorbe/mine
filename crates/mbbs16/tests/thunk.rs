//! End-to-end: 16-bit code calls a host function and uses the answer.
//!
//! This is the crate's whole purpose in one test. A stand-in for compiled
//! module code pushes two arguments, far-calls an import thunk, and the host
//! services the call and hands back a result the 16-bit code then keeps.
//!
//! The module bytes are hand-written, but every encoding was produced by `as`
//! and read back out of `objdump` rather than worked out by hand -- the
//! listing in [`test_module`] is what was assembled.

use mbbs16::{EXIT_THUNK, Exit, INITIAL_SP, Machine};

/// Thunk index the test module calls. Arbitrary; a real module would use the
/// import's ordinal.
const ADD_THUNK: u16 = 0;

const ARG_A: u16 = 35;
const ARG_B: u16 = 7;

/// A stand-in for compiled 16-bit module code, in the shape Borland's cdecl
/// emits:
///
/// ```text
///  0: b8 34 12        mov   $0x1234, %ax   marker: a wrong entry point shows
///  3: 6a 07           push  $7             arg 1 first -- cdecl is right-to-left
///  5: 6a 23           push  $35            arg 0
///  7: 9a <far ptr>    lcall $CS, $add      the import
///  c: 83 c4 04        add   $4, %sp        cdecl: the CALLER cleans up
///  f: 89 c6           mov   %ax, %si       keep the result somewhere callee-saved
/// 11: 9a <far ptr>    lcall $CS, $exit     done
/// ```
fn test_module() -> Vec<u8> {
    vec![
        0xb8, 0x34, 0x12, // mov   $0x1234, %ax
        0x6a, ARG_B as u8, // push  $7
        0x6a, ARG_A as u8, // push  $35
        0x9a, 0, 0, 0, 0, // lcall $CS, $add_thunk
        0x83, 0xc4, 0x04, // add   $4, %sp
        0x89, 0xc6, // mov   %ax, %si
        0x9a, 0, 0, 0, 0, // lcall $CS, $exit_thunk
    ]
}

/// Byte offsets of the two far pointers within the module above.
const ADD_CALL_SITE: usize = 8;
const EXIT_CALL_SITE: usize = 18;

#[test]
fn sixteen_bit_code_calls_a_host_function_and_uses_the_result() {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let add = machine.thunk_address(ADD_THUNK).to_bytes();
    let exit = machine.thunk_address(EXIT_THUNK).to_bytes();
    code[ADD_CALL_SITE..ADD_CALL_SITE + 4].copy_from_slice(&add);
    code[EXIT_CALL_SITE..EXIT_CALL_SITE + 4].copy_from_slice(&exit);
    machine.load_code(&code).expect("module fits");

    let mut exit_reason = machine.enter(0).expect("entered 16-bit mode");
    let mut serviced = 0;

    loop {
        match exit_reason {
            Exit::Call { index: ADD_THUNK } => {
                // cdecl pushes right to left, so argument 0 is the one nearest
                // the call frame.
                assert_eq!(machine.arg_u16(0), ARG_A, "first argument");
                assert_eq!(machine.arg_u16(1), ARG_B, "second argument");

                // Two words of arguments, then the far call's CS:IP.
                assert_eq!(machine.sp(), INITIAL_SP - 8, "stack depth at the call");

                serviced += 1;
                let sum = machine.arg_u16(0).wrapping_add(machine.arg_u16(1));
                exit_reason = machine.resume(sum).expect("resumed");
            }
            Exit::Call { index: EXIT_THUNK } => {
                // The module cleaned its own arguments, so all that is below
                // the initial stack pointer is this call's own frame. Getting
                // this wrong leaves a module running on a stack that drifts.
                assert_eq!(machine.sp(), INITIAL_SP - 4, "stack unwound cleanly");
                break;
            }
            Exit::Call { index } => panic!("module called an unexpected thunk {index}"),
            Exit::Fault { signo } => panic!("module faulted with signal {signo}"),
        }
    }

    assert_eq!(serviced, 1, "the host should have been called exactly once");
    assert_eq!(
        machine.si(),
        ARG_A + ARG_B,
        "16-bit code kept the host's answer across the call"
    );
}
