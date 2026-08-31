//! End-to-end: 16-bit code calls a host function and uses the answer.
//!
//! This is the crate's whole purpose in one test. A stand-in for compiled
//! module code pushes two arguments, far-calls an import thunk, and the host
//! services the call and hands back a result the 16-bit code then keeps.
//!
//! The module bytes are hand-written, but every encoding was produced by `as`
//! and read back out of `objdump` rather than worked out by hand -- the
//! listing in [`test_module`] is what was assembled.

use mbbs_machine::m16::{Exit, INITIAL_SP, Machine, Ret};

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
/// 11: cb              lret                 back to whoever called us
/// ```
fn test_module() -> Vec<u8> {
    let mut code = vec![0xb8, 0x34, 0x12]; // mov   $0x1234, %ax
    code.extend_from_slice(&[0x6a, ARG_B as u8]); // push  $7
    code.extend_from_slice(&[0x6a, ARG_A as u8]); // push  $35
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]); // lcall $CS, $add_thunk
    code.extend_from_slice(&[0x83, 0xc4, 0x04]); // add   $4, %sp
    code.extend_from_slice(&[0x89, 0xc6]); // mov   %ax, %si
    code.push(0xcb); // lret
    code
}

/// Byte offset of the far pointer within the module above.
const ADD_CALL_SITE: usize = 8;

#[test]
fn sixteen_bit_code_calls_a_host_function_and_uses_the_result() {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let add = machine.thunk_address(ADD_THUNK).to_bytes();
    code[ADD_CALL_SITE..ADD_CALL_SITE + 4].copy_from_slice(&add);
    machine.load_code(&code).expect("module fits");

    let mut exit_reason = machine
        .call(machine.code_ptr(0), &[])
        .expect("called the module");
    let mut serviced = 0;
    let returned;

    loop {
        match exit_reason {
            Exit::Call { index: ADD_THUNK } => {
                // cdecl pushes right to left, so argument 0 is the one nearest
                // the call frame.
                assert_eq!(machine.arg_u16(0), ARG_A, "first argument");
                assert_eq!(machine.arg_u16(1), ARG_B, "second argument");

                // The entry frame the host built, then two argument words,
                // then the far call's own CS:IP.
                assert_eq!(machine.sp(), INITIAL_SP - 12, "stack depth at the call");

                serviced += 1;
                let sum = machine.arg_u16(0).wrapping_add(machine.arg_u16(1));
                exit_reason = machine.resume(Ret::U16(sum)).expect("resumed");
            }
            Exit::Returned { ax, dx } => {
                // Getting here at all is the stack-discipline check. The
                // module's RETF finds the frame the host built only if every
                // push and pop in between balanced -- including the one
                // `resume` performs.
                returned = Some((ax, dx));
                break;
            }
            Exit::Call { index } => panic!("module called an unexpected thunk {index}"),
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
    assert_eq!(
        machine.si(),
        ARG_A + ARG_B,
        "16-bit code kept the host's answer across the call"
    );
    assert_eq!(
        returned,
        Some((ARG_A + ARG_B, 0)),
        "and returned it to the host"
    );
}
