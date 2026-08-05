//! Who pops the arguments: the two conventions, told apart by the stack.

use mbbs16::{Exit, Machine, Ret};

const THUNK: u16 = 0;

/// A module that pushes four words, far-calls the thunk, and reports how much
/// the stack moved across the whole call.
///
/// `BP` is the stack pointer before the pushes and `AX` is `BP - SP` after the
/// call returns -- so the answer is **0** when someone dropped the four words
/// and **8** when nobody did. Nothing in the module itself cleans up before the
/// measurement is taken, which is what makes this a measurement of the host
/// rather than of the test.
///
/// It has to be `BP` and not some scratch register: `SI`, `DI` and `BP` are the
/// only ones a host call promises to hand back, and a mark kept in `BX` would be
/// measuring the trampoline's leftovers. See `callee_saved.rs`.
///
/// `SP` is then restored from `BP` rather than adjusted by a constant, because
/// the whole point is that the test does not know how far it moved: the `RETF`
/// has to find its return address whichever convention the host used.
fn balance(machine: &mut Machine) -> Vec<u8> {
    let mut code = vec![0x89, 0xe5]; // mov bp,sp
    for word in [4u16, 3, 2, 1] {
        code.push(0x68); // push imm16
        code.extend_from_slice(&word.to_le_bytes());
    }
    code.push(0x9a); // lcall $CS, $thunk
    code.extend_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.extend_from_slice(&[
        0x89, 0xe8, // mov ax,bp
        0x29, 0xe0, // sub ax,sp
        0x89, 0xec, // mov sp,bp  -- back to the return address, wherever it is
        0xcb, // lret
    ]);
    code
}

/// Run `code` from offset 0, servicing its one call with `service`.
fn drive(machine: &mut Machine, code: &[u8], service: impl Fn(&mut Machine) -> Exit) -> u16 {
    machine.load_code(code).expect("module fits");
    let entry = machine.code_ptr(0);
    let mut exit = machine.call(entry, &[]).expect("called");
    loop {
        match exit {
            Exit::Call { index: THUNK } => exit = service(machine),
            Exit::Returned { ax, .. } => return ax,
            other => panic!("unexpected exit {other:?}"),
        }
    }
}

#[test]
fn a_caller_cleaned_routine_leaves_its_arguments_on_the_stack() {
    // The convention every host routine in this crate has used so far. The
    // module would issue its own `add sp,8`; this one does not, so the eight
    // bytes are still there and the stack has moved by exactly that much.
    let mut machine = Machine::new().expect("16-bit machine");
    let code = balance(&mut machine);
    let moved = drive(&mut machine, &code, |m| {
        m.resume(Ret::U16(0)).expect("resumed")
    });
    assert_eq!(moved, 8, "resume drops the return address and nothing else");
}

#[test]
fn a_callee_cleaned_routine_takes_its_arguments_with_it() {
    // What a Borland runtime helper needs: the host pops the arguments, because
    // the module is not going to.
    let mut machine = Machine::new().expect("16-bit machine");
    let code = balance(&mut machine);
    let moved = drive(&mut machine, &code, |m| {
        m.resume_cleaning(Ret::U16(0), 8).expect("resumed")
    });
    assert_eq!(moved, 0, "the stack came back exactly where it started");
}

#[test]
fn cleaning_nothing_is_the_same_as_not_cleaning() {
    // So that `Cleans::Callee(0)` is expressible and means what it says, rather
    // than being a special case someone has to remember.
    let mut machine = Machine::new().expect("16-bit machine");
    let code = balance(&mut machine);
    let moved = drive(&mut machine, &code, |m| {
        m.resume_cleaning(Ret::U16(0), 0).expect("resumed")
    });
    assert_eq!(moved, 8);
}
