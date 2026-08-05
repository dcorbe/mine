//! What a module had in its general-purpose registers when it called out.
//!
//! Borland's 32-bit runtime helpers take their operands in registers and
//! nowhere else -- `F_LXMUL@` is `DX:AX * CX:BX` -- so a host that cannot read
//! them cannot service 131 of `WCCMMUD.DLL`'s import sites. `AX` and `CX` are
//! the awkward two: the import thunk overwrites both to name itself, so they
//! have to be saved before it does, and the saving must not move the call frame
//! out from under everything that reads an argument.

use mbbs16::{Exit, INITIAL_SP, Machine, Ret};

const THUNK: u16 = 0;

/// A module that loads the four registers, far-calls the thunk, and returns.
fn loads(machine: &Machine, ax: u16, bx: u16, cx: u16, dx: u16) -> Vec<u8> {
    let mut code = Vec::new();
    for (opcode, value) in [(0xb8, ax), (0xbb, bx), (0xb9, cx), (0xba, dx)] {
        code.push(opcode); // mov $value, %<reg>
        code.extend_from_slice(&value.to_le_bytes());
    }
    code.push(0x9a); // lcall $CS, $thunk
    code.extend_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xcb); // lret
    code
}

/// Run `code` from offset 0 and stop at its call.
fn park(machine: &mut Machine, code: &[u8]) {
    machine.load_code(code).expect("module fits");
    let entry = machine.code_ptr(0);
    let exit = machine.call(entry, &[]).expect("called");
    assert!(matches!(exit, Exit::Call { index: THUNK }), "{exit:?}");
}

#[test]
fn a_shim_sees_the_four_registers_the_module_called_with() {
    // Distinct values in every register, because the failure that matters is
    // reading one where another was meant -- `F_LXMUL@`'s operands are `DX:AX`
    // and `CX:BX`, and swapping the pairs multiplies the wrong numbers and
    // reports a plausible answer.
    let mut machine = Machine::new().expect("16-bit machine");
    let code = loads(&machine, 0x1111, 0x2222, 0x3333, 0x4444);
    park(&mut machine, &code);

    assert_eq!(machine.ax(), 0x1111);
    assert_eq!(machine.bx(), 0x2222);
    assert_eq!(machine.cx(), 0x3333);
    assert_eq!(machine.dx(), 0x4444);
}

#[test]
fn saving_them_does_not_move_the_call_frame() {
    // The thunk pushes AX and CX before it can name itself, so the SP the
    // trampoline records is four bytes below the far-call frame. `frame_sp`
    // steps back over them, and this is the assertion that says so: the
    // arguments are where cdecl left them and SP is where it would have been.
    let mut machine = Machine::new().expect("16-bit machine");
    let mut code = Vec::new();
    for word in [0xbeefu16, 0xcafe, 0xf00d] {
        code.push(0x68); // push $word
        code.extend_from_slice(&word.to_le_bytes());
    }
    code.push(0x9a);
    code.extend_from_slice(&machine.thunk_address(THUNK).to_bytes());
    code.push(0xcb);
    park(&mut machine, &code);

    assert_eq!(machine.arg_u16(0), 0xf00d, "pushed last, nearest the frame");
    assert_eq!(machine.arg_u16(1), 0xcafe);
    assert_eq!(machine.arg_u16(2), 0xbeef);

    // The entry frame is four bytes, three pushed words are six, and the far
    // call's own frame is four. What the thunk saved is not in that sum.
    assert_eq!(machine.sp(), INITIAL_SP - 4 - 6 - 4);
}

#[test]
fn each_call_reports_its_own_registers() {
    // The saved words are read off the stack at the moment of the call, so a
    // stale copy from the previous one would look exactly like a correct answer
    // until the values happened to differ.
    let mut machine = Machine::new().expect("16-bit machine");
    let mut code = loads(&machine, 1, 2, 3, 4);
    code.pop(); // drop the `lret`, and call again with different values
    code.extend_from_slice(&loads(&machine, 5, 6, 7, 8));

    park(&mut machine, &code);
    assert_eq!(
        (machine.ax(), machine.bx(), machine.cx(), machine.dx()),
        (1, 2, 3, 4)
    );

    let exit = machine.resume(Ret::Void).expect("resumed");
    assert!(matches!(exit, Exit::Call { index: THUNK }), "{exit:?}");
    assert_eq!(
        (machine.ax(), machine.bx(), machine.cx(), machine.dx()),
        (5, 6, 7, 8)
    );
}

#[test]
fn reading_a_register_outside_a_call_panics() {
    // Rather than reporting whatever the last call left. A shim always has an
    // outstanding call, so an absent frame here is a host bug.
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&[0xcb]).expect("module fits");
    let entry = machine.code_ptr(0);
    machine.call(entry, &[]).expect("called");

    for read in [Machine::ax, Machine::bx, Machine::cx, Machine::dx] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read(&machine))).is_err(),
            "reading a register with no outstanding call must panic"
        );
    }
}
