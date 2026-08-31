//! `int 21h` from a 16-bit module: a resumable exit, not a death.

use mbbs_machine::m16::{Exit, Machine};

/// `pushf; pop ax; retf` -- hands the flags the module was entered with back
/// in AX.
fn flags_reporter() -> Vec<u8> {
    vec![0x9c, 0x58, 0xcb]
}

#[test]
fn the_carry_flag_set_by_the_host_is_the_one_the_module_sees() {
    for on in [true, false] {
        let mut machine = Machine::new().expect("16-bit machine");
        machine.load_code(&flags_reporter()).expect("module fits");
        machine.set_carry(on);
        match machine.call(machine.code_ptr(0), &[]).expect("called") {
            Exit::Returned { ax, .. } => assert_eq!(ax & 1 == 1, on, "CF on entry, set_carry({on})"),
            other => panic!("expected a return, got {other:?}"),
        }
    }
}
