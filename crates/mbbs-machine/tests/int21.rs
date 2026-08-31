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

/// `mov ah,19h; int 21h; jc L; mov ax,1; retf; L: mov ax,2; retf`
fn get_drive_module() -> Vec<u8> {
    vec![
        0xb4, 0x19, // mov ah, 0x19
        0xcd, 0x21, // int 21h            -- at offset 2
        0x72, 0x04, // jc L
        0xb8, 0x01, 0x00, // mov ax, 1
        0xcb, // retf
        0xb8, 0x02, 0x00, // L: mov ax, 2
        0xcb, // retf
    ]
}

#[test]
fn int_21h_is_a_resumable_exit_that_names_the_vector_and_the_site() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&get_drive_module()).expect("module fits");
    match machine.call(machine.code_ptr(0), &[]).expect("called") {
        Exit::Interrupt { vector, cs, ip } => {
            assert_eq!(vector, 0x21);
            assert_eq!(cs, machine.code_selector());
            assert_eq!(ip, 2, "the int instruction's own offset");
        }
        other => panic!("expected an interrupt, got {other:?}"),
    }
    assert!(machine.poisoned().is_none(), "a serviced trap is not a fault");
    assert_eq!(machine.regs().ax >> 8, 0x19, "AH as the module set it");
}

#[test]
fn a_serviced_interrupt_resumes_after_the_instruction_with_the_hosts_carry() {
    for (carry, expect) in [(false, 1u16), (true, 2u16)] {
        let mut machine = Machine::new().expect("16-bit machine");
        machine.load_code(&get_drive_module()).expect("module fits");
        let Exit::Interrupt { ip, .. } = machine.call(machine.code_ptr(0), &[]).expect("called") else {
            panic!("expected an interrupt");
        };
        machine.set_ax(0x1902);
        machine.set_carry(carry);
        machine.set_ip(ip + 2);
        match machine.jump().expect("resumed") {
            Exit::Returned { ax, .. } => assert_eq!(ax, expect, "carry={carry}"),
            other => panic!("expected a return, got {other:?}"),
        }
    }
}

#[test]
fn a_genuine_fault_still_poisons() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&[0x0f, 0x0b]).expect("ud2 fits");
    match machine.call(machine.code_ptr(0), &[]).expect("called") {
        Exit::Fault { signo, .. } => assert_eq!(signo, libc::SIGILL),
        other => panic!("expected a fault, got {other:?}"),
    }
    assert!(machine.poisoned().is_some());
}
