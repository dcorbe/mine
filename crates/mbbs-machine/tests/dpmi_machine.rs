//! The DPMI machine turns a guest's privileged instructions into structured
//! host events: `int` becomes a resumable service exit, `cli`/`sti` are
//! consumed in the fault handler and never surface, and a genuine fault is
//! still a fault. Test shape adopted from the parallel session's plan.

use mbbs_machine::m32::dpmi::{Exit, Machine};

const MAP_LEN: usize = 0x10000;
const STACK_TOP: u32 = 0xF000;

#[test]
fn int21_becomes_a_service_exit() {
    let mut m = Machine::new(MAP_LEN).unwrap();
    let base = m.base();
    // 0000: CD 21   int 21h
    m.mem()[0..2].copy_from_slice(&[0xCD, 0x21]);
    m.set_entry(base, base + STACK_TOP);

    match m.run().unwrap() {
        Exit::Service { vector: 0x21, eip } => assert_eq!(eip, base, "eip is the int's address"),
        other => panic!("expected Service(0x21), got {other:?}"),
    }
}

#[test]
fn resume_past_the_int_reaches_the_next_one() {
    let mut m = Machine::new(MAP_LEN).unwrap();
    let base = m.base();
    // CD 21 ; CD 31
    m.mem()[0..4].copy_from_slice(&[0xCD, 0x21, 0xCD, 0x31]);
    m.set_entry(base, base + STACK_TOP);

    assert!(matches!(m.run().unwrap(), Exit::Service { vector: 0x21, .. }));
    m.set_eip(base + 2);
    assert!(matches!(m.run().unwrap(), Exit::Service { vector: 0x31, .. }));
}

#[test]
fn cli_and_sti_are_consumed_and_move_the_virtual_if() {
    let mut m = Machine::new(MAP_LEN).unwrap();
    let base = m.base();
    // FA        cli
    // CD 21     int 21h      <- stop here, IF must be clear
    // FB        sti
    // CD 31     int 31h      <- stop here, IF must be set
    m.mem()[0..6].copy_from_slice(&[0xFA, 0xCD, 0x21, 0xFB, 0xCD, 0x31]);
    m.set_entry(base, base + STACK_TOP);

    match m.run().unwrap() {
        Exit::Service { vector: 0x21, eip } => assert_eq!(eip, base + 1),
        other => panic!("expected Service(0x21) after cli, got {other:?}"),
    }
    assert!(!m.interrupts_enabled(), "cli cleared the virtual IF");

    m.set_eip(base + 3);
    match m.run().unwrap() {
        Exit::Service { vector: 0x31, eip } => assert_eq!(eip, base + 4),
        other => panic!("expected Service(0x31) after sti, got {other:?}"),
    }
    assert!(m.interrupts_enabled(), "sti set the virtual IF");
}

#[test]
fn a_genuine_fault_is_still_a_fault() {
    let mut m = Machine::new(MAP_LEN).unwrap();
    let base = m.base();
    // 0F 0B   ud2 -- always #UD, decodes to nothing this ABI handles
    m.mem()[0..2].copy_from_slice(&[0x0F, 0x0B]);
    m.set_entry(base, base + STACK_TOP);

    match m.run().unwrap() {
        Exit::Fault { eip, .. } => assert_eq!(eip, base, "fault eip is the ud2 address"),
        other => panic!("expected Fault, got {other:?}"),
    }
}
