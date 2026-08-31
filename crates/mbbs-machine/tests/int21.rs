//! `int 21h` from a 16-bit module: a resumable exit, not a death.

use std::time::Duration;

use mbbs_machine::m16::{Exit, FarPtr, Machine, Poison};

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

/// `push ds; mov ax,ss; mov ds,ax; int 21h; mov ax,ds; pop ds; retf` -- the
/// module moves DS away from its own DGROUP (to SS, a segment distinct from
/// both DGROUP and the code segment) before trapping, then reports what DS
/// held right after resuming.
fn ds_mover() -> Vec<u8> {
    vec![
        0x1e, // push ds
        0x8c, 0xd0, // mov ax, ss
        0x8e, 0xd8, // mov ds, ax
        0xcd, 0x21, // int 21h
        0x8c, 0xd8, // mov ax, ds
        0x1f, // pop ds
        0xcb, // retf
    ]
}

/// A trap must report the module's *live* DS, not whichever segment the last
/// crossing happened to leave behind -- and a resume must hand that same DS
/// back, not silently replace it with the pre-trap value. Pins the fix to
/// `m16/fault.rs::rewrite`, which used to capture every `out_*` register but
/// `out_ds`, leaving [`Machine::regs`] to report a stale fold
/// (`Machine::enter`'s unconditional `self.ctx.ds = self.ctx.out_ds`) instead
/// of what the hardware DS register actually held at the trap.
#[test]
fn a_trap_reports_and_a_resume_preserves_the_modules_own_moved_ds() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.load_code(&ds_mover()).expect("module fits");
    let Exit::Interrupt { ip, .. } = machine.call(machine.code_ptr(0), &[]).expect("called") else {
        panic!("expected an interrupt");
    };
    assert_eq!(
        machine.regs().ds,
        machine.stack_selector(),
        "the trap must report the DS the module actually moved to, not data_selector()'s DGROUP"
    );
    machine.set_ip(ip + 2);
    match machine.jump().expect("resumed") {
        Exit::Returned { ax, .. } => assert_eq!(
            ax,
            machine.stack_selector(),
            "the resume must hand the module's own DS back, not the pre-trap crossing's"
        ),
        other => panic!("expected a return, got {other:?}"),
    }
}

/// The budget `tests/watchdog.rs` uses: small enough to keep the suite
/// quick, large enough that a scheduling hiccup cannot make a well-behaved
/// crossing look wedged.
const BUDGET: Duration = Duration::from_millis(50);

/// This thread's CPU time so far, from the same clock the watchdog arms.
/// Duplicated from `tests/watchdog.rs::cpu_time` -- integration test binaries
/// do not share code with each other.
fn cpu_time() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `clock_gettime` writes the `timespec` and nothing else.
    let ok = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    assert_eq!(ok, 0, "the thread CPU clock is not readable");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Burn `d` of **this thread's CPU time**, the clock the watchdog measures --
/// not wall clock. See `tests/watchdog.rs::burn` for why that distinction is
/// the whole point.
fn burn(d: Duration) {
    let start = cpu_time();
    while cpu_time() - start < d {
        std::hint::black_box(0u64);
    }
}

/// A tick that lands while the host is servicing a trap must still be honoured
/// at the next entry, not discarded because nothing was in 16-bit mode to
/// interrupt. `resume_cleaning` (the outstanding-call resume path) already
/// refuses to re-enter once `ctx.expired()`; `int 21h`'s resume goes through
/// `Machine::jump` instead, which is `tests/watchdog.rs`'s
/// `an_overrun_spent_in_host_code_still_counts` played out over that path:
/// the host burns the whole budget deciding how to service the trap, and the
/// module must not get to run again on the strength of a stale answer.
#[test]
fn jump_refuses_to_resume_a_trap_once_the_budget_is_gone() {
    let mut machine = Machine::new().expect("16-bit machine");
    machine.set_budget(BUDGET);
    machine.load_code(&get_drive_module()).expect("module fits");

    let Exit::Interrupt { ip, .. } = machine.call(machine.code_ptr(0), &[]).expect("called") else {
        panic!("expected an interrupt");
    };
    machine.set_ax(0x1902);
    machine.set_carry(false);
    machine.set_ip(ip + 2);

    burn(BUDGET * 3);

    match machine.jump().expect("jumped") {
        Exit::Timeout { .. } => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(
        matches!(machine.poisoned(), Some(Poison::Timeout { .. })),
        "a timed-out machine is poisoned"
    );
}

#[test]
fn read_answers_exactly_the_bytes_written_and_refuses_past_the_segment() {
    let mut machine = Machine::new().expect("16-bit machine");
    let at = FarPtr { selector: machine.data_selector(), offset: 0x10 };
    machine.write(at, b"hello").expect("fits");
    assert_eq!(machine.read(at, 5).expect("in bounds"), b"hello");
    let far = FarPtr { selector: machine.data_selector(), offset: 0xfffe };
    assert!(machine.read(far, 4).is_err(), "4 bytes at 0xfffe leave the segment");
}
