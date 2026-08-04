//! A module's globals live in `DS`, and a host call must not disturb it.
//!
//! Borland's huge model gives a module a data segment of its own -- `DGROUP` --
//! separate from its stack, which is what `DS != SS` means in practice. Code
//! reaches its globals through `DS` with a plain 16-bit offset, so the host has
//! to load `DS` before entering and hand back whatever the module had on every
//! resume. `DS` is callee-saved exactly like `SI`, `DI` and `BP`.

use mbbs16::{Exit, FarPtr, Machine, Ret};

const THUNK: u16 = 5;

/// Two globals, and the values planted in them.
const FIRST_AT: u16 = 0x0200;
const SECOND_AT: u16 = 0x0202;
const FIRST: u16 = 0xc0de;
const SECOND: u16 = 0xf00d;

/// ```text
///  0: 8b 36 00 02     mov   0x200, %si   read a global -- DS-relative
///  4: 9a <far ptr>    lcall $CS, $thunk  the host gets a turn
///  9: 8b 3e 02 02     mov   0x202, %di   read another, AFTER the call
///  d: cb              lret
/// ```
///
/// The second read is the point. It only lands on the right bytes if `DS` came
/// back from the host call unchanged.
fn test_module() -> Vec<u8> {
    let mut code = vec![0x8b, 0x36];
    code.extend_from_slice(&FIRST_AT.to_le_bytes());
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x8b, 0x3e]);
    code.extend_from_slice(&SECOND_AT.to_le_bytes());
    code.push(0xcb); // lret
    code
}

const CALL_SITE: usize = 5;

fn run() -> (u16, u16) {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let thunk = machine.thunk_address(THUNK).to_bytes();
    code[CALL_SITE..CALL_SITE + 4].copy_from_slice(&thunk);
    machine.load_code(&code).expect("module fits");

    // Plant the globals in the data segment, which is neither the code segment
    // nor the stack.
    let ds = machine.data_selector();
    machine
        .write(
            FarPtr {
                offset: FIRST_AT,
                selector: ds,
            },
            &FIRST.to_le_bytes(),
        )
        .expect("first global");
    machine
        .write(
            FarPtr {
                offset: SECOND_AT,
                selector: ds,
            },
            &SECOND.to_le_bytes(),
        )
        .expect("second global");

    let mut exit_reason = machine
        .call(machine.code_ptr(0), &[])
        .expect("called the module");
    loop {
        match exit_reason {
            Exit::Call { index: THUNK } => {
                exit_reason = machine.resume(Ret::Void).expect("resumed");
            }
            Exit::Returned { .. } => break,
            Exit::Call { index } => panic!("unexpected thunk {index}"),
            Exit::Fault { signo, cs, ip } => {
                panic!("module faulted with signal {signo} at {cs:#06x}:{ip:#06x}")
            }
            Exit::Timeout { cs, ip } => panic!("module timed out at {cs:#06x}:{ip:#06x}"),
        }
    }

    (machine.si(), machine.di())
}

#[test]
fn a_module_reads_its_globals_through_ds() {
    let (before, _) = run();
    assert_eq!(before, FIRST, "global read before any host call");
}

#[test]
fn ds_survives_a_host_call() {
    let (_, after) = run();
    assert_eq!(after, SECOND, "global read after a host call");
}

#[test]
fn the_data_segment_is_distinct_from_code_and_stack() {
    let machine = Machine::new().expect("16-bit machine");

    // Three segments, three selectors. If DGROUP were quietly aliased onto the
    // stack, the tests above would still pass and `DS != SS` would be a lie.
    let ds = machine.data_selector();
    let ss = machine.stack_selector();
    let cs = machine.code_selector();

    assert_ne!(ds, ss, "DS must not be SS -- that is the whole huge model");
    assert_ne!(ds, cs, "DS must not be CS");
    assert_ne!(ss, cs, "SS must not be CS");
}

/// Read this thread's current `DS`.
fn host_ds() -> u16 {
    let ds: u16;
    // SAFETY: reading a segment register has no side effects.
    unsafe {
        std::arch::asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags))
    };
    ds
}

#[test]
fn the_host_gets_its_own_ds_back() {
    // Hygiene rather than correctness: 64-bit mode ignores DS's base, so host
    // code would not notice a module's selector left behind. It would still be
    // wrong -- the selector outlives the `Machine` that owned the descriptor --
    // and it costs one instruction to not be.
    let before = host_ds();
    let _ = run();
    assert_eq!(host_ds(), before, "host DS restored after the excursion");
}
