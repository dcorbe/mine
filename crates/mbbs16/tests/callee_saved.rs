//! A host call must be transparent to the module's callee-saved registers.
//!
//! Borland's cdecl makes `SI`, `DI` and `BP` the callee's to preserve, and a
//! host shim is a callee like any other. This is a regression test: `DI` was
//! being destroyed by every host call, because `mbbs16_enter` is handed its
//! context in `%rdi`.
//!
//! The failure mode is the reason this has a test of its own. Nothing crashes.
//! The module carries on with a value it stored before the call quietly
//! replaced, and says nothing about it.

use mbbs16::{EXIT_THUNK, Exit, Machine};

const NOOP_THUNK: u16 = 1;

const SI_MARK: u16 = 0x1111;
const DI_MARK: u16 = 0x2222;
const BP_MARK: u16 = 0x3333;

/// ```text
///  0: be 11 11        mov   $0x1111, %si
///  3: bf 22 22        mov   $0x2222, %di
///  6: bd 33 33        mov   $0x3333, %bp
///  9: 9a <far ptr>    lcall $CS, $noop     takes nothing, returns nothing
///  e: 9a <far ptr>    lcall $CS, $exit
/// ```
fn test_module() -> Vec<u8> {
    let mut code = vec![0xbe];
    code.extend_from_slice(&SI_MARK.to_le_bytes());
    code.push(0xbf);
    code.extend_from_slice(&DI_MARK.to_le_bytes());
    code.push(0xbd);
    code.extend_from_slice(&BP_MARK.to_le_bytes());
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]);
    code
}

const NOOP_SITE: usize = 10;
const EXIT_SITE: usize = 15;

#[test]
fn a_host_call_preserves_si_di_and_bp() {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let noop = machine.thunk_address(NOOP_THUNK).to_bytes();
    let exit = machine.thunk_address(EXIT_THUNK).to_bytes();
    code[NOOP_SITE..NOOP_SITE + 4].copy_from_slice(&noop);
    code[EXIT_SITE..EXIT_SITE + 4].copy_from_slice(&exit);
    machine.load_code(&code).expect("module fits");

    let mut exit_reason = machine.enter(0).expect("entered 16-bit mode");

    loop {
        match exit_reason {
            Exit::Call { index: NOOP_THUNK } => {
                // Even at the call, the values the module set are visible.
                assert_eq!(machine.si(), SI_MARK, "SI at the call");
                assert_eq!(machine.di(), DI_MARK, "DI at the call");
                assert_eq!(machine.bp(), BP_MARK, "BP at the call");
                exit_reason = machine.resume(0).expect("resumed");
            }
            Exit::Call { index: EXIT_THUNK } => break,
            Exit::Call { index } => panic!("unexpected thunk {index}"),
            Exit::Fault { signo } => panic!("module faulted with signal {signo}"),
        }
    }

    // And they survived the round trip through the host untouched.
    assert_eq!(machine.si(), SI_MARK, "SI across the call");
    assert_eq!(machine.di(), DI_MARK, "DI across the call");
    assert_eq!(machine.bp(), BP_MARK, "BP across the call");
}
