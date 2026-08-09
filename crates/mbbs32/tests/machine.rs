//! `Machine::call` against hand-assembled code, before trusting it against a
//! real module in `tests/wccmmud.rs`.
//!
//! These are the synthetic layer `docs/plans/2026-08-08-mbbs32-design.md`'s
//! "Testing" section calls for: a plausibly-wrong thunk table would satisfy
//! "the falsifying test passes" just as well as a correct one if the only
//! thing ever exercised were the real module's own particular call shape.
//! Exercising an ordinary return, an ordinary import call, and a fault
//! against code this file controls closes that gap before the real module
//! (which can only ever prove the *first* host symbol's call shape) is
//! trusted.

use mbbs32::{Exit, Machine, Mapping};

/// A fresh low mapping holding exactly `code`, and the linear address of its
/// first byte.
fn code_at(code: &[u8]) -> (Mapping, u32) {
    let mut mapping = Mapping::new(4096).expect("a code mapping");
    mapping.as_mut_slice()[..code.len()].copy_from_slice(code);
    let addr = mapping.base() as usize as u32;
    (mapping, addr)
}

#[test]
fn a_module_that_returns_reaches_exit_returned() {
    let mut machine = Machine::new().expect("a Machine");

    // mov eax, 0x12345678 ; ret
    let (_code, entry) = code_at(&[0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3]);

    let exit = machine.call(entry, &[]).expect("an ordinary return");
    assert_eq!(
        exit,
        Exit::Returned {
            eax: 0x1234_5678,
            edx: 0
        }
    );
}

#[test]
fn arguments_arrive_in_cdecl_order_and_the_return_value_reflects_them() {
    let mut machine = Machine::new().expect("a Machine");

    // mov eax, [esp+4] ; sub eax, [esp+8] ; ret
    // A cdecl callee reading its own two arguments straight off the frame
    // Machine::call built -- arg 0 nearest the return address, arg 1 above
    // it -- and proving it with SUBTRACTION rather than addition or a single
    // fixed value: addition is commutative, so a frame that silently pushed
    // the two arguments in swapped order (or shifted everything by 4 because
    // the return-address slot went missing) would still sum to the same
    // total and this test would not notice. Subtraction is not commutative,
    // so a wrong order or a wrong offset both show up as a wrong difference.
    let (_code, entry) = code_at(&[
        0x8b, 0x44, 0x24, 0x04, // mov eax, [esp+4]
        0x2b, 0x44, 0x24, 0x08, // sub eax, [esp+8]
        0xc3, // ret
    ]);

    let exit = machine
        .call(entry, &[100, 23])
        .expect("an ordinary return");
    assert_eq!(exit, Exit::Returned { eax: 77, edx: 0 });
}

#[test]
fn a_module_that_calls_an_import_reaches_exit_call() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(7);

    // call rel32, straight to thunk 7's own address -- standing in for a
    // module's `call dword ptr [iat_slot]` once `iat_slot` has been patched
    // to hold that same address (see `tests/wccmmud.rs` for the patched
    // form). The thunk never returns to this call site: it far-jumps
    // straight to the trampoline, so nothing after this instruction runs.
    // The displacement is relative to the address just past this
    // instruction, which depends on where the mapping lands -- reserve the
    // mapping first, then compute and write the 5 bytes against its real
    // address.
    let (mut mapping, entry) = code_at(&[]);
    let mut code = vec![0xe8u8];
    let rel = target.wrapping_sub(entry + 5);
    code.extend_from_slice(&rel.to_le_bytes());
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    let exit = machine.call(entry, &[]).expect("the call is recovered as Exit::Call");
    assert_eq!(exit, Exit::Call { index: 7 });
}

#[test]
fn a_module_that_faults_poisons_the_machine_and_the_host_survives() {
    let mut machine = Machine::new().expect("a Machine");

    // mov eax, [0] -- an ordinary, unprefixed dereference of address zero.
    let (_code, entry) = code_at(&[0xa1, 0x00, 0x00, 0x00, 0x00]);

    let exit = machine
        .call(entry, &[])
        .expect("a fault is recovered, not fatal to the test process");
    match exit {
        Exit::Fault { signo, eip } => {
            assert_eq!(signo, libc::SIGSEGV, "wrong signal recorded");
            assert_eq!(eip, entry, "EIP did not name the faulting instruction");
        }
        other => panic!("expected Exit::Fault, got {other:?}"),
    }

    assert!(
        machine.poisoned().is_some(),
        "a machine that faulted must be poisoned"
    );
    assert!(
        machine.call(entry, &[]).is_err(),
        "a poisoned machine must refuse re-entry"
    );

    // The host's own thread-local storage -- the FS_BASE hazard `fault.rs`
    // documents -- must still work after this excursion, exactly as
    // `fault.rs`'s own `a_faulting_module_leaves_the_hosts_thread_locals_working`
    // proves at the lower level. Checked again here because this is the
    // level `Machine::poisoned` and `Exit::Fault` actually reach a caller
    // through.
    thread_local! {
        static PROBE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }
    PROBE.with(|p| p.set(0x1357_9bdf));
    assert_eq!(
        PROBE.with(|p| p.get()),
        0x1357_9bdf,
        "the host's thread_local storage did not survive a module fault"
    );
}
