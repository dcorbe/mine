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

use mbbs32::{Exit, Machine, Mapping, Ret};

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

/// A serviced import call resumes the module *at the instruction after its
/// `call`*, not merely "with the right value somewhere in EAX".
///
/// mov eax, [esp+4]      ; the argument
/// call <thunk 7>        ; host routine -- returns arg * 2
/// add eax, 1            ; proves execution CONTINUED past the call
/// ret
///
/// The assertion is on `arg * 2 + 1`, deliberately not on `arg * 2`:
/// `docs/plans/2026-08-12-btrieve-finish.md` (Task 1) is explicit that a
/// machine which serviced the call but resumed at the wrong address, or
/// which never resumed at all and just reported the thunk's own value back
/// as though it were the module's, would *still* produce `arg * 2` here --
/// only the `add eax, 1` after the call site distinguishes "resumed
/// correctly" from either of those failures.
#[test]
fn a_serviced_import_call_resumes_and_the_module_sees_the_return_value() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(7);

    // Reserve the mapping first so `call`'s displacement can be computed
    // against the real address, exactly as
    // `a_module_that_calls_an_import_reaches_exit_call` does.
    let (mut mapping, entry) = code_at(&[]);
    let mut code = vec![
        0x8b, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    ];
    code.push(0xe8); // call rel32
    let call_site_end = entry + code.len() as u32 + 4;
    let rel = target.wrapping_sub(call_site_end);
    code.extend_from_slice(&rel.to_le_bytes());
    code.extend_from_slice(&[
        0x83, 0xc0, 0x01, // add eax, 1
        0xc3, // ret
    ]);
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    const ARG: u32 = 21;
    let exit = machine.call(entry, &[ARG]).expect("reaches the import call");
    assert_eq!(
        exit,
        Exit::Call { index: 7 },
        "the module's call did not reach the thunk"
    );

    // The host's answer to thunk 7: ARG * 2. `resume` hands it back in EAX
    // and re-enters after the `call` -- `add eax, 1` then runs on top of it.
    let exit = machine
        .resume(Ret::U32(ARG * 2))
        .expect("resumes past the call site");
    assert_eq!(
        exit,
        Exit::Returned {
            eax: ARG * 2 + 1,
            edx: 0
        },
        "the module did not resume executing after its own call instruction"
    );
}

/// `resume()` on a poisoned machine must refuse gracefully, exactly as
/// `Machine::call` already does -- not depend on `frame_sp` happening to be
/// `None` too. `docs/plans/2026-08-12-btrieve-finish.md` (Task 1 review,
/// Finding 1): removing `frame_sp = None` from `run`'s `Fault` arm leaves
/// every test passing today, because the only fault path exercised (one
/// taken during a fresh `call`) already has `frame_sp` at `None` from
/// `call`'s own reset. This test pins the guard directly, not the
/// coincidence.
#[test]
fn resume_on_a_poisoned_machine_returns_a_graceful_error() {
    let mut machine = Machine::new().expect("a Machine");

    // mov eax, [0] -- the same faulting instruction
    // `a_module_that_faults_poisons_the_machine_and_the_host_survives` uses.
    let (_code, entry) = code_at(&[0xa1, 0x00, 0x00, 0x00, 0x00]);

    let exit = machine
        .call(entry, &[])
        .expect("a fault is recovered, not fatal to the test process");
    assert!(
        matches!(exit, Exit::Fault { .. }),
        "expected Exit::Fault, got {exit:?}"
    );
    assert!(machine.poisoned().is_some(), "the machine must be poisoned");

    let err = machine
        .resume(Ret::Void)
        .expect_err("resume() on a poisoned machine must return an error, not panic");
    assert!(
        err.to_string().contains("poisoned"),
        "error did not mention the machine is poisoned: {err}"
    );
}

/// `frame_sp` must be cleared by the `Exit::Returned` arm of `run`, not left
/// pointing at a frame `resume()` already consumed.
/// `docs/plans/2026-08-12-btrieve-finish.md` (Task 1 review, Finding 4):
/// removing that clear leaves every test passing, because no existing test
/// resumes a call, lets the module return normally, and then tries to
/// resume again. Unlike a bare `call()` followed by `resume()` (whose
/// `frame_sp` was already `None` from `call`'s own pre-`run` reset, so the
/// clear-on-return would be invisible there too), this drives `frame_sp`
/// through `Some` first via an actual serviced `Exit::Call`, so only the
/// `Exit::Returned` arm's own clear can make the second `resume()` panic.
#[test]
#[should_panic(expected = "no outstanding call")]
fn resuming_after_the_module_has_already_returned_panics() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(9);

    // call rel32 ; ret -- the module makes exactly one host call, then
    // returns as soon as it is resumed past it.
    let (mut mapping, entry) = code_at(&[]);
    let mut code = vec![0xe8u8];
    let rel = target.wrapping_sub(entry + 5);
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xc3); // ret
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    let exit = machine.call(entry, &[]).expect("reaches the import call");
    assert_eq!(exit, Exit::Call { index: 9 });

    let exit = machine
        .resume(Ret::Void)
        .expect("resumes past the call site and the module returns");
    assert_eq!(exit, Exit::Returned { eax: 0, edx: 0 });

    // frame_sp must have been cleared by the Exit::Returned arm above;
    // resuming again with no outstanding call must panic, not silently
    // reuse the frame the previous resume() already consumed.
    let _ = machine.resume(Ret::Void);
}

/// The callee-saved quad (`EBX`/`ESI`/`EDI`/`EBP`) must survive a serviced
/// host call, not just a bare crossing. `docs/plans/2026-08-12-btrieve-finish.md`
/// (Task 1 review, Finding 2): `run()`'s propagation --
/// `self.ctx.ebx = self.ctx.out_ebx` and its three siblings -- is completely
/// unexercised; replacing all four right-hand sides with `0` leaves every
/// test passing. `asm.rs::tests::callee_saved_registers_survive_a_crossing`
/// only proves the raw crossing preserves these registers *within one*
/// `run()` call; it says nothing about `Machine::resume` carrying them
/// *across* one, which is what a module relies on when it calls a host
/// routine with live values in these registers (as `wccmmud.dll` does).
///
/// Distinct sentinels per register, each written to a scratch slot in the
/// module's own mapping *after* the host call returns, so the test can read
/// all four back independently and say which one -- if any -- was lost,
/// rather than only that something was.
///
/// Deliberately avoids EBP as a frame pointer: this code never needs
/// stack-relative addressing (arguments and the scratch address are all
/// referenced directly), so EBP is free to carry a plain sentinel like the
/// other three.
#[test]
fn callee_saved_registers_survive_a_serviced_host_call() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(11);

    const EBX_SENTINEL: u32 = 0x1111_1111;
    const ESI_SENTINEL: u32 = 0x2222_2222;
    const EDI_SENTINEL: u32 = 0x3333_3333;
    const EBP_SENTINEL: u32 = 0x4444_4444;
    const SCRATCH_OFFSET: u32 = 3072; // well clear of the code below

    let (mut mapping, entry) = code_at(&[]);
    let scratch_addr = entry + SCRATCH_OFFSET;

    let mut code = vec![0xbbu8]; // mov ebx, imm32
    code.extend_from_slice(&EBX_SENTINEL.to_le_bytes());
    code.push(0xbe); // mov esi, imm32
    code.extend_from_slice(&ESI_SENTINEL.to_le_bytes());
    code.push(0xbf); // mov edi, imm32
    code.extend_from_slice(&EDI_SENTINEL.to_le_bytes());
    code.push(0xbd); // mov ebp, imm32
    code.extend_from_slice(&EBP_SENTINEL.to_le_bytes());

    code.push(0xe8); // call rel32
    let call_site_end = entry + code.len() as u32 + 4;
    let rel = target.wrapping_sub(call_site_end);
    code.extend_from_slice(&rel.to_le_bytes());

    // The host call returns here. If `run()` failed to carry EBX/ESI/EDI/EBP
    // forward into the resumed entry, these would read back as 0 (or
    // whatever `Ctx::default()` leaves), not the sentinels above.
    code.push(0x89); // mov [scratch_addr], ebx
    code.push(0x1d);
    code.extend_from_slice(&scratch_addr.to_le_bytes());
    code.push(0x89); // mov [scratch_addr+4], esi
    code.push(0x35);
    code.extend_from_slice(&(scratch_addr + 4).to_le_bytes());
    code.push(0x89); // mov [scratch_addr+8], edi
    code.push(0x3d);
    code.extend_from_slice(&(scratch_addr + 8).to_le_bytes());
    code.push(0x89); // mov [scratch_addr+12], ebp
    code.push(0x2d);
    code.extend_from_slice(&(scratch_addr + 12).to_le_bytes());
    code.push(0xc3); // ret

    assert!(
        code.len() <= SCRATCH_OFFSET as usize,
        "test code overran the scratch region"
    );
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    let exit = machine.call(entry, &[]).expect("reaches the import call");
    assert_eq!(exit, Exit::Call { index: 11 });

    let exit = machine
        .resume(Ret::Void)
        .expect("resumes past the call site");
    assert_eq!(exit, Exit::Returned { eax: 0, edx: 0 });

    let scratch = &mapping.as_mut_slice()[SCRATCH_OFFSET as usize..SCRATCH_OFFSET as usize + 16];
    let read_u32 = |off: usize| u32::from_le_bytes(scratch[off..off + 4].try_into().unwrap());
    assert_eq!(read_u32(0), EBX_SENTINEL, "EBX was not preserved across the host call");
    assert_eq!(read_u32(4), ESI_SENTINEL, "ESI was not preserved across the host call");
    assert_eq!(read_u32(8), EDI_SENTINEL, "EDI was not preserved across the host call");
    assert_eq!(read_u32(12), EBP_SENTINEL, "EBP was not preserved across the host call");
}

/// `Ret::U64` must split `EDX:EAX`, high half in `EDX`. Nothing calls
/// `resume(Ret::U64(_))` today (`docs/plans/2026-08-12-btrieve-finish.md`,
/// Task 1 review, Finding 3), so mutating `Ret::registers()`'s `U64` arm to
/// always emit a `0` high half is undetected.
#[test]
fn resume_with_ret_u64_splits_across_edx_and_eax() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(13);

    // call rel32 ; ret -- the module hands back exactly what it was resumed
    // with, unmodified, so the split is observable in Exit::Returned.
    let (mut mapping, entry) = code_at(&[]);
    let mut code = vec![0xe8u8];
    let rel = target.wrapping_sub(entry + 5);
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xc3); // ret
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    let exit = machine.call(entry, &[]).expect("reaches the import call");
    assert_eq!(exit, Exit::Call { index: 13 });

    const VALUE: u64 = 0x1122_3344_5566_7788;
    let exit = machine
        .resume(Ret::U64(VALUE))
        .expect("resumes past the call site");
    assert_eq!(
        exit,
        Exit::Returned {
            eax: 0x5566_7788,
            edx: 0x1122_3344,
        },
        "Ret::U64 did not split EDX:EAX correctly"
    );
}

/// `Ret::Void` must clear both `EAX` and `EDX`.
/// `docs/plans/2026-08-12-btrieve-finish.md` (Task 1 review, Finding 3).
#[test]
fn resume_with_ret_void_clears_eax_and_edx() {
    let mut machine = Machine::new().expect("a Machine");
    let target = machine.thunk_addr(15);

    let (mut mapping, entry) = code_at(&[]);
    let mut code = vec![0xe8u8];
    let rel = target.wrapping_sub(entry + 5);
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xc3); // ret
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

    let exit = machine.call(entry, &[]).expect("reaches the import call");
    assert_eq!(exit, Exit::Call { index: 15 });

    let exit = machine
        .resume(Ret::Void)
        .expect("resumes past the call site");
    assert_eq!(
        exit,
        Exit::Returned { eax: 0, edx: 0 },
        "Ret::Void did not clear both EAX and EDX"
    );
}
