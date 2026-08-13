//! §5's named debt, closed: "built for it isn't tested." The arbiter in
//! `src/fault.rs` was designed for concurrency from the start -- per-thread
//! alternate stacks (`install_altstack` is `thread_local`), a mutexed LDT
//! free list (`src/ldt.rs`), lock-free registry reads (`SLOTS`, published
//! with `Release`/read with `Acquire`) -- and the thread-per-machine
//! decision (`docs/plans/2026-08-12-abi-border-design.md` §4 point 2, landed
//! Task 20 of `docs/plans/2026-08-12-abi-border-implementation.md`) makes
//! that concurrency reachable in production. But nothing has ever exercised
//! it: `crates/mbbs/tests/fault_16_after_32.rs` and `fault_32_after_16.rs`
//! construct BOTH machines and fault only ONE of them, SEQUENTIALLY -- one
//! `machine.call` returns before the other machine's is ever made. This file
//! is the first test where a 16-bit fault and a 32-bit fault can be
//! in-flight, on two real threads, at the same wall-clock instant.
//! A second test further down does the same for the watchdog's
//! *asynchronous* signal (both machines timing out at once) -- see that
//! test's own section header for why it earns its place beside the fault
//! case rather than being deferred to a future task.
//!
//! # Why this is its own binary
//!
//! `crates/mbbs/tests/fault_16_alone.rs`'s own module comment records the
//! reason at length, and it applies with extra force here: `cargo test` runs
//! every test in one binary as THREADS of one process, and constructing an
//! `m16::Machine` or an `m32::Machine` anywhere in that process rearms the
//! process-wide SIGSEGV/SIGILL/SIGBUS/SIGFPE disposition for every thread in
//! it. An earlier draft that put a two-machine fault test beside unrelated
//! ones killed the WHOLE BINARY with SIGSEGV and reported an innocent
//! CONTROL test as the failure -- a false accusation, because the real
//! culprit was a sibling test's machine racing this one's signal handler
//! installation. This file's whole reason to exist is to run two machines
//! concurrently ON PURPOSE; sharing a process with anything else would make
//! every result -- this test's and every sibling's -- meaningless. So it
//! gets a file of its own, hence its own binary, hence its own process.
//!
//! **What "wrong" looks like here.** If the per-thread altstack or the
//! registry's claim dispatch were broken under real concurrency, this test
//! would not fail with a tidy `assert!` -- a signal handler stepping on
//! another thread's altstack, or misreading which ABI's `Ctx` a fault
//! belongs to, corrupts a register file that is about to be `sigreturn`ed
//! into. The likely outcome is the **whole process dying** (SIGSEGV with no
//! handler able to run, or a handler that runs and rewrites the wrong
//! thread's context into garbage) -- which `cargo test` reports as this
//! binary aborting, not as a named test failing. That is `fault_16_alone.rs`'s
//! "the whole binary died and reported the control as the failing test"
//! danger, aimed squarely at the case it was written to warn about. A hang
//! (one thread never returning from `machine.call`) is also a legitimate,
//! reportable outcome of a broken arbiter and is exactly why this is run
//! under the timeout wrapper the house rules require for every concurrency
//! test, never bare `cargo test`.

use std::sync::Arc;
use std::sync::Barrier;

use mbbs_machine::m16;
use mbbs_machine::m32;

/// Fault iterations each thread drives, after the barrier releases both.
/// Large enough that the two threads' faults are overwhelmingly likely to
/// land inside each other's wall-clock window somewhere in the run (a
/// single pair of faults could, by pure luck, never truly overlap) --
/// small enough that ten full repeats of this file (the house rule for a
/// concurrency test) stay fast. Each iteration builds and discards a
/// fresh machine: `crates/mbbs-machine/tests/fault.rs`'s
/// `a_faulted_machine_refuses_to_be_entered_again` already pins that a
/// poisoned machine refuses a second call, so "every fault recovered" for
/// `ITERATIONS` faults can only mean `ITERATIONS` machines, not one
/// reused.
const ITERATIONS: usize = 300;

/// `HLT` -- privileged, so `#GP`, arriving as SIGSEGV. Byte-for-byte
/// `crates/mbbs-machine/tests/fault.rs`'s own `suicidal_module` fixture, and
/// `crates/mbbs/tests/fault_16_alone.rs`'s.
fn suicidal_16() -> Vec<u8> {
    vec![
        0xb8, 0x34, 0x12, // mov $0x1234, %ax
        0xf4, // hlt
    ]
}

/// `mov eax, [0]` -- an ordinary, unprefixed dereference of address zero.
/// Byte-for-byte `crates/mbbs-machine/src/m32/fault.rs`'s own
/// `null_deref_code` fixture, and `crates/mbbs/tests/fault_32_after_16.rs`'s.
fn null_deref_32() -> [u8; 5] {
    [0xa1, 0x00, 0x00, 0x00, 0x00] // mov eax, moffs32(0)
}

/// One 16-bit fault, start to finish: a fresh machine, one `HLT`, recovered
/// and poisoned. Called `ITERATIONS` times in a loop on its own thread.
fn fault_16_once(iteration: usize) {
    let mut machine = m16::Machine::new().expect("a 16-bit machine");
    machine.load_code(&suicidal_16()).expect("module fits");
    let entry = machine.code_ptr(0);

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        m16::Exit::Fault { signo, .. } => {
            assert_eq!(signo, libc::SIGSEGV, "iteration {iteration}: HLT raises #GP");
        }
        other => panic!("iteration {iteration}: expected a recovered fault, got {other:?}"),
    }
    assert!(
        matches!(machine.poisoned(), Some(m16::Poison::Fault { .. })),
        "iteration {iteration}: a faulted 16-bit machine must be poisoned"
    );
}

/// The 32-bit mirror of [`fault_16_once`].
fn fault_32_once(iteration: usize) {
    let mut mapping = m32::Mapping::new(4096).expect("a low mapping for the fault code");
    let entry = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..5].copy_from_slice(&null_deref_32());

    let mut machine = m32::Machine::new().expect("a 32-bit machine");

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        m32::Exit::Fault { signo, eip } => {
            assert_eq!(signo, libc::SIGSEGV, "iteration {iteration}");
            assert_eq!(eip, entry, "iteration {iteration}: EIP did not name the faulting instruction");
        }
        other => panic!("iteration {iteration}: expected a recovered fault, got {other:?}"),
    }
    assert!(
        matches!(machine.poisoned(), Some(m32::Poison::Fault { .. })),
        "iteration {iteration}: a faulted 32-bit machine must be poisoned"
    );
}

/// Two threads, one `m16::Machine` and one `m32::Machine`, both faulting in
/// a tight loop, released by the same [`Barrier`] so neither gets a head
/// start -- the barrier's only job is to maximise overlap, not to order
/// anything: once released, the two loops race freely, exactly as two
/// machine threads inside `mbbs-server` would (design doc §4 point 2).
///
/// Every fault recovered, on both threads, or this test fails; a process
/// death instead of a clean pass/fail is this file's own module doc
/// comment's "what wrong looks like" -- see there before assuming a bare
/// hang or abort here is unrelated noise.
#[test]
fn both_machines_fault_at_once_on_two_threads_and_both_recover() {
    let barrier = Arc::new(Barrier::new(2));

    let sixteen = {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERATIONS {
                fault_16_once(i);
            }
        })
    };

    let thirty_two = {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERATIONS {
                fault_32_once(i);
            }
        })
    };

    sixteen.join().expect("the 16-bit thread must not panic, and the process must not die under it");
    thirty_two.join().expect("the 32-bit thread must not panic, and the process must not die under it");
}

// ---------------------------------------------------------------------
// A concurrent TIMEOUT case, not just a concurrent fault -- see this
// file's own module doc for why this half exists at all: design doc §5's
// watchdog section names the same debt a second time ("the thread-per-
// machine decision makes one more case reachable... both machines faulting
// simultaneously"), and Task 16 of
// `docs/plans/2026-08-12-abi-border-implementation.md` already measured
// that the SEQUENTIAL watchdog-coexistence pair
// (`crates/mbbs/tests/timeout_16_after_32.rs`,
// `timeout_32_after_16.rs`) is asymmetric: mutating `crate::fault::untag`
// to claim unconditionally turns `timeout_32_after_16` red but leaves
// `timeout_16_after_32` green even though the SAME corruption -- a tick
// meant for one ABI's watchdog misdelivered to the other's -- happens on
// both directions. That asymmetry is a property of the SEQUENTIAL tests'
// own shape (only one machine's timer is ever armed at a time in either
// file -- see each file's own module doc, "never arms a budget of its
// own"), not of the arbiter. A concurrent case, where BOTH machines' POSIX
// timers are armed and ticking at once, is a different, stronger
// question: every tick delivered while this test runs is genuinely
// contested between two live claimants, on both sides, simultaneously --
// which is exactly the shape `untag`'s tag check exists to arbitrate.
//
// **Measured, not hoped.** Mutating `untag` to claim unconditionally (the
// same mutation Task 16 ran) was run against
// `both_watchdogs_tick_at_once_on_two_threads_and_both_recover` below, 20
// times under the house rules' timeout wrapper: 20/20 caught it, every
// time landing on the SAME defensive panic
// (`crates/mbbs-machine/src/m16/mod.rs:1112`, "came back on a stack that
// is not the module's") that the sequential pair's one catching direction
// also lands on. The sequential pair only ever exercises ONE watchdog
// armed at a time, so it can only ever observe the mutation from one
// side; run concurrently, both sides are live at once and the mutation is
// reliably visible from either. That is genuinely more than the
// sequential pair proves, not merely a repeat of it -- see the
// implementation report for the full mutation table this measurement
// belongs to.
// ---------------------------------------------------------------------

use std::time::Duration;

/// Short enough that `TIMEOUT_ITERATIONS` iterations on each thread stay
/// fast; long enough that the machine genuinely enters its wedged loop
/// before the watchdog fires (`crates/mbbs/tests/timeout_16_after_32.rs`
/// and `timeout_32_after_16.rs` both use the same value).
const BUDGET: Duration = Duration::from_millis(20);

/// Fewer than [`ITERATIONS`]: each one costs at least [`BUDGET`] of real
/// wall-clock time (the watchdog has to actually tick), unlike a
/// synchronous fault, which costs whatever `HLT` or a bad dereference
/// costs -- effectively nothing. Still enough, at [`BUDGET`]'s width, for
/// both threads' timers to be armed and ticking at overlapping wall-clock
/// instants throughout the run.
const TIMEOUT_ITERATIONS: usize = 30;

/// `jmp $` -- byte-for-byte `crates/mbbs-machine/tests/watchdog.rs`'s own
/// `wedged_module` fixture, and `crates/mbbs/tests/timeout_16_after_32.rs`'s.
fn wedged_16() -> Vec<u8> {
    vec![0xeb, 0xfe]
}

/// `jmp $` -- byte-for-byte `crates/mbbs-machine/tests/m32_watchdog.rs`'s
/// own `wedged_code` fixture, and `crates/mbbs/tests/timeout_32_after_16.rs`'s.
fn wedged_32() -> [u8; 2] {
    [0xeb, 0xfe]
}

/// One 16-bit timeout, start to finish: a fresh machine with a tight
/// budget, one wedged `jmp $`, recovered and poisoned.
fn timeout_16_once(iteration: usize) {
    let mut machine = m16::Machine::new().expect("a 16-bit machine");
    machine.set_budget(BUDGET);
    machine.load_code(&wedged_16()).expect("module fits");
    let entry = machine.code_ptr(0);

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        m16::Exit::Timeout { .. } => {}
        other => panic!("iteration {iteration}: expected a timeout, got {other:?}"),
    }
    assert!(
        matches!(machine.poisoned(), Some(m16::Poison::Timeout { .. })),
        "iteration {iteration}: a timed-out 16-bit machine must be poisoned"
    );
}

/// The 32-bit mirror of [`timeout_16_once`].
fn timeout_32_once(iteration: usize) {
    let mut mapping = m32::Mapping::new(4096).expect("a low mapping for the wedged code");
    let entry = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..2].copy_from_slice(&wedged_32());

    let mut machine = m32::Machine::new().expect("a 32-bit machine");
    machine.set_budget(BUDGET);

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        m32::Exit::Timeout { eip } => {
            assert_eq!(eip, entry, "iteration {iteration}: the two-byte loop jumps back to itself");
        }
        other => panic!("iteration {iteration}: expected a timeout, got {other:?}"),
    }
    assert!(
        matches!(machine.poisoned(), Some(m32::Poison::Timeout { .. })),
        "iteration {iteration}: a timed-out 32-bit machine must be poisoned"
    );
}

/// Both watchdogs, armed and ticking at once, on two threads. Both
/// timers share the real-time signal `crate::fault`'s arbiter multiplexes
/// (see that module's own doc comment, "Two signal classes") -- so unlike
/// [`both_machines_fault_at_once_on_two_threads_and_both_recover`] above,
/// every delivery while this test runs is genuinely contested between two
/// live registrations, not merely offered to a second one that has
/// nothing armed. That is the scenario `crate::fault::untag`'s per-ABI tag
/// exists for, and the scenario the sequential coexistence pair
/// (`crates/mbbs/tests/timeout_16_after_32.rs`,
/// `timeout_32_after_16.rs`) cannot produce, because each of those arms
/// only one machine's timer at a time.
#[test]
fn both_watchdogs_tick_at_once_on_two_threads_and_both_recover() {
    let barrier = Arc::new(Barrier::new(2));

    let sixteen = {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for i in 0..TIMEOUT_ITERATIONS {
                timeout_16_once(i);
            }
        })
    };

    let thirty_two = {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for i in 0..TIMEOUT_ITERATIONS {
                timeout_32_once(i);
            }
        })
    };

    sixteen.join().expect("the 16-bit thread must not panic, and the process must not die under it");
    thirty_two.join().expect("the 32-bit thread must not panic, and the process must not die under it");
}
