//! Assertion 2 of Task 15's synthetic round trip (design doc §5, acceptance
//! stage 1): a module that faults comes back `Outcome::Stopped` with
//! `m32::Poison::Fault { .. }`, through the *generic* `Host<Wg32>::run` --
//! not merely `mbbs_machine::m32::Machine::call` directly
//! (`crates/mbbs-machine/tests/fault.rs` already proves that layer).
//!
//! Its own file, per `docs/plans/2026-08-12-abi-border-implementation.md`'s
//! isolation warning: `cargo test` runs a binary's `#[test]` functions as
//! threads of ONE process, and constructing an `m32::Machine` rearms that
//! process's signal disposition for every thread in the binary. This test
//! deliberately faults its machine; `wg32_round_trip.rs`'s own tests must
//! keep running cleanly regardless of scheduling order, and have no reason
//! to share a process with one that doesn't. `crates/mbbs/tests/fault_16_alone.rs`'s
//! own module comment documents how skipping this once produced a false
//! accusation -- a whole binary died and blamed the wrong test.
//!
//! `hlt` (`0xf4`), not a null dereference: privileged in ring 3, so it
//! raises `#GP`, delivered as `SIGSEGV` -- `crates/mbbs-machine/tests/fault.rs`'s
//! `suicidal_module` already establishes this is the idiom this crate
//! family uses for "a module that dies," and the plan's own Task 15 text
//! names `hlt` specifically.

use mbbs::abi::{Wg32, Wg32Cpu};
use mbbs::{Host, Outcome, Terms};
use mbbs_machine::m32::{Flat32Ptr, Machine, Memory, Poison};

const SIZE_OF_IMAGE: u32 = 0x0000_2000;

fn put_u32(v: &mut [u8], at: usize, val: u32) {
    v[at..at + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_bytes(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Byte-for-byte `wg32_round_trip.rs`'s own `skeleton`/`module_with_code` --
/// duplicated per this crate family's convention of not sharing private
/// test fixtures across files (see `wg32_abi.rs`'s own doc comment on the
/// same point). One section, `code` at its own entry point, no imports.
fn module_with_code(code: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes());
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());

    let opt = 0x98;
    put_u32(&mut v, opt + 16, 0x1000);
    put_u32(&mut v, opt + 28, 0x2222_0000);
    put_u32(&mut v, opt + 32, 0x1000);
    put_u32(&mut v, opt + 36, 0x400);
    put_u32(&mut v, opt + 56, SIZE_OF_IMAGE);

    let sec = opt + 0xe0;
    v.resize(sec + 40 + 0x400 + 0x200, 0);
    put_bytes(&mut v, sec, b"CODE\0\0\0\0");
    put_u32(&mut v, sec + 8, 0x400);
    put_u32(&mut v, sec + 12, 0x1000);
    put_u32(&mut v, sec + 16, 0x400);
    put_u32(&mut v, sec + 20, (sec + 40) as u32);
    put_u32(&mut v, sec + 36, 0x6000_0020);

    let raw = sec + 40;
    put_bytes(&mut v, raw, code);
    v
}

/// A `Wg32Cpu` ready to load: a real `Machine` (thunk table, TIB, fault
/// recovery armed), and an empty `Memory` -- see `wg32_round_trip.rs`'s
/// module doc comment, "The load-order hazard", for why a `Host<Wg32>`
/// built before `load` must normally be discarded and rebuilt afterward.
/// Irrelevant to *this* test: a `hlt` module faults on its very first
/// instruction, before it ever calls a shim, so no host-owned buffer is ever
/// touched -- one ordinary `Host::new` before `load` is enough here.
fn cpu_module_and_host(code: &[u8]) -> (Wg32Cpu, mbbs_machine::m32::Module, Host<Wg32>) {
    let mem = Memory::new(0x0002_0000).expect("arena mapping");
    let machine = Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);

    let mut host = Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), Terms::new(1)).expect("host");
    let file = module_with_code(code);
    let module = host.load(&mut cpu, &file).expect("the synthetic module loads (no imports)");
    (cpu, module, host)
}

/// Assertion 2: a module that faults comes back `Outcome::Stopped` naming
/// `m32::Poison::Fault`, through `Host<Wg32>::run` -- the generic host's
/// own `A::poisoned` wiring (`abi/wg32.rs`'s `convert_exit` collapsing
/// `Exit::Fault` into `Exit::Stopped`, then `Host::run`'s
/// `A::poisoned(machine).expect(..)`), not merely the lower-level
/// `Machine::call` that `crates/mbbs-machine/tests/fault.rs` already
/// proves.
#[test]
fn a_hlt_module_stops_the_host_with_a_fault_poison() {
    let (mut cpu, module, mut host) = cpu_module_and_host(&[0xf4]); // hlt
    let entry = Flat32Ptr(module.entry());

    let outcome = host
        .run(&mut cpu, &module, entry, &[], None)
        .expect("a fault is recovered, not fatal to the test process");

    let Outcome::Stopped(poison) = outcome else {
        panic!("expected Outcome::Stopped, got {outcome:?}");
    };
    match poison {
        Poison::Fault { signo, eip } => {
            assert_eq!(signo, libc::SIGSEGV, "HLT raises #GP, delivered as SIGSEGV");
            assert_eq!(eip, module.entry(), "the fault must be reported at the module's own entry point");
        }
        other => panic!("expected Poison::Fault, got {other:?}"),
    }
}
