//! `crate::shims::math`'s routines, proven against a real `Wg32Cpu` -- in its
//! own process, for the same reason every other `Wg32Cpu`-building test in
//! this crate lives under `tests/` rather than in a `#[cfg(test)]` module:
//! `mbbs_machine::m32::Machine::new` unconditionally registers with
//! `crates/mbbs-machine/src/fault.rs`'s shared arbiter, and there is no
//! reason for that registration to entangle with `cargo test -p mbbs --lib`'s
//! otherwise-pure unit tests. See `wg32_abi.rs`'s own module doc comment for
//! the measured history behind that convention (an earlier version of a
//! `Wg32Cpu`-building test lived inline and broke three unrelated `mbbs16`
//! fault-recovery tests).
//!
//! # What this proves that `shims::math`'s own `#[cfg(test)]` tests do not
//!
//! Those are pure Rust: `4.0_f64.sqrt() == 2.0` and the like, proving the
//! arithmetic is right and nothing about the ABI. This file drives real
//! 32-bit code through a real crossing -- `mbbs_machine::m32::asm::enter`, the
//! actual far jump, the actual `fld`/`fstp` -- calling `shims::math::sqrt`/
//! `::modf` directly (not through `crate::shims::entry`, which needs a
//! registration this workstream deliberately leaves to a separate one; see
//! `shims::math`'s own module doc comment) and having the *module* pop `ST0`
//! with its own `fstp` afterward. If [`mbbs_machine::m32::Machine::run`]'s
//! `Ret::F64` handling ever regressed to leaving the value in `EAX`/`EDX`
//! instead, or to not writing it at all, this is what would catch it -- the
//! guest's own `fstp` would store whatever garbage (or stale value) happened
//! to be on the FPU stack instead.
//!
//! **Compiles once `pub mod math;` is added to `crates/mbbs/src/shims/mod.rs`
//! alongside the routine registrations** -- this file was verified against a
//! temporary local copy of that one line, then the line was reverted so this
//! workstream leaves that file untouched. See the handoff report for exactly
//! what to add.

use mbbs::abi::{Abi, Call, Exit, Ret, Wg32, Wg32Cpu};
use mbbs::shims::math;
use mbbs::{Host, Terms};
use mbbs_machine::m32::{Flat32Ptr, Image, Machine, Mapping, Memory, PeImage};
use mbbs_machine::ptr::ModulePtr;

/// Byte-for-byte `wg32_abi.rs`'s own `minimal_with_one_section`/`SIZE_OF_IMAGE`
/// -- duplicated per this crate family's established convention (see that
/// file's own citation of `mbbs_machine::m32::flatptr`'s and `mem`'s test
/// modules) rather than shared, since a private fixture in one `tests/*.rs`
/// binary is not reachable from another -- each file is its own crate.
const SIZE_OF_IMAGE: u32 = 0x0000_2000;

fn minimal_with_one_section() -> Vec<u8> {
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
    v[opt + 16..opt + 20].copy_from_slice(&0x0000_1111u32.to_le_bytes());
    v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes());
    v[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
    v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes());
    v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

    let sec = opt + 0xe0;
    v.resize(sec + 40 + 0x200, 0);
    v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
    v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes());
    v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes());
    v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    v
}

/// A real `Wg32Cpu` (genuine `Machine` + `Memory`) and the `Host<Wg32>` every
/// `Shim<Wg32>` signature requires, even though none of `shims::math`'s
/// routines ever touch it. `0x20000` bytes of arena -- the same size
/// `wg32_round_trip.rs`'s own `machine_and_placeholder` reserves -- is more
/// than `Host::new`'s own startup buffers (`spr`/`mdf`/`l2as`/`empty`) need.
fn cpu_and_host() -> (Wg32Cpu, Host<Wg32>) {
    let file = minimal_with_one_section();
    let pe = PeImage::parse(&file).expect("fixture parses");
    let image = Image::load(&file, &pe).expect("fixture loads");
    let mem = Memory::new(image, 0x0002_0000).expect("arena mapping");
    let machine = Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);
    let host = Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), Terms::new(1))
        .expect("host builds against the placeholder memory");
    (cpu, host)
}

/// `push imm32` -- `68` then the 4-byte immediate, cdecl's own pushed-argument
/// encoding.
fn push_imm32(code: &mut Vec<u8>, value: u32) {
    code.push(0x68);
    code.extend_from_slice(&value.to_le_bytes());
}

/// `call rel32` to `target`, computed against the address right after this
/// 5-byte instruction -- the ordinary near-call encoding every crossing test
/// in this crate family uses.
fn call_rel32(code: &mut Vec<u8>, base: u32, target: u32) {
    let call_at = base + code.len() as u32;
    code.push(0xe8);
    let next_ip = call_at + 5;
    code.extend_from_slice(&target.wrapping_sub(next_ip).to_le_bytes());
}

/// The proof this file exists for: real 32-bit guest code pushes a `double`
/// cdecl-style (high dword, then low dword, so `[esp]` holds the low half),
/// calls out to a thunk `shims::math::sqrt` answers directly, cleans its own
/// 8 pushed bytes the way a cdecl caller must, and pops `ST0` with its own
/// `fstp` -- the module's own instruction, run only once
/// [`mbbs_machine::m32::Machine::resume`] has re-entered it. If the host's
/// `Ret::F64` answer never reached `ST0`, this stores whatever the FPU stack
/// happens to hold instead, never `12.0` by accident.
#[test]
fn sqrt_shim_answer_reaches_the_guests_own_fstp() {
    const VALUE: f64 = 144.0; // a perfect square: 12.0 is exact, no epsilon needed
    const SLOT: u16 = 0;
    const RESULT_OFF: usize = 512;

    let (mut cpu, mut host) = cpu_and_host();
    let thunk = cpu.machine.thunk_addr(SLOT);

    let mut mapping = Mapping::new(4096).expect("a code mapping");
    let base = mapping.base() as usize as u32;
    let result_addr = base + RESULT_OFF as u32;

    let bytes = VALUE.to_le_bytes();
    let lo = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    let hi = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes"));

    let mut code = Vec::new();
    push_imm32(&mut code, hi); // pushed first -> ends up at [esp+4]
    push_imm32(&mut code, lo); // pushed second -> ends up at [esp], argument 0
    call_rel32(&mut code, base, thunk);
    code.extend_from_slice(&[0x83, 0xc4, 0x08]); // add esp, 8 -- the caller cleans, cdecl
    // fstp qword ptr [result_addr] -- DD /3, disp32 -- the module's own
    // instruction, storing whatever is on ST0 right now.
    code.push(0xdd);
    code.push(0x1d);
    code.extend_from_slice(&result_addr.to_le_bytes());
    code.push(0xc3); // ret

    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);
    let entry = Flat32Ptr(base);

    // `Exit<A>`/`Ret<A>` do not implement `PartialEq` -- see `abi.rs`'s own
    // doc comment on why their `Debug`/`Clone`/`Copy` impls are hand-written
    // rather than derived; nothing here needed `Eq`, so nothing added it.
    // Every other `Wg32`-driving test in this crate family (`wg32_abi.rs`'s
    // `call_round_trips_a_hand_assembled_immediate_return`) checks these the
    // same way: `match`, not `assert_eq!`.
    let exit = Wg32::call(&mut cpu, entry, &[]).expect("the call is recovered, not fatal");
    match exit {
        Exit::Call { index } => assert_eq!(index, SLOT, "stopped at the host call"),
        other => panic!("expected Exit::Call {{ index: {SLOT} }}, got {other:?}"),
    }

    let frame = Wg32::arg_frame(&cpu).to_vec();
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let ret = math::sqrt(&mut call, &mut host).expect("the sqrt shim");
    match ret {
        Ret::F64(v) => assert_eq!(v, 12.0, "the shim's own answer, before it ever reaches ST0"),
        other => panic!("expected Ret::F64(12.0), got {other:?}"),
    }

    let exit = Wg32::resume(&mut cpu, ret, mbbs::Cleans::Caller).expect("the module resumes");
    match exit {
        Exit::Returned { lo, hi } => {
            assert_eq!((lo, hi), (0, 0), "Ret::F64 clears EAX/EDX -- the value lives in ST0");
        }
        other => panic!("expected Exit::Returned {{ lo: 0, hi: 0 }}, got {other:?}"),
    }

    let stored = mapping.as_slice()[RESULT_OFF..RESULT_OFF + 8]
        .try_into()
        .expect("8 bytes");
    assert_eq!(
        f64::from_le_bytes(stored),
        12.0,
        "the module's own fstp did not see sqrt(144.0) on ST0"
    );

    drop(mapping);
}

/// `modf` proves the one shape none of the other five routines exercise:
/// writing an out-parameter through module memory *and* answering through
/// `ST0` in the same call. `iptr` has to be a real arena pointer -- unlike
/// the `fstp` destination above, `iptr.write` goes through
/// `mbbs_machine::m32::Memory::write_at`, which only recognises the image,
/// the arena and the stack, not an arbitrary `Mapping` this test built by
/// hand (`Memory::read_at`/`write_at`'s own doc comments).
#[test]
fn modf_writes_the_integral_part_and_answers_the_fraction_through_st0() {
    const VALUE: f64 = 2.5;
    const SLOT: u16 = 0;
    const RESULT_OFF: usize = 512;

    let (mut cpu, mut host) = cpu_and_host();
    let iptr = cpu.mem.alloc(8).expect("arena has room for one double");
    let thunk = cpu.machine.thunk_addr(SLOT);

    let mut mapping = Mapping::new(4096).expect("a code mapping");
    let base = mapping.base() as usize as u32;
    let result_addr = base + RESULT_OFF as u32;

    let bytes = VALUE.to_le_bytes();
    let lo = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    let hi = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes"));

    let mut code = Vec::new();
    // Declaration order is `modf(double value, double *iptr)`; cdecl pushes
    // right to left, so `iptr` is pushed first (ends up furthest from esp,
    // argument 1), then `value`'s two dwords (argument 0, nearest esp).
    push_imm32(&mut code, iptr.0);
    push_imm32(&mut code, hi);
    push_imm32(&mut code, lo);
    call_rel32(&mut code, base, thunk);
    code.extend_from_slice(&[0x83, 0xc4, 0x0c]); // add esp, 12 -- 3 pushed dwords
    code.push(0xdd);
    code.push(0x1d);
    code.extend_from_slice(&result_addr.to_le_bytes());
    code.push(0xc3);

    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);
    let entry = Flat32Ptr(base);

    let exit = Wg32::call(&mut cpu, entry, &[]).expect("the call is recovered, not fatal");
    match exit {
        Exit::Call { index } => assert_eq!(index, SLOT, "stopped at the host call"),
        other => panic!("expected Exit::Call {{ index: {SLOT} }}, got {other:?}"),
    }

    let frame = Wg32::arg_frame(&cpu).to_vec();
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let ret = math::modf(&mut call, &mut host).expect("the modf shim");
    match ret {
        Ret::F64(v) => assert_eq!(v, 0.5, "the fractional part, before ST0"),
        other => panic!("expected Ret::F64(0.5), got {other:?}"),
    }

    Wg32::resume(&mut cpu, ret, mbbs::Cleans::Caller).expect("the module resumes");

    let stored = mapping.as_slice()[RESULT_OFF..RESULT_OFF + 8]
        .try_into()
        .expect("8 bytes");
    assert_eq!(
        f64::from_le_bytes(stored),
        0.5,
        "the module's own fstp did not see modf's fractional part on ST0"
    );

    let integral = iptr.resolve(&cpu.mem, 8).expect("iptr is a real arena pointer");
    assert_eq!(
        f64::from_le_bytes(integral.try_into().expect("8 bytes")),
        2.0,
        "the integral part must land in module memory through iptr, not only on ST0"
    );

    drop(mapping);
}
