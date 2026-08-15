//! Task 17 of `docs/plans/2026-08-12-abi-border-implementation.md` (design
//! doc §7, finding 1): `rtkick` was 16-bit-shaped end to end -- the negative
//! check tested bit `0x8000` of the raw argument and the delay truncated
//! `as u16`. Under `Wg32` an `int` is four bytes, so the sign test checked
//! the wrong bit entirely and the truncation threw away the top two bytes:
//! `rtkick(86400)` (one day) became `86400 mod 65536 == 20864` seconds.
//!
//! `rtkick` itself is not reachable from an integration test (`mod shims`
//! is private, and it is not among the re-exports at `crates/mbbs/src/lib.rs`).
//! So this proves the fix the same way `wg32_round_trip.rs` proves `l2as`
//! and `toupper`: a real PE import bound to `rtkick`, a hand-assembled
//! cdecl call through the bound thunk, `Host::run` end to end, then the
//! answer read back off `Host::kicks()` (which -- along with `Kick` itself
//! -- IS public).
//!
//! Its own file, on `wg32_abi.rs`'s own reasoning: a real `Wg32Cpu` needs a
//! real `mbbs_machine::m32::Machine`, and `cargo test -p mbbs --lib` runs
//! every 16-bit and 32-bit unit test as threads of one process. Nothing
//! here needs to depend on the shared fault arbiter behaving correctly to
//! stay isolated from unrelated tests, so, like every other file that
//! builds a `Wg32Cpu`, this stays a separate integration-test binary --
//! hence a separate process.
//!
//! # TDD order, per the plan
//!
//! The plan is explicit that the *negative* test has to exist before the
//! *positive* one, "so the mutation has a victim": `rtkick(86400)` alone
//! cannot distinguish a correct sign test from the original wrong one --
//! `86400`'s bit 15 is 0 either way (`0x0001_5180 & 0x0000_8000 == 0`, the
//! same arithmetic the design doc measured), so a mutation that restores
//! the `0x8000` test would leave a suite with only the positive test green.
//! `a_negative_32_bit_delay_is_refused_by_the_32_bit_sign_bit` below is
//! that victim: `0x8000_0000` is negative as a 32-bit `int` but has bit 15
//! clear, so only a sign test anchored at `Abi::INT_WIDTH * 8 - 1` catches
//! it.

use mbbs::abi::{Wg32, Wg32Cpu};
use mbbs::{Host, Kick, Outcome, Terms};
use mbbs_machine::m32::{Flat32Ptr, Image, Machine, Memory, PeImage, Poison};

/// Byte-for-byte `wg32_round_trip.rs`'s own `SIZE_OF_IMAGE`/`put_u32`/
/// `put_bytes`/`skeleton`/`module_with_import` -- duplicated per this crate
/// family's convention of not sharing private test fixtures across files
/// (see `wg32_abi.rs`'s own doc comment on the same point).
const SIZE_OF_IMAGE: u32 = 0x0000_2000;

fn put_u32(v: &mut [u8], at: usize, val: u32) {
    v[at..at + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_bytes(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

fn skeleton() -> Vec<u8> {
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
    v
}

/// A module with `code` at its own entry point, plus one real PE import
/// directory naming `library!symbol` -- the same shape
/// `wg32_round_trip.rs`'s own `module_with_import` builds.
fn module_with_import(code: &[u8], library: &str, symbol: &str) -> Vec<u8> {
    let mut v = skeleton();
    let raw = 0x98 + 0xe0 + 40;
    assert!(code.len() <= 0x40, "leave room for the import directory after it");
    put_bytes(&mut v, raw, code);

    let desc0 = raw + 0x40;
    let desc1 = desc0 + 20;
    let thunk = desc1 + 20;
    let hint_name = thunk + 8;
    let lib_name = hint_name + 2 + symbol.len() + 1;
    assert!(
        lib_name + library.len() < raw + 0x400,
        "import directory must fit SizeOfRawData"
    );

    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    put_u32(&mut v, desc0, 0);
    put_u32(&mut v, desc0 + 4, 0);
    put_u32(&mut v, desc0 + 8, 0);
    put_u32(&mut v, desc0 + 12, to_rva(lib_name));
    put_u32(&mut v, desc0 + 16, to_rva(thunk));

    put_u32(&mut v, desc1, 0);
    put_u32(&mut v, desc1 + 4, 0);
    put_u32(&mut v, desc1 + 8, 0);
    put_u32(&mut v, desc1 + 12, 0);
    put_u32(&mut v, desc1 + 16, 0);

    put_u32(&mut v, thunk, to_rva(hint_name));
    put_u32(&mut v, thunk + 4, 0);

    put_bytes(&mut v, hint_name, &0u16.to_le_bytes());
    put_bytes(&mut v, hint_name + 2, symbol.as_bytes());
    v[hint_name + 2 + symbol.len()] = 0;

    put_bytes(&mut v, lib_name, library.as_bytes());
    v[lib_name + library.len()] = 0;

    let dir = 0x98 + 96 + 8;
    put_u32(&mut v, dir, to_rva(desc0));
    put_u32(&mut v, dir + 4, 20);

    v
}

/// `rtkick(delay, dstrou)`: cdecl pushes right to left, so `dstrou` is
/// pushed first and `delay` last -- `delay` ends up nearest the return
/// address, which is what `Call::int()` (read before `Call::ptr()`) needs.
/// Caller cleans (`Cleans::Caller`, `shims/mod.rs`'s `ROUTINES` table), so
/// the code cleans its own two dwords after the call.
fn calls_rtkick(thunk: u32, delay: u32, dstrou: u32) -> Vec<u8> {
    let mut code = Vec::new();
    for &arg in [delay, dstrou].iter().rev() {
        code.push(0x68); // push imm32
        code.extend_from_slice(&arg.to_le_bytes());
    }
    code.push(0xB8);
    code.extend(thunk.to_le_bytes()); // mov eax, thunk
    code.extend([0xFF, 0xD0]); // call eax
    code.extend([0x83, 0xC4, 0x08]); // add esp, 8
    code.push(0xC3); // ret
    code
}

fn machine_and_placeholder() -> Wg32Cpu {
    let file = skeleton();
    let pe = PeImage::parse(&file).expect("fixture parses");
    let image = Image::load(&file, &pe).expect("fixture loads");
    let mem = Memory::new(image, 0x0002_0000).expect("arena mapping");
    let machine = Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

fn load_module_and_host(cpu: &mut Wg32Cpu, file: &[u8]) -> (mbbs_machine::m32::Module, Host<Wg32>) {
    let mut host = Host::<Wg32>::new(cpu, mbbs::testing::data(), Terms::new(1))
        .expect("host builds against the placeholder memory");
    let module = host.load(cpu, file).expect("the synthetic module loads and binds");
    (module, host)
}

/// An arbitrary, distinctive pointer value for `dstrou`. `rtkick` never
/// dereferences it -- it only stores it -- so it need not name real code.
const DSTROU: u32 = 0x2222_10a0;

/// Step 1 of the plan's TDD order: the victim a sign-bit mutation needs.
/// `0x8000_0000` is negative as a 32-bit `int` (top bit set) but has bit 15
/// *clear* (`0x8000_0000 & 0x0000_8000 == 0`), so only a sign test anchored
/// at `Abi::INT_WIDTH * 8 - 1` (bit 31 for `Wg32`) catches it. The original
/// `delay & 0x8000` test does not: it lets this through, `as u16` then
/// truncates it to `0`, and `rtkick` silently takes the *zero-delay*
/// no-op branch instead of refusing -- so this test is red against the
/// unfixed shim not merely because the delay is wrong, but because a
/// negative delay is accepted as if it were an ordinary zero one.
#[test]
fn a_negative_32_bit_delay_is_refused_by_the_32_bit_sign_bit() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);
    let file = module_with_import(&calls_rtkick(thunk, 0x8000_0000, DSTROU), "WGSERVER.EXE", "_rtkick");

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host
        .run(&mut cpu, &module, entry, &[], None)
        .expect("a refused call is recovered, not fatal to the test process");

    let Outcome::Stopped(poison) = outcome else {
        panic!("expected Outcome::Stopped (rtkick must refuse a negative 32-bit delay), got {outcome:?}");
    };
    match poison {
        // `Refused`, not `Unimplemented`. `rtkick` is implemented; it ran and
        // declined a delay it cannot honour, which is a different thing from
        // a symbol this host lacks, and since 2026-08-15 the two have
        // different variants. This test asserted `Unimplemented` before that
        // -- while its own panic message called it "rtkick's own refusal",
        // which is exactly the confusion the split removed.
        Poison::Refused { symbol, why, .. } => {
            assert_eq!(symbol, "rtkick", "the poison must name the routine");
            assert!(
                why.contains("negative delay"),
                "the poison must name why rtkick refused: {why}"
            );
        }
        other => panic!("expected Poison::Refused (rtkick ran and declined), got {other:?}"),
    }
    assert_eq!(host.kicks(), [], "a refused delay must not be stored");
}

/// Step 2: `rtkick(86400)` -- the design doc's own motivating example, one
/// day, which LunatiX ships daily events for -- must store a kick with
/// `delay == 86400`, not `86400 mod 65536 == 20864`.
#[test]
fn rtkick_stores_a_full_day_without_truncating_it_to_16_bits() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);
    let file = module_with_import(&calls_rtkick(thunk, 86_400, DSTROU), "WGSERVER.EXE", "_rtkick");

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host
        .run(&mut cpu, &module, entry, &[], None)
        .expect("the call is recovered, not fatal to the test process");

    assert!(matches!(outcome, Outcome::Returned { .. }), "expected a clean return: {outcome:?}");
    assert_eq!(
        host.kicks(),
        [Kick {
            delay: 86_400,
            dstrou: Flat32Ptr(DSTROU),
        }],
        "86400 must survive whole -- a 16-bit-shaped `as u16` truncates it to 20864"
    );
}
