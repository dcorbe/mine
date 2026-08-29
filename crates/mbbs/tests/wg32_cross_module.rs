//! Two 32-bit modules on one `Wg32` machine: the second one's imports bind
//! to the first one's exports.
//!
//! This is the gate for `docs/plans/2026-08-29-wg32-n-module-boot`'s whole
//! point -- `mbbs-server --module wccmmud.dll --module wccmmpls.dll`, where
//! Plus imports seven routines from `WCCMMUD.dll`. Three things had to
//! become true for that, and each has a test below:
//!
//! 1. `Wg32::load` *appends* its image and registers the module under its
//!    PE export-directory name, so `Host`'s cross-module registry can find
//!    it (`an_import_from_a_loaded_pe_binds_to_its_export_not_a_thunk`).
//! 2. That registry is case-insensitive: a PE export directory says
//!    `wccmmud.DLL` and the importing PE's import directory says
//!    `WCCMMUD.dll`. The first test spells the two halves in deliberately
//!    different cases (`EXPO.DLL` exported, `expo.dll` imported) so an
//!    identity `Host::registry_key` fails it.
//! 3. Thunk slots are machine-wide, not per-module, so two modules never
//!    collide on one physical slot
//!    (`a_thunk_reached_under_the_wrong_module_still_resolves_to_its_true_owner`).
//!
//! A module loaded *after* the importer is still no answer at all -- an
//! import binds at load time or not at all -- and
//! `an_import_from_a_module_loaded_later_is_an_unresolved_thunk_named_at_first_use`
//! pins that: the thunk survives, and the stop names what it could not
//! serve.
//!
//! Its own binary, not a case in `wg32_round_trip.rs`, for that file's own
//! stated reason: a real `Wg32Cpu` needs a real `mbbs_machine::m32::Machine`,
//! which arms this thread's fault recovery, and an integration-test binary
//! is a separate process. The fixture builders below are copied from
//! `wg32_round_trip.rs` rather than shared, because two test binaries have
//! no module to share them through.

use mbbs::abi::{Wg32, Wg32Cpu};
use mbbs::{Host, Outcome, Terms};
use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr as _;

/// `size_of_image`, generous enough that a one-section image with a whole
/// hand-built import directory maps comfortably inside it.
const SIZE_OF_IMAGE: u32 = 0x0000_2000;

fn put_u32(v: &mut [u8], at: usize, val: u32) {
    v[at..at + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_bytes(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// The MZ/PE/COFF/optional-header skeleton every module fixture in this
/// file shares: one section (`CODE`, rva `0x1000`, `SizeOfRawData` `0x400`
/// so code, an import directory and an export directory all fit without
/// colliding), entry point at that section's own start. Byte-for-byte the
/// same header field values `wg32_round_trip.rs` already uses.
fn skeleton() -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics (not RELOCS_STRIPPED)
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

    let opt = 0x98;
    put_u32(&mut v, opt + 16, 0x1000); // entry point rva: the section's own start
    put_u32(&mut v, opt + 28, 0x2222_0000); // image base
    put_u32(&mut v, opt + 32, 0x1000); // section alignment
    put_u32(&mut v, opt + 36, 0x400); // file alignment
    put_u32(&mut v, opt + 56, SIZE_OF_IMAGE);

    let sec = opt + 0xe0;
    v.resize(sec + 40 + 0x400 + 0x200, 0);
    put_bytes(&mut v, sec, b"CODE\0\0\0\0");
    put_u32(&mut v, sec + 8, 0x400); // VirtualSize
    put_u32(&mut v, sec + 12, 0x1000); // VirtualAddress
    put_u32(&mut v, sec + 16, 0x400); // SizeOfRawData
    put_u32(&mut v, sec + 20, (sec + 40) as u32); // PointerToRawData
    put_u32(&mut v, sec + 36, 0x6000_0020); // CODE | EXECUTE | READ | WRITE
    v
}

/// File offset of the one section's raw data -- rva `0x1000`.
const fn raw() -> usize {
    0x98 + 0xe0 + 40
}

/// Write an export directory at file offset `dir`, exporting rva `0x1000`
/// (the section's own start, where every fixture here puts its code) as
/// `symbol` at ordinal 1, under the export-directory name `expname`, and
/// point data directory 0 at it.
///
/// The layout is exactly what `mbbs_machine::m32::PeImage::parse` reads:
/// `Name@+12`, `Base@+16`, `NumberOfFunctions@+20`, `NumberOfNames@+24`,
/// `AddressOfFunctions@+28`, `AddressOfNames@+32`,
/// `AddressOfNameOrdinals@+36`. The directory `Size` must be non-zero --
/// the parser skips the whole export directory when either the rva or the
/// size is zero -- and it also bounds the forwarder range, so the exported
/// rva (`0x1000`, below `dir`'s own rva) is never mistaken for a forwarder
/// string.
fn put_export_directory(v: &mut [u8], dir: usize, expname: &str, symbol: &str) {
    let raw = raw();
    let functions = dir + 40; // 1 x u32 rva
    let names = functions + 4; // 1 x u32 rva
    let ordinals = names + 4; // 1 x u16
    let dll_name = ordinals + 2;
    let sym_name = dll_name + expname.len() + 1;
    assert!(sym_name + symbol.len() + 1 < raw + 0x400, "export directory must fit SizeOfRawData");
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    put_u32(v, dir + 12, to_rva(dll_name)); // Name
    put_u32(v, dir + 16, 1); // Base
    put_u32(v, dir + 20, 1); // NumberOfFunctions
    put_u32(v, dir + 24, 1); // NumberOfNames
    put_u32(v, dir + 28, to_rva(functions));
    put_u32(v, dir + 32, to_rva(names));
    put_u32(v, dir + 36, to_rva(ordinals));
    put_u32(v, functions, 0x1000); // the code's own rva
    put_u32(v, names, to_rva(sym_name));
    put_bytes(v, ordinals, &0u16.to_le_bytes()); // unbiased ordinal 0 -> Base+0 = 1
    put_bytes(v, dll_name, expname.as_bytes());
    v[dll_name + expname.len()] = 0;
    put_bytes(v, sym_name, symbol.as_bytes());
    v[sym_name + symbol.len()] = 0;

    let dd = 0x98 + 96; // opt + 96 + DIR_EXPORT(0) * 8
    put_u32(v, dd, to_rva(dir));
    put_u32(v, dd + 4, (sym_name + symbol.len() + 1 - dir) as u32);
}

/// A one-section PE whose code returns 0x1234 and whose export directory
/// names that code `symbol` (ordinal 1) under the DLL name `expname`.
fn exporter(expname: &str, symbol: &str) -> Vec<u8> {
    let mut v = skeleton();
    let raw = raw();
    put_bytes(&mut v, raw, &[0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3]);
    put_export_directory(&mut v, raw + 0x40, expname, symbol);
    v
}

/// A module with `code` at its own entry point, plus one real PE import
/// directory naming `library!symbol` -- copied from `wg32_round_trip.rs`,
/// whose module doc comment explains why the bytes are built by hand.
/// `code` must leave the first `0x40` bytes of the section for it.
fn module_with_import(code: &[u8], library: &str, symbol: &str) -> Vec<u8> {
    let mut v = skeleton();
    let raw = raw();
    assert!(code.len() <= 0x40, "leave room for the import directory after it");
    put_bytes(&mut v, raw, code);

    // One descriptor, one all-zero terminator, a single thunk array read as
    // both ILT and IAT (`OriginalFirstThunk == 0`, the "older linker"
    // fallback), one hint/name pair, one library-name string.
    let desc0 = raw + 0x40;
    let desc1 = desc0 + 20;
    let thunk = desc1 + 20;
    let hint_name = thunk + 8; // one thunk entry + a 0 terminator
    let lib_name = hint_name + 2 + symbol.len() + 1;
    assert!(
        lib_name + library.len() < raw + 0x400,
        "import directory must fit SizeOfRawData"
    );

    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    put_u32(&mut v, desc0, 0); // OriginalFirstThunk: fall back to FirstThunk
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

    // Data directory 1 (import): rva(desc0), size irrelevant -- the parser
    // never trusts the directory `Size` field as a bound, only the all-zero
    // terminator descriptor.
    let dir = 0x98 + 96 + 8; // opt + 96 + DIR_IMPORT(1) * 8
    put_u32(&mut v, dir, to_rva(desc0));
    put_u32(&mut v, dir + 4, 20);

    v
}

/// [`module_with_import`], plus an export directory at section offset
/// `0x100` -- clear of the import directory, which ends well before it.
///
/// A module has to be *findable by name* for `Host::import_owner`'s
/// cross-module fallback to reach it at all (`Host::loaded_modules` is
/// keyed by `Abi::module_name`, and a PE with no export directory has no
/// name to be keyed by), so
/// [`a_thunk_reached_under_the_wrong_module_still_resolves_to_its_true_owner`]
/// needs its module A to export something. Nothing calls the export; it
/// exists so the module has a name.
fn module_with_import_and_export(
    code: &[u8],
    library: &str,
    symbol: &str,
    expname: &str,
    export: &str,
) -> Vec<u8> {
    let mut v = module_with_import(code, library, symbol);
    put_export_directory(&mut v, raw() + 0x100, expname, export);
    v
}

/// A module that calls a thunk bound to an import the host's tables serve
/// no answer for.
fn calls_unimplemented(thunk: u32) -> Vec<u8> {
    let mut code = vec![0xB8];
    code.extend(thunk.to_le_bytes()); // mov eax, thunk
    code.extend([0xFF, 0xD0]); // call eax
    code.push(0xC3); // ret, never reached: the host stops on the call
    code
}

/// A `Machine` and an empty `Memory`: every module below is pushed onto it
/// by `Host::load`. Built before any module file is assembled, so
/// [`Machine::thunk_addr`] is known (stable from `Machine::new` onward --
/// the thunk table lives in `Machine`'s own bridge mapping, never in
/// `Memory`) before a `calls_unimplemented` body needs it baked in.
fn machine() -> Wg32Cpu {
    let mem = Memory::new(0x0002_0000).expect("arena mapping");
    let machine = Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

/// Build one `Host<Wg32>` and load `file` into it through the real
/// `Host::load`. One channel: nothing here drives a connection.
fn load_module_and_host(cpu: &mut Wg32Cpu, file: &[u8]) -> (mbbs_machine::m32::Module, Host<Wg32>) {
    let mut host = Host::<Wg32>::new(cpu, mbbs::testing::data(), Terms::new(1))
        .expect("host builds against the empty memory");
    let module = host.load(cpu, file).expect("the synthetic module loads and binds");
    (module, host)
}

#[test]
fn an_import_from_a_loaded_pe_binds_to_its_export_not_a_thunk() {
    let mut cpu = machine();
    let exp = exporter("EXPO.DLL", "_answer");
    let (exporter_mod, mut host) = load_module_and_host(&mut cpu, &exp);
    let answer = exporter_mod.export_by_name("_answer").expect("exported");

    // Mixed case on purpose: the importer spells the DLL `expo.dll`.
    let imp = module_with_import(&[0xC3], "expo.dll", "_answer");
    let importer_mod = host.load(&mut cpu, &imp).expect("the importer loads and binds");

    // The IAT slot holds EXPO's own code address, not one of this machine's thunks.
    let iat = Flat32Ptr(cpu.mem.images()[1].base() + 0x1068);
    let bound = u32::from_le_bytes(iat.resolve(&cpu.mem, 4).expect("iat").try_into().unwrap());
    assert_eq!(bound, answer, "bound to the exporter's export");
    assert!(
        importer_mod.imports().iter().all(|s| s.resolved || s.module != "expo.dll"),
        "a cross-module import is not an unresolved thunk: {:?}",
        importer_mod.imports()
    );

    // And calling that address really runs the exporter's code.
    let outcome = host.run(&mut cpu, &importer_mod, Flat32Ptr(answer), &[], None).expect("runs");
    assert!(matches!(outcome, Outcome::Returned { lo: 0x1234, .. }), "got {outcome:?}");
}

#[test]
fn an_import_from_a_module_loaded_later_is_an_unresolved_thunk_named_at_first_use() {
    let mut cpu = machine();
    let thunk0 = cpu.machine.thunk_addr(0);
    let imp = module_with_import(&calls_unimplemented(thunk0), "EXPO.DLL", "_answer");
    let (importer_mod, mut host) = load_module_and_host(&mut cpu, &imp);
    let entry = Flat32Ptr(importer_mod.entry());
    let outcome = host.run(&mut cpu, &importer_mod, entry, &[], None).expect("reported, not fatal");
    let Outcome::Stopped(mbbs_machine::m32::Poison::Unimplemented { module, symbol }) = outcome else {
        panic!("expected an unimplemented-import stop, got {outcome:?}");
    };
    assert_eq!(module, "EXPO.DLL");
    // `answer`, not `_answer`: the reported name is `Host::symbol_name`'s,
    // which runs `exports::c_name` and strips the leading underscore --
    // the same spelling `wg32_round_trip.rs`'s own unimplemented-stop test
    // asserts against.
    assert!(symbol.contains("answer"), "the stop must name the import: {symbol}");
}

#[test]
fn a_thunk_reached_under_the_wrong_module_still_resolves_to_its_true_owner() {
    let mut cpu = machine();
    // Module A: one unresolved import -> machine-wide slot 0.
    let thunk0 = cpu.machine.thunk_addr(0);
    let a = module_with_import_and_export(
        &calls_unimplemented(thunk0),
        "NOWHERE.DLL",
        "_a_only",
        "AAA.DLL",
        "_a_entry",
    );
    let (a_mod, mut host) = load_module_and_host(&mut cpu, &a);
    // Module B: its own unresolved import -> slot 1, never slot 0.
    let b = module_with_import(&[0xC3], "NOWHERE.DLL", "_b_only");
    let b_mod = host.load(&mut cpu, &b).expect("b loads");
    assert_eq!((a_mod.thunk_base(), b_mod.thunk_base()), (0, 1));

    // And the base is actually *applied*: B's one IAT slot holds slot 1's
    // thunk address, not slot 0's. `patch_thunk_addresses` numbers its
    // sites locally; `Wg32::load`'s closure is what adds `thunk_base`.
    let iat = Flat32Ptr(cpu.mem.images()[1].base() + 0x1068);
    let bound = u32::from_le_bytes(iat.resolve(&cpu.mem, 4).expect("iat").try_into().unwrap());
    assert_eq!(bound, cpu.machine.thunk_addr(1), "B's thunk is machine-wide slot 1");

    // Enter A's code *as B*: the stop must still name A's import.
    let outcome = host.run(&mut cpu, &b_mod, Flat32Ptr(a_mod.entry()), &[], None).expect("reported");
    let Outcome::Stopped(mbbs_machine::m32::Poison::Unimplemented { symbol, .. }) = outcome else {
        panic!("expected a stop, got {outcome:?}");
    };
    // `a_only`, not `_a_only` -- `Host::symbol_name` strips the leading
    // underscore; see the sibling test above.
    assert!(symbol.contains("a_only"), "named A's import, not B's: {symbol}");
}
