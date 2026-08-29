//! Acceptance stage 1 (design doc §5): a synthetic 32-bit module, loaded and
//! run through the *generic* `Host<Wg32>`, calling a real shared-table shim
//! through its own bound thunk and getting the answer back. Task 15 of
//! `docs/plans/2026-08-12-abi-border-implementation.md` -- the gate that
//! proves the border works end to end, not merely that the types check.
//!
//! # The binding question this file settles
//!
//! The shared shim table keys `l2as` as `("MAJORBBS", "l2as")`
//! (`crate::shims::routines`). The real PE spells the import
//! `WGSERVER.EXE!_l2as` (confirmed by `objdump -p` on the reference DLL --
//! see the implementation plan's "Corrections, measured during execution").
//! `crate::exports::c_name` already strips the leading underscore uniformly
//! for both container formats, so that half was never a gap. The library
//! name was: nothing in the tree normalised `WGSERVER.EXE` onto `MAJORBBS`
//! before this task. `Resolver::resolve` (which `Host::load` builds
//! internally, and which calls `shims::entry` with the import's own raw
//! library string) and `Host::run`'s dispatch (which does the same, from
//! the bound `ImportSite`) both look up `entry::<Wg32>("WGSERVER.EXE",
//! "l2as")`, and before this task that found nothing -- Task 10's "no gap
//! to close" was unverified precisely because no round trip had ever driven
//! a real `(module, symbol)` pair spelled the way the real PE spells it
//! through the resolver.
//!
//! **It did not work. This task made it work.**
//! `crate::shims::canonical_dll` (in `crates/mbbs/src/shims/mod.rs`)
//! aliases `WGSERVER.EXE` onto `MAJORBBS` at the one place both callers
//! already go through (`shims::entry`) -- see that function's own doc
//! comment, and `shims::tests::wgserver_exe_aliases_onto_majorbbs_for_wg32`
//! for the unit proof. This file is the end-to-end proof: every module
//! built below that binds an import spells its library `WGSERVER.EXE`, by
//! that exact byte sequence in a real PE import directory (not a shortcut
//! that hands the loader an already-built `Import` -- see "How the import
//! table is built" below) -- and
//! [`the_full_loop_calls_shim_resumes_and_returns_the_pointer`] would not
//! reach `Outcome::Returned` at all if the alias were missing: it would
//! stop with `Poison::Unimplemented` instead, exactly like
//! [`a_thunk_the_tables_do_not_serve_stops_the_host_naming_it`]'s
//! deliberately-unserved import does.
//!
//! # Why this is its own file, and why the fault test is not in it
//!
//! Same reasoning as `wg32_abi.rs`'s own module doc comment: a real
//! `Wg32Cpu` needs a real `mbbs_machine::m32::Machine`, and `Machine::new`
//! unconditionally arms this thread's fault recovery and registers a claim
//! with `crates/mbbs-machine/src/fault.rs`'s shared arbiter. `cargo test -p
//! mbbs --lib` runs every 16-bit and 32-bit unit test as threads of one
//! process; nothing here needs to depend on that arbiter's correctness to
//! stay isolated from `--lib`'s own tests, so, like `wg32_abi.rs`, this
//! stays out of it -- a separate integration-test binary is a separate
//! process.
//!
//! The fault assertion (a `hlt` module, deliberately poisoning its machine)
//! is a SECOND, further split: it lives in `wg32_round_trip_fault.rs`, its
//! own binary, per the implementation plan's own isolation warning. Every
//! test in *this* file must keep running cleanly after the one before it
//! (the meter test in particular re-derives a live machine and re-enters
//! it); a deliberately-faulting test has no reason to share a process with
//! them, even though `crates/mbbs-machine/src/fault.rs`'s arbiter is no
//! longer *destructive* across machines the way a standalone handler once
//! was (see `wg32_abi.rs`'s own history note on that).
//!
//! # How the import table is built
//!
//! By hand, as real PE bytes `PeImage::parse` walks itself -- an import
//! descriptor, a single thunk array read as both ILT and IAT, one hint/name
//! pair, one library-name string -- the same shape
//! `crates/mbbs-machine/tests/pe.rs`'s
//! `imports_walk_two_libraries_by_name_and_ordinal_with_the_iat_kept_separate_from_the_ilt`
//! already proves the parser accepts, reduced to one library and one
//! symbol. **Not** `image.rs`'s own `pe.imports.push(..)` shortcut (used by
//! its `bind_imports_refuses_an_absolute_answer...` test): that shortcut
//! only works because that test calls `Image::bind_imports` directly, after
//! its own `PeImage::parse`. `Abi::load`'s signature takes raw file bytes
//! and parses them itself (`fn load(cpu, file: &[u8], resolve: &dyn
//! ImportResolver<..>)`), so there is no seam for a pre-built `PeImage` to
//! reach it -- the import has to be real bytes in `file`, or `Host::load`
//! (the API this task's brief requires exercising, since `crate::Resolver`
//! is private and only `Host::load` can build one) never sees it at all.
//!
//! # The load-order hazard this file first exposed, now fixed
//!
//! `mbbs-server/src/host.rs`'s `life()` builds `Host::<Wg16>::new` and
//! *then* calls `host.load` -- safe for `Wg16` because `Wg16::load`
//! *mutates* the `Segments` a `Machine::new` scratch build already carries
//! (`abi/wg32.rs`'s own doc comment: "`Machine::load_ne` appends"), so a
//! `Host::new`-built buffer pointer stays valid after `load`. Building
//! `Host<Wg32>` the same way used to be unsafe: an earlier `Wg32::load`
//! *replaced* `cpu.mem` wholesale with a freshly mapped `Memory`, dropping
//! the old one -- and `Mapping::drop` really does `munmap` the old arena
//! (`crates/mbbs-machine/src/m32/map.rs`). A `Host<Wg32>` built the naive
//! way and then loaded carried buffer pointers (`self.l2as` among them)
//! computed against memory that no longer existed by the time any shim
//! tried to use them.
//!
//! Measured, not theorised: an earlier version of this harness built
//! `Host::new` against a placeholder `Memory` and then called `host.load`,
//! mirroring `host.rs` exactly. `l2as`'s own shim -- which writes its
//! formatted text through `self.l2as`, a pointer `Host::new` computed
//! against the placeholder -- then failed with `Flat32PtrError::OutOfBounds`
//! against the *new* memory `Wg32::load` had swapped in, and the round trip
//! came back `Outcome::Stopped` instead of `Outcome::Returned`. Not a
//! segfault (`Flat32Ptr::write` bounds-checks against the live `Memory`'s
//! own mapped ranges rather than dereferencing a raw address -- see
//! `flatptr.rs`), but a real, silent failure of every host-owned buffer the
//! moment a real module got loaded through the ordinary API.
//!
//! **That was a genuine gap in `Host<Wg32>`'s construction contract, not a
//! test-harness bug**, and Task 15's brief -- the synthetic round trip, not
//! a fix to `Wg32::load` -- was not the place to close it: at the time,
//! [`load_module_and_host`] below worked around the hazard rather than
//! fixing it, building a *first*, throwaway `Host<Wg32>` purely to reach
//! `Host::load` (and, through it, the real private `Resolver<Wg32>`),
//! discarding it the instant `load` returned, and building a *second*
//! `Host<Wg32>` against the now-final, now-stable `cpu.mem`.
//!
//! **The fix has since landed.** `Wg32::load` pushes the freshly loaded
//! `Image` onto `cpu.mem` (`mbbs_machine::m32::Memory::push_image`) while
//! leaving `cpu.mem`'s arena -- and every pointer already carved out of it
//! -- untouched (see `Abi::load`'s own doc comment in
//! `crates/mbbs/src/abi.rs`, which states the invariant this closes
//! generally: loading a module must never invalidate a pointer
//! `ModuleMem::alloc_region` already returned). [`machine_and_placeholder`]
//! below now builds `cpu.mem` with no image at all -- `Memory::new` no
//! longer requires one -- so the module `push_image` appends is the first
//! and only one, exactly the shape `Memory::image()` (still "the first
//! image loaded") expects. [`load_module_and_host`] builds exactly one
//! `Host<Wg32>`, the same order `host.rs` always used for `Wg16` and the
//! order that used to be unsafe here -- the workaround is gone because the
//! gap it worked around is closed, not merely papered over again.

use mbbs::abi::{Arg, ModuleMem, Wg32, Wg32Cpu};
use mbbs::{Host, Outcome, Terms};
use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

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
/// so code and an import directory both fit without colliding), entry point
/// at that section's own start. Byte-for-byte the same header field values
/// `wg32_abi.rs` and `crates/mbbs-machine/tests/pe.rs` already use.
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

/// A module with `code` at its own entry point and no imports at all.
fn module_with_code(code: &[u8]) -> Vec<u8> {
    let mut v = skeleton();
    let raw = 0x98 + 0xe0 + 40;
    assert!(code.len() <= 0x400, "must fit the section's raw data");
    put_bytes(&mut v, raw, code);
    v
}

/// A module with `code` at its own entry point, plus one real PE import
/// directory naming `library!symbol` -- see this file's own module doc
/// comment, "How the import table is built". `code` must leave the first
/// `0x40` bytes of the section for it; every caller here uses well under
/// that.
fn module_with_import(code: &[u8], library: &str, symbol: &str) -> Vec<u8> {
    let mut v = skeleton();
    let raw = 0x98 + 0xe0 + 40;
    assert!(code.len() <= 0x40, "leave room for the import directory after it");
    put_bytes(&mut v, raw, code);

    // One descriptor, one all-zero terminator, a single thunk array read as
    // both ILT and IAT (`OriginalFirstThunk == 0`, the "older linker"
    // fallback `crates/mbbs-machine/tests/pe.rs` also exercises), one
    // hint/name pair, one library-name string.
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

    // Hint (never read by this loader -- `pe.rs`'s own tests say so too),
    // then the name, NUL-terminated. The leading underscore is part of the
    // name itself, matching the real DLL's own spelling (`_l2as`) exactly.
    put_bytes(&mut v, hint_name, &0u16.to_le_bytes());
    put_bytes(&mut v, hint_name + 2, symbol.as_bytes());
    v[hint_name + 2 + symbol.len()] = 0;

    put_bytes(&mut v, lib_name, library.as_bytes());
    v[lib_name + library.len()] = 0;

    // Data directory 1 (import): rva(desc0), size irrelevant -- `pe.rs`
    // never trusts the directory `Size` field as a bound, only the all-zero
    // terminator descriptor.
    let dir = 0x98 + 96 + 8; // opt + 96 + DIR_IMPORT(1) * 8
    put_u32(&mut v, dir, to_rva(desc0));
    put_u32(&mut v, dir + 4, 20);

    v
}

/// `l2as(LONG) -> CHAR*`: push `5017` (`LONG` is one dword under `Wg32`),
/// call the thunk directly, caller cleans, the pointer comes back in `EAX`.
/// The plan's own code, verbatim.
fn calls_l2as(thunk: u32) -> Vec<u8> {
    let mut code = vec![0x68];
    code.extend(5017u32.to_le_bytes()); // push 5017
    code.push(0xB8);
    code.extend(thunk.to_le_bytes()); // mov eax, thunk
    code.extend([0xFF, 0xD0]); // call eax
    code.extend([0x83, 0xC4, 0x04]); // add esp, 4
    code.push(0xC3); // ret
    code
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

/// A `Machine`, and a `Wg32Cpu` bundling it with an empty `Memory` --
/// [`load_module_and_host`] pushes the real image onto it via `host.load`.
/// Built first, on its own, so [`Machine::thunk_addr`] is known (stable from
/// `Machine::new` onward, independent of `cpu.mem` -- the thunk table lives
/// in `Machine`'s own `bridge` mapping, never in `Memory`) before any module
/// file is even assembled -- every `calls_*` helper above needs the target
/// thunk address baked into the module's own code before that code exists.
fn machine_and_placeholder() -> Wg32Cpu {
    let mem = Memory::new(0x0002_0000).expect("arena mapping");
    let machine = Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

/// Build one `Host<Wg32>` and load `file` into it through the real
/// `Host::load` -- the same order `mbbs-server/src/host.rs` always used for
/// `Wg16`, and the order that used to be unsafe for `Wg32` before
/// `Wg32::load` was fixed to preserve `cpu.mem`'s arena (see this file's own
/// module doc comment, "The load-order hazard this file first exposed, now
/// fixed"). One channel: nothing here drives a connection.
fn load_module_and_host(cpu: &mut Wg32Cpu, file: &[u8]) -> (mbbs_machine::m32::Module, Host<Wg32>) {
    let mut host = Host::<Wg32>::new(cpu, mbbs::testing::data(), Terms::new(1))
        .expect("host builds against the placeholder memory");
    let module = host.load(cpu, file).expect("the synthetic module loads and binds");
    (module, host)
}

/// Assertion 1 (the full loop): `Host::run` reaches `Outcome::Returned`,
/// `lo` names a real pointer, and reading it back out of `cpu.mem` as a
/// `Flat32Ptr` cstring is exactly `l2as(5017)`'s decimal rendering --
/// call -> shim -> resume -> return, through `Ret<Wg32>::Ptr`, with the
/// `WGSERVER.EXE` binding this file's module doc comment settles actually
/// exercised (the import pushed below spells it that way, not `MAJORBBS`).
#[test]
fn the_full_loop_calls_shim_resumes_and_returns_the_pointer() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);
    let file = module_with_import(&calls_l2as(thunk), "WGSERVER.EXE", "_l2as");

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host
        .run(&mut cpu, &module, entry, &[], None)
        .expect("the call is recovered, not fatal to the test process");

    let Outcome::Returned { lo, hi } = outcome else {
        panic!("expected Outcome::Returned, got {outcome:?}");
    };
    assert_ne!(lo, 0, "l2as must answer a real pointer, not a null one");
    assert_eq!(hi, 0, "nothing set EDX; hi must be zero");

    let ptr = Flat32Ptr(lo);
    let text = ptr.read_cstr(&cpu.mem).expect("l2as's answer is NUL-terminated");
    assert_eq!(text, b"5017", "l2as(5017) must render its argument as decimal text");
}

/// Assertion 3 (the unimplemented path): a thunk bound to a name the tables
/// do not serve stops the host with `Poison::Unimplemented`, naming the
/// module and symbol it could not answer -- the same `WGSERVER.EXE`-spelled
/// import binding, deliberately pointed at a symbol nothing in this crate
/// implements.
#[test]
fn a_thunk_the_tables_do_not_serve_stops_the_host_naming_it() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);
    let file = module_with_import(
        &calls_unimplemented(thunk),
        "WGSERVER.EXE",
        "_this_routine_does_not_exist",
    );

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host
        .run(&mut cpu, &module, entry, &[], None)
        .expect("an unimplemented import is reported, not fatal");

    let Outcome::Stopped(poison) = outcome else {
        panic!("expected Outcome::Stopped, got {outcome:?}");
    };
    match poison {
        mbbs_machine::m32::Poison::Unimplemented { module, symbol } => {
            assert_eq!(module, "WGSERVER.EXE");
            assert!(
                symbol.contains("this_routine_does_not_exist"),
                "the poison must name the symbol the module actually asked for: {symbol}"
            );
        }
        other => panic!("expected Poison::Unimplemented, got {other:?}"),
    }
}

/// Assertion 4: a dispatch-count meter for the l2as round trip, the `Wg32`
/// sibling of `lib.rs`'s eight 16-bit meters.
///
/// **Derivation: exactly 1.** `Host::run`'s dispatch loop increments
/// `self.calls` exactly once per `Entry::Routine` it actually invokes
/// (`lib.rs`, immediately before `shims::call`/the shim itself run); it is
/// never incremented for the initial `A::call` that enters the module, nor
/// for the terminal `Exit::Returned` that ends the loop. This module's own
/// code makes exactly one host call (`l2as`, via the single `call eax`
/// `calls_l2as` emits) and nothing else -- no `poll`, no `cycle`, no
/// channel dispatch. Assumes one channel (`Terms::new(1)`), survey mode
/// off (never enabled here), and no globals touched by this module's own
/// code (it never reads `usrnum`/`margv`/anything else `Host::new` placed) --
/// none of those participate in this module's call graph, so none of them
/// could add a second dispatch.
#[test]
fn the_l2as_round_trip_dispatches_exactly_once() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);
    let file = module_with_import(&calls_l2as(thunk), "WGSERVER.EXE", "_l2as");

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let before = host.calls();
    let outcome = host.run(&mut cpu, &module, entry, &[], None).expect("recovered");

    assert!(matches!(outcome, Outcome::Returned { .. }), "expected a clean return: {outcome:?}");
    assert_eq!(before, 0, "a freshly built host must start at zero dispatches");
    assert_eq!(host.calls(), 1, "exactly one shim -- l2as -- was ever dispatched");
}

/// Beyond the four required assertions: proves the round trip is sensitive
/// to `Abi::INT_WIDTH` -- design §6's "founding falsifiability argument" --
/// which [`the_full_loop_calls_shim_resumes_and_returns_the_pointer`] is
/// NOT: `l2as` takes a `LONG` (`Abi::LONG_WIDTH == 4` in both ABIs, so it
/// cannot discriminate), read through `Call::long()`, never
/// `Call::int()`. `toupper(int) -> int` is a second, real, generic-core
/// shim (`crate::shims::text::toupper`), reached through the identical
/// `Host<Wg32>::run` dispatch and bound-thunk machinery, on a second
/// synthetic module -- whose argument IS read through `Call::int()`, the
/// one call in this whole crate whose byte width is `Abi::INT_WIDTH`. See
/// this task's own report for the mutation this test exists to catch
/// (`Wg32::INT_WIDTH = 2`): it panics inside `Wg32::int_from_bytes`
/// (`bytes.try_into().expect("INT_WIDTH bytes")` on a 2-byte slice), not a
/// silently wrong fold -- still a failing test, just not a quiet one.
#[test]
fn a_second_shim_call_proves_the_int_width_the_l2as_round_trip_cannot() {
    let mut cpu = machine_and_placeholder();
    let thunk = cpu.machine.thunk_addr(0);

    let mut code = vec![0x68];
    code.extend(u32::from(b'a').to_le_bytes()); // push 'a', one dword under Wg32
    code.push(0xB8);
    code.extend(thunk.to_le_bytes()); // mov eax, thunk
    code.extend([0xFF, 0xD0]); // call eax
    code.extend([0x83, 0xC4, 0x04]); // add esp, 4
    code.push(0xC3); // ret
    let file = module_with_import(&code, "WGSERVER.EXE", "_toupper");

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host.run(&mut cpu, &module, entry, &[], None).expect("recovered");

    let Outcome::Returned { lo, hi } = outcome else {
        panic!("expected Outcome::Returned, got {outcome:?}");
    };
    assert_eq!(lo, u32::from(b'A'), "toupper('a') must fold to 'A'");
    assert_eq!(hi, 0);
}

/// Beyond the four required assertions: the `Arg` dword-order mutation
/// design §6 names, applied to entering a module directly through
/// `Host::run`'s own `args` parameter -- a different `Arg<Wg32>` encoding
/// surface from the two `wg32_abi.rs` already proves (`Cursor`-level
/// decode, and a shim-call frame reached through a direct thunk entry).
/// SUBTRACTION, not addition, so a swap of the two arguments' dword order
/// changes the answer rather than agreeing with a swap by coincidence --
/// `crates/mbbs-machine/tests/machine.rs`'s own
/// `arguments_arrive_in_cdecl_order_and_the_return_value_reflects_them`
/// makes the identical choice one layer below `Arg` itself, for the
/// identical reason.
#[test]
fn host_run_encodes_entry_args_in_order_through_arg() {
    let mut cpu = machine_and_placeholder();
    // mov eax, [esp+4] ; sub eax, [esp+8] ; ret
    let code = vec![0x8b, 0x44, 0x24, 0x04, 0x2b, 0x44, 0x24, 0x08, 0xc3];
    let file = module_with_code(&code);

    let (module, mut host) = load_module_and_host(&mut cpu, &file);
    let entry = Flat32Ptr(module.entry());
    let outcome = host
        .run(&mut cpu, &module, entry, &[Arg::Long(100), Arg::Long(23)], None)
        .expect("recovered");

    let Outcome::Returned { lo, .. } = outcome else {
        panic!("expected Outcome::Returned, got {outcome:?}");
    };
    assert_eq!(lo, 77, "the first Arg minus the second, in the order they were given");
}

/// The regression this file's whole "load-order hazard" module doc section
/// is about: a pointer allocated out of `cpu.mem`'s arena *before* a module
/// is loaded must still resolve to the same bytes *after*. This is exactly
/// the shape `Host::new`'s own `spr`/`mdf`/`l2as`/`empty` buffers take --
/// carved out of the arena at `Host::new` time, then read and written by
/// shims for the rest of the host's life, load included.
///
/// Before `Wg32::load` was fixed to call `Memory::replace_image` instead of
/// rebuilding `cpu.mem` wholesale, this failed with
/// `Flat32PtrError::OutOfBounds`: the pattern below was written into the
/// *old* arena, and `Wg32::load` had since `munmap`'d it out from under the
/// pointer. See `Memory::replace_image`'s own doc comment
/// (`crates/mbbs-machine/src/m32/mem.rs`) and `Abi::load`'s own doc comment
/// (`crates/mbbs/src/abi.rs`) for the invariant this now upholds generally,
/// not just for this one buffer.
#[test]
fn loading_a_module_does_not_invalidate_a_pointer_the_host_already_holds() {
    let mut cpu = machine_and_placeholder();
    let mut host = Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), Terms::new(1))
        .expect("host builds against the placeholder memory");

    // A host-owned buffer, allocated straight out of the arena before any
    // module is loaded -- deliberately not through `Host::new`'s own
    // buffers, so this proves the general `ModuleMem::alloc_region`
    // contract rather than one specific field surviving by luck.
    let ptr = ModuleMem::alloc_region(&mut cpu.mem, 4).expect("4 bytes fit the placeholder arena");
    let pattern = *b"ABCD";
    ptr.write(&mut cpu.mem, &pattern).expect("the arena just handed this pointer back");

    let file = module_with_code(&[0xC3]); // ret -- nothing here needs to run
    host.load(&mut cpu, &file).expect("a module loads after the buffer was allocated");

    let got = ptr.resolve(&cpu.mem, 4).expect(
        "loading a module must not invalidate a pointer ModuleMem::alloc_region already \
         returned -- see Memory::replace_image's own doc comment",
    );
    assert_eq!(got, pattern, "the pointer's bytes must survive the load unchanged");
}
