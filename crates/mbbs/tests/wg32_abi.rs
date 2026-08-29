//! `Call<Wg32>`, proven against a real `Wg32Cpu` -- in its own process.
//!
//! **Why this is not `crates/mbbs/src/abi/wg32.rs`'s own `#[cfg(test)] mod
//! tests`, unlike every sibling `Abi` file.** A real `Wg32Cpu` needs a real
//! `mbbs_machine::m32::Machine`, and `mbbs_machine::m32::Machine::new` unconditionally registers
//! with `crates/mbbs-machine/src/fault.rs`'s shared arbiter. Registering is no longer
//! destructive to another ABI's recovery -- see below, that is the whole
//! point of the arbiter -- but `cargo test -p mbbs --lib` still runs every
//! 16-bit and 32-bit unit test as threads of ONE process, sharing the one
//! per-thread alternate signal stack and the one process-wide claim
//! registry `crates/mbbs-machine/src/fault.rs` owns. Nothing about that is unsafe by
//! itself, but it is still global state a `Wg32Cpu`-building test has no
//! reason to entangle with `abi/wg32.rs`'s otherwise-pure unit tests, so it
//! stays here, in its own process, on the same reasoning as always.
//!
//! Measured, not assumed: an earlier version of this file's test lived in
//! `abi/wg32.rs` instead, and `cargo test -p mbbs --lib` went from
//! `1281 passed; 0 failed` to `1282 passed; 3 failed` -- three unrelated
//! `mbbs16` fault-recovery tests broke, every one of them because this
//! file's `Wg32Cpu` had already clobbered the process's SIGSEGV handler
//! before they ran. That was `mbbs_machine::m32::fault`'s own standalone handler
//! stealing the disposition `mbbs_machine::m16::fault`'s handler needed, exactly the
//! bug `crates/mbbs-machine/src/fault.rs` now exists to fix -- but `cargo test`'s own
//! process model is still the right isolation for *this* file regardless:
//! each file under `tests/` is a separate binary, hence a separate process,
//! so nothing here needs to depend on the arbiter behaving correctly to stay
//! isolated from unrelated tests.
//!
//! **This no longer describes a production limitation.** A host serving both
//! a 16-bit and a 32-bit module from one process now can: `mbbs_machine::m16::fault` and
//! `mbbs_machine::m32::fault` each register a *positive* claim over the faulting `CS`
//! with `crates/mbbs-machine/src/fault.rs`'s shared arbiter instead of installing a
//! standalone handler, so the second `Machine::new` (whichever ABI is
//! second) no longer steals the first ABI's recovery. See
//! `crates/mbbs/tests/fault_16_after_32.rs`, `fault_16_alone.rs` and
//! `fault_32_after_16.rs` for the constructions this now proves recover
//! correctly in both orders.

use mbbs::abi::{Abi, Arg, Call, Cursor, Exit, ModuleMem, Ret, Wg16, Wg32, Wg32Cpu};

/// Byte-for-byte the same fixture `mbbs_machine::m32::flatptr`'s and `mbbs_machine::m32::mem`'s own
/// test modules build -- duplicated per this crate family's own convention
/// (see those modules' doc comments on `minimal_with_one_section`) rather
/// than shared, since a private test fixture in one source file is not
/// reachable from another.
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

/// A real `Wg32Cpu`: a genuine `mbbs_machine::m32::Machine` (thunk table, TIB,
/// fault recovery armed) bundled with a genuine `mbbs_machine::m32::Memory`
/// wrapping a loaded (if inert) image.
///
/// **Task 6 update:** this file's own doc comment used to say "nothing here
/// is entered" -- true when only `Call<Wg32>`'s frame-reading was proven
/// (Task 5's `Cursor`/`Call` proof, below). It stopped being true once
/// `mbbs_machine::m32::Machine::arg_frame` and `Machine::poison` landed and
/// `abi/wg32.rs`'s two `todo!()`s retired: `call_round_trips_a_hand_assembled_immediate_return`,
/// the `Cleans::Callee` panic test, and the `Arg` differential test below all
/// genuinely cross into 32-bit code through `Wg32::call`/`Machine::call` and
/// come back. This `cpu()` fixture is still not itself *executed against* --
/// its `Memory`/`Image` stay inert -- but the `Wg32Cpu` it returns is now a
/// real target for `Abi::call`, not merely `Call::new`'s frame-reading.
fn cpu() -> Wg32Cpu {
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 0x1000).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

/// The `Wg32::load(&mut cpu, ..)` sibling of [`cpu`]: an empty `Memory`,
/// no placeholder image, so the module `load` pushes lands at `images[0]`
/// -- the shape `cpu.mem.image()` expects. `cpu()` itself must keep its
/// placeholder for the tests above that read `cpu.mem.image()` with no
/// load in between; the two helpers serve disjoint sets of tests, and a
/// single shared one cannot correctly serve both once a load can push a
/// second image onto it.
fn cpu_for_load() -> Wg32Cpu {
    let mem = mbbs_machine::m32::Memory::new(0x1000).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

/// The proof this task exists for. `f(ptr, int, int)`: `Wg16` reads bytes
/// `0-4, 4-6, 6-8` (its `int` is 2 bytes); `Wg32` must read `0-4, 4-8, 8-12`
/// (its `int` is 4). Not "the numbers differ" in the abstract -- the same
/// three cursor calls, over the same bytes, land at different offsets
/// depending only on which `Abi` reads them. That divergence, not merely
/// "`Wg32` compiles", is what makes this test the point of the whole
/// abstraction. See this crate's own mutation record (in the task report)
/// for `Wg32::INT_WIDTH` set to `2`: this test is the one that catches it.
#[test]
fn call_reads_a_ptr_int_int_frame_at_32_bit_offsets_not_16_bit_ones() {
    // Distinct bytes per field, and a distinct high/low half within each
    // `int`, so a transposition or a short read fails loudly rather than
    // passing by coincidence.
    let ptr_bytes = 0xAABB_CCDDu32.to_le_bytes();
    let first_int = 0x1111_2222u32.to_le_bytes();
    let second_int = 0x3333_4444u32.to_le_bytes();
    let frame: Vec<u8> = [ptr_bytes, first_int, second_int].concat();
    assert_eq!(frame.len(), 12, "ptr(4) + int(4) + int(4) is 12 bytes under Wg32");

    let mut cpu = cpu();
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    assert_eq!(call.ptr(), mbbs_machine::m32::Flat32Ptr(0xAABB_CCDD), "bytes 0-4: the pointer");
    assert_eq!(
        call.int(),
        0x1111_2222,
        "bytes 4-8: the first int -- Wg16 would stop at byte 6, reading only \
         the low half (0x2222) of this word"
    );
    assert_eq!(
        call.int(),
        0x3333_4444,
        "bytes 8-12: the second int -- Wg16 would read this at bytes 6-8 \
         instead, two bytes early, landing inside what is actually the first \
         int's high half"
    );

    // Contrast against `Wg16`'s cursor over the exact same bytes: its
    // `int()` reads only 2 of the 12 bytes above, proving the divergence is
    // in the ABI, not merely asserted in prose. `Cursor` (not `Call`) here
    // because a `Wg16` cursor needs no `Machine` at all -- see `abi.rs`'s own
    // fixture tests for the same reasoning, and this file's own module doc
    // comment for why a `Wg16` `Machine` is not welcome in this binary
    // either way (moot here -- `Cursor` never builds one).
    let mut w16 = Cursor::<Wg16>::new(&frame);
    let _ = w16.ptr(); // bytes 0-4: PTR_WIDTH is 4 in both ABIs.
    assert_eq!(
        w16.int(),
        0x2222,
        "Wg16's int is 2 bytes -- the low half of Wg32's first int, not the \
         whole word"
    );
}

/// `Call::mem()` must reborrow the *same* `Memory` the `Wg32Cpu` was built
/// with, not a disconnected copy -- the same property `Call<Wg16>`'s own
/// test proves against a live `Machine`.
#[test]
fn call_mem_reborrows_the_same_memory_the_cpu_owns() {
    let mut cpu = cpu();
    let want = cpu.mem.image().expect("image").base();

    let mut call = Call::<Wg32>::new(&mut cpu, &[]);
    assert_eq!(call.mem().image().expect("image").base(), want);
}

/// `Abi::data_ptr` names the module's own image base -- the same answer an
/// ordinary pointer built from that base already gives, now that flat
/// addressing has no near/far distinction left to collapse.
#[test]
fn data_ptr_is_the_images_own_base() {
    let cpu = cpu();
    assert_eq!(Wg32::data_ptr(&cpu), mbbs_machine::m32::Flat32Ptr(cpu.mem.image().expect("image").base()));
}

/// `ModuleMem::alloc_region` reaches `mbbs_machine::m32::Memory`'s real allocator -- not
/// a stub that always errors, and not a pointer into the image by mistake.
/// The generic `Heap<A>`/`Arena<A>` core (`crates/mbbs/src/heap.rs`,
/// `arena.rs`) calls exactly this method, so this is also the smallest
/// possible proof that `Heap<Wg32>`/`Arena<Wg32>` have something real to grow
/// through, without standing up either type end to end (see this task's
/// report for what that would still take).
#[test]
fn alloc_region_reaches_the_real_arena() {
    let mut cpu = cpu();
    let ptr = ModuleMem::alloc_region(&mut cpu.mem, 8).expect("8 bytes fit");
    assert!(
        ptr.0.wrapping_sub(cpu.mem.image().expect("image").base()) >= SIZE_OF_IMAGE,
        "an allocated region must not land inside the image"
    );
}

/// Task 6, requirement 1: `Wg32::call` against real hand-assembled 32-bit
/// code, round-tripped through a genuine crossing -- `Machine::new`'s thunk
/// table and TIB, `asm::enter`, the lot -- not merely "the types check".
///
/// `mov eax, imm32 ; ret` (`B8 xx xx xx xx C3`) is the smallest program that
/// proves both halves at once: the module actually ran (a `Ret` that never
/// entered silicon could not produce `imm` from nothing), and `Exit::Returned`
/// carries it back correctly (`lo` from `EAX`).
#[test]
fn call_round_trips_a_hand_assembled_immediate_return() {
    let mut cpu = cpu();

    const IMM: u32 = 0x1234_5678;
    let mut mapping = mbbs_machine::m32::Mapping::new(4096).expect("a code mapping");
    let mut code = vec![0xB8]; // mov eax, imm32
    code.extend_from_slice(&IMM.to_le_bytes());
    code.push(0xC3); // ret
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);
    let entry = mbbs_machine::m32::Flat32Ptr(mapping.base() as usize as u32);

    let exit = Wg32::call(&mut cpu, entry, &[]).expect("the call is recovered, not fatal");
    match exit {
        Exit::Returned { lo, hi } => {
            assert_eq!(lo, IMM, "EAX must come back as lo, unmodified");
            assert_eq!(hi, 0, "nothing set EDX; hi must be zero, not garbage");
        }
        other => panic!("expected Exit::Returned{{lo: {IMM:#x}, hi: 0}}, got {other:?}"),
    }
}

/// Task (closing the `Wg32` stdcall gap): `Wg32::resume` given
/// `Cleans::Callee` used to panic unconditionally -- see the git history of
/// `abi/wg32.rs`'s doc comment on `Abi::resume` for the old claim ("32-bit
/// Worldgroup is uniformly cdecl, so a `Cleans::Callee` row reaching this ABI
/// is a bug in the host's shim table") and why it was wrong: true of
/// `WGSERVER`'s own exports, false of the Win32 API a Worldgroup NT module
/// imports directly (`KERNEL32.dll!GetModuleHandleA`/`!GetProcAddress`,
/// measured `stdcall` at `LUNATIX.DLL`'s own call sites -- see
/// `crate::shims::borland`'s own module doc comment).
///
/// This is the 32-bit analogue of
/// `crates/mbbs-machine/tests/cleanup.rs`'s "who pops the arguments" pair,
/// told apart the same way: real hand-assembled code, a genuine `call`
/// executed by the CPU (not simulated), and a stack-pointer measurement the
/// *module* takes -- `EBP` marks `ESP` before the pushes, `EAX = EBP - ESP`
/// after the relayed call returns -- rather than an assumption about what
/// `Cleans` "should" do. Two dwords (8 bytes) pushed either way, matching
/// `GetProcAddress`'s own arity; only `cleans` differs between the two tests
/// below.
fn relay_two_dwords(thunk: u32, mapping_base: u32) -> Vec<u8> {
    let mut code = vec![0x89, 0xe5]; // mov ebp, esp
    for dword in [2u32, 1] {
        code.push(0x68); // push imm32
        code.extend_from_slice(&dword.to_le_bytes());
    }
    // `call rel32` -- computed against this mapping's own base, known only
    // once it is allocated, so the displacement is patched in after the
    // pushes above are already in `code`, not hand-computed offline.
    let next_instruction = mapping_base + code.len() as u32 + 5;
    code.push(0xe8);
    code.extend_from_slice(&thunk.wrapping_sub(next_instruction).to_le_bytes());
    code.extend_from_slice(&[
        0x89, 0xe8, // mov eax, ebp
        0x29, 0xe0, // sub eax, esp
        0x89, 0xec, // mov esp, ebp
        0xc3, // ret
    ]);
    code
}

/// Build the relay above into a fresh code mapping, drive it through
/// `Wg32::call`/`Wg32::resume`, and answer how far `ESP` moved -- `0` if
/// `cleans` popped the two pushed dwords along with the near return address,
/// `8` if it left them for the module.
fn stack_delta_under(cpu: &mut Wg32Cpu, cleans: mbbs::Cleans) -> u32 {
    let thunk = cpu.machine.thunk_addr(0);
    let mut mapping = mbbs_machine::m32::Mapping::new(4096).expect("a code mapping");
    let base = mapping.base() as usize as u32;
    let code = relay_two_dwords(thunk, base);
    mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);
    let entry = mbbs_machine::m32::Flat32Ptr(base);

    let exit = Wg32::call(cpu, entry, &[]).expect("the relay's own call is recovered, not fatal");
    assert!(
        matches!(exit, Exit::Call { index: 0 }),
        "the relay must reach thunk 0, got {exit:?}"
    );
    let exit = Wg32::resume(cpu, Ret::<Wg32>::Void, cleans).expect("resumed");
    match exit {
        Exit::Returned { lo, .. } => lo,
        other => panic!("expected Exit::Returned, got {other:?}"),
    }
}

#[test]
fn a_caller_cleaned_wg32_routine_leaves_its_arguments_on_the_stack() {
    // cdecl, what every `WGSERVER` export is: `Cleans::Caller` drops only the
    // near return address, so the module's own (never-executed here) `add
    // esp, 8` is what was supposed to remove the rest.
    let mut cpu = cpu();
    let moved = stack_delta_under(&mut cpu, mbbs::Cleans::Caller);
    assert_eq!(moved, 8, "resume_on drops only the near return address");
}

#[test]
fn a_callee_cleaned_wg32_routine_takes_its_arguments_with_it() {
    // stdcall, what `GetProcAddress` is: the callee -- this host's own shim,
    // via `Wg32::resume` -- pops its own two dwords too.
    //
    // This is also this task's mutation check: if `resume_on_cleaning` (or
    // the `Cleans::Callee(8)` registered for `getprocaddress` in
    // `shims::mod::routines`) ever cleaned the wrong number of bytes, `moved`
    // would read that number's difference from `0` here instead -- e.g.
    // `Cleans::Callee(4)` (one byte short of the real 8) reports `moved ==
    // 4`, not `0`, and this assertion catches it. Confirmed by hand: passing
    // `mbbs::Cleans::Callee(4)` here instead of `8` fails with `left: 4,
    // right: 0` -- a corrupted module stack the old code would have left
    // silently in place under `Cleans::Caller`, or panicked on for the wrong
    // stated reason under the pre-fix `Cleans::Callee` arm.
    let mut cpu = cpu();
    let moved = stack_delta_under(&mut cpu, mbbs::Cleans::Callee(8));
    assert_eq!(moved, 0, "resume_on_cleaning must pop the near return address and both dwords");
}

#[test]
fn cleaning_zero_bytes_under_wg32_is_the_same_as_not_cleaning() {
    // So that `Cleans::Callee(0)` is expressible and means what it says,
    // mirroring `crates/mbbs-machine/tests/cleanup.rs`'s identical Wg16 case.
    let mut cpu = cpu();
    let moved = stack_delta_under(&mut cpu, mbbs::Cleans::Callee(0));
    assert_eq!(moved, 8);
}

/// Task 6, requirement 3 -- **the one that matters** (design §6). Both `Abi`
/// implementations agree `PTR_WIDTH == LONG_WIDTH == 4`; a ptr/long confusion
/// in generic code is invisible to either. Only `INT_WIDTH` (2 under `Wg16`,
/// 4 under `Wg32`) discriminates, and this is the differential test that
/// proves it still does, end to end through `Arg` and `Abi::call` -- not a
/// hand-built byte array agreeing with itself (that proof already exists,
/// decode-only, in `call_reads_a_ptr_int_int_frame_at_32_bit_offsets_not_16_bit_ones`
/// above; this one drives the SAME `Arg` list through a genuine crossing of
/// BOTH machines and reads the result back through each one's own `Call<A>`).
///
/// The harness trick: `entry` is the machine's own thunk address, entered
/// directly as if it *were* the module's entry point. `Machine::call` builds
/// its frame (near/far return address, then `args`) and jumps straight to
/// `entry` either way; when `entry` happens to be thunk code, the thunk sets
/// its `Exit::Call` markers and reports back immediately, with `frame_sp`
/// landing exactly where a real module's own call to that thunk would have
/// left it (`arg_frame`'s own doc comment on both machines: only the
/// near/far return address separates the two, and the thunk's own AX/CX save
/// -- `crate::m16::mod.rs`'s `THUNK_SAVES` -- is exactly compensated by
/// `frame_sp`'s own `+ THUNK_SAVES`). So this needs no hand-assembled relay
/// code: the frame `arg_frame()` reads back afterward is genuinely the one
/// `Wg16::call`/`Wg32::call` encoded from `args`, not a stand-in for it.
#[test]
fn the_same_arg_list_encodes_to_a_different_byte_length_under_each_abi() {
    const A: u32 = 0x1111_2222;
    const B: u32 = 0x3333_4444;

    // Wg32: two Arg::Int -> two dwords, 8 bytes. B lands at byte 4.
    let mut cpu = cpu();
    let entry32 = mbbs_machine::m32::Flat32Ptr(cpu.machine.thunk_addr(3));
    let exit32 = Wg32::call(&mut cpu, entry32, &[Arg::Int(A), Arg::Int(B)])
        .expect("reaches the thunk directly");
    assert!(
        matches!(exit32, Exit::Call { index: 3 }),
        "expected Exit::Call{{index: 3}}, got {exit32:?}"
    );
    let frame32 = Wg32::arg_frame(&cpu).to_vec();
    let mut call32 = Call::<Wg32>::new(&mut cpu, &frame32);
    assert_eq!(call32.int(), A, "Wg32's first Int");
    assert_eq!(
        call32.int(),
        B,
        "Wg32's second Int must start at byte 4 -- one whole dword in"
    );

    // Wg16: the same two values, truncated to Wg16::Int (u16) -- one word
    // each, 4 bytes total. B lands at byte 2.
    let mut machine16 = mbbs_machine::m16::Machine::new().expect("a 16-bit machine");
    let entry16 = machine16.thunk_address(3);
    let exit16 = Wg16::call(&mut machine16, entry16, &[Arg::Int(A as u16), Arg::Int(B as u16)])
        .expect("reaches the thunk directly");
    assert!(
        matches!(exit16, Exit::Call { index: 3 }),
        "expected Exit::Call{{index: 3}}, got {exit16:?}"
    );
    let frame16 = machine16.arg_frame().to_vec();
    let mut call16 = Call::<Wg16>::new(&mut machine16, &frame16);
    assert_eq!(call16.int(), A as u16, "Wg16's first Int");
    assert_eq!(
        call16.int(),
        B as u16,
        "Wg16's second Int must start at byte 2 -- one whole word in"
    );

    // The proof itself, stated as a byte offset rather than only as two
    // passing assertions above: B's own bytes sit at a DIFFERENT position in
    // each frame for the IDENTICAL two-element Arg list -- the same
    // "same input, different byte length" divergence design §6 calls the
    // founding falsifiability argument of this whole abstraction.
    assert_eq!(&frame16[2..4], &(B as u16).to_le_bytes(), "Wg16: B's bytes at offset 2");
    assert_eq!(&frame32[4..8], &B.to_le_bytes(), "Wg32: B's bytes at offset 4");
}

/// `alcmem`/`alczer` on a real `Wg32` ABI: an ordinary request still packs
/// into one shared `crate::heap::Heap` region, rather than each taking a
/// dedicated one of its own through
/// [`Heap::reserve_large`](mbbs::heap::Heap::reserve_large) -- the guard
/// against `shims::memory::alcmem`/`alczer`'s own `u16::try_from(want)`
/// branch silently becoming the only path (see this task's own mutation
/// table: flipping that branch's arms is exactly the mutation this test
/// exists to catch, and it is the one mutation `Wg16`-only coverage cannot
/// reach on its own, since `Wg16::Int` never produces a `want` past
/// `u16::MAX` in the first place).
///
/// A real `Call<Wg32>`/`Host<Wg32>`, not merely `Heap<Wg32>` in isolation:
/// `Host::heap()`'s own public accessor is what this reaches the heap
/// through, so this proves the *shim* dispatches correctly, not only that
/// the heap underneath it can.
///
/// [`Heap::block`](mbbs::heap::Heap::block), not
/// [`Heap::segments`](mbbs::heap::Heap::segments), is the discriminator:
/// `Host::new` already primes at least one packed region before this test's
/// own `alcmem` calls run (measured -- see the arena-sizing comment below),
/// so segment *count* cannot tell "packed into what was already there"
/// apart from "took a dedicated region that happens not to move the count
/// either", since `reserve_large` never touches `Heap`'s own `regions` at
/// all. `Heap::block` reads the opposite bookkeeping instead: it only ever
/// answers for a pointer `Heap::reserve` recorded in its own `blocks` map, a
/// `reserve_large` pointer never appears there, so it answers `None` for
/// one every time -- correctly or not.
#[test]
fn alcmem_and_alczer_still_pack_ordinary_wg32_sizes() {
    // `cpu()`'s own 4 KiB placeholder arena is too small here: `Host::new`
    // itself reserves some of it before this test ever calls `alcmem`
    // (measured: 13,216 bytes), and `Heap::reserve`'s own grow-by-region
    // policy maps a full `SEGMENT` (65,535 bytes, `crate::heap`'s own
    // constant) the first time anything asks it for room, regardless of how
    // small that first request is -- so even one `alcmem(256)` needs far
    // more arena than 256 bytes behind it. 256 KiB clears both with room to
    // spare.
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 256 * 1024).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);

    let mut host = mbbs::Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), mbbs::Terms::new(1))
        .expect("host builds against the placeholder memory");

    let frame = 256u32.to_le_bytes();

    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(a) = mbbs::shims::memory::alcmem(&mut call, &mut host).expect("alcmem(256)")
    else {
        panic!("alcmem returns a pointer")
    };

    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(b) = mbbs::shims::memory::alcmem(&mut call, &mut host).expect("alcmem(256) again")
    else {
        panic!("alcmem returns a pointer")
    };
    assert_ne!(a, b, "two allocations must not overlap");
    assert!(
        host.heap().block(a).is_some() && host.heap().block(b).is_some(),
        "both ordinary alcmem(256) calls must land in Heap::reserve's packed \
         accounting, not Heap::reserve_large's dedicated one"
    );

    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(c) = mbbs::shims::memory::alczer(&mut call, &mut host).expect("alczer(256)")
    else {
        panic!("alczer returns a pointer")
    };
    assert!(
        host.heap().block(c).is_some(),
        "alczer(256) must land in Heap::reserve's packed accounting too -- \
         it is the same branch alcmem's own assertion above proves"
    );

    // galfree round-trips the first block back, through the real shim, on
    // the real Wg32 ABI -- shims::memory::galfree itself needed no change
    // for this task; only Heap::free's own large-block list did.
    let free_frame = <Wg32 as Abi>::ptr_to_bytes(a);
    let mut call = Call::<Wg32>::new(&mut cpu, &free_frame);
    mbbs::shims::memory::galfree(&mut call, &mut host)
        .expect("galfree frees a packed Wg32 block");
}

/// The defect this task exists to close, end to end: MajorMUD-NT's own
/// module-init call, `alcblok(1501, 1544)` -- `1501 * 1544 + 8 =
/// 2,317,552` bytes, about 35x `Heap::reserve`'s packed-region ceiling --
/// against a real `Call<Wg32>`/`Host<Wg32>`. Before this task this refused
/// outright (`shims::memory::alcblok32`'s own doc comment carries the exact
/// error text); now it must take a dedicated region through
/// [`Heap::reserve_large`](mbbs::heap::Heap::reserve_large) and free
/// cleanly back through `freblok32`.
#[test]
fn alcblok32_answers_majormud_nts_own_call_and_frees_cleanly() {
    // A 4 MiB arena: `Memory::alloc`'s own ceiling, comfortably past the
    // 2,317,552 bytes this request needs -- `cpu()`'s own 4 KiB placeholder
    // arena exists only to satisfy `Mapping::new`'s "no zero-length
    // mapping" requirement for tests that never allocate anything real, and
    // is far too small here.
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 4 * 1024 * 1024).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);

    let mut host = mbbs::Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), mbbs::Terms::new(1))
        .expect("host builds against the placeholder memory");

    let mut frame = Vec::new();
    frame.extend(1501u32.to_le_bytes());
    frame.extend(1544u32.to_le_bytes());
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(block) = mbbs::shims::memory::alcblok32(&mut call, &mut host).expect(
        "alcblok(1501, 1544) -- MajorMUD-NT's own module-init call -- must no longer refuse",
    ) else {
        panic!("alcblok32 returns a pointer")
    };

    // Writable across the block's full length, not merely at its head --
    // the same "did the pointer actually resolve, end to end" proof this
    // task's own heap.rs unit tests hold `reserve_large` to directly.
    let full = vec![0xABu8; 1501 * 1544 + 8];
    mbbs_machine::ptr::ModulePtr::write(&block, &mut cpu.mem, &full)
        .expect("the whole 2,317,552-byte block must be writable");

    let free_frame = <Wg32 as Abi>::ptr_to_bytes(block);
    let mut call = Call::<Wg32>::new(&mut cpu, &free_frame);
    mbbs::shims::memory::freblok32(&mut call, &mut host)
        .expect("freblok32 frees the dedicated region back");
}

/// `alcblok`'s `qty` and `size` are `USHORT` -- **sixteen bits, in the
/// 32-bit build too** -- so the upper half of each 32-bit stack slot is not
/// the caller's to promise, and this host must not read it.
///
/// `re/wg33src/INC/GCOMM.H:261-264` declares
/// `alcblok(USHORT qty, USHORT size)`, and `ALCBLOK.C`'s own flat branch
/// casts *once it has them* -- `alczer(((ULONG)qty*size)+8)` -- a cast that
/// exists precisely because the two operands are sixteen bits each. The
/// vendor's compiled prologue reads them with `movzx`; it cannot see the
/// high half and neither may we. (`archive/.../wg1/GALDSRC/SRC/GCOMM.H:485`
/// spells the same pair `unsigned`, which *was* sixteen bits under the
/// 16-bit compiler this shim's own doc comment used to cite -- the type
/// widened with the compiler, the vendor's declaration deliberately did
/// not.)
///
/// # The live frame, measured three times
///
/// MajorMUD-NT's fourth module-init `alcblok` is `alcblok(751, 1072)`, and
/// the module leaves a stale pointer in the top half of `qty`'s slot --
/// `mov ax, [...]` into an `eax` that still held an address, then
/// `push eax`. Three otherwise identical boots of
/// `mbbs-server --module32 wccmmud.dll` put `0x405202ef`, `0x417202ef` and
/// `0x409202ef` in that slot: the low sixteen bits are `0x02ef` (751) every
/// time, and the varying halves are all inside this host's own m32 arena
/// range, which moves per run because `Memory::alloc`'s mapping is not
/// `MAP_FIXED`.
///
/// Reading all thirty-two bits turned an 805,080-byte request into
/// 1,156,812,916,952 bytes and stopped module init outright:
///
/// ```text
/// WGSERVER.EXE.alcblok refused: alcblok: 1156812916952 bytes does not fit
/// a 32-bit region length
/// ```
///
/// This test uses that exact frame. It is `0x405202ef` rather than a tidy
/// `0xdead02ef` on purpose: an invented constant would prove the masking
/// and lose the evidence that the garbage is a real address this host
/// itself handed the module.
#[test]
fn alcblok32_reads_a_ushort_qty_and_ignores_the_callers_stale_high_half() {
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 4 * 1024 * 1024).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);

    let mut host = mbbs::Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), mbbs::Terms::new(1))
        .expect("host builds against the placeholder memory");

    // The measured frame: qty's slot carries a leftover address in its top
    // half, size's slot happens to be clean. Both are USHORT, so both are
    // masked -- size's clean slot must not be what makes this pass, so the
    // sibling assertion below dirties it too.
    let mut frame = Vec::new();
    frame.extend(0x4052_02efu32.to_le_bytes());
    frame.extend(0x0000_0430u32.to_le_bytes());
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(block) = mbbs::shims::memory::alcblok32(&mut call, &mut host).expect(
        "alcblok(751, 1072) is an 805,080-byte request; reading qty's high half asks for \
         1,156,812,916,952 bytes and refuses",
    ) else {
        panic!("alcblok32 returns a pointer")
    };

    // The block is exactly 751 * 1072 + 8 bytes and every one of them
    // resolves -- a shim that masked qty to some *other* narrow width, or
    // that clamped rather than masked, lands here with a block too short to
    // write. `size` is `1072`, already even, so `rounded_blok_size` leaves
    // it alone and this is the vendor's own `((ULONG)qty*size)+8`.
    let full = vec![0xABu8; 751 * 1072 + 8];
    mbbs_machine::ptr::ModulePtr::write(&block, &mut cpu.mem, &full)
        .expect("the whole 805,080-byte block must be writable");

    let free_frame = <Wg32 as Abi>::ptr_to_bytes(block);
    let mut call = Call::<Wg32>::new(&mut cpu, &free_frame);
    mbbs::shims::memory::freblok32(&mut call, &mut host).expect("freblok32 frees it back");

    // `size`'s own slot, dirtied the same way. Nothing in the live trace
    // dirtied it, but the parameter is the same USHORT and a host that
    // masked only `qty` would be correct by accident on this module and
    // wrong on the next one. Before the fix this did not merely mis-size
    // the block -- `heap_size_arg` REFUSED it outright, so the failure is a
    // different one from `qty`'s and needs its own assertion.
    let mut frame = Vec::new();
    frame.extend(0x4052_02efu32.to_le_bytes());
    frame.extend(0x417f_0430u32.to_le_bytes());
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(block) = mbbs::shims::memory::alcblok32(&mut call, &mut host)
        .expect("size is USHORT too: its stale high half must be masked, not refused")
    else {
        panic!("alcblok32 returns a pointer")
    };
    let full = vec![0xCDu8; 751 * 1072 + 8];
    mbbs_machine::ptr::ModulePtr::write(&block, &mut cpu.mem, &full)
        .expect("masking size must give the same 805,080-byte block, not a larger one");
}

/// `ptrblok(VOID *bigptr, USHORT idx)` -- `GCOMM.H:270-273` -- has the same
/// sixteen-bit parameter as its `alcblok` sibling, and the same stale high
/// half would be fatal in a quieter way: `idx` is bounds-checked against the
/// block's `qty`, so an unmasked `0x4052_0005` is not a wild pointer but a
/// **NULL return**, which the vendor's own flat `ptrblok` can never produce
/// (its body is unconditional pointer arithmetic). The module would
/// dereference that NULL somewhere else entirely -- the exact shape
/// `shims::memory::alcmem`'s own doc comment records costing eighteen calls
/// to diagnose.
///
/// Not reached in a live boot yet, because `alcblok` refused first. That is
/// the reason to hold it here rather than wait for it.
#[test]
fn ptrblok32_reads_a_ushort_idx_and_ignores_the_callers_stale_high_half() {
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 4 * 1024 * 1024).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    let mut cpu = Wg32Cpu::new(machine, mem);

    let mut host = mbbs::Host::<Wg32>::new(&mut cpu, mbbs::testing::data(), mbbs::Terms::new(1))
        .expect("host builds against the placeholder memory");

    let mut frame = Vec::new();
    frame.extend(751u32.to_le_bytes());
    frame.extend(1072u32.to_le_bytes());
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(block) = mbbs::shims::memory::alcblok32(&mut call, &mut host)
        .expect("a clean alcblok(751, 1072) to index into")
    else {
        panic!("alcblok32 returns a pointer")
    };

    // Element 5 of 751, asked for with a stale address in the top half of
    // `idx`'s slot -- the same `0x4052` this file's alcblok test measured.
    let mut frame = <Wg32 as Abi>::ptr_to_bytes(block);
    frame.extend(0x4052_0005u32.to_le_bytes());
    let mut call = Call::<Wg32>::new(&mut cpu, &frame);
    let Ret::Ptr(elem) = mbbs::shims::memory::ptrblok32(&mut call, &mut host)
        .expect("ptrblok32 answers")
    else {
        panic!("ptrblok32 returns a pointer")
    };
    assert_ne!(
        elem,
        <Wg32 as Abi>::null_ptr(),
        "element 5 is in range: reading idx's high half puts it past qty and returns NULL, \
         which the vendor's own flat ptrblok cannot do"
    );

    // And it is the RIGHT element, not merely non-NULL: `bigptr + 8 +
    // size*idx`, the vendor's own arithmetic. A shim that masked `idx` to
    // zero would also pass the assertion above.
    let expect = <Wg32 as Abi>::ptr_checked_add(block, 8 + 1072 * 5)
        .expect("element 5 is inside the block");
    assert_eq!(
        elem, expect,
        "ptrblok must land on element 5, at bigptr + 8 + 1072*5"
    );
}

/// A live `mbbs-server` bug, reproduced twice against a real board: booting
/// `LUNATIX.DLL` faulted --
/// `module faulted with signal 11 at 0x413de00d` (and, a second run under a
/// different ASLR base, `0x40c9100d`) -- both thirteen bytes into whatever
/// `Wg32::init_entry` handed the host, and both offsets page-aligned once
/// the loaded base is subtracted (`0x413de00d - 0x100d == 0x413dd000`).
/// `0x100d` is `AddressOfEntryPoint + 0xd`: the host was entering the PE's
/// raw entry point -- a Borland C runtime startup stub for a DLL that is
/// never meant to run through `DllMain` -- instead of the module's real
/// init routine.
///
/// Every in-process test before this one resolved init by name
/// (`pe.export_rva("_init__lunatix")`, see `tests/lunatix.rs`) and called
/// `Host::run` directly, never `Abi::init_entry`. That is a *different*
/// code path from what `mbbs-server` actually calls -- `crates/mbbs-server`
/// `Wg32 as Abi>::init_entry` -- so the whole suite stayed green while
/// production's own boot sequence was broken. This test is the one that
/// goes through `Abi::init_entry` itself, against a real, unmodified
/// `LUNATIX.DLL`.
///
/// `_init__lunatix` is exported ordinal 1 at RVA `0x115c` -- measured
/// directly from the file's export directory (`Base = 1`, so ordinal 1 is
/// function index 0), independently confirmed by `objdump -p` (see
/// `tests/lunatix.rs`'s own doc comment on `the_init_entry_surveys`).
/// `AddressOfEntryPoint` is RVA `0x1000`, the address `Wg32::init_entry`
/// answered before this fix.
mod boot_bug {
    use super::*;

    /// The repository root, from this crate's own manifest directory.
    /// Duplicated from `tests/lunatix_offsets.rs` rather than shared --
    /// integration test binaries do not share code with each other.
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("the crate's own manifest directory resolves")
    }

    /// LunatiX 5.3F, as recovered -- byte-for-byte the same fixture
    /// `tests/lunatix.rs` and `tests/lunatix_offsets.rs` read. `None` (and
    /// every test below skips) when this tree does not have it, exactly
    /// like every other real-module test in this crate.
    fn lunatix_bytes() -> Option<Vec<u8>> {
        let path = repo_root().join("archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL");
        if !path.exists() {
            eprintln!("skipping: {} is not in this tree", path.display());
            return None;
        }
        Some(std::fs::read(&path).expect("LUNATIX.DLL reads"))
    }

    /// Answers `None` for every import -- `Image::bind_imports` still gives
    /// each one a thunk (see its own doc comment: "an unresolved symbol is
    /// given an index rather than skipped"), so `Wg32::load` succeeds
    /// without needing a single shim wired up. This test is about *which
    /// address* the host enters, not about running the module to
    /// completion -- `tests/lunatix.rs` already owns that (full `Host<Wg32>`
    /// with the real shim table).
    fn no_host(
        _library: &str,
        _symbol: &mbbs_machine::module::Symbol,
    ) -> Option<mbbs_machine::module::Import<mbbs_machine::m32::Flat32Ptr>> {
        None
    }

    /// The proof this bug fix exists for: `<Wg32 as Abi>::init_entry`, the
    /// exact method `crates/mbbs-server`'s host thread calls, must resolve
    /// to `_init__lunatix` (ordinal 1) and not to `Module::entry()` (the PE
    /// entry stub) -- through `Wg32::load`, the same loader the server
    /// uses, not a hand-built `Module`.
    ///
    /// # Mutation check
    ///
    /// Reverting `Wg32::init_entry` to
    /// `Some(mbbs_machine::m32::Flat32Ptr(module.entry()))` makes this fail
    /// with `left: 0x1000, right: 0x115c` -- verbatim in the task report.
    #[test]
    fn init_entry_resolves_ordinal_1_not_the_pe_entry_stub() {
        let Some(file) = lunatix_bytes() else { return };
        let mut cpu = cpu_for_load();

        let module = Wg32::load(&mut cpu, &file, &no_host)
            .expect("LunatiX's own imports all bind -- unresolved ones just get a thunk");

        let base = cpu.mem.image().expect("image").base();
        let got = <Wg32 as Abi>::init_entry(&module).expect("LunatiX exports ordinal 1");

        assert_eq!(
            got.0.wrapping_sub(base),
            0x115c,
            "init_entry must answer _init__lunatix's RVA (ordinal 1), not \
             AddressOfEntryPoint's 0x1000"
        );
        assert_ne!(
            got.0,
            module.entry(),
            "the bug itself: init_entry must not answer the same address as \
             Module::entry() (the Borland startup stub) -- entering that \
             stub is exactly what faulted mbbs-server"
        );
    }

    /// The same bug, reproduced and then shown fixed by actually entering
    /// silicon -- not just comparing addresses. Entering the raw PE entry
    /// point on this real module does not get where entering `init_entry`
    /// gets, which is why the server crashed while answering the former.
    ///
    /// `Wg32::call` recovers a fault into `Exit::Stopped` rather than
    /// taking the test process down with it (`crates/mbbs-machine/src/m32/fault.rs`),
    /// so this can assert on the *shape* of what happened without a
    /// subprocess.
    ///
    /// This test used to assert that the stub *faults*, and failed about one
    /// run in four because that is not an invariant -- see the comment where
    /// the stub is entered. The asymmetry it demonstrates is real; the
    /// particular way the wrong entry point misbehaves is not fixed.
    /// The import `_init__lunatix` stops at, as `bind_imports` numbers them.
    /// Fixture-derived and stable: it is a property of LunatiX's own import
    /// table, not of anything this test does.
    const INIT_FIRST_IMPORT: u16 = 48;

    #[test]
    fn the_pe_entry_stub_does_not_reach_what_the_real_init_routine_reaches() {
        let Some(file) = lunatix_bytes() else { return };

        // The bug, reproduced: entering `Module::entry()` -- what
        // `Wg32::init_entry` answered before this fix -- on the real,
        // unmodified module.
        let mut stub_cpu = cpu_for_load();
        let module = Wg32::load(&mut stub_cpu, &file, &no_host).expect("LunatiX loads");
        let stub = mbbs_machine::m32::Flat32Ptr(module.entry());
        let stub_exit =
            Wg32::call(&mut stub_cpu, stub, &[]).expect("a fault is recovered, not fatal");

        // Deliberately *not* asserted: that this faults. It usually does --
        // SIGSEGV at `base + 0xc0d`, which is the crash the server took -- but
        // measured over 60 runs it instead reaches an unresolved import on
        // roughly a quarter of them, answering `Call { index: 35 }` or `38`
        // with no poison at all. Which of the two happens is decided by where
        // the kernel put the image: `Image::load` maps with `MAP_32BIT` and no
        // `MAP_FIXED` (see `m32/flatptr.rs`), so the base is a different
        // address every run and the stub's path through it changes with it.
        //
        // So "it faults" was never the invariant, only the common case, and
        // asserting it made this test fail about one run in four. What is
        // invariant is that entering the stub does not get where entering the
        // real init routine gets -- which is the actual claim, and the reason
        // the server crashed when `init_entry` answered this address.

        // The fix: a fresh machine, entering `init_entry`'s answer instead.
        let mut init_cpu = cpu_for_load();
        let module = Wg32::load(&mut init_cpu, &file, &no_host).expect("LunatiX loads");
        let entry = <Wg32 as Abi>::init_entry(&module).expect("LunatiX exports ordinal 1");
        let init_exit =
            Wg32::call(&mut init_cpu, entry, &[]).expect("must not error building the call");

        // `_init__lunatix` runs and stops at the first import it needs, every
        // time -- the one deterministic outcome in this test, 10 runs out of
        // 10 while the stub was busy being random. The index is fixture-
        // derived (LunatiX's own import order under `bind_imports`), and
        // pinning it exactly is what makes the regression detectable: revert
        // `init_entry` to `Module::entry()` and this line fails on every run,
        // where asserting merely "did not fault" would have missed it on the
        // quarter of runs the stub does not fault.
        assert!(
            matches!(init_exit, Exit::Call { index: INIT_FIRST_IMPORT }),
            "the real init routine must run and stop at its first import \
             (index {INIT_FIRST_IMPORT}), got {init_exit:?}, poison {:?}",
            Wg32::poisoned(&init_cpu)
        );
        assert!(
            Wg32::poisoned(&init_cpu).is_none(),
            "and it must not fault on the way there, got {:?}",
            Wg32::poisoned(&init_cpu)
        );
        assert!(
            !matches!(stub_exit, Exit::Call { index: INIT_FIRST_IMPORT }),
            "the Borland startup stub must not reach the same place \
             _init__lunatix does -- if it does, init_entry is answering the \
             entry stub again and the server is about to take signal 11"
        );
    }
}

/// `<Wg32 as Abi>::export_address`, through `Wg32::load` -- the same loader
/// `mbbs-server` uses -- rather than a hand-built `Module`.
///
/// Until this existed `Wg32` inherited the trait's default `None`, so
/// `mbbs-lua`'s declare-time probe could not resolve a single name on the
/// PE32 board: `M.declare{...}` failed at boot on whichever name Lua's
/// `pairs` visited first (`get_item_from_name`, in the live report) even
/// though `objdump -p` showed `_get_item_from_name` at ordinal 59.
mod exports {
    use super::*;

    fn put_u32(v: &mut [u8], at: usize, val: u32) {
        v[at..at + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn put_u16(v: &mut [u8], at: usize, val: u16) {
        v[at..at + 2].copy_from_slice(&val.to_le_bytes());
    }

    /// `minimal_with_one_section` grown to 0x400 bytes, with an export
    /// directory at the section's start: `exports[i]` is exported by name at
    /// RVA `exports[i].1`, public ordinal `i + 1` (`Base = 1`). Data
    /// directory 0 covers exactly the directory and its strings, so a
    /// function RVA anywhere else in the section is code, not a forwarder.
    fn exporting(exports: &[(&str, u32)]) -> Vec<u8> {
        let mut v = minimal_with_one_section();
        let sec = 0x98 + 0xe0;
        let raw = sec + 40;
        put_u32(&mut v, sec + 8, 0x400); // VirtualSize
        put_u32(&mut v, sec + 16, 0x400); // SizeOfRawData
        v.resize(raw + 0x400, 0);
        let to_rva = |off: usize| 0x1000u32 + (off - raw) as u32;

        let n = exports.len();
        let dir = raw;
        let functions = dir + 40;
        let names = functions + 4 * n;
        let ordinals = names + 4 * n;
        let mut strings = ordinals + 2 * n;

        put_u32(&mut v, dir + 16, 1); // Base
        put_u32(&mut v, dir + 20, n as u32); // NumberOfFunctions
        put_u32(&mut v, dir + 24, n as u32); // NumberOfNames
        put_u32(&mut v, dir + 28, to_rva(functions));
        put_u32(&mut v, dir + 32, to_rva(names));
        put_u32(&mut v, dir + 36, to_rva(ordinals));
        for (i, (name, rva)) in exports.iter().enumerate() {
            put_u32(&mut v, functions + 4 * i, *rva);
            put_u32(&mut v, names + 4 * i, to_rva(strings));
            put_u16(&mut v, ordinals + 2 * i, i as u16);
            v[strings..strings + name.len()].copy_from_slice(name.as_bytes());
            strings += name.len() + 1;
        }

        let data_dir = 0x98 + 96; // optional header + 96: data directory 0 (export)
        put_u32(&mut v, data_dir, to_rva(dir));
        put_u32(&mut v, data_dir + 4, (strings - dir) as u32);
        v
    }

    /// Answers `None` for every import, exactly like `boot_bug::no_host`
    /// (duplicated: integration-test modules do not share private items).
    fn no_host(
        _library: &str,
        _symbol: &mbbs_machine::module::Symbol,
    ) -> Option<mbbs_machine::module::Import<mbbs_machine::m32::Flat32Ptr>> {
        None
    }

    fn name(s: &str) -> mbbs_machine::module::Symbol {
        mbbs_machine::module::Symbol::Name(s.to_owned())
    }

    /// A named export resolves to the image's **linear** address for its
    /// RVA -- exact-case, which is what `mbbs-lua`'s four-spelling probe
    /// relies on to tell `_get_player` (PE32) from `_GET_PLAYER` (NE).
    #[test]
    fn export_address_answers_a_named_export_at_its_linear_address() {
        let file = exporting(&[("_alpha", 0x1300), ("_beta", 0x1310)]);
        let mut cpu = cpu_for_load();
        let module = Wg32::load(&mut cpu, &file, &no_host).expect("a PE with no imports loads");
        let base = cpu.mem.image().expect("image").base();

        assert_eq!(
            <Wg32 as Abi>::export_address(&module, &name("_alpha")),
            Some(mbbs_machine::m32::Flat32Ptr(base + 0x1300))
        );
        assert_eq!(
            <Wg32 as Abi>::export_address(&module, &name("_beta")),
            Some(mbbs_machine::m32::Flat32Ptr(base + 0x1310))
        );
        assert_eq!(<Wg32 as Abi>::export_address(&module, &name("_ALPHA")), None, "exact-case");
        assert_eq!(<Wg32 as Abi>::export_address(&module, &name("alpha")), None);
    }

    /// An ordinal symbol resolves through the same table, `Base`-relative.
    #[test]
    fn export_address_answers_a_public_ordinal() {
        let file = exporting(&[("_alpha", 0x1300), ("_beta", 0x1310)]);
        let mut cpu = cpu_for_load();
        let module = Wg32::load(&mut cpu, &file, &no_host).expect("a PE with no imports loads");
        let base = cpu.mem.image().expect("image").base();
        let ordinal = mbbs_machine::module::Symbol::Ordinal;

        assert_eq!(
            <Wg32 as Abi>::export_address(&module, &ordinal(2)),
            Some(mbbs_machine::m32::Flat32Ptr(base + 0x1310))
        );
        assert_eq!(<Wg32 as Abi>::export_address(&module, &ordinal(0)), None, "below Base(1)");
        assert_eq!(<Wg32 as Abi>::export_address(&module, &ordinal(3)), None, "past the table");
    }

    /// The board's own module. `~/peepeebbs/wccmmud.dll` is byte-identical
    /// (md5 `4c73ad7b…`) to this archive copy; every RVA below was measured
    /// from it with `objdump -p` before this test was written:
    /// `_init__wccmmud` ordinal 1 at `0x1aaa`, `_get_item_from_name`
    /// ordinal 59 at `0x1ad5c`, `_get_player` ordinal 201 at `0x320d9`.
    /// Skips when the archive copy is not in this tree.
    #[test]
    fn the_pe32_majormud_module_resolves_the_names_the_declared_lib_probes_for() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../archive/modules/github-sysopnetwork-majormud/v1.11p/wccmmud.dll");
        let Ok(file) = std::fs::read(&path) else {
            eprintln!("skipping: {} is not in this tree", path.display());
            return;
        };
        let mut cpu = cpu_for_load();
        let module = Wg32::load(&mut cpu, &file, &no_host)
            .expect("MajorMUD NT's imports all bind -- unresolved ones just get a thunk");
        let base = cpu.mem.image().expect("image").base();
        let at = |rva: u32| Some(mbbs_machine::m32::Flat32Ptr(base + rva));

        assert_eq!(<Wg32 as Abi>::export_address(&module, &name("_get_item_from_name")), at(0x1ad5c));
        assert_eq!(<Wg32 as Abi>::export_address(&module, &name("_get_player")), at(0x320d9));
        assert_eq!(
            <Wg32 as Abi>::export_address(&module, &name("_GET_ITEM_FROM_NAME")),
            None,
            "the NE spelling is not this module's; the probe must fall through to the lower-case one"
        );
        assert_eq!(
            <Wg32 as Abi>::export_address(&module, &mbbs_machine::module::Symbol::Ordinal(1)),
            at(0x1aaa),
            "ordinal 1 is _init__wccmmud"
        );
        assert_eq!(
            <Wg32 as Abi>::init_entry(&module),
            at(0x1aaa),
            "and it is the same address init_entry already answers"
        );
    }
}
