//! `Call<Wg32>`, proven against a real `Wg32Cpu` -- in its own process.
//!
//! **Why this is not `crates/mbbs/src/abi/wg32.rs`'s own `#[cfg(test)] mod
//! tests`, unlike every sibling `Abi` file.** A real `Wg32Cpu` needs a real
//! `mbbs32::Machine`, and `mbbs32::Machine::new` unconditionally arms
//! `mbbs32`'s SIGSEGV/SIGILL/SIGBUS/SIGFPE handler
//! (`crates/mbbs32/src/fault.rs`). That module's own doc comment says why
//! that cannot share a process with `mbbs16`'s: "There is exactly one
//! SIGSEGV disposition per process... Installing this one instead breaks
//! the same thing in reverse." `cargo test -p mbbs --lib` runs every 16-bit
//! and 32-bit unit test in ONE process, so a `Wg32Cpu`-building test placed
//! there would install `mbbs32`'s handler over whatever `mbbs16`'s own fault
//! tests need armed -- and never restore it, because nothing in either crate
//! arbitrates one process running both ABIs yet (`fault.rs` again: "Running
//! both ABIs in one process needs a single arbiter... deliberately NOT
//! built here").
//!
//! Measured, not assumed: an earlier version of this file's test lived in
//! `abi/wg32.rs` instead, and `cargo test -p mbbs --lib` went from
//! `1281 passed; 0 failed` to `1282 passed; 3 failed` -- three unrelated
//! `mbbs16` fault-recovery tests broke, every one of them because this
//! file's `Wg32Cpu` had already clobbered the process's SIGSEGV handler
//! before they ran. `cargo test`'s own process model is the fix: each file
//! under `tests/` is a separate binary, hence a separate process, with its
//! own independent signal disposition table -- so arming `mbbs32`'s handler
//! here cannot reach any `mbbs16` test, in this binary or any other, no
//! matter how `cargo test` schedules them relative to each other.
//!
//! This is not merely a test-suite inconvenience. It means a *production*
//! host that wants to serve both a 16-bit and a 32-bit module from the same
//! process cannot safely do so yet: the second `Machine::new` (whichever ABI
//! is second) silently steals the fault handler the first ABI's modules
//! depend on to survive a crash rather than take the whole process down.
//! See this task's report for the specific fix `fault.rs` already names --
//! one arbiter dispatching on the faulting `CS` -- and why it is out of this
//! task's scope.

use mbbs::abi::{Abi, Call, Cursor, ModuleMem, Wg16, Wg32, Wg32Cpu};

/// Byte-for-byte the same fixture `mbbs32::flatptr`'s and `mbbs32::mem`'s own
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

/// A real `Wg32Cpu`: a genuine `mbbs32::Machine` (thunk table, TIB, fault
/// recovery armed) bundled with a genuine `mbbs32::Memory` wrapping a loaded
/// (if inert) image. Nothing here is entered -- this task does not service a
/// call end to end (that needs `mbbs32::Machine::resume`, unmerged; see the
/// design's Task 3 note) -- but `Call<Wg32>` must be buildable from the real
/// thing, not only a fixture standing in for it, the same way `Call<Wg16>`'s
/// own proof needed a live `mbbs16::Machine`.
fn cpu() -> Wg32Cpu {
    let file = minimal_with_one_section();
    let pe = mbbs32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs32::Memory::new(image, 0x1000).expect("arena mapping");
    let machine = mbbs32::Machine::new().expect("thunk table, TIB, fault recovery");
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
    assert_eq!(call.ptr(), mbbs32::Flat32Ptr(0xAABB_CCDD), "bytes 0-4: the pointer");
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
    let want = cpu.mem.image().base();

    let mut call = Call::<Wg32>::new(&mut cpu, &[]);
    assert_eq!(call.mem().image().base(), want);
}

/// `Abi::data_ptr` names the module's own image base -- the same answer an
/// ordinary pointer built from that base already gives, now that flat
/// addressing has no near/far distinction left to collapse.
#[test]
fn data_ptr_is_the_images_own_base() {
    let cpu = cpu();
    assert_eq!(Wg32::data_ptr(&cpu), mbbs32::Flat32Ptr(cpu.mem.image().base()));
}

/// `ModuleMem::alloc_region` reaches `mbbs32::Memory`'s real allocator -- not
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
        ptr.0.wrapping_sub(cpu.mem.image().base()) >= SIZE_OF_IMAGE,
        "an allocated region must not land inside the image"
    );
}
