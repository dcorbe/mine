//! `Wg32`'s own `FILE.flags` offset, proven by actually reading a stream to
//! EOF -- not merely asserting the constant against itself.
//!
//! # The bug this guards
//!
//! A human playing LunatiX 5.3F crashed the module twice, identically:
//! `strcpy` running off the end of the image. Root cause, established by
//! disassembly (`crates/mbbs/src/stream.rs`'s and `abi.rs`'s own doc
//! comments carry the full trace): the host wrote `FILE.flags` at byte
//! offset 2 -- Borland's *16-bit* `STDIO.H` layout -- for every ABI, but
//! `feof`/`ferror` are macros with no import record, so a 32-bit module
//! inlines a direct read of its own runtime's layout instead of calling
//! anything. `cw3220mt`'s own runtime (measured off its exported `_feof`,
//! `re/wg/CW3220MT.DLL` RVA `0x6b24`: `mov ax,[eax+0x12] / and eax,0x20`)
//! puts `flags` at offset `0x12`. Offset 2 of the host's fabricated `FILE`
//! is never written for a `Wg32` stream, so `_F_EOF` was always zero to
//! the module -- it could never observe true end of file.
//!
//! # Why this lives here and not in `abi/wg32.rs`'s own tests
//!
//! Same reason `tests/wg32_abi.rs` does (see that file's own module doc
//! comment): a real `Wg32Cpu` arms `mbbs_machine::m32::Machine`'s fault
//! recovery, and `cargo test -p mbbs --lib` runs every 16- and 32-bit unit
//! test as threads of one process. A `Wg32Cpu`-building test has no reason
//! to entangle that shared state with `abi/wg32.rs`'s otherwise-pure unit
//! tests, so -- like every other real-`Wg32Cpu` test -- this is a separate
//! integration binary, hence a separate process.
//!
//! The `cpu()` fixture below is byte-for-byte `tests/wg32_abi.rs`'s own,
//! duplicated rather than shared per this crate family's stated convention
//! (see that file's doc comment on `minimal_with_one_section`): a private
//! test fixture in one source file is not reachable from another.

use mbbs::abi::{Abi, ModuleMem, Wg32, Wg32Cpu};
use mbbs::stream::{FILE_SIZE, Mode, Streams};
use mbbs::testing::scratch;
use mbbs_machine::ptr::ModulePtr;

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

/// A real `Wg32Cpu`: a genuine `mbbs_machine::m32::Machine` bundled with a
/// genuine `mbbs_machine::m32::Memory` wrapping a loaded (if inert) image.
/// Never entered -- this file only needs `cpu.mem` to open and read a
/// stream through, not to run any 32-bit code.
///
/// Unlike `tests/wg32_abi.rs`'s own `cpu()`, this one asks for a 128 KiB
/// arena rather than 0x1000: `Streams::open_mem` places a `FILE` through
/// `Arena<A>::reserve`, and `Arena::carve` allocates a whole 64 KiB region
/// (`SEGMENT`, `crates/mbbs/src/arena.rs`) up front for its very first
/// placement, whatever the placement's own size -- `wg32_abi.rs`'s smaller
/// arena is enough for its own direct 8-byte `ModuleMem::alloc_region`
/// call, but not for one that goes through the arena's region-at-a-time
/// packing.
fn cpu() -> Wg32Cpu {
    let file = minimal_with_one_section();
    let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
    let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
    let mem = mbbs_machine::m32::Memory::with_image(image, 128 * 1024).expect("arena mapping");
    let machine = mbbs_machine::m32::Machine::new().expect("thunk table, TIB, fault recovery");
    Wg32Cpu::new(machine, mem)
}

/// A `Streams<Wg32>` with somewhere for its `FILE` structs to live.
///
/// Every `FILE` is carved out of the module-visible `_streams` array as of
/// Phases 3+4 Task 4.4, so `Streams` has to be told where that array is
/// before it can open anything -- `Host::new` does this from the placed
/// global, and a test that builds a bare `Streams` has to do the equivalent.
/// The region is `NFILE` structs at **this ABI's own** `FILE_SIZE`, which is
/// 27 here and not `Wg16`'s 20; asking for the wrong one would put the last
/// slots outside the region.
fn place_streams(cpu: &mut Wg32Cpu) -> Streams<Wg32> {
    let bytes = usize::from(mbbs::stream::NFILE) * <Wg32 as Abi>::FILE_SIZE;
    let base = cpu.mem.alloc_region(bytes).expect("room for _streams");
    let mut streams = Streams::<Wg32>::default();
    streams.place(base);
    streams
}

/// The test that matters (per the task brief): read a `Wg32` stream to
/// true EOF and assert bit `0x20` (`_F_EOF`) is set at `cookie +
/// Wg32::FILE_FLAGS_OFFSET` -- exactly where `cw3220mt`'s own `_feof`
/// looks, not where `Wg16`'s runtime would.
///
/// # Mutation check
///
/// Setting `Wg32::FILE_FLAGS_OFFSET` back to `2` (Wg16's own offset) makes
/// this fail: the flags word this test reads at offset `0x12` is never
/// written by `Streams::open_mem`/`Streams::sync` in that case (they still
/// write at offset 2), so it stays the fixture's own zeroed arena memory
/// and the assertion fails with `left: 0x0, right: 0x20`. Verbatim result
/// in the task report.
#[test]
fn reading_a_wg32_stream_to_eof_sets_f_eof_at_cw3220mts_own_offset() {
    let mut cpu = cpu();

    let root = scratch("wg32-stream-flags-offset");
    let path = root.join("short.txt");
    std::fs::write(&path, b"hi\n").expect("a scratch file to open");

    let mut streams = place_streams(&mut cpu);
    let cookie = streams
        .open_mem(
            &mut cpu.mem,
            "short.txt",
            &path,
            Mode::parse("r").expect("a mode"),
        )
        .expect("opens");

    // One line covers the whole file; the next read finds nothing, which is
    // what latches `_F_EOF` (`Stream::getc`'s `n == 0` arm).
    loop {
        let line = streams
            .line_mem(&mut cpu.mem, cookie, 128)
            .expect("reads without error");
        if line.is_none() {
            break;
        }
    }

    let image = cookie
        .resolve(&cpu.mem, FILE_SIZE)
        .expect("the FILE cookie resolves")
        .to_vec();

    // The literal `0x12`, not `Wg32::FILE_FLAGS_OFFSET` -- measured
    // independently from `re/wg/CW3220MT.DLL`'s own exported `_feof` (RVA
    // `0x6b24`), the fact the constant is supposed to encode. Reading
    // through the constant under test would make this assertion agree with
    // whatever the constant says even if the constant itself regressed:
    // the write site (`Streams::open_mem`/`Streams::sync`) and a read that
    // trusted `Wg32::FILE_FLAGS_OFFSET` would move together under a
    // mutation of that one constant, and the test would keep passing.
    // Confirmed by hand: that is exactly what happened using
    // `Wg32::FILE_FLAGS_OFFSET` on both sides before this literal replaced
    // it -- see the task report's mutation check.
    const CW3220MT_FEOF_OFFSET: usize = 0x12;

    let flags = u16::from_le_bytes([
        image[CW3220MT_FEOF_OFFSET],
        image[CW3220MT_FEOF_OFFSET + 1],
    ]);
    assert_eq!(
        flags & 0x20,
        0x20,
        "cw3220mt's own _feof reads FILE.flags at offset {CW3220MT_FEOF_OFFSET:#x} \
         (measured from re/wg/CW3220MT.DLL's exported _feof, RVA 0x6b24); a \
         host that wrote _F_EOF anywhere else leaves this bit permanently \
         zero to a 32-bit module, which is the LunatiX 5.3F strcpy crash"
    );
}

/// `Wg32`'s own `FILE.fd` offset and width, by the same standard as the
/// flags test above: literals measured from the runtime, not the constants
/// under test.
///
/// # The bug this guards
///
/// The Rose 3.0NT would not boot. It calls `read(fileno(fp), buf, 5000)` at
/// four sites, and `fileno` is a **macro** -- it reads `FILE.fd` inline and
/// never calls the host, so nothing in an import survey can see it happen.
/// `cw3220mt.DLL`'s own exported `_fileno` (RVA `0x6b44`) is
/// `mov eax,[eax+0x16]`: a full 32-bit `int` at offset 22. This host wrote a
/// single byte at offset 4 -- Borland's *16-bit* layout -- into a 20-byte
/// `FILE`, so the module's read ran four bytes **past the end of the struct
/// entirely** and handed `read` whatever the arena held next. Measured:
/// `458752`.
///
/// Each of the four call sites is `push dword [reg+0x16]` immediately before
/// its `call _read`, which is what makes the offset attributable rather than
/// merely plausible.
#[test]
fn a_wg32_streams_descriptor_is_a_four_byte_int_at_cw3220mts_own_offset() {
    let mut cpu = cpu();

    let root = scratch("wg32-stream-fd-offset");
    let path = root.join("fd.txt");
    std::fs::write(&path, b"hi\n").expect("a scratch file to open");

    let mut streams = place_streams(&mut cpu);
    let cookie = streams
        .open_mem(
            &mut cpu.mem,
            "fd.txt",
            &path,
            Mode::parse("r").expect("a mode"),
        )
        .expect("opens");

    // Literals for the same reason the flags test gives at length: reading
    // through `Wg32::FILE_FD_OFFSET` would make this agree with the constant
    // even if the constant regressed, because the write site reads it too.
    //
    // `0x16` and four bytes are `_fileno`'s own `mov eax,[eax+0x16]`; `27` is
    // the stride `___getStream` (RVA `0x1a880`) multiplies an index by before
    // adding `__streams` -- `lea eax,[eax+eax*2]` then `lea eax,[eax+eax*8]`.
    const CW3220MT_FILENO_OFFSET: usize = 0x16;
    const CW3220MT_SIZEOF_FILE: usize = 27;

    let image = cookie
        .resolve(&cpu.mem, CW3220MT_SIZEOF_FILE)
        .expect("a 27-byte FILE cookie resolves -- a shorter one would not")
        .to_vec();

    let fd = u32::from_le_bytes([
        image[CW3220MT_FILENO_OFFSET],
        image[CW3220MT_FILENO_OFFSET + 1],
        image[CW3220MT_FILENO_OFFSET + 2],
        image[CW3220MT_FILENO_OFFSET + 3],
    ]);
    assert_eq!(
        fd, 5,
        "the first descriptor this host issues is 5 (`stream::FIRST_FD`), and \
         cw3220mt's own _fileno reads it as a 32-bit int at offset \
         {CW3220MT_FILENO_OFFSET:#x}; a host writing one byte at offset 4 leaves \
         these four bytes as whatever the arena held"
    );

    // Nothing above would notice a host that wrote all four bytes but left
    // the struct 20 bytes long: the fd would land past the reservation and
    // `resolve` would be reading someone else's memory that happened to hold
    // the right value. This is the assertion that the *size* is right.
    assert!(
        cookie.resolve(&cpu.mem, CW3220MT_SIZEOF_FILE).is_ok(),
        "the whole 27-byte struct has to be inside the reservation"
    );
}
