//! What differs between the ABIs a module can be compiled for.
//!
//! Four associated types, because four things vary independently: how a
//! pointer is represented, what it resolves against, what executes, and how
//! wide a C `int` is. Binding them into one trait is what stops a 16-bit
//! pointer being resolved against 32-bit memory -- the compiler rejects it
//! rather than a runtime check catching it.
//!
//! This module adds the vocabulary only. `Wg16` is the sole implementation;
//! nothing in `crates/mbbs` reads a shim's arguments through it yet -- shims
//! still take `&mut mbbs16::Machine` and still call `arg_far`/`arg_u16`. That
//! conversion is a later task. See
//! `docs/plans/2026-08-11-abi-abstraction-design.md` (Parts 1 and 2) and
//! `docs/plans/2026-08-11-abi-abstraction-implementation.md` (Task 2).
//!
//! # Why there is no `Call` here yet
//!
//! The design sketches a bundle that a converted shim would take instead of
//! `&mut Machine`:
//!
//! ```text
//! pub struct Call<'a, A: Abi> {
//!     pub cpu: &'a mut A::Cpu,
//!     pub mem: &'a mut A::Mem,
//!     pub args: Cursor<'a, A>,
//! }
//! ```
//!
//! Building that for `Wg16` does not typecheck as written. `Abi::Cpu` for
//! 16-bit is `mbbs16::Machine`, and `Abi::Mem` is `mbbs16::Segments` -- but
//! `Machine` *owns* a `Segments` as its `mem` field (see
//! `crates/mbbs16/src/lib.rs`'s `Machine::mem`). `&mut A::Cpu` and
//! `&mut A::Mem` held at once are therefore two mutable borrows of one
//! object, which the borrow checker refuses. The design's own diagram says
//! `mbbs32` already draws this line cleanly because `mbbs32::Machine` does
//! not own its `Image`; `mbbs16::Machine` does own its `Segments`, and Task 1
//! deliberately left it that way -- it added a delegating facade so
//! `crates/mbbs`'s 247 existing `&mut Machine` call sites keep compiling,
//! which is incompatible with also handing out an independent `&mut Segments`
//! from the same value.
//!
//! Resolving that by extracting an `Exec` type (mirroring `mbbs32::Machine`
//! exactly) is a second structural refactor of `mbbs16::Machine`, on top of
//! the one Task 1 just finished. Task 2 does not ask for `Call`, only for
//! `Abi`, `Cursor` and `Wg16` to exist -- so rather than force that split
//! ahead of evidence, `Call` is left unbuilt and the borrow question is
//! deferred to the task that actually constructs one. Two things make that
//! deferral cheap rather than a debt:
//!
//! - **`Cursor` never needs `&mut Cpu`.** Argument reads are immutable
//!   (`Machine::arg_u16`/`arg_far`/`arg_u32` all take `&self`), and they read
//!   from the stack segment, not from execution state. So a cursor only ever
//!   needs a read-only view of the bytes making up one call's argument frame
//!   -- not a live, mutably-borrowed `&Mem`, and certainly not `&Cpu`.
//! - So `Cursor` here holds a **borrowed byte slice** rather than a `Mem`
//!   reference: `frame` position plus the bytes, decoded through the `Abi`.
//!   That sidesteps the aliasing question entirely for argument reading, and
//!   it is also what makes a cheap fixture possible -- see [`fixture_cursor`]
//!   below, which needs no `Machine`, no `Segments`, no thunk table, just an
//!   array of bytes.
//!
//! Whether `Call<A>` ends up holding `&mut A::Cpu` alongside a `Cursor`
//! borrowed from `A::Mem` (which would need `Cpu` split from `Mem` after
//! all), or whether the 16-bit `Call` instead holds one `&mut Machine` and
//! reaches memory through its facade, is a decision to make against real
//! call sites in the task that builds `Call` -- not here, from a diagram.

/// What differs between the ABIs a module can be compiled for.
pub trait Abi {
    /// A pointer as this ABI's modules write one.
    type Ptr: mbbs_ptr::ModulePtr + Copy + Eq + std::hash::Hash;

    /// What a pointer resolves against. `Segments` for 16-bit; `Image` plus
    /// its allocator for 32-bit. Never the executing machine -- `mbbs32`'s
    /// `Machine` does not own one.
    type Mem: ModuleMem<Ptr = Self::Ptr>;

    /// Execution state: the thunk table, fault recovery, the call frame.
    type Cpu;

    /// A C `int` in this ABI. `u16` for 16-bit, `u32` for 32-bit -- an
    /// associated type so a shim that stuffs one into a `u16` stops
    /// compiling rather than truncating in silence.
    type Int: Copy + Into<u32>;

    /// Bytes a pointer occupies in this ABI's argument frame. 4 in both ABIs
    /// today, for different reasons: `seg:off` in 16-bit, flat in 32-bit --
    /// stated per-`Abi` rather than assumed, since the reason the numbers
    /// agree is not that they must.
    const PTR_WIDTH: usize;

    /// Bytes a C `int` occupies in this ABI's argument frame: 2 in 16-bit, 4
    /// in 32-bit. The single number this whole abstraction exists to stop a
    /// naive generic conversion from getting wrong -- see [`Cursor`].
    const INT_WIDTH: usize;

    /// Bytes a C `long` occupies in this ABI's argument frame: 4 in both.
    const LONG_WIDTH: usize;

    /// Decode a pointer from exactly [`PTR_WIDTH`](Abi::PTR_WIDTH) bytes, in
    /// this ABI's own layout.
    fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr;

    /// Decode a C `int` from exactly [`INT_WIDTH`](Abi::INT_WIDTH) bytes.
    fn int_from_bytes(bytes: &[u8]) -> Self::Int;

    /// Decode a C `long` from exactly [`LONG_WIDTH`](Abi::LONG_WIDTH) bytes.
    fn long_from_bytes(bytes: &[u8]) -> u32;
}

/// Memory a module can address, and the host's ability to hand it more.
pub trait ModuleMem {
    type Ptr;

    /// Give the module `bytes` of addressable memory. The 16-bit
    /// implementation is one LDT segment, and refuses more than 64 KiB
    /// because no far pointer spans one -- chaining several of these
    /// together to serve a single larger request is the caller's job (a
    /// generic `Heap`, in a later task), not this method's; the 32-bit
    /// implementation carves a single `Mapping` with no such limit. The
    /// bookkeeping above this -- first-fit, sizes held host-side keyed by
    /// pointer -- is shared and does not live here.
    fn alloc_region(&mut self, bytes: usize) -> std::io::Result<Self::Ptr>;
}

/// Where the next argument sits in a module's raw argument frame, and how to
/// decode one.
///
/// The type this replaces took a WORD OFFSET into the 16-bit frame --
/// `arg_far(0)`, `arg_far(2)`, `arg_u16(4)` for `strncpy`. Those literals
/// encode 16-bit widths at 218 sites; under a 32-bit ABI the same prototype
/// sits at bytes 0, 4, 8. Reading them generically would compile and return
/// garbage.
///
/// So reads are named by C type and advance in BYTES, and each `Abi` states
/// its own widths through [`Abi::PTR_WIDTH`], [`Abi::INT_WIDTH`] and
/// [`Abi::LONG_WIDTH`]. The reads themselves are the prototype; there is no
/// number to get wrong.
///
/// Holds a borrowed byte slice rather than a `Cpu`/`Mem` pair -- see this
/// module's doc comment for why, and for what that defers to the task that
/// builds `Call`.
pub struct Cursor<'a, A: Abi> {
    frame: &'a [u8],
    pos: usize,
    abi: std::marker::PhantomData<A>,
}

impl<'a, A: Abi> Cursor<'a, A> {
    /// A cursor over a raw argument frame: the bytes as the ABI's module
    /// stack lays them out, starting at the first argument.
    pub fn new(frame: &'a [u8]) -> Self {
        Self {
            frame,
            pos: 0,
            abi: std::marker::PhantomData,
        }
    }

    /// Take the next `width` bytes and advance past them.
    ///
    /// # Panics
    ///
    /// If fewer than `width` bytes remain. `arg_far`/`arg_u16` are
    /// infallible reads off a frame the caller is trusted to have sized
    /// correctly (see the design's Part 2); a cursor over a frame too short
    /// for the routine it is reading is the same kind of host bug, not
    /// something a module caused.
    fn take(&mut self, width: usize) -> &'a [u8] {
        let bytes = &self.frame[self.pos..self.pos + width];
        self.pos += width;
        bytes
    }

    /// The next argument, as a pointer.
    pub fn ptr(&mut self) -> A::Ptr {
        A::ptr_from_bytes(self.take(A::PTR_WIDTH))
    }

    /// The next argument, as a C `int`.
    pub fn int(&mut self) -> A::Int {
        A::int_from_bytes(self.take(A::INT_WIDTH))
    }

    /// The next argument, as a C `long`.
    pub fn long(&mut self) -> u32 {
        A::long_from_bytes(self.take(A::LONG_WIDTH))
    }
}

/// The ABI Galacticomm's 16-bit modules were compiled for: Borland huge
/// model, `seg:off` pointers, cdecl with ten callee-cleaned exceptions (see
/// `Cleans::Callee` in `crates/mbbs/src/shims/mod.rs`).
///
/// The only implementation Task 2 builds. A `Wg32` following the same shape
/// is Task 3's thin slice.
pub struct Wg16;

impl Abi for Wg16 {
    type Ptr = mbbs16::FarPtr;
    type Mem = mbbs16::Segments;
    type Cpu = mbbs16::Machine;
    type Int = u16;

    const PTR_WIDTH: usize = 4;
    const INT_WIDTH: usize = 2;
    const LONG_WIDTH: usize = 4;

    fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr {
        mbbs16::FarPtr::from_bytes(bytes.try_into().expect("PTR_WIDTH bytes"))
    }

    fn int_from_bytes(bytes: &[u8]) -> Self::Int {
        u16::from_le_bytes(bytes.try_into().expect("INT_WIDTH bytes"))
    }

    fn long_from_bytes(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().expect("LONG_WIDTH bytes"))
    }
}

impl ModuleMem for mbbs16::Segments {
    type Ptr = mbbs16::FarPtr;

    /// One LDT segment, exactly as `Heap::grow` already gets its backing
    /// store today (`crates/mbbs/src/heap.rs:162`) -- this is that call site
    /// named through the trait rather than new behaviour. `alloc_segment`
    /// itself refuses `bytes > 64 KiB`; chaining several regions to serve a
    /// request larger than one segment is `ModuleMem::alloc_region`'s
    /// caller's job, not this one's, per the trait's own doc comment.
    fn alloc_region(&mut self, bytes: usize) -> std::io::Result<Self::Ptr> {
        let selector = self.alloc_segment(bytes)?;
        Ok(mbbs16::FarPtr {
            offset: 0,
            selector,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs16::FarPtr;

    /// A cursor over a byte array, with no `Machine`, no `Segments`, no
    /// thunk table -- see this module's doc comment for why a cursor can be
    /// tested this cheaply. Named to read alongside `Fixture::invoke`, which
    /// is the equivalent for a real shim: that one drives an actual `lcall`
    /// to prove where cdecl leaves its arguments, because a test that laid
    /// them out itself would agree with a shim that read them wrongly. This
    /// one has no such risk to guard against -- it is only checking that the
    /// cursor's byte arithmetic matches the word arithmetic `arg_far`/
    /// `arg_u16` already do, so a literal byte array is the whole fixture.
    fn fixture_cursor<A: Abi>(frame: &[u8]) -> Cursor<'_, A> {
        Cursor::new(frame)
    }

    // `CHAR *stzcpy(CHAR *dst, const CHAR *src, UINT num)` --
    // `re/wg33src/INC/GCOMM.H:396-400`. `shims/text.rs::stzcpy` reads
    // `arg_far(0)` (dst), `arg_far(2)` (src), `arg_u16(4)` (num) -- words 0,
    // 2, 4. Under `Wg16`'s byte widths (ptr 4, int 2) that is bytes 0, 4, 8.
    #[test]
    fn the_cursor_walks_stzcpys_frame_at_the_same_offsets_arg_far_and_arg_u16_read() {
        let dst = FarPtr {
            offset: 0x1000,
            selector: 0x0038,
        };
        let src = FarPtr {
            offset: 0x2000,
            selector: 0x0040,
        };
        let num: u16 = 16;

        let frame = [
            dst.to_bytes().as_slice(),
            src.to_bytes().as_slice(),
            &num.to_le_bytes(),
        ]
        .concat();

        let mut c = fixture_cursor::<Wg16>(&frame);
        assert_eq!(c.ptr(), dst, "byte 0: dst, word 0 under arg_far(0)");
        assert_eq!(c.ptr(), src, "byte 4: src, word 2 under arg_far(2)");
        assert_eq!(c.int(), num, "byte 8: num, word 4 under arg_u16(4)");
    }

    // `CHAR *l2as(LONG longin)` -- `re/wg33src/INC/GCOMM.H:351-353`.
    // `shims/text.rs::l2as` reads `arg_u32(0)` -- word 0, both halves of one
    // `long`. Under `Wg16`'s widths that is byte 0, width 4.
    #[test]
    fn the_cursor_walks_l2ass_frame_at_the_same_offset_arg_u32_reads() {
        let longin: u32 = 0x8000_0001;
        let frame = longin.to_le_bytes();

        let mut c = fixture_cursor::<Wg16>(&frame);
        assert_eq!(c.long(), longin, "byte 0: longin, word 0 under arg_u32(0)");
    }

    // `INT otstcrd(INT unum, LONG amt, GBOOL real)` --
    // `re/wg33src/INC/USRACC.H:82`. `shims/credits.rs::otstcrd` reads
    // `arg_u16(0)` (unum), `arg_u32(1)` (amt), `arg_u16(3)` (real) -- words
    // 0, 1-2, 3. Under `Wg16`'s widths (int 2, long 4) that is bytes 0, 2, 6
    // -- amt's word offset is 1, not 2, because it is read in *words* while
    // the cursor advances in *bytes*, and int (unum) is only one word wide.
    #[test]
    fn the_cursor_walks_otstcrds_frame_at_the_same_offsets_arg_u16_and_arg_u32_read() {
        let unum: u16 = 7;
        let amt: u32 = 500;
        let real: u16 = 1;

        let frame = [
            unum.to_le_bytes().as_slice(),
            &amt.to_le_bytes(),
            &real.to_le_bytes(),
        ]
        .concat();

        let mut c = fixture_cursor::<Wg16>(&frame);
        assert_eq!(c.int(), unum, "byte 0: unum, word 0 under arg_u16(0)");
        assert_eq!(c.long(), amt, "byte 2: amt, word 1 under arg_u32(1)");
        assert_eq!(c.int(), real, "byte 6: real, word 3 under arg_u16(3)");
    }
}
