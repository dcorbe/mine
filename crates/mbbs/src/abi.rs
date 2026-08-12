//! What differs between the ABIs a module can be compiled for.
//!
//! Four associated types, because four things vary independently: how a
//! pointer is represented, what it resolves against, what executes, and how
//! wide a C `int` is. Binding them into one trait is what stops a 16-bit
//! pointer being resolved against 32-bit memory -- the compiler rejects it
//! rather than a runtime check catching it.
//!
//! This module adds the vocabulary: `Abi`, `Cursor`, `Call`, `Ret<A>`, and
//! `Wg16` as the sole implementation. Nothing in `crates/mbbs` reads a
//! shim's arguments through any of it yet -- shims still take
//! `&mut mbbs16::Machine`, still call `arg_far`/`arg_u16`, and still return
//! `mbbs16::Ret` directly (`crates/mbbs/src/shims/mod.rs:55`). That
//! conversion is a later task. See
//! `docs/plans/2026-08-11-abi-abstraction-design.md` (Parts 1 and 2) and
//! `docs/plans/2026-08-11-abi-abstraction-implementation.md` (Tasks 2 and 5).
//!
//! # Why `Call` owns its frame
//!
//! Task 2's version of this comment left `Call` unbuilt, reasoning that
//! `mbbs16::Machine` owning its `Segments` outright made `cpu: &mut A::Cpu`
//! and `mem: &mut A::Mem` two mutable borrows of one object for `Wg16`.
//! Reviewing that before anything was built on it found a second, independent
//! problem that would have survived splitting `Cpu` from `Mem` anyway: a real
//! 16-bit argument frame lives in the *stack segment* (`Machine::arg_u16`,
//! `crates/mbbs16/src/lib.rs:729`, reads
//! `self.mem.stack().read_u16(sp + 4 + n * 2)`), so a `Cursor` that borrows
//! its bytes out of `A::Mem` holds a *shared* borrow of `Mem` for as long as
//! it lives -- and `Call` needs `mem: &mut A::Mem` at the same time, for the
//! whole of a shim body. That is a shared and a unique borrow of the same
//! object held concurrently, and no amount of splitting `Cpu` out of `Mem`
//! touches it, because both borrows are of `Mem`.
//!
//! **The decision:** `Call` copies the argument frame into an owned
//! `Vec<u8>` once, at construction (see [`Call::new`]), and reads from that
//! instead of from `Mem`. The frame is a few bytes and the copy happens once
//! per host call. `Call::ptr`/`int`/`long` are written directly on `Call`
//! rather than wrapping a stored `Cursor` -- a stored `Cursor<'_, A>` would
//! borrow `self.frame`, a field of `Call` itself, which reintroduces the same
//! shape of problem one level in: that borrow would still be live when a
//! later read needs `&mut self` to advance position. Building a fresh
//! `Cursor` per read and decoding through it was tried and rejected too: it
//! puts a read's byte width in two places at once (inside the throwaway
//! `Cursor`'s own `take`, and again in `Call`'s separately-tracked position),
//! and a mutation to only one of them can pass every test silently -- exactly
//! the failure this whole cursor design exists to prevent. So `Call::take`
//! duplicates `Cursor::take` outright, a few lines, both in this module: one
//! function, one width, one advance, per read. `Cursor` itself is unchanged
//! and kept for the fixture tests below, which need no `Call`, no `Machine`,
//! no `Segments` at all -- that cheapness is what makes testing a
//! prototype's byte layout this cheap.
//!
//! # What is still open: `Call<Wg16>` is not yet constructible
//!
//! `Call<'a, A>` is generic and compiles for any `Abi`. Building one for
//! `Wg16` specifically -- `cpu: &mut Machine, mem: &mut Segments` sourced
//! from one live module -- does not, for the reason Task 2's version of this
//! comment gave: `Machine` owns its `Segments` as a private field
//! (`crates/mbbs16/src/lib.rs:296`), and Task 1 deliberately kept it that
//! way, adding only a *delegating* facade so `crates/mbbs`'s existing
//! `&mut Machine` call sites kept compiling -- it never exposes an
//! independent `&mut Segments`. So `cpu` and `mem` sourced from one real
//! `Machine` are still two mutable borrows of the same object. Nothing here
//! resolves that, because nothing here needs to: this task's scope is the
//! vocabulary, and no shim constructs a `Call` yet. Whoever flips
//! `pub type Shim` next has to resolve this first, by either finishing the
//! `Exec`/`Segments` split `mbbs32::Machine`/`Image` already model (the
//! "second structural refactor" the original comment declined to force ahead
//! of evidence), or deciding that the 16-bit `Call` is built from one
//! `&mut Machine` and reaches `mem` through the facade rather than through an
//! independently-borrowed field. This module's own tests below sidestep the
//! question the same way `Cursor`'s did: they exercise `Call` against a
//! minimal fixture `Abi` whose `Cpu`/`Mem` are trivial types, not against
//! `Wg16`, because the read methods never touch `cpu` or `mem` at all.

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

/// A host call in progress: what a converted shim will take instead of
/// `&mut Machine`.
///
/// `cpu` and `mem` are borrowed straight from the caller, for as long as the
/// call runs -- a shim needs both mutably, the same way it always has. The
/// argument frame is not borrowed at all: it is copied once into `frame` at
/// construction. See this module's doc comment ("Why `Call` owns its frame")
/// for why, and ("What is still open") for why a real `Call<Wg16>` cannot yet
/// be built from one live `Machine`.
pub struct Call<'a, A: Abi> {
    pub cpu: &'a mut A::Cpu,
    pub mem: &'a mut A::Mem,
    frame: Vec<u8>,
    pos: usize,
}

impl<'a, A: Abi> Call<'a, A> {
    /// Begin a call. `frame` is the outstanding call's raw argument bytes --
    /// for `Wg16`, `Machine::arg_frame()` -- copied here rather than
    /// borrowed, so nothing below re-touches `mem` to read an argument.
    pub fn new(cpu: &'a mut A::Cpu, mem: &'a mut A::Mem, frame: &[u8]) -> Self {
        Self {
            cpu,
            mem,
            frame: frame.to_vec(),
            pos: 0,
        }
    }

    /// Take the next `width` bytes of the owned frame and advance past them.
    ///
    /// Deliberately shaped like [`Cursor::take`] rather than sharing it --
    /// see this module's doc comment for why building a `Cursor` per read
    /// was tried and rejected. `self.pos` is advanced *before* the borrow of
    /// `self.frame` is taken, so the two never overlap: nothing here holds an
    /// immutable borrow of `self` across the mutation the way a stored
    /// `Cursor` would.
    ///
    /// # Panics
    ///
    /// If fewer than `width` bytes remain -- the same contract as
    /// [`Cursor::take`], for the same reason: a `Call` reading past its own
    /// frame is a host bug in the shim's prototype, not something a module
    /// caused.
    fn take(&mut self, width: usize) -> &[u8] {
        let start = self.pos;
        self.pos += width;
        &self.frame[start..self.pos]
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

/// What a host call hands back to the module, generic over the ABI's width
/// and pointer representation.
///
/// Mirrors `mbbs16::Ret` with the two ABI-dependent shapes generalised:
/// `Far(FarPtr)` becomes `Ptr(A::Ptr)` and `U16(u16)` becomes `Int(A::Int)`.
/// `Void` and the 32-bit `Long` do not vary -- a `long` is
/// [`Abi::LONG_WIDTH`] bytes in every ABI this crate has met so far (4, in
/// both), so there is nothing for an ABI to name here the way `PTR_WIDTH` and
/// `INT_WIDTH` do for the other two.
///
/// `mbbs16::Ret` itself is unchanged and stays that way -- it is what
/// `Machine::resume` takes, and this crate does not get to add a generic
/// parameter to a type `mbbs16` owns. So the 16-bit boundary is a conversion,
/// not a shared type: see `impl From<Ret<Wg16>> for mbbs16::Ret` below.
///
/// *Where* the value lands is deliberately not this type's business, the same
/// way it was not `mbbs16::Ret`'s: 16-bit Worldgroup returns a pointer in
/// `DX:AX` (`mbbs16::Ret::Far`'s own doc comment); 32-bit Worldgroup returns
/// one in `EAX` alone. Each `Abi` implementation's own conversion decides
/// that placement.
pub enum Ret<A: Abi> {
    /// Nothing to return.
    Void,

    /// A C `int`.
    Int(A::Int),

    /// A C `long`: [`Abi::LONG_WIDTH`] bytes in every ABI met so far.
    Long(u32),

    /// A pointer, in this ABI's own representation.
    Ptr(A::Ptr),
}

// Manual, not `#[derive(..)]`. The derive macro's generated bound is `A:
// Trait` -- wrong here, because `Ret<A>`'s fields are `A::Int`/`A::Ptr`
// (associated types), not `A` itself, and a derived `Debug` in particular
// would generate a bound that does not imply the one the `write!` call
// actually needs. `Clone`/`Copy` happen to be the one case a naive derive
// would still compile, purely because `Abi::Ptr`/`Abi::Int` already require
// `Copy` in the trait itself -- but relying on that coincidence for some
// derives and not others is worse than just writing all of them the same way.
impl<A: Abi> Clone for Ret<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for Ret<A> {}

impl<A: Abi> std::fmt::Debug for Ret<A>
where
    A::Int: std::fmt::Debug,
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Void => write!(f, "Void"),
            Self::Int(v) => f.debug_tuple("Int").field(v).finish(),
            Self::Long(v) => f.debug_tuple("Long").field(v).finish(),
            Self::Ptr(v) => f.debug_tuple("Ptr").field(v).finish(),
        }
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

impl From<Ret<Wg16>> for mbbs16::Ret {
    /// The 16-bit boundary conversion this module's doc comment names:
    /// `Machine::resume` still takes `mbbs16::Ret`, unchanged, so this is
    /// where a `Ret<Wg16>` a converted shim hands back becomes it.
    ///
    /// `Ptr` maps to `Far` and `Int` maps to `U16` with no repacking --
    /// `Wg16::Ptr` already is `FarPtr` and `Wg16::Int` already is `u16` -- so
    /// there is no width or byte order to get wrong here, only the variant to
    /// pick correctly. `Int`/`Long` both carry a plain integer, which is
    /// exactly the shape a swap between the two would not be caught by the
    /// type checker; the mutation test below is aimed at exactly that.
    fn from(ret: Ret<Wg16>) -> Self {
        match ret {
            Ret::Void => mbbs16::Ret::Void,
            Ret::Int(v) => mbbs16::Ret::U16(v),
            Ret::Long(v) => mbbs16::Ret::U32(v),
            Ret::Ptr(v) => mbbs16::Ret::Far(v),
        }
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

    /// A minimal `Abi` for exercising `Call`'s frame reads without a real
    /// `Machine`/`Segments` pair -- see this module's doc comment ("What is
    /// still open") for why `Call<Wg16>` cannot yet be built from one. `Ptr`
    /// and `Int` are `Wg16`'s own real types, and every width and decode
    /// function delegates straight to `Wg16`'s -- only `Cpu` and `Mem` are
    /// replaced, with types `Call`'s read methods never touch.
    struct FixtureAbi;

    /// `Call`'s `mem` field needs an `Abi::Mem`, which needs `ModuleMem`.
    /// Never actually called: nothing below allocates.
    struct FixtureMem;

    impl ModuleMem for FixtureMem {
        type Ptr = FarPtr;

        fn alloc_region(&mut self, _bytes: usize) -> std::io::Result<Self::Ptr> {
            unreachable!("Call's read tests never allocate memory")
        }
    }

    impl Abi for FixtureAbi {
        type Ptr = FarPtr;
        type Mem = FixtureMem;
        type Cpu = ();
        type Int = u16;

        const PTR_WIDTH: usize = Wg16::PTR_WIDTH;
        const INT_WIDTH: usize = Wg16::INT_WIDTH;
        const LONG_WIDTH: usize = Wg16::LONG_WIDTH;

        fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr {
            Wg16::ptr_from_bytes(bytes)
        }

        fn int_from_bytes(bytes: &[u8]) -> Self::Int {
            Wg16::int_from_bytes(bytes)
        }

        fn long_from_bytes(bytes: &[u8]) -> u32 {
            Wg16::long_from_bytes(bytes)
        }
    }

    /// Same prototype and same frame as
    /// `the_cursor_walks_stzcpys_frame_at_the_same_offsets_arg_far_and_arg_u16_read`
    /// above -- `CHAR *stzcpy(CHAR *dst, const CHAR *src, UINT num)`,
    /// `re/wg33src/INC/GCOMM.H:396-400` -- read through `Call` instead of
    /// `Cursor`, to prove the two agree. All three reads chained (not just
    /// the last one) matters: `int()` is the frame's last argument, so a
    /// mutation to only its own advance would go unnoticed by a test that
    /// read nothing after it. Nothing does here either, but the frame is
    /// exactly 10 bytes -- `ptr` + `ptr` + `int` -- so an `int()` that
    /// advances (or decodes) the wrong width still has nowhere further to go
    /// unnoticed within its own read: see the mutation below.
    #[test]
    fn call_reads_stzcpys_frame_at_the_same_offsets_the_cursor_does() {
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

        let mut cpu = ();
        let mut mem = FixtureMem;
        let mut call = Call::<FixtureAbi>::new(&mut cpu, &mut mem, &frame);
        assert_eq!(call.ptr(), dst, "byte 0: dst, matching the cursor's word 0");
        assert_eq!(call.ptr(), src, "byte 4: src, matching the cursor's word 2");
        assert_eq!(call.int(), num, "byte 8: num, matching the cursor's word 4");
    }

    /// `INT otstcrd(INT unum, LONG amt, GBOOL real)` --
    /// `re/wg33src/INC/USRACC.H:82` -- the same prototype
    /// `the_cursor_walks_otstcrds_frame_at_the_same_offsets_arg_u16_and_arg_u32_read`
    /// above uses, read through `Call`. Covers `.long()`, which the stzcpy
    /// test above does not, and puts a read *after* the `long()` call (the
    /// trailing `int()`), so a mutation to `long`'s advance -- not just
    /// `int`'s -- has somewhere to go wrong and be caught.
    #[test]
    fn call_reads_otstcrds_frame_at_the_same_offsets_the_cursor_does() {
        let unum: u16 = 7;
        let amt: u32 = 500;
        let real: u16 = 1;

        let frame = [
            unum.to_le_bytes().as_slice(),
            &amt.to_le_bytes(),
            &real.to_le_bytes(),
        ]
        .concat();

        let mut cpu = ();
        let mut mem = FixtureMem;
        let mut call = Call::<FixtureAbi>::new(&mut cpu, &mut mem, &frame);
        assert_eq!(call.int(), unum, "byte 0: unum, matching the cursor's word 0");
        assert_eq!(call.long(), amt, "byte 2: amt, matching the cursor's word 1");
        assert_eq!(call.int(), real, "byte 6: real, matching the cursor's word 3");
    }

    /// The four `Ret<Wg16>` variants, converted at the 16-bit boundary. Values
    /// are chosen with a distinct high and low half (`0x1234`, `0x5678`) so a
    /// transposition -- offset and selector swapped, or the `U16`/`U32` halves
    /// swapped -- would be caught rather than accidentally agreeing.
    #[test]
    fn ret_wg16_converts_to_mbbs16_ret_for_all_four_variants() {
        assert_eq!(mbbs16::Ret::from(Ret::<Wg16>::Void), mbbs16::Ret::Void);
        assert_eq!(
            mbbs16::Ret::from(Ret::<Wg16>::Int(0x1234)),
            mbbs16::Ret::U16(0x1234)
        );
        assert_eq!(
            mbbs16::Ret::from(Ret::<Wg16>::Long(0x1234_5678)),
            mbbs16::Ret::U32(0x1234_5678)
        );

        // `Ret::Far`'s own doc comment: "segment in DX, offset in AX" --
        // i.e. `FarPtr::offset` is the low half and `FarPtr::selector` is the
        // high half, the same order a `long`'s `U32` splits. `Ret::Ptr` must
        // carry that pair through unchanged, offset staying offset and
        // selector staying selector, not swapped.
        let ptr = FarPtr {
            offset: 0x5678,
            selector: 0x1234,
        };
        assert_eq!(
            mbbs16::Ret::from(Ret::<Wg16>::Ptr(ptr)),
            mbbs16::Ret::Far(ptr),
            "offset (AX) and selector (DX) must land unswapped"
        );
    }
}
