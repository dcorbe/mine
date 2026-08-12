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
//! # `Call` holds one handle, not two
//!
//! An earlier version of this module gave `Call` both `cpu: &'a mut A::Cpu`
//! and `mem: &'a mut A::Mem` as fields, following the design's Part 1
//! sketch. That does not compile for `Wg16`: `Machine` owns its `Segments`
//! as a private field (`crates/mbbs16/src/lib.rs:296`), and Task 1
//! deliberately kept it that way, adding only a *delegating* facade so
//! `crates/mbbs`'s existing `&mut Machine` call sites kept compiling --
//! never an independent `&mut Segments`. So `cpu` and `mem` sourced from one
//! real `Machine` were two mutable borrows of the same object, and no amount
//! of care at the call site fixes that; `Call<Wg16>` was simply
//! unconstructible.
//!
//! **The fix:** [`Abi::mem`] turns "borrow `Mem` independently" into "reborrow
//! it through `Cpu`" -- `fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem`.
//! `Call` keeps only `cpu`, and [`Call::mem`] calls `A::mem(self.cpu)` on
//! demand. A reborrow is legal where a second stored borrow was not, because
//! it does not outlive the single call that produces it; nothing holds two
//! `'a`-long borrows of the same object anymore. `Wg16`'s implementation is
//! `mbbs16::Machine::mem_mut`, the one deliberate exception to Task 1's
//! "delegate a method, never expose the field" rule -- see that method's own
//! doc comment for why generic access needs the field itself. `Wg32`'s `Cpu`
//! will not own its `Mem` the same way `Wg16`'s does, and both still answer
//! `Abi::mem`, which is the point: the bundling lives in the ABI's `Cpu`
//! type, not in `Call`'s fields, so it serves both shapes instead of only
//! one. See the implementation plan's "Step 1b: `Call` holds ONE handle, not
//! two" for the two options weighed and why this one was chosen over
//! extracting an `Exec` type from `Machine`.
//!
//! This module's tests now build a real `Call<Wg16>` from a live
//! `mbbs16::Machine` (`the_cursor_and_a_real_machine_agree_on_stzcpys_frame`
//! below), not only the `FixtureAbi` used to test byte arithmetic cheaply.
//! The fixture tests stay, for the same reason `Cursor`'s do -- they need no
//! `Machine` at all -- but they no longer stand in for the one path that
//! matters: whether `Call<Wg16>` can be built from a machine actually
//! executing a call.

/// What differs between the ABIs a module can be compiled for.
pub trait Abi {
    /// A pointer as this ABI's modules write one.
    ///
    /// Bound to resolve against **this ABI's own memory**, which is what makes
    /// generic memory access expressible: `ModulePtr` already carries
    /// `resolve`/`read_cstr`/`write`, but without `Memory = Self::Mem` the
    /// compiler cannot know that `A::Ptr` reads out of `A::Mem`, so no generic
    /// caller can use them. `arena.rs` had been carrying this bound privately
    /// on its own impl; hoisting it here is what lets `Globals`, `Users` and
    /// eventually every shim body read module memory without naming `FarPtr`.
    ///
    /// The cost is that an `Abi` may not pair one ABI's pointer with another's
    /// memory -- which is the property being bought, not a limitation.
    type Ptr: mbbs_ptr::ModulePtr<Memory = Self::Mem> + Copy + Eq + std::hash::Hash;

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

    /// Build a pointer `delta` bytes into a region [`ModuleMem::alloc_region`]
    /// handed back.
    ///
    /// `Heap` and `Arena` (`crates/mbbs/src/heap.rs`,
    /// `crates/mbbs/src/arena.rs`) both pack many small placements into ONE
    /// region rather than taking a fresh region per placement -- that packing
    /// is the entire reason either type exists -- so both need to turn "a
    /// region's base" plus "how far into it" into an addressable pointer,
    /// generically, with no idea what shape `Self::Ptr` actually has.
    /// `Wg16`'s is `seg:off`: offsetting means adding to `offset` and leaving
    /// `selector` alone. `Wg32`'s will be a flat address -- ordinary integer
    /// addition -- when Task 3 implements it.
    ///
    /// `delta` is `u16`, not `usize`: nothing here ever offsets past the end
    /// of one region, and no region this crate hands out today exceeds
    /// 64 KiB -- `Wg16`'s only backing implementation refuses more (see
    /// `ModuleMem::alloc_region`'s own doc comment). A wider type would only
    /// let an out-of-range offset compile instead of refusing to build.
    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr;

    /// Reach this ABI's memory through its execution handle.
    ///
    /// A reborrow, not a second field: see the module doc comment ("`Call`
    /// holds one handle, not two"). `Wg16`'s `Cpu` (`mbbs16::Machine`) owns
    /// its `Mem` (`mbbs16::Segments`) outright, so `cpu: &mut Cpu` and
    /// `mem: &mut Mem` sourced independently from one live module are two
    /// mutable borrows of the same object -- it does not compile. `Wg32`'s
    /// `Cpu` will not own its `Mem` the same way, and both still answer this
    /// one method, which is what lets `Call` stay generic over the
    /// difference instead of needing a second field only one ABI can fill.
    fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem;
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
/// `cpu` is the only borrow `Call` holds. Memory is reached through
/// [`Call::mem`], a reborrow of `cpu` via [`Abi::mem`] -- see this module's
/// doc comment ("`Call` holds one handle, not two") for why holding a second
/// `mem: &'a mut A::Mem` field alongside `cpu` does not compile for `Wg16`.
/// The argument frame is not borrowed at all: it is copied once into `frame`
/// at construction. See "Why `Call` owns its frame" for that half.
pub struct Call<'a, A: Abi> {
    pub cpu: &'a mut A::Cpu,
    frame: Vec<u8>,
    pos: usize,
}

impl<'a, A: Abi> Call<'a, A> {
    /// Begin a call. `frame` is the outstanding call's raw argument bytes --
    /// for `Wg16`, `Machine::arg_frame()` -- copied here rather than
    /// borrowed, so nothing below needs `mem` to read an argument.
    pub fn new(cpu: &'a mut A::Cpu, frame: &[u8]) -> Self {
        Self {
            cpu,
            frame: frame.to_vec(),
            pos: 0,
        }
    }

    /// Reach this call's memory: a reborrow of `cpu`, not a second stored
    /// borrow. Callable any number of times, unlike a field, which is exactly
    /// what makes it compile where `mem: &'a mut A::Mem` did not -- each call
    /// reborrows `self.cpu` for a shorter lifetime than `'a` instead of
    /// holding a second independent `'a` borrow of the same underlying
    /// object for the whole of `Call`'s life.
    pub fn mem(&mut self) -> &mut A::Mem {
        A::mem(self.cpu)
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

    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        mbbs16::FarPtr {
            offset: base.offset + delta,
            selector: base.selector,
        }
    }

    /// `Machine::mem_mut` is the one deliberate exception Task 1's facade
    /// left: every other memory method is a narrow delegation (`resolve`,
    /// `read_cstr`, `write`, ...), but reaching `Segments` generically means
    /// handing back the field itself, not one more method that reads through
    /// it. See `Machine::mem_mut`'s own doc comment.
    fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem {
        cpu.mem_mut()
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
    /// `Machine`/`Segments` pair -- see this module's doc comment ("`Call`
    /// holds one handle, not two") for the real path this sidesteps. `Ptr`
    /// and `Int` are `Wg16`'s own real types, and every width and decode
    /// function delegates straight to `Wg16`'s -- only `Cpu` and `Mem` are
    /// replaced, with types `Call`'s read methods never touch.
    struct FixtureAbi;

    impl Abi for FixtureAbi {
        type Ptr = FarPtr;

        /// `mbbs16::Segments`, not a stub, and not because this fixture ever
        /// touches memory -- it does not. `Abi::Ptr` is bound
        /// `ModulePtr<Memory = Self::Mem>`, so an ABI whose `Ptr` is `FarPtr`
        /// has no choice: `FarPtr` resolves against `Segments` and nothing
        /// else. That bound is what makes a generic `resolve`/`read_cstr`/
        /// `write` expressible at all, and the price is that a fixture cannot
        /// invent its own memory type while borrowing a real pointer type.
        /// Cheap here, because `Cpu` is still `()` and the reads under test
        /// never leave the frame.
        type Mem = mbbs16::Segments;
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

        fn ptr_offset(_base: Self::Ptr, _delta: u16) -> Self::Ptr {
            // Same reasoning as `mem` below: nothing in `Call`'s frame-read
            // tests places anything, so nothing computes an offset either.
            unreachable!("Call's read tests never allocate memory")
        }

        fn mem(_cpu: &mut Self::Cpu) -> &mut Self::Mem {
            // `Cpu = ()` owns no `FixtureMem` to reborrow -- there is
            // nothing this could correctly return, which is fine because
            // `Call`'s frame-read tests below never call `Call::mem`.
            unreachable!("Call's read tests never call Call::mem")
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
        let mut call = Call::<FixtureAbi>::new(&mut cpu, &frame);
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
        let mut call = Call::<FixtureAbi>::new(&mut cpu, &frame);
        assert_eq!(call.int(), unum, "byte 0: unum, matching the cursor's word 0");
        assert_eq!(call.long(), amt, "byte 2: amt, matching the cursor's word 1");
        assert_eq!(call.int(), real, "byte 6: real, matching the cursor's word 3");
    }

    /// The proof this task exists for: `Call<Wg16>` built from a *live*
    /// `mbbs16::Machine` -- not `FixtureAbi`'s trivial `Cpu`/`Mem` -- reading
    /// a real argument frame `Fixture::call` pushed with genuine 16-bit code
    /// and a genuine `lcall`. See the module doc comment ("`Call` holds one
    /// handle, not two") for why this was previously impossible to write at
    /// all: `Call::new` used to take `mem: &mut A::Mem` as a second field,
    /// and `Machine` has no way to hand out an independent `&mut Segments`
    /// alongside `&mut Machine`.
    ///
    /// `CHAR *stzcpy(CHAR *dst, CHAR *src, UINT num)` --
    /// `re/wg33src/INC/GCOMM.H:396-400`, the same prototype the fixture
    /// tests above already check, so all three agree on where cdecl leaves
    /// its arguments.
    #[test]
    fn call_reads_a_real_machines_frame_for_stzcpy() {
        let mut f = crate::testing::Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("Newhaven");

        f.call(&[dst.offset, dst.selector, src.offset, src.selector, 5]);

        // Copied out before `Call::new` takes `&mut f.machine` -- `Call`
        // itself does the same copy internally (see "Why `Call` owns its
        // frame"), this just makes the borrow's end visible at the call
        // site too.
        let frame = f.machine.arg_frame().to_vec();

        let mut call = Call::<Wg16>::new(&mut f.machine, &frame);
        assert_eq!(call.ptr(), dst, "byte 0: dst");
        assert_eq!(call.ptr(), src, "byte 4: src");
        assert_eq!(call.int(), 5, "byte 8: num");

        // `Call::mem` is the other half of this task: prove it reborrows the
        // *same* `Segments` the machine actually runs against, not a
        // disconnected copy, by resolving `src` through it and reading back
        // the exact bytes `Fixture::text` wrote before the call.
        let text = call
            .mem()
            .read_cstr(src)
            .expect("src is what Fixture::text wrote")
            .to_vec();
        assert_eq!(text, b"Newhaven");
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
