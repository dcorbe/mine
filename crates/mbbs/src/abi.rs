//! What differs between the ABIs a module can be compiled for.
//!
//! Four associated types, because four things vary independently: how a
//! pointer is represented, what it resolves against, what executes, and how
//! wide a C `int` is. Binding them into one trait is what stops a 16-bit
//! pointer being resolved against 32-bit memory -- the compiler rejects it
//! rather than a runtime check catching it.
//!
//! This module adds the vocabulary: `Abi`, `Cursor`, `Call`, `Ret<A>` -- with
//! `Wg16` (`abi/wg16.rs`) and `Wg32` (`abi/wg32.rs`) as its two
//! implementations. When this vocabulary was first built, `Wg16` was the
//! only implementation and nothing in `crates/mbbs` read a shim's arguments
//! through any of it yet: shims took `&mut mbbs_machine::m16::Machine`
//! directly, called `arg_far`/`arg_u16`, and returned `mbbs_machine::m16::Ret`
//! directly. That conversion has since landed -- every shim in the shared
//! table (`crate::shims::entry`'s generic core) now takes `&mut Call<A>` and
//! returns `Ret<A>`, for both ABIs; the ten routines behind `Wg16`'s own door
//! ([`Abi::native`]) are the deliberate, documented exception. See
//! `docs/plans/2026-08-11-abi-abstraction-design.md` (Parts 1 and 2) and
//! `docs/plans/2026-08-11-abi-abstraction-implementation.md` (Tasks 2 and 5)
//! for that history.
//!
//! # Why `Call` owns its frame
//!
//! Task 2's version of this comment left `Call` unbuilt, reasoning that
//! `mbbs_machine::m16::Machine` owning its `Segments` outright made `cpu: &mut A::Cpu`
//! and `mem: &mut A::Mem` two mutable borrows of one object for `Wg16`.
//! Reviewing that before anything was built on it found a second, independent
//! problem that would have survived splitting `Cpu` from `Mem` anyway: a real
//! 16-bit argument frame lives in the *stack segment* (`Machine::arg_u16`,
//! `crates/mbbs-machine/src/m16/mod.rs:747`, reads
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
//! as a private field (`crates/mbbs-machine/src/m16/mod.rs:311`), and Task 1
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
//! `mbbs_machine::m16::Machine::mem_mut`, the one deliberate exception to Task 1's
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
//! `mbbs_machine::m16::Machine` (`call_reads_a_real_machines_frame_for_stzcpy`
//! in `abi/wg16.rs`), not only the `FixtureAbi` used to test byte arithmetic cheaply.
//! The fixture tests stay, for the same reason `Cursor`'s do -- they need no
//! `Machine` at all -- but they no longer stand in for the one path that
//! matters: whether `Call<Wg16>` can be built from a machine actually
//! executing a call.

mod wg16;
mod wg32;

pub use wg16::Wg16;
pub use wg32::{Wg32, Wg32Cpu};

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
    type Ptr: mbbs_machine::ptr::ModulePtr<Memory = Self::Mem> + Copy + Eq + std::hash::Hash;

    /// What a pointer resolves against. `Segments` for 16-bit; `Image` plus
    /// its allocator for 32-bit. Never the executing machine -- `mbbs32`'s
    /// `Machine` does not own one.
    type Mem: ModuleMem<Ptr = Self::Ptr>;

    /// Execution state: the thunk table, fault recovery, the call frame.
    type Cpu;

    /// A C `int` in this ABI. `u16` for 16-bit, `u32` for 32-bit -- an
    /// associated type so a shim that stuffs one into a `u16` stops
    /// compiling rather than truncating in silence.
    ///
    /// `From<u16>` (the other direction from `Into<u32>` above) is what a
    /// generic shim body needs to *build* one from a small computed value --
    /// `shims::user::haskey`'s boolean answer, for instance -- without
    /// knowing this ABI's width. `u16::from` is the identity for `Wg16`'s own
    /// `Int` and a free zero-extend for a wider one, which is exactly what a
    /// small `int` returned from a `bool` should do in either ABI. Free for
    /// every implementation so far: `u16: From<u16>` and `u32: From<u16>` are
    /// both in `std`, so neither `Wg16` nor a future `Wg32` writes an impl
    /// for this, only names the bound.
    type Int: Copy + Into<u32> + From<u16>;

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

    /// This ABI's own name, exactly as `mmud.abi` reports it to a Lua
    /// script -- `"wg16"` or `"wg32"`. Lets one `scripts/lib/<module>.lua`
    /// declarations file branch on which build it is running against (the
    /// design's own `if mmud.abi ~= "wg16" then ...` example) without this
    /// crate growing any Lua-facing type of its own -- a `&'static str` is
    /// the whole surface `mbbs-lua` needs.
    const NAME: &'static str;

    /// Whether this ABI's host was built with Galacticomm's `GCV2` flag set.
    ///
    /// **Not a width, and not derivable from one.** `GCV2` is a compile-time
    /// switch that changes which *fields* a struct has, and several of
    /// Galacticomm's headers declare a struct twice behind it --
    /// `re/wg33src/INC/MAJORBBS.H:98` declares `struct user` two different
    /// ways, and `re/wg33src/INC/UStructs.h:52` gives `struct usracc` two
    /// different sizes. Pick the wrong branch and every offset past byte 0 is
    /// wrong silently, because a wrong `int` read still returns a number.
    ///
    /// Measured, not assumed. `Wg16`'s layout is the one this host already
    /// implements and its offsets are GCV2's field order at 16-bit widths
    /// (`crate::users::UserLayout`'s own test says which). `Wg32`'s stride was
    /// read off a genuine PE32 `WGSERVER.EXE`: 88 bytes, which is the non-GCV2
    /// declaration's sum and not the GCV2 one's 64.
    ///
    /// Named here rather than spelled `INT_WIDTH >= 4` at each use site,
    /// because the two axes are independent and a reader who sees a width test
    /// has no way to know a field *set* was meant.
    const GCV2: bool;

    /// Byte offset of the runtime `FILE.flags` word in this ABI's own C
    /// library. `feof`/`ferror` are macros with no import record (see
    /// `stream.rs`'s module doc), so a module inlines this read rather than
    /// calling anything -- which is why the host must write the flags where
    /// that ABI's runtime expects them.
    ///
    /// Measured, not assumed, the same way [`Abi::GCV2`] is. `Wg16`'s is
    /// Borland 16-bit `STDIO.H:104-114`'s own field order. `Wg32`'s is
    /// `cw3220mt`'s own runtime, read off its exported `_feof`
    /// (`re/wg/CW3220MT.DLL`, RVA `0x6b24`): `mov ax, [eax+0x12] / and
    /// eax, 0x20`. A module compiled against that runtime and linked into
    /// this host inlines the identical read, so a host that kept writing
    /// `flags` at `Wg16`'s offset 2 left the module reading two bytes that
    /// were never written -- always zero, so `feof` could never observe
    /// true. `crates/mbbs/src/stream.rs`'s own module doc names the crash
    /// this produced in LunatiX 5.3F.
    const FILE_FLAGS_OFFSET: u16;

    /// Bytes of the `FILE` struct this ABI's runtime uses.
    ///
    /// What [`crate::stream::Streams::open_mem`] reserves and what `fopen`
    /// hands back a pointer to. It is not a buffer size this host is free to
    /// choose: a module reads fields out of it by macro, at fixed offsets,
    /// without ever calling the host, so anything short of the real size is
    /// memory the module reads and this host never wrote.
    const FILE_SIZE: usize;

    /// Byte offset of `FILE.fd` -- what `fileno(f)` expands to a read of.
    ///
    /// **A macro, not a call.** `fileno` never reaches this host, so getting
    /// this wrong is invisible until the module passes the value it read to
    /// something that does -- `read`, `write`, `close` -- with a number this
    /// host never put there.
    const FILE_FD_OFFSET: u16;

    /// Width of `FILE.fd`, in bytes.
    ///
    /// One in Borland's 16-bit `STDIO.H` (`char fd`), four in `cw3220mt`'s
    /// 32-bit runtime (`int`). Read as unsigned little-endian either way; no
    /// descriptor this host issues is ever negative.
    ///
    /// # No test can currently tell the two widths apart, and that is a fact
    /// about the data rather than a gap in the tests
    ///
    /// Measured by mutation: setting this to `1` for `Wg32` leaves the whole
    /// suite green. Every descriptor this host issues is a `u8`
    /// (`stream::FIRST_FD..=u8::MAX`) and the struct image is zero-filled
    /// before the fields are written, so one byte of `5` and four bytes of
    /// `5` are the same bytes. The distinction only becomes observable if
    /// descriptors ever outgrow a byte, or if the image stops being zeroed.
    ///
    /// It is kept at the measured width anyway, because the alternative is a
    /// host whose correctness depends on two accidents holding at once, and
    /// because the *offset* -- which is what actually broke The Rose -- is
    /// pinned by a real test either way
    /// (`tests/wg32_stream_flags_offset.rs`).
    const FILE_FD_WIDTH: u16;

    /// This ABI's layout of `struct fsdfld`, the FSD's per-field record.
    ///
    /// Load-bearing for the same reason [`Abi::FILE_FLAGS_OFFSET`] is, and it
    /// broke the same way: a module indexes `fsdscb->flddat[]` **without
    /// calling this host**. `WCCMMUD` sets `FFFAVD` on fourteen fields with a
    /// bare `or byte [flddat + n*sizeof(struct fsdfld) + 12], 0x80`, and the
    /// only thing that makes those writes and this host's reads name the same
    /// byte is agreeing on `sizeof`. They did not: the 16-bit struct is 23
    /// bytes and the 32-bit one is 36, because `INT` is `int`
    /// (`re/wg33src/INC/GCTYPDEF.H:88`). A host that used 23 for both saw the
    /// module's flags only for field 0 -- the one index where the two strides
    /// coincide -- so every "avoid" field past it stayed enterable and
    /// MajorMUD's character sheet let the player type over the *minimum and
    /// maximum* columns of each stat. See [`crate::fsd::FieldLayout`] for the
    /// measurement both numbers come from.
    const FSD_FIELD: crate::fsd::FieldLayout;

    /// Decode a pointer from exactly [`PTR_WIDTH`](Abi::PTR_WIDTH) bytes, in
    /// this ABI's own layout.
    fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr;

    /// Encode a pointer into exactly [`PTR_WIDTH`](Abi::PTR_WIDTH) bytes, in
    /// this ABI's own layout -- the inverse of [`Abi::ptr_from_bytes`].
    ///
    /// Nothing needed this direction until a generic caller had to embed a
    /// pointer *inside* a struct it writes into module memory (`TextVars`'s
    /// `varrou` field, `crates/mbbs/src/textvar.rs`) rather than only decode
    /// one out of an argument frame -- reading a module's own arguments never
    /// writes one back, which is why [`Cursor`]/[`Call`] only ever needed
    /// [`Abi::ptr_from_bytes`].
    fn ptr_to_bytes(ptr: Self::Ptr) -> Vec<u8>;

    /// Decode a C `int` from exactly [`INT_WIDTH`](Abi::INT_WIDTH) bytes.
    fn int_from_bytes(bytes: &[u8]) -> Self::Int;

    /// Narrow a `u32` to a C `int` for `A`, keeping the low
    /// [`INT_WIDTH`](Abi::INT_WIDTH) bytes.
    ///
    /// The counterpart to `Self::Int: Into<u32>`, and the *only* way to build
    /// an `A::Int` whose value does not fit in a `u16`.
    ///
    /// # Why `From<u16>` is not enough
    ///
    /// [`Self::Int`](Abi::Int) is bound `From<u16>`, which zero-extends. That
    /// is correct for a count or a channel number and silently wrong for
    /// anything negative: `A::Int::from(0xFFFFu16)` is `-1` under `Wg16` and
    /// `65535` under `Wg32`, because the bits that carry the sign under a
    /// 4-byte `int` were never there to extend. Every shim returning a C
    /// sentinel -- `toupper(EOF)`, and anything else answering `-1` -- needs
    /// the value to be all-ones at `A`'s own width, and `From<u16>` cannot
    /// express that.
    fn int_from_u32(value: u32) -> Self::Int;

    /// Encode a C `int` as exactly [`INT_WIDTH`](Abi::INT_WIDTH) bytes,
    /// little-endian.
    ///
    /// The inverse of [`int_from_bytes`](Abi::int_from_bytes), and the
    /// counterpart to [`ptr_to_bytes`](Abi::ptr_to_bytes). Needed because a
    /// host that *seeds* an `int` global -- `crate::globals::Globals::new`
    /// writes `usrnum`, `nterms` and `hichp1` before any module runs -- has
    /// to write the same number of bytes the module will read, and
    /// `(-1i16).to_le_bytes()` is two of them regardless of `A`. Under
    /// `Wg32` that left `usrnum` reading back as `65535` instead of `-1`.
    fn int_to_bytes(value: Self::Int) -> Vec<u8>;

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

    /// Offset `base` by `by` bytes, refusing rather than wrapping if the sum
    /// would leave the address space this ABI's own pointer can name.
    ///
    /// [`Abi::ptr_offset`] exists for a caller that already knows `delta`
    /// fits (a region [`ModuleMem::alloc_region`] just handed back, at most
    /// 64 KiB) -- this is for the opposite case: `by` is computed from a
    /// value module memory holds (`shims::fsd`'s `fsdscb->numfld`,
    /// `->ansoff`, ...), so a corrupted or hostile one must be refused
    /// rather than silently wrapped into a pointer at the front of the same
    /// segment, which would *resolve* and read as a plausible answer. Task
    /// 5's `shims::fsd::offset` used to do this by hand -- `base.offset`
    /// plus `by`, checked against `u16` -- which only typechecks for
    /// `Wg16`'s own `seg:off` shape; this is that check, moved onto the
    /// `Abi` each implementation answers for its own pointer, the same
    /// reason [`Abi::ptr_offset`] itself is not one shared formula.
    ///
    /// `None` when the ABI has no room to represent the result -- `Wg16`'s
    /// `u16` offset overflowing, or a future flat `Wg32` address overflowing
    /// `u32`.
    fn ptr_checked_add(base: Self::Ptr, by: usize) -> Option<Self::Ptr>;

    /// The null pointer, in this ABI's own representation.
    ///
    /// `crate::btrieve::Btrieve<A>` needs one to fill its ten-deep `setbtv`
    /// stack (`FarPtr::NULL` before this task) and to answer `goodptr`-style
    /// null checks (`bb == NULL`, `bb->filnam == NULL`) generically -- see
    /// `crate::btrieve::Btrieve::null`'s own doc comment. `Wg16`'s is
    /// `mbbs_machine::m16::FarPtr::NULL`, a `seg:off` of `0:0`; `Wg32`'s is a flat
    /// address of `0`, the ordinary meaning of a null pointer once "near" and
    /// "far" collapse to one address space -- the same collapse
    /// [`Abi::data_ptr`]'s own doc comment describes.
    fn null_ptr() -> Self::Ptr;

    /// Reach this ABI's memory through its execution handle.
    ///
    /// A reborrow, not a second field: see the module doc comment ("`Call`
    /// holds one handle, not two"). `Wg16`'s `Cpu` (`mbbs_machine::m16::Machine`) owns
    /// its `Mem` (`mbbs_machine::m16::Segments`) outright, so `cpu: &mut Cpu` and
    /// `mem: &mut Mem` sourced independently from one live module are two
    /// mutable borrows of the same object -- it does not compile. `Wg32`'s
    /// `Cpu` will not own its `Mem` the same way, and both still answer this
    /// one method, which is what lets `Call` stay generic over the
    /// difference instead of needing a second field only one ABI can fill.
    fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem;

    /// [`Abi::mem`]'s shared-borrow twin: reach this ABI's memory for reading
    /// without demanding `&mut Self::Cpu`.
    ///
    /// Added in Task 12 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`. Before this, a
    /// generic caller that only ever *read* module memory still had to widen
    /// its own parameter to `&mut A::Cpu`, purely to have something to hand
    /// [`Abi::mem`] -- Task 11's `refill_polls` paid exactly that cost
    /// widening from `&Machine` to `&mut A::Cpu`, and three of its test call
    /// sites widened with it. That is not a borrow-checker inconvenience;
    /// it erases a real distinction. `ModulePtr::resolve`/`read_cstr` both
    /// take `&'m Self::Memory` (`crates/mbbs-machine/src/ptr.rs`), so the
    /// *pointer* half of a read-only access was already shared-borrow-only --
    /// `Abi::mem`'s signature was the only thing forcing `&mut` onto a caller
    /// that never writes. A reader forced to hold `&mut` can still write, so
    /// nothing at the type level distinguishes "this touches module memory"
    /// from "this only reads it"; every caller of this method is exactly the
    /// place that distinction becomes visible again.
    ///
    /// `Wg16`'s is `Machine::mem`, the shared-borrow sibling of `mem_mut`
    /// that [`Abi::mem`]'s own doc comment already cites; `Wg32`'s is `&cpu.mem`,
    /// the same field [`Abi::mem`] reborrows mutably.
    fn mem_ref(cpu: &Self::Cpu) -> &Self::Mem;

    /// The base of this ABI's own data segment -- offset zero, in the
    /// module's own `DGROUP` -- as a pointer.
    ///
    /// What `crate::fmt`'s `%N` conversion names: a near pointer's one
    /// argument word is an offset into the module's *own* data, not into any
    /// region a `ModuleMem::alloc_region` call handed back, so it cannot be
    /// expressed as [`Abi::ptr_offset`] from something a caller already has
    /// -- nothing else in this trait names the module's own data segment at
    /// all. `Wg16`'s is `Machine::data_selector()` at offset 0, the same
    /// selector `crate::fmt`'s near-pointer conversion used to build by hand
    /// before the format walk went generic. A future `Wg32`, with one flat
    /// address space and no near/far distinction, would answer the same base
    /// its ordinary pointers already use -- there being nothing else it
    /// could mean once "near" and "far" collapse to the same address space.
    fn data_ptr(cpu: &Self::Cpu) -> Self::Ptr;

    /// A routine that answers only for this `Abi`, when the shared table
    /// (`crate::shims::entry`) has nothing generic to offer.
    ///
    /// **The second door**, named in
    /// `docs/plans/2026-08-11-abi-abstraction-implementation.md`'s "`Shim<A>`
    /// as specified is unreachable, and the table needs a second door": most
    /// of `crate::shims`'s routines are `fn<A: Abi>(&mut Call<A>, &mut
    /// Host<A>) -> Result<Ret<A>, ShimError>` and live in one shared table,
    /// keyed only by DLL and symbol name. Ten are not, all genuinely 16-bit
    /// by design with no meaning under any other `Abi` at all:
    /// `shims::runtime`'s eight Borland callee-cleaned helpers
    /// (`WGSERVER.DEF`'s `#ifdef GCDOS` block; 32-bit Worldgroup is uniformly
    /// cdecl and needs none of them) and `shims::memory`'s `alctile`/
    /// `ptrtile` (segment tiling; a flat address space has nothing to tile).
    ///
    /// This door used to hold twenty-seven: `shims::btrieve`'s seventeen
    /// Btrieve routines sat behind it too, because the engine behind them
    /// (`crate::btrieve::Btrieve`) was concrete, keyed by
    /// `mbbs_machine::m16::FarPtr` and `mbbs_machine::m16::Machine`. They were never a
    /// 16-bit-by-design difference the way the ten above are -- only a
    /// coverage gap, closed once `Btrieve<A>` and `Host<A>`'s own `btrieve`
    /// field stopped eliding their type parameter and the seventeen moved
    /// into the shared table (`da17681`, `597ce40`).
    ///
    /// Default `None`: an `Abi` with nothing to add here (`Wg32`, today)
    /// writes no code at all. `Wg16`'s override
    /// (`crates/mbbs/src/abi/wg16.rs`'s `impl Abi for Wg16`) delegates to
    /// [`crate::shims::wg16_native`], which is where the actual table of ten
    /// lives -- kept in `shims::mod` alongside the shared table and
    /// `ABSOLUTES`/`GLOBALS`, rather than here, so this trait states only
    /// that the door exists and not what is behind it.
    ///
    /// A symbol this returns `None` for is not necessarily unimplemented --
    /// `crate::shims::entry` still has `ABSOLUTES` and `GLOBALS` to check, and
    /// only answers [`crate::shims::Entry::Unimplemented`] once every door has
    /// been asked. That is already how this host reports a truly
    /// unimplemented symbol; an `Abi` simply not carrying a routine walks the
    /// same, already-tested path.
    fn native(dll: &str, symbol: &str) -> Option<(crate::shims::Shim<Self>, crate::shims::Cleans)>
    where
        Self: Sized,
    {
        let _ = (dll, symbol);
        None
    }

    /// `crate::shims::routines` for this ABI, built once and keyed for lookup.
    ///
    /// # Why this exists
    ///
    /// `crate::shims::entry` runs on every shim **call**, not just at load
    /// time, and it used to rebuild the whole 445-row routine table -- a `Vec`
    /// of tuples -- and linear-scan it, per call. Measured at 17.6us per
    /// lookup in a debug build, which is what the board actually runs.
    ///
    /// MajorMUD calls `ptrtile` 141,326 times in one init pass (measured with
    /// `MBBS_TRACE_SHIMS`: 90% of all its shim traffic, because `ptrtile` is
    /// the arithmetic helper that reaches tile *n* of a tiled region and the
    /// module walks its big tables element by element). At 17.6us that is
    /// **2.5 seconds of symbol lookup for one routine**, against a 5-second
    /// watchdog -- so the host was spending half the budget deciding which
    /// function to call, and a `finrou` over a played-in board blew through
    /// it. That is the watchdog firing on correct behaviour, which
    /// `m16::DEFAULT_BUDGET`'s own doc comment names as worse than no watchdog
    /// at all.
    ///
    /// A per-ABI `OnceLock` rather than one cache inside `entry`, because the
    /// value type is `Shim<Self>` and a generic `static` cannot exist. This is
    /// the same shape [`Abi::native`] already uses: one hook, two concrete
    /// implementations.
    ///
    /// Returns the pair by value rather than lending the map out, so no
    /// `'static` reference escapes and `entry` needs no `A: 'static` bound --
    /// which would otherwise ripple through every generic `Host<A>` method that
    /// resolves a symbol.
    ///
    /// The default is `None`, meaning "no cache, fall back to rebuilding" --
    /// so an `Abi` that has not opted in still resolves correctly, just
    /// slowly. `crate::shims::entry` is the only caller.
    /// Whether [`Abi::routine_lookup`] is authoritative -- that is, whether a
    /// `None` from it means "not registered" rather than "not cached".
    ///
    /// Without this, `entry` would have to run the linear rebuild after every
    /// cached *miss* to stay correct, and a miss is the common case: every
    /// `Datum`, every `Absolute`, and every genuinely unimplemented symbol
    /// misses the routine table. That would have left the hot path exactly as
    /// slow as before for the lookups that reach `GLOBALS`.
    const HAS_ROUTINE_LOOKUP: bool = false;

    fn routine_lookup(dll: &str, symbol: &str) -> Option<(crate::shims::Shim<Self>, crate::shims::Cleans)>
    where
        Self: Sized,
    {
        let _ = (dll, symbol);
        None
    }

    /// Why this ABI's machine refuses to run again -- `mbbs_machine::m16::Poison`
    /// for `Wg16`, `mbbs_machine::m32::Poison` for `Wg32`.
    ///
    /// Bound the same way [`crate::shims::ShimError`]'s callers need: cloned out
    /// of the machine by [`Abi::poisoned`] (which borrows `Cpu`, so the answer
    /// cannot itself borrow), formatted for the host's own stop message, and
    /// compared in tests. The machine keeps owning the real enum -- an ABI
    /// answers with it, never redefines it -- see design §2.
    type Poison: Clone + std::fmt::Debug + std::fmt::Display + PartialEq;

    /// Call a module entry point with `args`, the way the real host does.
    ///
    /// `args` are in declaration order, encoded into this ABI's own frame
    /// shape by the implementation -- see [`Arg`]'s own doc comment for what
    /// that means per-ABI. Delegates straight to this ABI's machine (`Wg16`
    /// to `mbbs_machine::m16::Machine::call`, `Wg32` to
    /// `mbbs_machine::m32::Machine::call`), converting the machine's own
    /// `Exit` into [`Exit<Self>`] on the way out.
    fn call(cpu: &mut Self::Cpu, entry: Self::Ptr, args: &[Arg<Self>]) -> std::io::Result<Exit<Self>>
    where
        Self: Sized;

    /// Continue a module past the [`Exit::Call`] it stopped at, handing back
    /// `ret` and popping `cleans`' worth of arguments first if this ABI's
    /// calling convention requires the *callee* to.
    ///
    /// Folds `mbbs_machine::m16::Machine::resume_cleaning` in rather than adding a
    /// second trait method for it: `Cleans::Caller` is `machine.resume(ret)`,
    /// `Cleans::Callee(bytes)` is `machine.resume_cleaning(ret, bytes)`. `Wg32`
    /// has no callee-cleaned routines at all (32-bit Worldgroup is uniformly
    /// cdecl) -- its `Cleans::Callee` arm panics naming the host-table bug a
    /// callee-clean row reaching it would be. See design §2.
    fn resume(cpu: &mut Self::Cpu, ret: Ret<Self>, cleans: crate::shims::Cleans) -> std::io::Result<Exit<Self>>
    where
        Self: Sized;

    /// The outstanding call's raw argument frame -- what [`Cursor`]/[`Call`]
    /// read. Direct delegation to the machine's own `arg_frame`.
    fn arg_frame(cpu: &Self::Cpu) -> &[u8];

    /// Mark this ABI's machine as refusing to run again, and say why.
    ///
    /// The generic `Host::stop` needs this to record a host-side judgement
    /// (an unimplemented import, most often -- see [`Abi::unimplemented`])
    /// that never came from the machine's own `Exit`, the same way
    /// `mbbs_machine::m16::Machine::poison` already lets `Host::run` do today.
    fn poison(cpu: &mut Self::Cpu, why: Self::Poison) -> std::io::Result<()>;

    /// Why this ABI's machine will not be entered again, if it will not.
    ///
    /// Clones out of the machine's own `Option<&Poison>` -- borrowing `cpu`
    /// only for the call, not for as long as the answer lives, which is what
    /// lets a caller hold the result past the point it stops borrowing `cpu`
    /// (`Host::run`'s own stop path does exactly that).
    fn poisoned(cpu: &Self::Cpu) -> Option<Self::Poison>;

    /// Build the poison that says a module called an import this host has no
    /// implementation for.
    ///
    /// The one constructor a generic `Host::stop` needs for the case with no
    /// `Exit` behind it at all: the host recognised the call landed at a
    /// thunk, looked the symbol up, and found nothing. Every `Poison` this
    /// crate's machines carry has an `Unimplemented { module, symbol }`
    /// variant with the same wording -- see `mbbs_machine::m16::Poison::Unimplemented`
    /// and its `mbbs_machine::m32` mirror.
    fn unimplemented(module: String, symbol: String) -> Self::Poison;

    /// The library an [`Abi::unimplemented`] poison names, or `None` for
    /// every other stop.
    ///
    /// The inverse of the constructor above, and the only way a caller
    /// generic over `A: Abi` can read the library back out: `Self::Poison`
    /// is an opaque associated type, so a driver that wants to say
    /// something about *which* DLL went missing would otherwise have to
    /// re-parse the `Display` string. `mbbs-server`'s boot driver uses it
    /// to notice that the missing library is a module the operator listed
    /// later on the command line.
    fn unimplemented_library(poison: &Self::Poison) -> Option<&str>;

    /// Build the poison that says a routine this host **does** implement
    /// refused to answer.
    ///
    /// The counterpart to [`Abi::unimplemented`], and deliberately not the
    /// same thing: one says the routine is missing, the other says it ran and
    /// could not answer. Reporting a refusal as "not implemented" sends a
    /// reader looking for a symbol that has been present for months -- see
    /// `mbbs_machine::m16::Poison::Refused` for the incident that separated
    /// them.
    fn refused(module: String, symbol: String, why: String) -> Self::Poison;

    /// A module loaded for this ABI: what selector or section each of its
    /// pieces got, and what sits behind each thunk.
    ///
    /// `mbbs_machine::m16::Module` for `Wg16` (already existed before this
    /// trait grew a loading surface at all -- see `crate::abi::wg16`).
    /// `Wg32`'s own is Task 10's to build
    /// (`docs/plans/2026-08-12-abi-border-implementation.md`); until then
    /// `Wg32`'s answer is a placeholder no code calls, guarded by a `load`
    /// that refuses to run rather than fabricate one -- see [`Abi::load`]'s
    /// own `Wg32` implementation.
    ///
    /// **`Clone`**, since `Host::load` (`crates/mbbs/src/lib.rs`) keeps a
    /// copy of every module it loads, keyed by [`Abi::module_name`], so that
    /// a *later* `Host::load` call's [`Abi::export_address`] can answer
    /// "what is `WCCMMUD.mmlog`?" against a `WCCMMUD` this same `Host` loaded
    /// earlier in the same life -- see `crate::LoadError`'s own doc comment
    /// for cross-module imports, the feature this bound exists for. Both
    /// `Wg16`'s and `Wg32`'s own `Module` already derived `Clone` before this
    /// bound was added; it costs neither implementation anything, and a
    /// future third `Abi` inherits the requirement rather than being able to
    /// silently skip it.
    type Module: Clone;

    /// Parse and map `file` into this ABI's own memory, resolving every
    /// import through `resolve`.
    ///
    /// **Format mechanics stay inside this method; only policy crosses
    /// `resolve`.** `resolve` answers "what does the host know about
    /// `module.symbol`" -- a thunk, a datum's address, or (`Wg16` only) an
    /// absolute constant, see [`mbbs_machine::module::Import`]'s own doc
    /// comment for why that third arm cannot exist under any other ABI. How
    /// an import site gets patched -- an NE relocation chain's fixup kinds,
    /// a PE image's whole-slot IAT writes -- never surfaces through
    /// `resolve` at all; it is exactly the machinery `mbbs_machine::m16::ne`
    /// and `mbbs_machine::m32::image` already own, unrelated between the two,
    /// and this method's implementation for `Self` is what calls into it. See
    /// `docs/plans/2026-08-12-abi-border-design.md` §3.
    ///
    /// **The `MissingGlobal` refusal folds into this walk.** `Host::load`
    /// (the generic wrapper that calls this) builds `resolve` so that every
    /// symbol this method asks it about which the module *addresses as
    /// data* (a fixup shape only NE relocations can express -- see
    /// `crate::addressed_as_data`'s own doc comment) and which the host
    /// cannot honestly place gets recorded, not merely answered `None`.
    /// After this method returns, `Host::load` drains those records into
    /// [`crate::LoadError::Globals`] if any exist -- so a `Wg16` module
    /// that addresses an unplaced or too-small global still refuses to
    /// load, exactly as it always has, but the check is no longer a
    /// separate pass over the whole image before this one runs.
    ///
    /// **Loading a module must not invalidate a pointer
    /// [`ModuleMem::alloc_region`] has already returned.** `Self::Mem` is
    /// the module's own memory *and* the host's allocation arena together
    /// (see [`ModuleMem`]'s own doc comment); a caller may build `Self::Cpu`,
    /// carve host-owned regions out of that arena with `alloc_region` --
    /// `Host::new`'s own buffers are the ordinary case -- and only then call
    /// this method to load or reload the module those buffers will be read
    /// and written alongside. This method may replace, relocate or discard
    /// anything that belongs to the *module* (the image it just parsed), but
    /// the arena, and every pointer already handed out of it, must still
    /// resolve to the same bytes once this method returns `Ok`. `Wg16::load`
    /// gets this for free: `Machine::load_ne` *appends* a fresh segment to
    /// the `Segments` a scratch `Machine::new` already carries, so nothing
    /// already allocated ever moves. `Wg32::load` has to earn it instead --
    /// see that implementation's own doc comment, and
    /// `mbbs_machine::m32::Memory::push_image`, for how: the image is
    /// appended, never touching the arena. This was not always true of
    /// `Wg32::load` (`crates/mbbs/tests/wg32_round_trip.rs`'s module doc
    /// comment records the bug this invariant now rules out by
    /// construction, and this trait method's own doc comment previously
    /// said nothing about it at all).
    ///
    /// # Errors
    ///
    /// If `file` is not a well-formed module for this ABI. The
    /// `MissingGlobal` refusal above is reported by the caller, not by this
    /// method -- see `crate::LoadError`'s own doc comment.
    fn load(
        cpu: &mut Self::Cpu,
        file: &[u8],
        resolve: &dyn mbbs_machine::module::ImportResolver<Self::Ptr>,
    ) -> Result<Self::Module, crate::LoadError>
    where
        Self: Sized;

    /// What thunk `index` stands for, as this ABI's own `Exit::Call` reports
    /// it -- the only way an unimplemented import is named rather than
    /// merely numbered. Direct delegation to the module's own lookup
    /// (`mbbs_machine::m16::Module::import` for `Wg16`).
    fn import(module: &Self::Module, index: u16) -> Option<&mbbs_machine::module::ImportSite>;

    /// Where in the module the call being refused came from, as a place a
    /// disassembly names -- best-effort diagnostics for `Host::run`'s own
    /// stop message, never load-bearing for anything this crate decides.
    ///
    /// `None` whenever the answer would mislead rather than help: no
    /// outstanding call, a stack that will not resolve, a selector or
    /// section the module does not own. Segment:offset for `Wg16`
    /// (delegates to the free function this crate already had); section and
    /// offset for a future `Wg32` implementation, once `Wg32::Module`
    /// carries enough to answer it (design §3).
    fn caller(cpu: &Self::Cpu, module: &Self::Module) -> Option<String>;

    /// Where a **fault or timeout** stopped, as a place a disassembly names.
    ///
    /// [`Self::caller`]'s counterpart for the poison the module did not
    /// choose. A refusal names a symbol and gets `caller` to say who called
    /// it; a fault has only a raw `cs:ip`, and **a selector is not a
    /// segment** -- the loader hands out whatever LDT entries are free on
    /// the run that happened, so the same module's segment 1 is a different
    /// selector under `mbbs-server` (host segments allocated first) than in
    /// a test that loads it alone. Reading a selector as though it were
    /// stable sends the reader to the wrong function in a different segment,
    /// which is a failure that has actually happened here (see this
    /// function's `Wg16` implementation).
    ///
    /// `None` on exactly `caller`'s rule -- no guess is better than a wrong
    /// address: a poison that carries no code address at all (every refusal),
    /// or a `cs` this module does not own (host code, or another module).
    fn fault_site(module: &Self::Module, poison: &Self::Poison) -> Option<String>;

    /// Where the module's init routine sits -- resolved by NAME in both
    /// ABIs now (`_init__<dll>` PE-side, `_INIT__<DLL>` NE-side, both
    /// case-insensitive), with exported ordinal 1 as a fallback rather than
    /// the rule it was first believed to be. `Wg16` reads it from an NE
    /// module's own export/ordinal table (`m16::ne::Module::init`). `Wg32`
    /// reads it from the PE export table (`m32::PeImage::init_rva`), which
    /// is **not** `AddressOfEntryPoint`: for a Borland-linked DLL like
    /// `LUNATIX.DLL`, the PE entry point is a C-runtime startup stub (RVA
    /// `0x1000`), while its init routine is `_init__lunatix` (RVA
    /// `0x115c`), the routine that actually calls `register_module`.
    /// Conflating entry point and init routine was a real, measured bug --
    /// `mbbs-server` faulted taking the entry point as the init routine --
    /// fixed in `abi/wg32.rs`'s `Wg32::load` and `Wg32::init_entry`. Added
    /// for `crates/mbbs-server/src/host.rs`'s `life`, generic since Task 20
    /// of `docs/plans/2026-08-12-abi-border-implementation.md`: it used to
    /// call `mbbs_machine::m16::Module::entry(1)` directly, which has no
    /// `Wg32` analogue by that name or that signature.
    ///
    /// "Ordinal 1 is the convention" was itself a bug, caught on The Rose's
    /// PE and NE builds (both named `RCIROSE.DLL`): both `LUNATIX.DLL` and
    /// MajorMUD's NE build happen to have their real init routine at
    /// ordinal 1, and
    /// generalizing that coincidence into a rule sent the host into
    /// `RCIROSE.DLL`'s ordinal 1, which is gameplay code (`_his_mods`), and
    /// the NE build's ordinal 1, which is `BCC286_EXE`, Borland C++ 286's
    /// crt0 startup stub -- not an entry point at all. See
    /// `m32::PeImage::init_rva` and `m16::ne::Module::init`'s own doc
    /// comments for the full measurement.
    ///
    /// `None` if this ABI's module has no such entry -- an NE module with
    /// neither a named `_INIT__<dll>` export nor ordinal 1 (`Wg16`), or a
    /// PE with no export directory and neither a named nor an ordinal-1
    /// export (`Wg32`; `mbbs_machine::m32::Module::init`, distinct from
    /// `Module::entry` -- see that method's own doc comment). Both ABIs'
    /// init lookups carry that `Option` now, so neither has to fabricate an
    /// answer this method could not honestly give.
    fn init_entry(module: &Self::Module) -> Option<Self::Ptr>;

    /// This ABI's own name for `module` -- what a *different* module's own
    /// import table has to say to reach it, not to be confused with the DLL
    /// names a module itself imports *from*.
    ///
    /// Consulted by `Host::load`'s cross-module import registry
    /// (`crates/mbbs/src/lib.rs`'s `Resolver`, and see `crate::LoadError`'s
    /// own doc comment): once a module has loaded, `Host` remembers it keyed
    /// by whatever this answers, so a *later* `Host::load` call resolving an
    /// import against it can find it by the same name its own import table
    /// would have used.
    ///
    /// Default `None`, the same convention [`Abi::native`]'s own doc comment
    /// explains: an `Abi` with nothing to add here writes no code at all.
    /// `Wg16`'s override (`abi/wg16.rs`) reads
    /// [`mbbs_machine::m16::Module::name`], the NE resident name table's own
    /// first entry -- see that method's own doc comment for where the string
    /// comes from. `Wg32`'s (`abi/wg32.rs`) reads the PE export directory's
    /// own `Name` string (`wccmmud.DLL`), `None` for an image with no
    /// export directory. `Host` uppercases whatever this answers before
    /// keying by it, because a PE exports `wccmmud.DLL` and its importer
    /// spells the same library `WCCMMUD.dll`.
    fn module_name(module: &Self::Module) -> Option<&str>
    where
        Self: Sized,
    {
        let _ = module;
        None
    }

    /// Where `symbol` lives in `module`'s own export table, in this ABI's
    /// pointer type -- the read half of the cross-module registry
    /// [`Abi::module_name`] is the write half of, and what `mbbs-lua`'s
    /// declare-time probe resolves a lib's names against. `None` for a
    /// symbol `module` does not export.
    ///
    /// Only ever consulted for a symbol the host's own tables (`shims::entry`
    /// and friends) had no answer for -- see `Resolver::resolve`'s own doc
    /// comment ("Order matters") for why a loaded module is never given the
    /// chance to shadow a host routine.
    ///
    /// Default `None`, matching [`Abi::module_name`]. `Wg16`'s override
    /// (`abi/wg16.rs`) delegates to [`mbbs_machine::m16::Module::entry`] for
    /// an ordinal symbol and [`mbbs_machine::m16::Module::entry_by_name`]
    /// for a named one -- both of which this crate's loader already builds
    /// for every module it maps. `Wg32`'s (`abi/wg32.rs`) reads the
    /// [`mbbs_machine::m32::Exports`] table `Wg32::load` rebases from the
    /// PE export directory -- the one thing a loaded `m32::Module` retains
    /// beyond what the import path needs, kept precisely for this.
    fn export_address(module: &Self::Module, symbol: &mbbs_machine::module::Symbol) -> Option<Self::Ptr>
    where
        Self: Sized,
    {
        let _ = (module, symbol);
        None
    }
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

    /// The next argument, as a C `double`: eight raw bytes, decoded
    /// little-endian, with no `Abi`-varying width the way [`Call::ptr`]/
    /// [`Call::int`] have.
    ///
    /// Evidence::Standard, not measured: a cdecl `double` argument is pushed
    /// as the IEEE 754 bit pattern occupies memory -- `sub esp, 8; fstp qword
    /// ptr [esp]` is the shape a compiler emits for it, the same instruction
    /// [`Machine::arm_st0_return`](mbbs_machine::m32::Machine) uses on the
    /// *return* side -- so there is nothing here for an `Abi::LONG_WIDTH`-style
    /// associated constant to name: it is 8 bytes in every ABI a `double`
    /// exists in at all, both the ones this crate has so far (`Wg16`'s
    /// Borland huge model and `Wg32`'s flat cdecl agree at 8, unlike
    /// `Abi::INT_WIDTH`, which is where the two actually diverge).
    ///
    /// # Panics
    ///
    /// If fewer than 8 bytes remain -- the same contract every other read on
    /// `Call` carries.
    pub fn double(&mut self) -> f64 {
        let bytes: [u8; 8] = self
            .take(8)
            .try_into()
            .expect("take(8) always returns exactly 8 bytes");
        f64::from_le_bytes(bytes)
    }
}

/// What a host call hands back to the module, generic over the ABI's width
/// and pointer representation.
///
/// Mirrors `mbbs_machine::m16::Ret` with the two ABI-dependent shapes generalised:
/// `Far(FarPtr)` becomes `Ptr(A::Ptr)` and `U16(u16)` becomes `Int(A::Int)`.
/// `Void` and the 32-bit `Long` do not vary -- a `long` is
/// [`Abi::LONG_WIDTH`] bytes in every ABI this crate has met so far (4, in
/// both), so there is nothing for an ABI to name here the way `PTR_WIDTH` and
/// `INT_WIDTH` do for the other two.
///
/// `mbbs_machine::m16::Ret` itself is unchanged and stays that way -- it is what
/// `Machine::resume` takes, and this crate does not get to add a generic
/// parameter to a type `mbbs16` owns. So the 16-bit boundary is a conversion,
/// not a shared type: see `impl From<Ret<Wg16>> for mbbs_machine::m16::Ret` below.
///
/// *Where* the value lands is deliberately not this type's business, the same
/// way it was not `mbbs_machine::m16::Ret`'s: 16-bit Worldgroup returns a pointer in
/// `DX:AX` (`mbbs_machine::m16::Ret::Far`'s own doc comment); 32-bit Worldgroup returns
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

    /// An `f64` result, delivered through the FPU's `ST(0)` register rather
    /// than through the general-purpose registers `Int`/`Long`/`Ptr` use.
    /// Evidence::Standard, not measured: ISO C / the Intel ABI say a
    /// `double`-returning function leaves its result on the x87 stack for
    /// the caller, the same convention `cw3220mt.DLL!__ftol`'s *argument*
    /// side already measures at 13 call sites
    /// ([`mbbs_machine::m32::Machine::arm_st0_capture`]'s own doc comment).
    ///
    /// **`Wg32` only.** [`mbbs_machine::m32::Machine::run`] has a return-path
    /// stub -- [`mbbs_machine::m32::Machine::arm_st0_return`], the outbound
    /// counterpart to `arm_st0_capture` -- that can honestly place this
    /// value in `ST0` before the module resumes. `mbbs_machine::m16::Machine`
    /// has no such counterpart: no scratch qword, no bridge-mapped stub to
    /// build one in, nothing that ever touches the FPU at all, so a 16-bit
    /// shim can never honestly construct this. No `CW3220MT`-linked routine
    /// (the only library this variant's producers -- `crate::shims::math` --
    /// are registered against) is ever bound to `Wg16`, so in practice this
    /// variant is never built at `A = Wg16`; if that convention were ever
    /// violated, `abi/wg16.rs`'s `From<Ret<Wg16>> for mbbs_machine::m16::Ret`
    /// panics naming the same missing capability
    /// [`crate::shims::crt::setjmp`]'s own refusal does, rather than
    /// pretending a 16-bit machine can do this.
    F64(f64),
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
            Self::F64(v) => f.debug_tuple("F64").field(v).finish(),
        }
    }
}

/// An outbound argument, in this ABI's own frame encoding -- the mirror of
/// [`Call`]'s inbound reads, and what [`Abi::call`] takes.
///
/// `Ptr` is [`Abi::PTR_WIDTH`] bytes laid out the same way
/// [`Abi::ptr_to_bytes`] would: two words, offset then selector, under
/// `Wg16`; one dword, the flat address, under `Wg32`. `Long` is a plain
/// `u32` rather than `A::Long` because no `Abi` implementation has ever
/// needed a `long` wider than that (see [`Abi::LONG_WIDTH`]'s own doc
/// comment) -- there is nothing per-ABI left for this variant to carry.
pub enum Arg<A: Abi> {
    /// A C `int`, `A::INT_WIDTH` bytes.
    Int(A::Int),
    /// A C `long`, always four bytes.
    Long(u32),
    /// A pointer, in this ABI's own representation.
    Ptr(A::Ptr),
}

/// How an excursion into module code came back, with everything ABI-specific
/// already converted out.
///
/// `Fault` and `Timeout` collapse to `Stopped` because every caller's next
/// move is identical: read [`Abi::poisoned`]. The per-ABI location shapes
/// (`cs:ip` vs `eip`) stay in each machine's own `Exit`/`Poison` and never
/// cross this border -- see design §2.
pub enum Exit<A: Abi> {
    /// The module reached host thunk `index` (`u16` in both machines).
    Call { index: u16 },

    /// The module returned. `lo` is `AX`/`EAX` zero-extended, `hi` is
    /// `DX`/`EDX`; each `Abi` implementation's own conversion documents the
    /// mapping (`Ret`'s own doc comment covers the direction back in).
    Returned { lo: u32, hi: u32 },

    /// Terminal. The poison is already stored machine-side -- see
    /// [`Abi::poisoned`].
    Stopped,

    /// Not a variant. `Exit<A>` names no field of `A`'s own -- every real
    /// variant above is the same shape in both ABIs -- so without this the
    /// type parameter would be unused and the compiler would refuse to
    /// accept it (E0392). Keeping `Exit` parameterised anyway is deliberate:
    /// `Outcome<A>`/`Vector<A>` (Task 10) wrap it and want the parameter
    /// there, not bolted on later. `Infallible` makes this uninhabitable, so
    /// no match arm anywhere ever needs to produce one; only construct it by
    /// matching `Infallible`'s own zero variants, which is to say: never.
    #[doc(hidden)]
    _Phantom(std::convert::Infallible, std::marker::PhantomData<A>),
}

// Hand-written, not `#[derive(..)]`, for the same reason `Ret<A>`'s impls
// above are: the derive macro's generated bound is `A: Trait`, which is both
// wrong (every field here is `u16`/`u32`/`Infallible`/`PhantomData<A>`, none
// of which need `A` itself to implement anything) and, for `Wg16`/`Wg32`
// (unit structs implementing nothing but `Abi`), simply unsatisfiable.
impl<A: Abi> Clone for Exit<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for Exit<A> {}

impl<A: Abi> std::fmt::Debug for Exit<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call { index } => f.debug_struct("Call").field("index", index).finish(),
            Self::Returned { lo, hi } => f.debug_struct("Returned").field("lo", lo).field("hi", hi).finish(),
            Self::Stopped => write!(f, "Stopped"),
            // `_Phantom` holds an `Infallible`, which has no values -- this
            // arm can never run, and matching on the `Infallible` (rather
            // than writing `unreachable!()`) is what lets the compiler prove
            // that rather than trust a comment saying so.
            Self::_Phantom(never, _) => match *never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::FarPtr;

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

        /// `mbbs_machine::m16::Segments`, not a stub, and not because this fixture ever
        /// touches memory -- it does not. `Abi::Ptr` is bound
        /// `ModulePtr<Memory = Self::Mem>`, so an ABI whose `Ptr` is `FarPtr`
        /// has no choice: `FarPtr` resolves against `Segments` and nothing
        /// else. That bound is what makes a generic `resolve`/`read_cstr`/
        /// `write` expressible at all, and the price is that a fixture cannot
        /// invent its own memory type while borrowing a real pointer type.
        /// Cheap here, because `Cpu` is still `()` and the reads under test
        /// never leave the frame.
        type Mem = mbbs_machine::m16::Segments;
        type Cpu = ();
        type Int = u16;

        const PTR_WIDTH: usize = Wg16::PTR_WIDTH;
        const INT_WIDTH: usize = Wg16::INT_WIDTH;
        const LONG_WIDTH: usize = Wg16::LONG_WIDTH;
        const NAME: &'static str = Wg16::NAME;
        const GCV2: bool = Wg16::GCV2;
        const FILE_FLAGS_OFFSET: u16 = Wg16::FILE_FLAGS_OFFSET;
        const FILE_SIZE: usize = Wg16::FILE_SIZE;
        const FILE_FD_OFFSET: u16 = Wg16::FILE_FD_OFFSET;
        const FILE_FD_WIDTH: u16 = Wg16::FILE_FD_WIDTH;
        const FSD_FIELD: crate::fsd::FieldLayout = Wg16::FSD_FIELD;

        fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr {
            Wg16::ptr_from_bytes(bytes)
        }

        fn ptr_to_bytes(ptr: Self::Ptr) -> Vec<u8> {
            Wg16::ptr_to_bytes(ptr)
        }

        fn int_from_u32(value: u32) -> Self::Int {
            Wg16::int_from_u32(value)
        }

        fn int_to_bytes(value: Self::Int) -> Vec<u8> {
            Wg16::int_to_bytes(value)
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

        fn ptr_checked_add(_base: Self::Ptr, _by: usize) -> Option<Self::Ptr> {
            // Same reasoning as `ptr_offset` above.
            unreachable!("Call's read tests never offset a pointer by a module-held value")
        }

        fn null_ptr() -> Self::Ptr {
            Wg16::null_ptr()
        }

        fn mem(_cpu: &mut Self::Cpu) -> &mut Self::Mem {
            // `Cpu = ()` owns no `FixtureMem` to reborrow -- there is
            // nothing this could correctly return, which is fine because
            // `Call`'s frame-read tests below never call `Call::mem`.
            unreachable!("Call's read tests never call Call::mem")
        }

        fn mem_ref(_cpu: &Self::Cpu) -> &Self::Mem {
            // Same reasoning as `mem` above.
            unreachable!("Call's read tests never call Abi::mem_ref")
        }

        fn data_ptr(_cpu: &Self::Cpu) -> Self::Ptr {
            // Same reasoning as `mem` above: `Cpu = ()` has no data segment
            // to name, which is fine because `Call`'s frame-read tests below
            // never format a near pointer.
            unreachable!("Call's read tests never call Abi::data_ptr")
        }

        // `Cpu = ()` cannot execute anything, so none of the six methods
        // Task 5 added has a real implementation to give -- same reasoning
        // as `mem`/`data_ptr`/`ptr_offset`/`ptr_checked_add` above, repeated
        // six more times rather than left implicit: `Call`'s frame-read
        // tests build a `Call<FixtureAbi>` directly from a byte slice and
        // never call [`Machine::call`](mbbs_machine::m16::Machine::call) or
        // anything downstream of it.
        type Poison = mbbs_machine::m16::Poison;

        fn call(_cpu: &mut Self::Cpu, _entry: Self::Ptr, _args: &[Arg<Self>]) -> std::io::Result<Exit<Self>> {
            unreachable!("Call's read tests never call Abi::call")
        }

        fn resume(_cpu: &mut Self::Cpu, _ret: Ret<Self>, _cleans: crate::shims::Cleans) -> std::io::Result<Exit<Self>> {
            unreachable!("Call's read tests never call Abi::resume")
        }

        fn arg_frame(_cpu: &Self::Cpu) -> &[u8] {
            unreachable!("Call's read tests never call Abi::arg_frame")
        }

        fn poison(_cpu: &mut Self::Cpu, _why: Self::Poison) -> std::io::Result<()> {
            unreachable!("Call's read tests never call Abi::poison")
        }

        fn poisoned(_cpu: &Self::Cpu) -> Option<Self::Poison> {
            unreachable!("Call's read tests never call Abi::poisoned")
        }

        fn refused(_module: String, _symbol: String, _why: String) -> Self::Poison {
            unreachable!("Call's read tests never call Abi::refused")
        }

        fn unimplemented(_module: String, _symbol: String) -> Self::Poison {
            unreachable!("Call's read tests never call Abi::unimplemented")
        }

        fn unimplemented_library(poison: &Self::Poison) -> Option<&str> {
            match poison {
                mbbs_machine::m16::Poison::Unimplemented { module, .. } => Some(module),
                _ => None,
            }
        }

        // Same reasoning as `mem`/`data_ptr`/`call`/`resume` above: `Call`'s
        // frame-read tests never load a module at all.
        type Module = ();

        fn load(
            _cpu: &mut Self::Cpu,
            _file: &[u8],
            _resolve: &dyn mbbs_machine::module::ImportResolver<Self::Ptr>,
        ) -> Result<Self::Module, crate::LoadError> {
            unreachable!("Call's read tests never call Abi::load")
        }

        fn import(_module: &Self::Module, _index: u16) -> Option<&mbbs_machine::module::ImportSite> {
            unreachable!("Call's read tests never call Abi::import")
        }

        fn caller(_cpu: &Self::Cpu, _module: &Self::Module) -> Option<String> {
            unreachable!("Call's read tests never call Abi::caller")
        }

        fn fault_site(_module: &Self::Module, _poison: &Self::Poison) -> Option<String> {
            unreachable!("Call's read tests never call Abi::fault_site")
        }

        fn init_entry(_module: &Self::Module) -> Option<Self::Ptr> {
            unreachable!("Call's read tests never call Abi::init_entry")
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

    /// `double sqrt(double x)` -- the shape `crate::shims::math`'s routines
    /// all share: an 8-byte argument with no `Abi`-varying width. Two doubles
    /// back to back, mirroring `call_reads_otstcrds_frame_...`'s own "a read
    /// after the one under test" discipline: a mutation to `double`'s advance
    /// would leave the second `PI` read misaligned and this would fail on
    /// the second assertion rather than pass by never being checked.
    #[test]
    fn call_reads_two_back_to_back_doubles_at_byte_offsets_0_and_8() {
        let x: f64 = 2.0;
        let y: f64 = std::f64::consts::PI;
        let frame = [x.to_le_bytes(), y.to_le_bytes()].concat();

        let mut cpu = ();
        let mut call = Call::<FixtureAbi>::new(&mut cpu, &frame);
        assert_eq!(call.double(), x, "byte 0");
        assert_eq!(call.double(), y, "byte 8");
    }

    // `call_reads_a_real_machines_frame_for_stzcpy` and the `Ret<Wg16>`
    // boundary-conversion tests moved to `abi/wg16.rs`, alongside `Wg16`
    // itself and the `mbbs_machine::m16::Ret` conversions they exercise --
    // `FixtureAbi` and the tests above stay here because they exercise
    // `Cursor`/`Call`, which stay here too, and need nothing Wg16-specific
    // beyond its width constants and decode functions (delegated, not
    // reimplemented).

    /// `mmud.abi`'s whole surface: a plain associated const, both `Abi`
    /// implementations. Reading it needs no `Machine`/`Cpu` of either
    /// ABI's own (unlike most of `Wg32`'s own tests -- see this file's own
    /// module doc comment on why `Wg32`'s real construction stays out of
    /// `cargo test -p mbbs --lib`), so both go here rather than split
    /// across `abi/wg16.rs` and a `crates/mbbs/tests/*.rs` integration
    /// binary.
    #[test]
    fn each_abi_names_itself_for_mmud_abi() {
        assert_eq!(Wg16::NAME, "wg16");
        assert_eq!(Wg32::NAME, "wg32");
    }
}
