//! `Wg32`: the flat 32-bit cdecl ABI Worldgroup NT modules were compiled
//! for.
//!
//! The second [`Abi`] implementation -- and the whole reason Task 2 built a
//! trait rather than a `Machine`-shaped struct: a trait with one
//! implementation is not known to be an abstraction, only hoped to be one.
//! Building this surfaced three places the rest of this crate family was,
//! without saying so, shaped only for `Wg16`. All three are load-bearing
//! enough to explain here rather than only in a commit message: two are
//! compile-time trait-bound collisions (below), and the third is a
//! process-wide runtime one -- no test module lives in this file at all; see
//! the comment in its place, at the bottom, for why and where its tests
//! actually live.
//!
//! # Collision 1: `Abi::Ptr`'s bound forced `Abi::Mem`'s shape
//!
//! `Abi::Ptr` is bound `mbbs_machine::ptr::ModulePtr<Memory = Self::Mem>`. Before this
//! file existed, `mbbs_machine::m32::Flat32Ptr`'s only `ModulePtr` impl
//! (then `crates/mbbs32/src/flatptr.rs`, today
//! `crates/mbbs-machine/src/m32/flatptr.rs`) answered
//! `type Memory = mbbs_machine::m32::Image` -- and `mbbs-ptr`'s own doc
//! comment said as much: "concretely ... `mbbs_machine::m32::Image` for
//! `Flat32Ptr`".
//!
//! **Both quotes are historical and neither file still says it.**
//! `m32/flatptr.rs:54` now answers `type Memory = Memory`, and `ptr.rs` now
//! says "the module's loaded `Image` plus the host's own allocation arena,
//! not `Image` alone" -- which is this section's own conclusion, landed. The
//! citations are kept because they are what forced the decision below, not
//! because they describe the tree you are reading. So `type Mem = Image` was the only
//! choice that would satisfy the bound at all, and everything else this
//! design says about a 32-bit `Mem` -- "Image plus its allocator", "a 32-bit
//! allocator gets its own `Mapping`" (design doc, Part 3 and its correction
//! #2) -- was unreachable without widening `Image` itself into an
//! allocator, which both that correction and this task's own brief reject:
//! `Image` is a fixed-size mapping made once at load, and staying that way
//! is deliberate (`crates/mbbs-machine/src/m32/image.rs`'s own module doc comment).
//!
//! Neither horn is acceptable, so the actual fix reaches one file this
//! task's brief did not originally name: `crates/mbbs-machine/src/m32/flatptr.rs`'s
//! `ModulePtr` impl now answers `type Memory = mbbs_machine::m32::Memory`, a new type
//! (`crates/mbbs-machine/src/m32/mem.rs`) that owns the loaded `Image` *and* a second
//! `Mapping` for host-allocated regions -- exactly the `tib`-owns-its-own-
//! stack-mapping precedent the design cites, just written down where the
//! trait bound could actually see it. `Image` itself is untouched: still a
//! fixed-size mapping, still made once at load, still with no
//! allocate-more operation. This is not a workaround chosen to make the
//! bound typecheck; it is the design's own Part 3 architecture, applied to
//! the one file that had baked in the older answer before a second `Abi`
//! existed to test it against.
//!
//! # Collision 2: `Abi::Cpu` cannot be bare `mbbs_machine::m32::Machine`
//!
//! `Abi::mem` is `fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem` -- a
//! reborrow, not a second field (see `Call`'s "holds one handle, not two").
//! For `Wg16` that works because `mbbs_machine::m16::Machine` owns its `Segments`
//! outright. `mbbs_machine::m32::Machine` does not own an `Image` "unlike
//! `mbbs_machine::m16::Machine`... **deliberately**" (`crates/mbbs-machine/src/m32/mod.rs`,
//! `Machine`'s own doc comment) -- so there is no `&mut Self::Mem` inside a
//! bare `mbbs_machine::m32::Machine` for `Abi::mem` to reborrow. `type Cpu =
//! mbbs_machine::m32::Machine` compiles as a bare assignment, but `fn mem` cannot then
//! be implemented for it at all: there is nothing in a `Machine` to return
//! `&mut`.
//!
//! [`Wg32Cpu`] is the fix, and it is not a new idea: it is the design's own
//! later correction, restated here as code -- "`Wg32::Cpu` is a struct the
//! host builds holding a `Machine` and its `Image`"
//! (`docs/plans/2026-08-11-abi-abstraction-implementation.md`, "Tasks 5 and
//! 6 are in the wrong order"). `Wg32::Cpu` is that struct, not bare
//! `mbbs_machine::m32::Machine`.

use super::{Abi, Arg, Exit, ModuleMem, Ret};

/// Execution plus memory, bundled because `Abi::mem` needs somewhere to
/// reborrow `&mut mbbs_machine::m32::Memory` out of `&mut Self::Cpu`, and a bare
/// `mbbs_machine::m32::Machine` has nowhere to keep one -- see this module's doc
/// comment ("Collision 2").
///
/// Public fields, not a constructor-only opaque struct: this is a bundle a
/// host builds once, at module load, out of two things it already has to
/// build anyway (a `Machine` to run code, a `Memory` to hold the loaded
/// image) -- there is no invariant between them for a constructor to
/// enforce beyond "both exist".
pub struct Wg32Cpu {
    pub machine: mbbs_machine::m32::Machine,
    pub mem: mbbs_machine::m32::Memory,
}

impl Wg32Cpu {
    /// Bundle a machine and its memory, moving the module's stack out of the
    /// former and into the latter.
    ///
    /// # The transfer is the point, not a detail
    ///
    /// `Memory` resolves every linear address the module can name. Until
    /// this call it owned two mappings -- the loaded image and the host
    /// arena -- while the stack was a third, hidden inside the machine's
    /// `Tib`. A module that passed a pointer to one of its own locals, which
    /// is what `char buf[128]; fgets(buf, sizeof buf, f);` does, handed the
    /// host an address that resolved in neither and got a refusal naming the
    /// image. LunatiX's init died exactly there.
    ///
    /// This is the one place both halves are in scope, so it is the one
    /// place the move can happen. See
    /// [`Memory::adopt_stack`](mbbs_machine::m32::Memory::adopt_stack) for
    /// why ownership moves rather than being shared.
    pub fn new(mut machine: mbbs_machine::m32::Machine, mut mem: mbbs_machine::m32::Memory) -> Self {
        if let Some(stack) = machine.take_stack() {
            mem.adopt_stack(stack);
        }
        Self { machine, mem }
    }
}

/// The ABI Worldgroup NT modules were compiled for: flat 32-bit addresses,
/// cdecl throughout (no `Cleans::Callee` -- see the design's Part 2, "32-bit
/// Worldgroup is uniformly cdecl").
pub struct Wg32;

impl Abi for Wg32 {
    type Ptr = mbbs_machine::m32::Flat32Ptr;
    type Mem = mbbs_machine::m32::Memory;
    type Cpu = Wg32Cpu;

    /// `u32`, not `u16` -- the single number this whole abstraction exists
    /// to get right. See [`Abi::INT_WIDTH`] below and this crate's mutation
    /// test: setting it to `2` (matching `Wg16`) is the one bug a second
    /// `Abi` implementation was built to catch, and it does.
    type Int = u32;

    const PTR_WIDTH: usize = 4;
    const INT_WIDTH: usize = 4;
    const LONG_WIDTH: usize = 4;

    fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr {
        mbbs_machine::m32::Flat32Ptr(u32::from_le_bytes(
            bytes.try_into().expect("PTR_WIDTH bytes"),
        ))
    }

    fn ptr_to_bytes(ptr: Self::Ptr) -> Vec<u8> {
        ptr.0.to_le_bytes().to_vec()
    }

    fn int_from_bytes(bytes: &[u8]) -> Self::Int {
        u32::from_le_bytes(bytes.try_into().expect("INT_WIDTH bytes"))
    }

    fn int_from_u32(value: u32) -> Self::Int {
        value
    }

    fn int_to_bytes(value: Self::Int) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn long_from_bytes(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().expect("LONG_WIDTH bytes"))
    }

    /// Plain addition, unchecked -- the same shape `Wg16::ptr_offset` uses
    /// for its own pointer's offset field. Callers of this method only ever pass
    /// `delta` bytes into a region [`ModuleMem::alloc_region`] just handed
    /// back (see [`Abi::ptr_offset`]'s own doc comment), which is at most a
    /// few tens of kilobytes -- nowhere near `u32::MAX` -- so there is no
    /// realistic overflow for a checked version to catch that a debug build's
    /// own overflow panic would not already catch first.
    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        mbbs_machine::m32::Flat32Ptr(base.0 + u32::from(delta))
    }

    fn ptr_checked_add(base: Self::Ptr, by: usize) -> Option<Self::Ptr> {
        let by = u32::try_from(by).ok()?;
        base.0.checked_add(by).map(mbbs_machine::m32::Flat32Ptr)
    }

    /// Flat address `0` -- there is no `seg:off` pair to be zero in both
    /// halves of, only the one address space every other `Wg32` pointer
    /// already names. See [`Abi::null_ptr`]'s own doc comment.
    fn null_ptr() -> Self::Ptr {
        mbbs_machine::m32::Flat32Ptr(0)
    }

    fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem {
        &mut cpu.mem
    }

    /// `&cpu.mem`, `mem`'s shared-borrow sibling. See [`Abi::mem_ref`]'s own
    /// doc comment.
    fn mem_ref(cpu: &Self::Cpu) -> &Self::Mem {
        &cpu.mem
    }

    /// The module's own loaded image, at its own base -- there is no
    /// near/far distinction left to collapse once every pointer is already
    /// flat, so "the module's own data segment" and "an ordinary pointer
    /// into it" are the same address. See [`Abi::data_ptr`]'s own doc
    /// comment.
    fn data_ptr(cpu: &Self::Cpu) -> Self::Ptr {
        mbbs_machine::m32::Flat32Ptr(cpu.mem.image().base())
    }

    type Poison = mbbs_machine::m32::Poison;

    /// Encode `args` into the dwords `mbbs_machine::m32::Machine::call` takes,
    /// then delegate. One dword each, whatever the variant: `Wg32`'s
    /// `PTR_WIDTH`/`INT_WIDTH`/`LONG_WIDTH` all agree at 4, unlike `Wg16`'s
    /// `INT_WIDTH` of 2 -- see `abi.rs`'s own module doc comment ("Only
    /// `INT_WIDTH` ... discriminates") and design §6, which is exactly what
    /// `wg32_abi.rs`'s differential test (Task 6) checks for.
    fn call(cpu: &mut Self::Cpu, entry: Self::Ptr, args: &[Arg<Self>]) -> std::io::Result<Exit<Self>> {
        let dwords: Vec<u32> = args
            .iter()
            .map(|arg| match arg {
                Arg::Int(v) => *v,
                Arg::Long(v) => *v,
                Arg::Ptr(p) => p.0,
            })
            .collect();
        let exit = convert_exit(cpu.machine.call_on(cpu.mem.stack_mut(), entry.0, &dwords)?);
        debug_assert_attributable(&exit, &cpu.machine);
        Ok(exit)
    }

    /// `Wg32` has no callee-cleaned routines -- 32-bit Worldgroup is
    /// uniformly cdecl (`WGSERVER.DEF`'s `#ifdef GCDOS` block only; see this
    /// module's own doc comment and design §2). `Cleans::Callee` reaching
    /// this arm therefore names a bug in the host's own shim table -- some
    /// entry wrongly marked callee-cleaned under this ABI -- not a case to
    /// guess an answer for. This panic is permanent, not a stub awaiting
    /// Task 6: there is no future implementation of it to write.
    fn resume(cpu: &mut Self::Cpu, ret: Ret<Self>, cleans: crate::shims::Cleans) -> std::io::Result<Exit<Self>> {
        match cleans {
            crate::shims::Cleans::Callee(bytes) => panic!(
                "Wg32::resume asked to clean {bytes} callee-side bytes -- 32-bit \
                 Worldgroup is uniformly cdecl, so a Cleans::Callee row reaching \
                 this ABI is a bug in the host's shim table, not something to guess at"
            ),
            crate::shims::Cleans::Caller => {
                let ret32: mbbs_machine::m32::Ret = ret.into();
                let exit = convert_exit(cpu.machine.resume_on(cpu.mem.stack_mut(), ret32)?);
                debug_assert_attributable(&exit, &cpu.machine);
                Ok(exit)
            }
        }
    }

    /// Direct delegation -- `mbbs_machine::m32::Machine::arg_frame` (Task 6)
    /// already returns exactly the window `Call<Wg32>::new` needs: the bytes
    /// starting right after the near return address, running to the end of
    /// the module's stack. See that method's own doc comment for why there is
    /// no `THUNK_SAVES`-sized register-save area to step over here, unlike
    /// `Wg16`'s arm.
    fn arg_frame(cpu: &Self::Cpu) -> &[u8] {
        cpu.machine.arg_frame(cpu.mem.stack())
    }

    /// Direct delegation -- `mbbs_machine::m32::Machine::poison` mirrors
    /// `mbbs_machine::m16::Machine::poison` exactly since Task 16 landed the
    /// 32-bit watchdog, disarm included. Forward the reason and the
    /// `io::Result` straight through.
    fn poison(cpu: &mut Self::Cpu, why: Self::Poison) -> std::io::Result<()> {
        cpu.machine.poison(why)
    }

    fn poisoned(cpu: &Self::Cpu) -> Option<Self::Poison> {
        cpu.machine.poisoned().cloned()
    }

    fn unimplemented(module: String, symbol: String) -> Self::Poison {
        mbbs_machine::m32::Poison::Unimplemented { module, symbol }
    }

    type Module = mbbs_machine::m32::Module;

    /// The real arm, Task 10 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: `pe::PeImage::parse`
    /// → `Image::load` → `Image::relocate` → `Image::bind_imports` →
    /// `Image::patch_thunk_addresses`, the same sequence
    /// `examples/both_loaders.rs`'s `pe()` proves interactively -- but driven
    /// by this host's own `resolve`, not a closure that answers `Routine` to
    /// everything.
    ///
    /// **No adapter sits between `resolve` and `Image::bind_imports`.**
    /// `resolve`'s `Ptr` is already `Self::Ptr` (`Flat32Ptr`), and
    /// `m32::image::ImportResolver`/`Import32` are a re-export and a type
    /// alias onto that same shared trait/enum now (`m32/image.rs`'s own
    /// module doc comment, "Reconciled" -- mirroring `Wg16::load`'s
    /// identical note). Task 9 left this reconciliation to this task because
    /// this is the file that owns the real PE arm.
    ///
    /// **Only the image is replaced -- the arena is not.** `cpu.mem`'s
    /// arena is the host's own allocation, not the module's: every pointer
    /// [`ModuleMem::alloc_region`] has ever handed out (`Host::new`'s
    /// `spr`/`mdf`/`l2as`/`empty` buffers among them) resolves against it,
    /// and loading a module has no business freeing memory it does not own
    /// -- see [`Abi::load`]'s own doc comment, which states that as the
    /// border's general contract, not a `Wg32`-specific courtesy. This
    /// method upholds it through
    /// [`mbbs_machine::m32::Memory::replace_image`], which swaps in a
    /// freshly loaded `Image` while leaving `cpu.mem`'s arena -- and every
    /// pointer already carved from it -- exactly as they were; see that
    /// method's own doc comment for why an outright `cpu.mem = Memory::new(image,
    /// ..)` cannot do the same (it drops the old arena `Mapping`, and
    /// `Mapping::drop` really does `munmap` it).
    ///
    /// **This was not always true.** An earlier version of this method did
    /// exactly that -- replaced `cpu.mem` wholesale -- and it was a real,
    /// measured bug, not a theoretical one:
    /// `crates/mbbs/tests/wg32_round_trip.rs`'s module doc comment records
    /// the failure it produced (a host-owned buffer pointer computed before
    /// `load`, resolving as `Flat32PtrError::OutOfBounds` after it) and the
    /// harness workaround Task 15 needed until this method was fixed to
    /// call `replace_image` instead.
    ///
    /// Unlike `Wg16::load`, which mutates the `Segments` a `Machine::new`
    /// scratch build already carries (`Machine::load_ne` appends), there is
    /// no way to grow `mbbs_machine::m32::Image` itself in place -- it is a
    /// fixed-size mapping made once at load (`mem.rs`'s own module doc
    /// comment, "why not fold this into `Image`"). So this method builds
    /// the whole `Image` first, against `file` alone, and only once
    /// loading, relocating, binding and patching have all succeeded does it
    /// commit -- calling `cpu.mem.replace_image` in the same motion that
    /// returns `Ok`. `cpu.machine` is never rebuilt: its thunk table,
    /// fault-recovery arming and TID binding all predate this call and must
    /// survive it, which is exactly why `cpu.machine.thunk_addr` is read
    /// from but `cpu.machine` itself is never reassigned.
    ///
    /// # Errors
    ///
    /// [`crate::LoadError::Image`] if `file` does not parse as PE32, is not
    /// i386, or its relocations cannot be applied (stripped, but the image
    /// did not land at its own preferred base). [`crate::LoadError::Absolute`]
    /// if `resolve` answers [`mbbs_machine::module::Import::Absolute`] for any
    /// import site -- see [`mbbs_machine::m32::AbsoluteImport`]'s own doc
    /// comment for why a PE loader can never honour one. `cpu.mem` is
    /// unchanged in every error case: nothing is assigned to it until every
    /// step above has already succeeded.
    fn load(
        cpu: &mut Self::Cpu,
        file: &[u8],
        resolve: &dyn mbbs_machine::module::ImportResolver<Self::Ptr>,
    ) -> Result<Self::Module, crate::LoadError> {
        let pe = mbbs_machine::m32::PeImage::parse(file)?;

        let mut image = mbbs_machine::m32::Image::load(file, &pe)?;
        image.relocate(&pe)?;

        let thunks = image.bind_imports(&pe, resolve)?;

        image.patch_thunk_addresses(&pe, &thunks, |index| {
            cpu.machine.thunk_addr(u16::try_from(index).expect("bind_imports never exceeds MAX_THUNKS"))
        });

        let entry = image.base().wrapping_add(pe.entry_point);

        // Every step above succeeded -- commit. `replace_image` swaps in
        // `image` without touching `cpu.mem`'s arena -- see this method's
        // own doc comment ("Only the image is replaced -- the arena is
        // not.").
        cpu.mem.replace_image(image);

        Ok(mbbs_machine::m32::Module::new(entry, thunks))
    }

    /// Direct delegation -- `mbbs_machine::m32::Module::import` (this task).
    fn import(module: &Self::Module, index: u16) -> Option<&mbbs_machine::module::ImportSite> {
        module.import(index)
    }

    /// `None`, always. [`Wg32::Module`] now carries the bound import table,
    /// but not a section table or symbol map to resolve a return address
    /// against -- "section and offset, once `Wg32::Module` carries enough
    /// to answer it" (this trait method's own doc comment) is still future
    /// work, not something this task's `Module` composes. Best-effort
    /// diagnostics staying `None` costs nothing today: nothing through this
    /// task calls `Host::run` against a `Wg32` module (that is Task 15's
    /// synthetic round-trip), so nothing yet reads this answer.
    fn caller(_cpu: &Self::Cpu, _module: &Self::Module) -> Option<String> {
        None
    }

    /// Always `Some` -- `mbbs_machine::m32::Module::entry` is a bare `u32`
    /// set unconditionally by [`Wg32::load`](Abi::load), never an
    /// `Option`. See [`Abi::init_entry`]'s own doc comment for why that is
    /// not the same claim as "every PE has a meaningful entry point".
    fn init_entry(module: &Self::Module) -> Option<Self::Ptr> {
        Some(mbbs_machine::m32::Flat32Ptr(module.entry()))
    }
}

/// [`mbbs_machine::m32::Ret`] has no `Far` counterpart -- this ABI is flat, so
/// a pointer comes back in `EAX` exactly as an `int` does. `Ret::Long` maps
/// the same way as `Ret::Int`: both are [`Abi::LONG_WIDTH`]/[`Abi::INT_WIDTH`]
/// bytes wide (4, agreeing under `Wg32`), so there is no wider `U64` case to
/// reach here -- see `Ret`'s own doc comment ("`Void` and the 32-bit `Long`
/// do not vary").
impl From<Ret<Wg32>> for mbbs_machine::m32::Ret {
    fn from(ret: Ret<Wg32>) -> Self {
        match ret {
            Ret::Void => mbbs_machine::m32::Ret::Void,
            Ret::Int(v) => mbbs_machine::m32::Ret::U32(v),
            Ret::Long(v) => mbbs_machine::m32::Ret::U32(v),
            Ret::Ptr(p) => mbbs_machine::m32::Ret::U32(p.0),
        }
    }
}

/// [`mbbs_machine::m32::Exit`] converted to [`Exit<Wg32>`] -- the same
/// `Fault`/`Timeout` collapse `abi/wg16.rs`'s `convert_exit` documents.
/// `Wg32` gained a real `Timeout` variant with Task 16's 32-bit watchdog;
/// both it and `Fault` fold into [`Exit::Stopped`] here, exactly as
/// `abi/wg16.rs`'s `Fault { .. } | Timeout { .. }` arm does.
/// The 32-bit half of the check `abi/wg16.rs`'s namesake documents at
/// length: [`Exit::Stopped`] is only honest if [`Abi::poisoned`] can still
/// say why, and that rests on the machine poisoning itself before it hands
/// back a terminal `Exit`. Here that is `m32::Machine::terminate`'s
/// `get_or_insert` on both the fault and timeout paths. Convention, not
/// construction -- so it is checked, not asserted in prose.
fn debug_assert_attributable(exit: &Exit<Wg32>, machine: &mbbs_machine::m32::Machine) {
    debug_assert!(
        !matches!(exit, Exit::Stopped) || machine.poisoned().is_some(),
        "Exit::Stopped with no poison stored: the machine has stopped and \
         cannot say why, so Abi::poisoned cannot recover what the collapse \
         of Fault into Stopped discarded"
    );
}

fn convert_exit(exit: mbbs_machine::m32::Exit) -> Exit<Wg32> {
    match exit {
        mbbs_machine::m32::Exit::Call { index } => Exit::Call { index },
        mbbs_machine::m32::Exit::Returned { eax, edx } => Exit::Returned { lo: eax, hi: edx },
        mbbs_machine::m32::Exit::Fault { .. } | mbbs_machine::m32::Exit::Timeout { .. } => {
            Exit::Stopped
        }
    }
}

/// `mbbs_machine::m32::Memory`'s host-allocation half, named through the trait
/// `crates/mbbs`'s generic `Heap`/`Arena`/`Globals` already grow through.
/// Thin delegation on purpose -- `mbbs_machine::m32::Memory::alloc` (not named
/// `alloc_region` itself, so this impl body calls it rather than
/// recursing) already is the bump allocator; this is only the seam that
/// lets `A::Mem::alloc_region` reach it generically.
impl ModuleMem for mbbs_machine::m32::Memory {
    type Ptr = mbbs_machine::m32::Flat32Ptr;

    fn alloc_region(&mut self, bytes: usize) -> std::io::Result<Self::Ptr> {
        self.alloc(bytes)
    }
}

// No `#[cfg(test)] mod tests` here, unlike every sibling `Abi` file --
// deliberately. Any test that builds a real `Wg32Cpu` must build a real
// `mbbs_machine::m32::Machine`, and `mbbs_machine::m32::Machine::new` unconditionally calls
// `mbbs_machine::m32::fault::arm`, which registers this ABI's fault claim with
// `crates/mbbs-machine/src/fault.rs`'s shared arbiter. Registering no longer steals another
// ABI's recovery the way installing a standalone handler used to -- see
// `crates/mbbs-machine/src/fault.rs`'s module doc comment -- but `cargo test -p mbbs --lib`
// still runs every unit test, 16-bit and 32-bit, as threads of ONE process,
// sharing the one per-thread alternate signal stack and the one process-wide
// claim registry. A `Wg32Cpu`-building test has no reason to entangle that
// shared, process-global state with this file's otherwise-pure unit tests,
// so it stays out.
//
// This was not theoretical before the arbiter existed: an earlier version of
// this file built a real `Wg32Cpu` right here and `cargo test -p mbbs --lib`
// went from 1281/0 to 1282/3 --
// `tests::survey_mode_still_stops_on_a_fault_reached_after_a_continued_call`,
// `tests::cycle_names_the_channel_a_poll_sourced_stop_happened_on`, and
// `shims::fsd::tests::a_module_that_dies_inside_whndun_stops_the_host_cleanly`
// all failed, every one of them an `mbbs16` fault-recovery test running
// *after* this file's test had already clobbered the process's SIGSEGV
// handler with `mbbs32`'s standalone one. That specific failure mode is
// exactly what `crates/mbbs-machine/src/fault.rs` now fixes -- see
// `crates/mbbs/tests/fault_16_after_32.rs`, `fault_16_alone.rs` and
// `fault_32_after_16.rs` -- but the isolation below is worth keeping on its
// own merits regardless.
//
// The tests that need a real `Wg32Cpu` -- `Call<Wg32>`'s offset-divergence
// proof among them -- live in `crates/mbbs/tests/wg32_abi.rs` instead: a
// separate `cargo test` integration binary is a separate OS process, so
// nothing built there needs to depend on the arbiter's correctness to stay
// isolated from this file's own tests, no matter how `cargo test` schedules
// the two binaries.
