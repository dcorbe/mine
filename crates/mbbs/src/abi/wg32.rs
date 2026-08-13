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
//! (`crates/mbbs32/src/flatptr.rs`) answered `type Memory = mbbs_machine::m32::Image`
//! -- and `mbbs-ptr`'s own doc comment said as much: "concretely ...
//! `mbbs_machine::m32::Image` for `Flat32Ptr`". So `type Mem = Image` was the only
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
    pub fn new(machine: mbbs_machine::m32::Machine, mem: mbbs_machine::m32::Memory) -> Self {
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
        Ok(convert_exit(cpu.machine.call(entry.0, &dwords)?))
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
                Ok(convert_exit(cpu.machine.resume(ret32)?))
            }
        }
    }

    /// **Stub awaiting Task 6.** `mbbs_machine::m32::Machine` has no
    /// `arg_frame` yet -- Task 6's Step 1 adds it, mirroring
    /// `mbbs_machine::m16::Machine::arg_frame`. Nothing in this task calls
    /// this arm; no test exercises it.
    fn arg_frame(_cpu: &Self::Cpu) -> &[u8] {
        todo!(
            "Task 6: mbbs_machine::m32::Machine::arg_frame does not exist yet -- \
             see docs/plans/2026-08-12-abi-border-implementation.md"
        )
    }

    /// **Stub awaiting Task 6.** `mbbs_machine::m32::Machine` has no poison
    /// *setter* -- only the fault path sets its `poisoned` field today.
    /// Nothing in this task calls this arm; no test exercises it.
    fn poison(_cpu: &mut Self::Cpu, _why: Self::Poison) -> std::io::Result<()> {
        todo!(
            "Task 6: mbbs_machine::m32::Machine has no poison() setter yet -- \
             see docs/plans/2026-08-12-abi-border-implementation.md"
        )
    }

    fn poisoned(cpu: &Self::Cpu) -> Option<Self::Poison> {
        cpu.machine.poisoned().cloned()
    }

    fn unimplemented(module: String, symbol: String) -> Self::Poison {
        mbbs_machine::m32::Poison::Unimplemented { module, symbol }
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
/// `Fault` collapse `abi/wg16.rs`'s `convert_exit` documents; `Wg32` has no
/// `Timeout` variant of its own yet (Task 16 adds the 32-bit watchdog).
fn convert_exit(exit: mbbs_machine::m32::Exit) -> Exit<Wg32> {
    match exit {
        mbbs_machine::m32::Exit::Call { index } => Exit::Call { index },
        mbbs_machine::m32::Exit::Returned { eax, edx } => Exit::Returned { lo: eax, hi: edx },
        mbbs_machine::m32::Exit::Fault { .. } => Exit::Stopped,
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
