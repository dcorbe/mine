//! A pointer abstraction shared by every ABI a module can be compiled for.
//!
//! `crates/mbbs` used to name `mbbs16::FarPtr` directly in 382+ places. This
//! crate exists so that coupling can be to a trait instead, ahead of a second
//! implementation (`mbbs32`'s `Flat32Ptr`) needing the same call sites.
//! See `docs/plans/2026-08-09-modulept-abstraction-design.md`.

use std::fmt;

/// A pointer a module handed the host, in whatever shape that module's ABI
/// uses, plus how to resolve one against the memory it names.
///
/// `Copy + Eq + Hash` because a host keys allocations by the exact pointer
/// value a module holds (see `crates/mbbs/src/heap.rs`'s `blocks` map).
pub trait ModulePtr: Copy + Eq + std::hash::Hash + fmt::Debug + fmt::Display {
    /// What this pointer resolves against. Concretely `mbbs16::Machine` for
    /// `FarPtr` (which owns both execution and memory) and `mbbs32::Image`
    /// for `Flat32Ptr` (which owns only memory -- `mbbs32::Machine` does
    /// not own a loaded `Image`; see that crate's `Machine::call` doc
    /// comment).
    type Memory;

    /// This pointer's error type. An associated type, not a shared enum,
    /// because the two ABIs' failure modes do not overlap (no LDT for a flat
    /// address space).
    type Error: std::error::Error;

    /// Borrow `len` bytes of module memory through this pointer.
    fn resolve<'m>(&self, memory: &'m Self::Memory, len: usize) -> Result<&'m [u8], Self::Error>;

    /// Read a NUL-terminated string through this pointer, without the NUL.
    fn read_cstr<'m>(&self, memory: &'m Self::Memory) -> Result<&'m [u8], Self::Error>;

    /// Write into module memory through this pointer.
    fn write(&self, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error>;
}
