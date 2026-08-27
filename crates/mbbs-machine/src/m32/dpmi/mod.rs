//! Native execution of DOS/4GW-era protected-mode programs: runexe as the
//! extender, with no KVM.
//!
//! A submodule of [`crate::m32`] on purpose. The DPMI machine reuses m32's
//! crate-internal `Mapping`, entry asm (`asm::{mbbs32_enter_raw, Ctx,
//! USER32_CS}`) and the process-wide fault arbiter (`crate::fault`); living
//! *inside* m32 is what lets it reach those without widening m32's public
//! surface. See `docs/superpowers/specs/2026-08-27-runexe-le-dpmi-native-design.md`.
//!
//! The guest↔host boundary is the fault, not a thunk table: in ring 3 the
//! guest's `int n`/`in`/`out`/`cli`/`sti` all raise #GP, and this ABI's
//! recovery arm decodes the faulting bytes and turns each into a structured,
//! resumable exit (or an in-place resume for `cli`/`sti`). Asynchronous
//! timer/keyboard IRQs are injected by rewriting the guest's signal context to
//! enter its own registered ISR.

pub mod decode;
pub mod fault;
pub mod machine;
pub mod virq;

pub use machine::{Exit, Machine};

#[cfg(test)]
mod spike;
