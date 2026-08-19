//! The machines a module can be compiled for, and the process-global
//! state they must agree on.
//!
//! One crate, not five: `fault` and `ldt` arbitrate resources the process
//! has exactly one of (signal dispositions, the LDT), so they must be
//! visible to every machine -- and with one machine crate they can be
//! private modules instead of public leaf crates. The rule that keeps it
//! this way: a crate exists only when the dependency graph forces it.
//! See docs/plans/2026-08-12-abi-border-design.md §1.

pub mod m16;
pub mod m32;
pub mod module;
pub mod ptr;
pub mod library;

pub(crate) mod fault;
pub(crate) mod ldt;
