//! Proof of concept for `docs/2026-08-16-dos-trap-edges.md`.
//!
//! **This is a proposal, not a merge candidate.** It exists to demonstrate one
//! claim before anyone writes a plan around it: that the DOS services are
//! independent of how the `int 21h` reached them, and that saying so with a
//! trait costs nothing and buys unit-testability.
//!
//! Three pieces:
//!
//! - [`guest`] -- the seam. No `ucontext`, no vCPU, no LDT.
//! - [`dos`] -- the services. One match on `AH`; knows nothing about either edge.
//! - [`kvm`] and [`testguest`] -- two implementors of the seam, one a real
//!   real-mode CPU and one a `Vec<u8>`.
//!
//! The third implementor is the argument that does not depend on KVM: it is
//! what makes every service in [`dos`] testable without a machine at all.
//! `m16`'s signal handler would be a fourth, and is deliberately absent here so
//! that this crate cannot collide with the work in flight on that branch.

pub mod dos;
pub mod guest;
pub mod kvm;
pub mod testguest;
