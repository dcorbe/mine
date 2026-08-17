//! A DOS runtime, begun as the proof of concept for
//! `docs/2026-08-16-dos-trap-edges.md` and kept because it serves a real door:
//! LORD runs under it as a Synchronet external program.
//!
//! The claim it was written to demonstrate still holds and is still the
//! organising idea -- that the DOS services are independent of how the
//! `int 21h` reached them, and that saying so with a trait costs nothing and
//! buys unit-testability.
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

pub mod bios;
pub use ::dos::kernel as dos;
pub mod driver;
pub use ::dos::files;
pub mod fossil;
pub use ::dos::guest;
pub mod kvm;
pub mod mz;
pub mod screen;
pub mod terminal;
pub mod uart;
pub use ::dos::testguest;
