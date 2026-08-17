//! The DOS kernel, and the seam that makes it independent of how a program's
//! `int 21h` reached it.
//!
//! Two consumers, neither of which may depend on the other: a KVM real-mode
//! runtime that serves DOS doors, and the MBBS host, whose 16-bit modules trap
//! into DOS from protected mode. See
//! `docs/plans/2026-08-16-dos-border-design.md`.

pub mod guest;
pub mod files;
pub mod kernel;
pub mod service;
pub mod testguest;
