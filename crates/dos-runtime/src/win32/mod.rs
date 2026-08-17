//! A Win32 process, around the PE32 image loader that already exists.
//!
//! [`mbbs_machine::m32`] parses, maps, relocates and binds a PE32 image, and
//! its own documentation is emphatic that it "is not a Windows loader": it has
//! no process, no command line, no console, and it enters a module at a
//! Galacticomm `register_module` export rather than at the image's entry
//! point. All of that is what this module adds, and it adds it here rather
//! than in `m32` so that the machine stays a machine.
//!
//! Scope is the vendor's offline board utilities, a bounded family -- see
//! `docs/plans/2026-08-17-offline-utilities-phases-design.md`. A symbol is
//! implemented because one of them calls it.

pub mod advapi32;
pub mod console;
pub mod crt;
pub mod kernel32;
pub mod load;
pub mod process;
pub mod survey;
