//! A DOS *runtime*, begun as the proof of concept for
//! `docs/2026-08-16-dos-trap-edges.md` and kept because it serves a real door:
//! LORD runs under it as a Synchronet external program.
//!
//! This crate used to hold the DOS kernel itself; the border refactor moved
//! that (the seam and the services) out into the `dos` crate, so what remains
//! here is the *machine*: a real-mode KVM guest ([`kvm`]), the BIOS, FOSSIL
//! over a UART ([`bios`], [`fossil`], [`uart`]), the text-mode [`screen`], a
//! [`terminal`] and scripted/interactive [`driver`] for feeding it input, and
//! the `.EXE`/`.COM` loader ([`mz`]). [`dos`], [`files`], [`guest`] and
//! [`testguest`] below are re-exports of the `dos` crate's `kernel`, `files`,
//! `guest` and `testguest` modules, not defined in this crate -- see that
//! crate's own `lib.rs` for what they are.
//!
//! The claim this crate was written to demonstrate still holds, and is now
//! *realised* rather than merely claimed: the DOS services in [`dos`] know
//! nothing about how their `int 21h` arrived. [`kvm`]'s `VmGuest` is one
//! implementor of the seam ([`guest::Guest`]); [`testguest`]'s `TestGuest` (a
//! `Vec<u8>` and a register file) is another, and this crate's own `Bios` and
//! `Fossil` services are unit-tested against it directly, no machine
//! required. [`win32`] is the one part of this crate that is not about DOS at
//! all: the vendor's later board utilities ship as PE32 console programs, and
//! it puts a process -- an entry point, a command line, a console -- around the
//! PE32 image loader in `mbbs-machine`, which deliberately provides none of
//! those. It lives here rather than beside that loader so the machine stays a
//! machine, and because `bin/runexe.rs` is the front door for both formats.
//!
//! `bin/runexe.rs` and `main.rs` both compose the services this
//! crate and `dos` provide behind `dos::service::Services`, which is what
//! turns "independent of the edge" from a design note into routing that
//! actually runs that way. `m16`'s signal handler would be a third
//! implementor of the seam, and is deliberately absent here so that this
//! crate cannot collide with the work in flight on that branch.

pub mod bios;
pub mod btrieve;
pub mod btrieve_open_path;
pub use ::dos::kernel as dos;
pub mod driver;
pub use ::dos::files;
pub mod fossil;
pub use ::dos::guest;
pub mod kvm;
pub mod mz;
pub mod pit;
pub mod screen;
pub mod terminal;
pub mod uart;
pub use ::dos::testguest;
pub mod win32;
