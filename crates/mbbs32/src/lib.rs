//! Running 32-bit Worldgroup modules on x86-64 Linux, natively.
//!
//! The 32-bit sibling of [`mbbs16`](../mbbs16/index.html). Same idea -- a module
//! is a coroutine that runs until it wants something from the host -- against a
//! different container (PE32 rather than NE) and a different ABI (flat 32-bit
//! cdecl rather than Borland's 16-bit huge model).
//!
//! The design, and every measurement the tests assert, is in
//! `docs/plans/2026-08-08-mbbs32-design.md`.
//!
//! # Two things this is not
//!
//! It is not a Windows loader. No TLS callbacks, no SEH, no resources, no
//! delay-imports -- the module measured here needs none of them, and a loader
//! that implements what its input does not contain is untested code pretending
//! to be a feature.
//!
//! Forwarded exports are the one thing here that is *detected but not
//! serviced*: a forwarder's "address" is a `"DLL.Symbol"` string rather than
//! code, so mistaking one for an RVA hands back a pointer into text. The
//! measured module forwards nothing, and following a forwarder into another DLL
//! is a Windows loader's job, not this one's.
//!
//! Exports with no name (`NumberOfFunctions > NumberOfNames`) are not
//! surfaced by [`PeImage::exports`] at all -- not hypothetical:
//! `WGSERVER.EXE` has 222 such ordinal-only exports out of 1615 functions,
//! and `GALGSBL.DLL` has 20 out of 109. Nothing through Task 17 parses those
//! files, so it is inert today, but `export_rva` returning `None` for one is
//! indistinguishable from the symbol not existing.
//!
//! It is not a host. Imports bind to thunks that report which symbol was wanted;
//! nothing services them.
//!
//! [`Image::load`] maps a [`PeImage`] and copies its sections into place, but
//! leaves every page `PROT_READ | PROT_WRITE | PROT_EXEC` -- section
//! characteristics are parsed (`Section::characteristics`) but not yet turned
//! into per-page protections. `CODE` being writable and `.reloc` being
//! present at runtime at all are both looser than the real module needs;
//! tightening that is later work, not a gap this crate is unaware of.
//!
//! # Testing
//!
//! **Run the tests in both profiles.** `cargo test -p mbbs32` and
//! `cargo test -p mbbs32 --release` are not the same check -- see the sibling
//! crate's note for the measurement behind that.

mod image;
mod map;
mod pe;

pub use image::{Image, Import32, ImportResolver, ThunkSite};
pub use map::Mapping;
pub use pe::{Export, ExportAddress, Import, PeError, PeImage, Relocation, Section, Symbol};
