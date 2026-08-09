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
//! It is not a host. Imports bind to thunks that report which symbol was wanted;
//! nothing services them.
//!
//! # Testing
//!
//! **Run the tests in both profiles.** `cargo test -p mbbs32` and
//! `cargo test -p mbbs32 --release` are not the same check -- see the sibling
//! crate's note for the measurement behind that.

mod pe;

pub use pe::PeError;
