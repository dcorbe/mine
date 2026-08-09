//! The transport: a tokio edge in front of one synchronous 16-bit host.
//!
//! Async stops at the socket. One dedicated thread owns the `Machine` and the
//! `Host` for the process's whole life, and that is forced rather than
//! preferred -- `mbbs16::Machine` is `!Send` because its segments are `Rc`s
//! over `mmap`s, its watchdog timer is bound to the `gettid()` of the thread
//! that created it, and the fault handler's alternate stack is a
//! `thread_local`. The thread constructs its own `Machine`; nothing hands it
//! one.
//!
//! See `docs/plans/2026-08-08-tokio-transport-design.md`.

pub mod host;
pub mod iac;
pub mod msg;
pub mod pool;
