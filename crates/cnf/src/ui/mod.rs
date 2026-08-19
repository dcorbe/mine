//! Screens for the sysop editor: widgets that draw, and (from Task 14 on)
//! editors that take keystrokes.
//!
//! Everything here is exercised by rendering into a `Cells` and reading it
//! back with `line()`/`contains()`/`highlighted_rows()` -- no terminal
//! required.

pub mod help;
pub mod list;
