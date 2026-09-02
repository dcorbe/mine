//! A text screen: the codepage, the cell grid, and the painter that turns one
//! into ANSI.
//!
//! Extracted from `dos-runtime`, which is a DOS runtime and not the right
//! home for a screen model a Win32 console needs just as much.

pub mod cell;
pub mod cp437;
pub mod paint;
pub mod widget;
