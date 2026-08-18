//! A text screen: the codepage, the cell grid, and the painter that turns one
//! into ANSI.
//!
//! Extracted from `dos-runtime` and `mud-core`, which each owned a private
//! copy of part of it. The duplication was documented rather than fixed --
//! `dos-runtime`'s table said "this is a second copy of a table the workspace
//! already has" -- because neither crate was the right home: `mud-core` is the
//! MUD game crate and `dos-runtime` is a DOS runtime, and a Win32 console
//! needs the same grid as both.

pub mod cell;
pub mod cp437;
pub mod paint;
pub mod widget;
