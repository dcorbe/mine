//! The LE/LX "linear executable" loader: parse a DOS/4GW-era protected-mode
//! image and map it flat below 4 GiB, ready to run under `crate::m32::dpmi`.
//!
//! `parse` reads the header, object table, and page map; `load` maps the
//! objects into a `crate::m32::Mapping` and applies fixups. Neither runs the
//! image -- that is the DPMI machine's job.

pub mod load;
pub mod parse;

pub use load::{LeLoaded, load};
pub use parse::{Flavour, LeError, LeImage, LeObject, PageEntry, parse};
