//! A loaded module's own export table, rebased onto the linear addresses
//! its [`Image`](super::Image) actually landed at.

use std::collections::HashMap;

use super::pe::{ExportAddress, PeImage};

/// [`PeImage::exports`]/[`PeImage::export_table`] with every RVA turned into
/// the linear address it has once the image is mapped -- the same rebasing
/// `Wg32::load` (`crates/mbbs/src/abi/wg32.rs`) already does for
/// [`Module::entry`](super::Module::entry)/[`Module::init`](super::Module::init),
/// done once for the whole table so a later lookup needs no `Image` in hand.
/// Built at load time, read by `Abi::export_address`.
///
/// Forwarders are absent from both views: a forwarder's "address" is a
/// `"DLL.Symbol"` string, not code (see the `m32` module doc, "Two things
/// this is not"), so there is nothing to rebase and `None` is the honest
/// answer -- matching [`PeImage::export_rva`] and
/// [`PeImage::export_rva_by_ordinal`].
#[derive(Debug, Default)]
pub struct Exports {
    /// Named, non-forwarded exports. Exact-case, like [`PeImage::export_rva`].
    by_name: HashMap<String, u32>,
    /// Every `AddressOfFunctions` slot, 0-based; `None` for a forwarder.
    /// Nameless slots (`NumberOfFunctions > NumberOfNames`) live here and
    /// only here.
    by_index: Vec<Option<u32>>,
    /// The export directory's `Base`: what a public ordinal is offset by
    /// before it indexes `by_index`. `None` when the image has no export
    /// directory, so every ordinal lookup refuses.
    base: Option<u32>,
}

impl Exports {
    /// Rebase every export of `pe` onto an image mapped at `image_base`.
    #[must_use]
    pub fn rebased(pe: &PeImage, image_base: u32) -> Self {
        let rebase = |address: &ExportAddress| match address {
            ExportAddress::Rva(rva) => Some(image_base.wrapping_add(*rva)),
            ExportAddress::Forwarded(_) => None,
        };
        Self {
            by_name: pe
                .exports
                .iter()
                .filter_map(|e| rebase(&e.address).map(|addr| (e.name.clone(), addr)))
                .collect(),
            by_index: pe.export_table.iter().map(rebase).collect(),
            base: pe.export_base,
        }
    }

    /// The linear address of the named export; `None` for a name the module
    /// does not export, or exports as a forwarder.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// The linear address of the export at *public* ordinal `ordinal` --
    /// the same `ordinal - Base` indexing as [`PeImage::export_rva_by_ordinal`],
    /// so a nameless slot is reachable here and nowhere else. `None` below
    /// `Base`, past the table, or for a forwarder.
    #[must_use]
    pub fn by_ordinal(&self, ordinal: u16) -> Option<u32> {
        let index = u32::from(ordinal).checked_sub(self.base?)?;
        self.by_index.get(index as usize).copied().flatten()
    }
}
