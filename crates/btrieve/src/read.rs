//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use crate::format::generation::{identify, NotBtrieve};
use crate::model::File;

/// Read a whole Btrieve file into a model.
///
/// # Errors
///
/// If [`identify`] refuses the control record, or the bytes are not yet fully
/// described by this crate.
pub fn file(bytes: &[u8]) -> Result<File, NotBtrieve> {
    let id = identify(bytes)?;
    Err(NotBtrieve {
        why: format!(
            "identified as {:?} with {}-byte pages, but this crate does not \
             yet describe every byte of a Btrieve file, and a model with \
             undescribed ranges is not a model this crate will produce",
            id.generation, id.page_size
        ),
    })
}
