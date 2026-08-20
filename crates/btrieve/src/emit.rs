//! Model to bytes.
//!
//! # The signature is the guarantee
//!
//! [`file`] takes a [`File`] and nothing else. It cannot see the bytes
//! [`crate::read::file`] was given, so a byte-identical round trip cannot be
//! achieved by copying the input -- the only way to reproduce a file is to
//! have described it. Any function added here that accepts the source bytes
//! defeats the crate's entire correctness argument.

use crate::model::File;

/// Produce the bytes of the file this model describes.
#[must_use]
pub fn file(model: &File) -> Vec<u8> {
    // Deliberately not `vec![0; len]`: emitting zeroes would be a plausible
    // wrong answer that could accidentally match a sparse file. An empty
    // answer never accidentally matches anything.
    let _ = model;
    Vec::new()
}
