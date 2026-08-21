//! Model to bytes.
//!
//! # The signature is the guarantee
//!
//! [`file`] takes a [`File`] and nothing else. It cannot see the bytes
//! [`crate::read::file`] was given, so a byte-identical round trip cannot be
//! achieved by copying the input -- the only way to reproduce a file is to
//! have described it. Any function added here that accepts the source bytes
//! defeats the crate's entire correctness argument.
//!
//! Bytes are produced through a [`Canvas`], never a `vec![0; len]` written
//! into directly: a byte the model does not describe is a reported fault,
//! not a silent zero. Today [`crate::model::File`] describes nothing beyond
//! the length, so [`file`] always faults -- that is honest, matching
//! [`crate::read::file`] refusing every input, and is why the round-trip pin
//! stays at zero.

use crate::canvas::{Canvas, Emitted, Fault};
use crate::model::File;

/// Produce the bytes of the file this model describes.
///
/// # Errors
///
/// If the model does not yet describe every byte of the file -- today, that
/// is every file, since [`crate::model::File`] carries nothing beyond
/// generation, page size and length.
pub fn file(model: &File) -> Result<Emitted, Fault> {
    let canvas = Canvas::new(model.len as usize);
    canvas.finish()
}
