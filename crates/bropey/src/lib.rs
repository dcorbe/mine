//! A byte-first persistent rope.
//!
//! Bropey stores arbitrary bytes. It has no notion of characters, encodings,
//! or lines — a caller that needs those applies them on top. Cloning a `Rope`
//! is O(1) and shares structure; editing a shared rope copies O(log n) nodes
//! and leaves every other handle untouched.

mod tune;

// Unused until a later task builds `Rope` on top and reaches it from the
// crate root. Scoped to the module so unrelated dead code still warns.
#[allow(dead_code)]
mod tree;
