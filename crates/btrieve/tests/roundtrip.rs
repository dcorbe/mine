//! The mismatch diagnostic the round-trip harness renders.
//!
//! When emitted bytes differ from the original file, the message must name
//! the first differing byte and the field that owns it. A diagnostic nobody
//! has seen produce output is a diagnostic that does not work, so these tests
//! build a deliberate mismatch and read the message back.

use btrieve::canvas::Emitted;

/// Describe a mismatch between emitted bytes and the original file: the
/// first differing byte, and which field owns it. Exercised directly, on a
/// deliberate mismatch -- see `a_mismatch_names_the_field_that_owns_the_differing_byte` below.
fn describe_mismatch(emitted: &Emitted, original: &[u8]) -> String {
    let produced = emitted.bytes();
    let at = produced
        .iter()
        .zip(original.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| produced.len().min(original.len()));
    let owner = match emitted.owner_of(at) {
        Some(owner) => format!("owned by {}", owner.label()),
        None => "but no field claims that byte".to_string(),
    };
    format!(
        "first difference at byte {at:#x}, {owner} \
         (produced {} bytes, original {})",
        produced.len(),
        original.len()
    )
}

/// A diagnostic nobody has seen produce output is a diagnostic that does not
/// work -- the round trip cannot currently reach the mismatched class (every
/// corpus file is refused before it gets that far), so this test builds one
/// directly: a canvas emitted with known owners, then compared against bytes
/// altered at a byte one of those owners wrote. The message must name that
/// owner, not just announce that two buffers differ.
#[test]
fn a_mismatch_names_the_field_that_owns_the_differing_byte() {
    use btrieve::canvas::{Canvas, Owner};

    let mut canvas = Canvas::new(4);
    canvas
        .put(0, &[0xaa, 0xbb], Owner { structure: "fcr", field: "page_size", index: None })
        .expect("in range");
    canvas
        .put(
            2,
            &[0xcc, 0xdd],
            Owner { structure: "fcr", field: "key_descriptor", index: Some(3) },
        )
        .expect("in range");
    let emitted = canvas.finish().expect("every byte written");

    // Alter byte 2, the first byte "key_descriptor[3]" wrote, so it
    // disagrees with what the canvas actually produced.
    let mut original = emitted.bytes().to_vec();
    original[2] = 0xff;

    let message = describe_mismatch(&emitted, &original);
    assert!(
        message.contains("fcr.key_descriptor[3]"),
        "message names the owning field and its repetition: {message}"
    );
    assert!(message.contains("0x2"), "message names the byte offset: {message}");
}

/// The other branch of the same rendering: a byte outside every recorded
/// placement must say so explicitly, not print nothing and not panic.
#[test]
fn a_mismatch_past_every_placement_says_no_field_claims_it() {
    use btrieve::canvas::{Canvas, Owner};

    let mut canvas = Canvas::new(2);
    canvas
        .put(0, &[0x01, 0x02], Owner { structure: "fcr", field: "lead", index: None })
        .expect("in range");
    let emitted = canvas.finish().expect("every byte written");

    // A longer "original" that agrees with every byte the canvas actually
    // wrote finds no differing byte within the shared range, so
    // `describe_mismatch` falls back to the first index past the emitted
    // bytes -- a position no placement covers.
    let original: Vec<u8> = vec![0x01, 0x02, 0x03];

    let message = describe_mismatch(&emitted, &original);
    assert!(
        message.contains("but no field claims that byte"),
        "an unowned byte is named as such, in a sentence, not silently \
         omitted or stapled onto a fragment: {message}"
    );
}
