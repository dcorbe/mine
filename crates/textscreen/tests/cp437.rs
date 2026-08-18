//! CP437 is one table with two readings. These tests pin both, and pin that
//! they differ in exactly one place.

use textscreen::cp437::{decode_screen, decode_wire, encode};

#[test]
fn ascii_is_itself_in_both_readings() {
    for b in 0x20u8..0x7f {
        let s = String::from(b as char);
        assert_eq!(decode_wire(&[b]), s, "wire, byte {b:#04x}");
        assert_eq!(decode_screen(&[b]), s, "screen, byte {b:#04x}");
    }
}

#[test]
fn the_two_readings_differ_on_control_bytes() {
    // On the wire a C0 byte is a control code and must pass through: the ANSI
    // escapes, the line endings, the anti-bot backspaces all live here.
    assert_eq!(decode_wire(&[0x11]), "\u{11}");
    assert_eq!(decode_wire(&[0x1b]), "\u{1b}");
    // On a text screen the same byte is a glyph. 0x11 is a left-pointing
    // triangle, which is what a DOS menu draws its arrows with.
    assert_eq!(decode_screen(&[0x11]), "\u{25c4}");
    // 0x7f is the other place they differ: CP437 maps it to a house glyph,
    // but the wire reading is the identity below 0x80.
    assert_eq!(decode_wire(&[0x7f]), "\u{7f}");
    assert_eq!(decode_screen(&[0x7f]), "\u{2302}");
}

#[test]
fn above_0x7f_the_two_readings_agree_entry_for_entry() {
    // This is the test that makes one table correct. If the high halves ever
    // diverge, the crate is secretly two tables again.
    for b in 0x80u8..=0xff {
        assert_eq!(
            decode_wire(&[b]),
            decode_screen(&[b]),
            "byte {b:#04x} disagrees between the two readings"
        );
    }
}

#[test]
fn the_high_half_is_box_drawing_and_accents() {
    assert_eq!(decode_wire(&[0xc9, 0xcd, 0xbb]), "\u{2554}\u{2550}\u{2557}");
    assert_eq!(decode_wire(&[0x82]), "\u{e9}");
}

#[test]
fn every_byte_survives_a_wire_round_trip() {
    let all: Vec<u8> = (0u8..=0xff).collect();
    assert_eq!(encode(&decode_wire(&all)), all);
}

#[test]
fn unmappable_characters_become_question_marks() {
    assert_eq!(encode("\u{4e2d}"), b"?".to_vec());
}

#[test]
fn encode_can_synthesize_the_telnet_iac_byte() {
    // CP437 0xFF is a non-breaking space -- and 0xFF is also telnet IAC. A
    // caller on a telnet path must double it. Pinned here so the hazard lives
    // with the function instead of in one caller's comment.
    assert_eq!(encode("\u{a0}"), vec![0xff]);
}
