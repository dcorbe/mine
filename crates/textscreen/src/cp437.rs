//! CP437, in the two readings a host needs.
//!
//! **The readings are not interchangeable and must not be merged.** On the
//! wire, bytes below `0x20` are control codes -- the ANSI escapes, the line
//! endings, the anti-bot backspaces -- and have to pass through untouched. In
//! a text-screen cell the same bytes are glyphs: `0x11` is a left-pointing
//! triangle, and a menu draws its arrows with it. Decoding a screen with the
//! wire reading throws the arrows away; decoding the wire with the screen
//! reading turns every escape into a face card.
//!
//! Both readings share one table. Below `0x80` the wire reading is the
//! identity, which is also what Python's `cp437` codec does -- the oracle
//! harness relies on that agreement.

/// CP437 as Unicode, all 256 entries. Index is the byte.
pub const TABLE: [char; 256] = [
    '\u{0}', '\u{263a}', '\u{263b}', '\u{2665}', '\u{2666}', '\u{2663}', '\u{2660}', '\u{2022}',
    '\u{25d8}', '\u{25cb}', '\u{25d9}', '\u{2642}', '\u{2640}', '\u{266a}', '\u{266b}', '\u{263c}',
    '\u{25ba}', '\u{25c4}', '\u{2195}', '\u{203c}', '\u{b6}', '\u{a7}', '\u{25ac}', '\u{21a8}',
    '\u{2191}', '\u{2193}', '\u{2192}', '\u{2190}', '\u{221f}', '\u{2194}', '\u{25b2}', '\u{25bc}',
    ' ', '!', '"', '#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '{', '|', '}', '~', '\u{2302}',
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Decode bytes arriving from or leaving for a terminal.
///
/// Identity below `0x80`, so control bytes pass through as themselves.
#[must_use]
pub fn decode_wire(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if b < 0x80 { b as char } else { TABLE[b as usize] })
        .collect()
}

/// Decode the contents of text-screen cells.
///
/// Every byte is a glyph, C0 included.
#[must_use]
pub fn decode_screen(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| TABLE[b as usize]).collect()
}

/// Encode text as CP437.
///
/// Characters outside the codepage become `?` -- one byte, like every other
/// character, because a DOS client reads whatever we send as CP437 no matter
/// what we meant.
///
/// # This can produce `0xFF`
///
/// `U+00A0` maps to `0xFF`, which on a telnet connection is IAC. Callers on a
/// telnet path must double it. That is not this function's job -- it does not
/// know what its output travels over -- but it is this function's hazard.
#[must_use]
pub fn encode(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| {
            if (c as u32) < 0x80 {
                c as u8
            } else {
                TABLE[0x80..]
                    .iter()
                    .position(|&high| high == c)
                    .map_or(b'?', |i| (i + 0x80) as u8)
            }
        })
        .collect()
}
