//! Options, with the part of them `msg.rs` throws away.
//!
//! `crates/mbbs/src/msg.rs` reads a `.MSG` as a numbered list of message text
//! and deliberately drops the type letter and its arguments -- "keeping the
//! spec would mean keeping a second, unused answer to the same question". This
//! is the consumer that makes it used. It is additive: `MsgFile` is untouched
//! and stays the authority on numbering.

/// What kind of value an option holds, and the constraints on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionType {
    Number { floor: i64, ceiling: i64 },
    Long { floor: i64, ceiling: i64 },
    Hex { floor: i64, ceiling: i64 },
    Str { maxlen: usize, prompt: Vec<u8> },
    Text,
    Bool,
    Enum { choices: Vec<Vec<u8>> },
    Char,
}

/// Parse the `[type] [args]` that follow an option's closing `}`.
///
/// `None` means "this message is not an option" -- which is the common case:
/// most messages in a `.MSG` are plain text. They are still numbered, so
/// returning `None` must never remove anything from the numbering.
#[must_use]
pub fn parse_tail(tail: &[u8]) -> Option<OptionType> {
    let text = tail.strip_prefix(b" ").unwrap_or(tail);
    let mut parts = text.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let letter = parts.next()?;
    if letter.len() != 1 {
        return None;
    }
    let rest: Vec<&[u8]> = parts.collect();

    let bounds = |radix: u32| -> Option<(i64, i64)> {
        let floor = i64::from_str_radix(std::str::from_utf8(rest.first()?).ok()?, radix).ok()?;
        let ceiling = i64::from_str_radix(std::str::from_utf8(rest.get(1)?).ok()?, radix).ok()?;
        Some((floor, ceiling))
    };

    match letter[0] {
        b'N' => bounds(10).map(|(floor, ceiling)| OptionType::Number { floor, ceiling }),
        b'L' => bounds(10).map(|(floor, ceiling)| OptionType::Long { floor, ceiling }),
        b'H' => bounds(16).map(|(floor, ceiling)| OptionType::Hex { floor, ceiling }),
        b'S' => {
            let maxlen = std::str::from_utf8(rest.first()?).ok()?.parse().ok()?;
            let prompt = rest[1..].join(&b' ');
            Some(OptionType::Str { maxlen, prompt })
        }
        b'E' => {
            let list = rest.first()?;
            Some(OptionType::Enum {
                choices: list.split(|b| *b == b',').map(<[u8]>::to_vec).collect(),
            })
        }
        b'T' => Some(OptionType::Text),
        b'B' => Some(OptionType::Bool),
        b'C' => Some(OptionType::Char),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_carries_its_floor_and_ceiling() {
        assert_eq!(
            parse_tail(b"N 0 32767"),
            Some(OptionType::Number { floor: 0, ceiling: 32767 })
        );
    }

    #[test]
    fn a_string_carries_its_maxlen_and_prompt() {
        assert_eq!(
            parse_tail(b"S 30 Enter your activation code"),
            Some(OptionType::Str {
                maxlen: 30,
                prompt: b"Enter your activation code".to_vec(),
            })
        );
    }

    #[test]
    fn the_argless_types_parse_bare() {
        assert_eq!(parse_tail(b"B"), Some(OptionType::Bool));
        assert_eq!(parse_tail(b"C"), Some(OptionType::Char));
        assert_eq!(parse_tail(b"T Log-on Message to users"), Some(OptionType::Text));
    }

    #[test]
    fn an_enum_carries_its_choices() {
        assert_eq!(
            parse_tail(b"E NONE,SOME,ALL"),
            Some(OptionType::Enum {
                choices: vec![b"NONE".to_vec(), b"SOME".to_vec(), b"ALL".to_vec()],
            })
        );
    }

    #[test]
    fn long_and_hex_carry_bounds_like_a_number() {
        assert_eq!(
            parse_tail(b"L 0 2000000000"),
            Some(OptionType::Long { floor: 0, ceiling: 2_000_000_000 })
        );
        assert_eq!(
            parse_tail(b"H 0 FFFF"),
            Some(OptionType::Hex { floor: 0, ceiling: 0xffff })
        );
    }

    #[test]
    fn a_message_that_is_not_an_option_has_no_type() {
        // Most messages in a .MSG are plain text with no type letter. They are
        // still numbered, and must not be mistaken for options.
        assert_eq!(parse_tail(b""), None);
        assert_eq!(parse_tail(b"   "), None);
        assert_eq!(parse_tail(b"just some prose"), None);
    }

    #[test]
    fn a_bounded_type_without_bounds_is_not_an_option() {
        // Refuse rather than default. A silently-zeroed ceiling would let the
        // editor accept a value the module rejects.
        assert_eq!(parse_tail(b"N"), None);
        assert_eq!(parse_tail(b"N 0"), None);
    }
}
