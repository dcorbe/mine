//! Is this value one the option can hold?
//!
//! The bounds come from the `.MSG` itself -- `N 0 32767` -- so this is the
//! module's own answer, not ours. Validating before writing is the difference
//! between a sysop seeing "0 to 32767" and a module quietly misbehaving.

use mbbs::msg::value as last_token;

use crate::spec::OptionType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    OutOfRange { floor: i64, ceiling: i64, got: i64 },
    TooLong { maxlen: usize, got: usize },
    NotANumber,
    NotABool,
    NotAChoice { choices: Vec<Vec<u8>> },
    NotOneCharacter,
}

pub fn check(kind: &OptionType, value: &[u8]) -> Result<(), Invalid> {
    let token = last_token(value);
    let ranged = |floor: i64, ceiling: i64, radix: u32| -> Result<(), Invalid> {
        let text = std::str::from_utf8(token).map_err(|_| Invalid::NotANumber)?;
        let got = i64::from_str_radix(text, radix).map_err(|_| Invalid::NotANumber)?;
        if got < floor || got > ceiling {
            return Err(Invalid::OutOfRange { floor, ceiling, got });
        }
        Ok(())
    };

    match kind {
        OptionType::Number { floor, ceiling } | OptionType::Long { floor, ceiling } => {
            ranged(*floor, *ceiling, 10)
        }
        OptionType::Hex { floor, ceiling } => ranged(*floor, *ceiling, 16),
        OptionType::Str { maxlen, .. } => {
            if value.len() > *maxlen {
                Err(Invalid::TooLong { maxlen: *maxlen, got: value.len() })
            } else {
                Ok(())
            }
        }
        OptionType::Bool => {
            if token.eq_ignore_ascii_case(b"YES") || token.eq_ignore_ascii_case(b"NO") {
                Ok(())
            } else {
                Err(Invalid::NotABool)
            }
        }
        OptionType::Enum { choices } => {
            if choices.iter().any(|c| c.eq_ignore_ascii_case(token)) {
                Ok(())
            } else {
                Err(Invalid::NotAChoice { choices: choices.clone() })
            }
        }
        OptionType::Char => {
            if token.len() == 1 {
                Ok(())
            } else {
                Err(Invalid::NotOneCharacter)
            }
        }
        OptionType::Text => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num() -> OptionType {
        OptionType::Number { floor: 0, ceiling: 32767 }
    }

    #[test]
    fn a_number_inside_its_bounds_passes_and_outside_fails() {
        assert!(check(&num(), b"60").is_ok());
        assert!(check(&num(), b"0").is_ok());
        assert!(check(&num(), b"32767").is_ok());
        assert!(matches!(check(&num(), b"32768"), Err(Invalid::OutOfRange { .. })));
        assert!(matches!(check(&num(), b"-1"), Err(Invalid::OutOfRange { .. })));
    }

    #[test]
    fn a_number_option_takes_the_last_token_as_its_value() {
        // `GAMCRD {Credits per minute consumed while in the game 60}` -- the
        // prompt is part of the message and the value is the last token.
        assert!(check(&num(), b"Credits per minute 60").is_ok());
        assert!(matches!(
            check(&num(), b"Credits per minute 99999"),
            Err(Invalid::OutOfRange { .. })
        ));
    }

    #[test]
    fn a_non_numeric_number_is_refused() {
        assert!(matches!(check(&num(), b"lots"), Err(Invalid::NotANumber)));
    }

    #[test]
    fn a_string_longer_than_its_maxlen_is_refused() {
        let s = OptionType::Str { maxlen: 5, prompt: Vec::new() };
        assert!(check(&s, b"abcde").is_ok());
        assert!(matches!(check(&s, b"abcdef"), Err(Invalid::TooLong { .. })));
    }

    #[test]
    fn a_bool_takes_yes_or_no_and_nothing_else() {
        assert!(check(&OptionType::Bool, b"Profanity checking? YES").is_ok());
        assert!(check(&OptionType::Bool, b"NO").is_ok());
        assert!(matches!(check(&OptionType::Bool, b"MAYBE"), Err(Invalid::NotABool)));
    }

    #[test]
    fn an_enum_takes_only_a_listed_choice() {
        let e = OptionType::Enum { choices: vec![b"NONE".to_vec(), b"ALL".to_vec()] };
        assert!(check(&e, b"ALL").is_ok());
        assert!(matches!(check(&e, b"SOME"), Err(Invalid::NotAChoice { .. })));
    }

    #[test]
    fn a_char_option_takes_exactly_one_character_including_a_space() {
        // `TLCCHR { =}` and `ANSCHR { \}` are real: a leading space then one
        // character. The value is the last token, so a lone space is one too.
        assert!(check(&OptionType::Char, b"=").is_ok());
        assert!(matches!(check(&OptionType::Char, b"ab"), Err(Invalid::NotOneCharacter)));
    }

    #[test]
    fn text_is_never_range_checked() {
        assert!(check(&OptionType::Text, b"anything at all, %s included").is_ok());
    }
}
