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

use mbbs::msg::{MsgError, MsgFile};

/// A byte range in the original file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// One configurable option, and where in the file it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionSpec {
    /// The message number. What `stgopt(N)` indexes by.
    pub index: usize,
    pub name: Vec<u8>,
    pub kind: OptionType,
    pub hinge: Option<crate::hinge::Hinge>,
    /// The comment paragraph above the option, as the editor shows it.
    pub help: Vec<u8>,
    /// The bytes between `{` and its matching `}`.
    pub value: Span,
    /// Name through the end of the type tail.
    pub whole: Span,
}

/// Why a file could not be read as an option set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// The underlying message reader refused.
    Message(MsgError),
    /// An option's `{` has no matching `}`.
    ///
    /// `msg.rs` does not refuse this: its `State::Value` simply runs to
    /// end of file with no closing `}`, the loop ends still inside
    /// `Value`, and the pending message is never pushed -- it is silently
    /// dropped, undercounting by one, and `MsgFile::parse` still returns
    /// `Ok`. `scan` refuses instead. This is a deliberate divergence from
    /// the authority, not an oversight: this layer exists to write a
    /// `.MSG` back out, and opening a file whose message count we have
    /// already silently changed would shift every `stgopt(N)` after the
    /// dropped message on the next save. A refused open is recoverable --
    /// the sysop sees an error and nothing is written. A save built on an
    /// undercount is not.
    Unterminated { name: Vec<u8>, at: usize },
    /// `scan` and `MsgFile` disagree on how many messages the file holds. The
    /// two parsers have drifted, and every index below is suspect.
    CountMismatch { scanned: usize, counted: usize },
}

/// One `.MSG` file: its bytes, its messages, and its options.
#[derive(Debug)]
pub struct SpecFile {
    name: String,
    source: Vec<u8>,
    messages: MsgFile,
    options: Vec<OptionSpec>,
}

impl SpecFile {
    pub fn parse(name: &str, source: &[u8]) -> Result<Self, SpecError> {
        let messages = MsgFile::parse(name, source).map_err(SpecError::Message)?;
        let options = scan(source, &messages)?;
        Ok(Self {
            name: name.to_string(),
            source: source.to_vec(),
            messages,
            options,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    #[must_use]
    pub fn messages(&self) -> &MsgFile {
        &self.messages
    }

    #[must_use]
    pub fn options(&self) -> &[OptionSpec] {
        &self.options
    }
}

/// The option name that declares the file's language rather than a message.
/// Mirrors `msg.rs`'s own `LANGUAGE` constant, which it does not export.
const LANGUAGE: &[u8] = b"LANGUAGE";

/// Characters an option name is made of. Mirrors `msg.rs`'s `is_name`, which
/// it does not export: digits and *upper-case* letters only, so comment prose
/// (ordinary sentences) does not start a name by accident.
///
/// `pub(crate)` rather than private: `hinge::parse` reuses this exact
/// definition to decide whether a `(...)` it found is really a hinge or just
/// parenthesised prose that happens to contain a `#` or `=` -- see that
/// function's doc comment.
pub(crate) fn is_name(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase()
}

/// The byte offset of the next `\n` at or after `pos`, or `source.len()` if
/// there is none.
fn find_line_end(source: &[u8], pos: usize) -> usize {
    source[pos..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(source.len(), |i| pos + i)
}

/// Drop one trailing `\r`, if present. A `.MSG` is CRLF; this is applied
/// wherever a line's content is read for comparison rather than spliced back
/// into a raw span.
fn strip_cr(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// Where the next *confirmed* option name is, searching from `start`.
///
/// A name is confirmed only once a `{` is found immediately after it (past
/// any intervening non-name bytes). Until then it is a candidate: if another
/// name-shaped run turns up before the `{`, the old candidate is abandoned
/// and the new run replaces it -- mirroring `msg.rs`'s `PostName` exactly
/// ("what looked like a name was prose; whatever starts here is the real
/// candidate"). That is what stops a stray all-caps word in ordinary comment
/// prose (rare, but not impossible) from being mistaken for a name.
///
/// Returns `(name_start, name_end, brace_pos)`, or `None` if no more names
/// are confirmed before the end of the file.
fn find_next_name(source: &[u8], start: usize) -> Option<(usize, usize, usize)> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum St {
        /// No candidate yet.
        Pre,
        /// A candidate is actively growing.
        Name,
        /// Past the candidate's last name byte, watching for `{`.
        Post,
    }

    let mut state = St::Pre;
    let mut name_start = 0usize;
    let mut name_end = 0usize;
    let mut i = start;
    while i < source.len() {
        let byte = source[i];
        match state {
            St::Pre => {
                if is_name(byte) {
                    state = St::Name;
                    name_start = i;
                    name_end = i + 1;
                }
            }
            St::Name => {
                if is_name(byte) {
                    name_end = i + 1;
                } else if byte == b'{' {
                    return Some((name_start, name_end, i));
                } else {
                    state = St::Post;
                }
            }
            St::Post => {
                if byte == b'{' {
                    return Some((name_start, name_end, i));
                } else if is_name(byte) {
                    // What looked like a name was prose. Whatever starts
                    // here is the real candidate.
                    state = St::Name;
                    name_start = i;
                    name_end = i + 1;
                }
            }
        }
        i += 1;
    }
    None
}

/// The last comment paragraph in `source[start..end]` -- the region between
/// the end of the previous construct and the start of the next confirmed
/// name. Paragraphs are separated by blank lines; a single leading space per
/// line is stripped (the `MSGRDR` convention for indenting comment prose).
/// Everything else in the region (earlier paragraphs, abandoned name
/// candidates swept up as prose) is discarded -- only the paragraph
/// *immediately* above the option becomes its help.
fn last_paragraph(source: &[u8], start: usize, end: usize) -> Vec<u8> {
    let region = &source[start..end];
    let mut paragraphs: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos < region.len() {
        let line_end = region[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(region.len(), |i| pos + i);
        let content = strip_cr(&region[pos..line_end]);
        if content.is_empty() {
            if !current.is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
        } else {
            let text = content.strip_prefix(b" ").unwrap_or(content);
            if !current.is_empty() {
                current.push(b' ');
            }
            current.extend_from_slice(text);
        }
        pos = if line_end < region.len() { line_end + 1 } else { region.len() };
    }
    if !current.is_empty() {
        paragraphs.push(current);
    }
    paragraphs.pop().unwrap_or_default()
}

/// Scan `source` for options, left to right, cross-checked against the
/// messages `MsgFile` already counted.
///
/// Validated against every distinct `.MSG` in the tree (`tests/corpus.rs`,
/// 186 files, ~26300 `T` options, 0 refusals as of 2026-08-18). Two rules
/// that corpus run forced, both fixed in `hinge::parse` rather than here
/// (this function only calls it before `parse_tail`, per the ordering `scan`
/// has always used) -- see that function's doc comment for the full detail:
///
/// - A hinge is not always a trailing suffix of the tail. The corpus writes
///   `=`/`#` hinges *before* the type letter (`(NEEDAPPR=YES) S 18 prompt`);
///   only `*` (exclude-always) shows up after it too. Treating the hinge as
///   always-trailing silently deleted the type letter on every before-form
///   hinge, dropping the option from `options()` rather than mis-parsing it
///   -- no hand-written fixture caught this because every fixture happened
///   to put the hinge last.
/// - A `(...)` is only a hinge if the name before `=`/`#`/`*` is name-shaped
///   (`is_name`, the same alphabet as an option name). Without that check,
///   ordinary prose in a `T`/`S`/`E` tail's free-text portion that happens to
///   contain `=`/`#` -- e.g. `WGSEDTM.MSG`'s `FSENIM`, tail
///   `T FSE Import Rebuff (Bad #)` -- parsed as a hinge on the nonsense
///   target `"Bad "`.
fn scan(source: &[u8], messages: &MsgFile) -> Result<Vec<OptionSpec>, SpecError> {
    let mut options = Vec::new();
    let mut index = 0usize;
    let mut prev_end = 0usize;
    let mut pos = 0usize;

    while let Some((name_start, name_end, brace_pos)) = find_next_name(source, pos) {
        let name = source[name_start..name_end].to_vec();
        let help = last_paragraph(source, prev_end, name_start);

        // A `}` closes the value -- always -- unless the byte before it is
        // `~`. `~}` is a literal brace and the tilde is dropped; `~~` is a
        // literal tilde, so a `~` that was itself consumed by a preceding `~`
        // does not go on to escape what follows. Mirrors `msg.rs`'s
        // `State::Value` arm exactly; that reader is validated against
        // 10,569 messages and is the authority on this rule.
        let value_start = brace_pos + 1;
        let mut at = value_start;
        let mut previous = 0u8;
        let close = loop {
            let Some(&byte) = source.get(at) else {
                // Refuse rather than mirror msg.rs's silent drop-and-undercount
                // here -- see SpecError::Unterminated's doc for why. This is
                // the one place scan's grammar is deliberately stricter than
                // the authority it otherwise mirrors exactly.
                return Err(SpecError::Unterminated { name, at: value_start });
            };
            match byte {
                b'}' if previous == b'~' => previous = 0,
                b'}' => break at,
                b'~' if previous == b'~' => previous = 0,
                other => previous = other,
            }
            at += 1;
        };

        let tail_start = close + 1;
        let tail_line_end = find_line_end(source, tail_start);
        let tail = strip_cr(&source[tail_start..tail_line_end]);
        let (hinge, tail) = crate::hinge::parse(tail);
        let kind = parse_tail(&tail);

        if name != LANGUAGE {
            if let Some(kind) = kind {
                options.push(OptionSpec {
                    index,
                    name,
                    kind,
                    hinge,
                    help,
                    value: Span { start: value_start, end: close },
                    whole: Span { start: name_start, end: tail_line_end },
                });
            }
            index += 1;
        }

        prev_end = tail_line_end;
        pos = tail_line_end;
    }

    if index != messages.len() {
        return Err(SpecError::CountMismatch { scanned: index, counted: messages.len() });
    }

    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"LANGUAGE {English}\r\n\
LEVEL0 {}\r\n\
\r\n\
\x20This is the number of credits.\r\n\
\r\n\
GAMCRD {Credits per minute 60} N 0 32767\r\n\
\r\n\
ACTIVATE {DEMO} S 30 Enter your activation code\r\n";

    #[test]
    fn options_are_found_with_their_type_and_name() {
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        let names: Vec<&[u8]> = f.options().iter().map(|o| o.name.as_slice()).collect();
        assert_eq!(names, vec![&b"GAMCRD"[..], &b"ACTIVATE"[..]]);
        assert_eq!(
            f.options()[0].kind,
            OptionType::Number { floor: 0, ceiling: 32767 }
        );
    }

    #[test]
    fn a_before_position_hinge_wires_through_scan_with_the_type_intact() {
        // The bug tests/corpus.rs caught: a hinge written before the type
        // letter (the corpus's actual convention for =/# hinges -- see
        // hinge::parse's doc comment) used to have its splice truncate the
        // tail at the hinge, discarding the type letter and everything after
        // it, so the option vanished from `options()` entirely rather than
        // mis-parsing. The corpus test caught the aggregate effect (13
        // hinges found across 4 files against a measured 76-of-186); this
        // localises the same wiring to `scan`, in isolation, so a future
        // regression there does not need a 186-file run to be caught.
        let src = b"APPRUSER {Sysop} (NEEDAPPR=YES) S 18 Userid to receive new description email?\r\n";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options().len(), 1, "the option must not vanish");
        let opt = &f.options()[0];
        assert_eq!(
            opt.kind,
            OptionType::Str {
                maxlen: 18,
                prompt: b"Userid to receive new description email?".to_vec(),
            },
            "the type letter and its arguments must survive the hinge splice"
        );
        let hinge = opt.hinge.as_ref().expect("the before-position hinge must be attached");
        assert_eq!(hinge.on, b"NEEDAPPR");
        assert_eq!(hinge.op, crate::hinge::HingeOp::Eq);
        assert_eq!(hinge.values, vec![b"YES".to_vec()]);
    }

    #[test]
    fn the_value_span_covers_exactly_what_is_between_the_braces() {
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        let v = f.options()[0].value;
        assert_eq!(&SAMPLE[v.start..v.end], b"Credits per minute 60");
        let v = f.options()[1].value;
        assert_eq!(&SAMPLE[v.start..v.end], b"DEMO");
    }

    #[test]
    fn the_index_is_the_message_number_not_the_option_number() {
        // LEVEL0 is a numbered message and is not an option. GAMCRD is the
        // second message and the first option. Confusing the two shifts every
        // stgopt(N) in the module.
        //
        // SAMPLE's leading LANGUAGE line is deliberate, not incidental: this
        // assertion is what guards LANGUAGE's exclusion from the numbering.
        // If `scan` ever counted it, GAMCRD's index would come out as 2
        // instead of 1 -- and it does when tested by mutation (see
        // task-2-4-report.md).
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        assert_eq!(f.options()[0].index, 1, "GAMCRD is message 1");
        assert_eq!(f.options()[1].index, 2, "ACTIVATE is message 2");
    }

    #[test]
    fn the_comment_paragraph_above_an_option_becomes_its_help() {
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        assert_eq!(f.options()[0].help, b"This is the number of credits.".to_vec());
        assert!(f.options()[1].help.is_empty(), "ACTIVATE has no comment above it");
    }

    #[test]
    fn every_option_index_addresses_a_real_message() {
        // The cross-check that makes the rest safe. Note what it does NOT
        // assert: that the raw span equals the message. It cannot. `MsgFile`
        // stores DECODED text -- `~}` collapsed to `}`, `\r` dropped, and `\n`
        // rewritten to `\r` by `line_endings` for hard breaks -- while the span
        // is raw source, which is what the writer must splice. The two are
        // equal only for a single-line value with no escapes.
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        for opt in f.options() {
            let message = f.messages().get(opt.index).expect("option index addresses a real message");
            let raw = &f.source()[opt.value.start..opt.value.end];
            let simple = !raw.contains(&b'~') && !raw.contains(&b'\r') && !raw.contains(&b'\n');
            if simple {
                assert_eq!(message, raw, "option {:?} points at the wrong message", opt.name);
            }
        }
    }

    #[test]
    fn the_option_count_never_exceeds_the_message_count() {
        // Options are a subset of messages: every option is a message, but most
        // messages are plain text. If `scan` ever finds more options than
        // `MsgFile` found messages, the two parsers have diverged and every
        // index below is suspect.
        let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
        assert!(f.options().len() <= f.messages().len());
        for opt in f.options() {
            assert!(opt.index < f.messages().len(), "index {} out of range", opt.index);
        }
    }

    #[test]
    fn a_plain_value_closes_at_its_brace() {
        // A baseline: no escaping in play at all. Kept separate from the two
        // tests below that actually discriminate on tilde handling.
        let src = b"OPT {plain} S 10 p
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        let v = f.options()[0].value;
        assert_eq!(&src[v.start..v.end], b"plain");
    }

    #[test]
    fn an_escaped_brace_does_not_close_the_value() {
        // `~}` is a literal brace. Closing on it would truncate the option and
        // shift every message after it.
        let src = b"OPT {a ~} b} S 10 p
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options().len(), 1);
        let v = f.options()[0].value;
        assert_eq!(&src[v.start..v.end], b"a ~} b", "span keeps the escape as written");
    }

    #[test]
    fn a_multi_line_value_closes_mid_line_not_at_a_line_start() {
        // 4271 corpus values do exactly this. A line-initial rule runs them to EOF.
        let src = b"OPT {line one
line two} S 10 p
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options().len(), 1);
        let v = f.options()[0].value;
        assert_eq!(&src[v.start..v.end], b"line one
line two");
    }

    #[test]
    fn a_text_option_closing_at_a_line_start_still_works() {
        // The shape that misled the original draft. It parses because the `}`
        // is the first unescaped one, not because it begins a line.
        let src = b"AFKALT {
AFK v%s.
} T Log-on Message
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options()[0].kind, OptionType::Text);
        let v = f.options()[0].value;
        assert_eq!(&src[v.start..v.end], b"
AFK v%s.
");
    }

    #[test]
    fn a_double_tilde_is_a_literal_tilde_and_does_not_escape_a_brace() {
        // `~~}` is an escaped tilde followed by a REAL closing brace: the first
        // tilde consumes the second, so the brace is unescaped.
        let src = b"OPT {a~~} S 10 p
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options().len(), 1);
        let v = f.options()[0].value;
        assert_eq!(&src[v.start..v.end], b"a~~");
    }

    #[test]
    fn a_name_longer_than_optlen_is_read_in_full() {
        // MSGRDR.H documents OPTLEN as 8, but msg.rs's own reader enforces no
        // such cap -- State::Name accumulates every is_name byte until a
        // non-name byte or `{`, with no length bound anywhere in its logic.
        // scan must agree with msg.rs, not with the header comment: it is
        // the authority. No name in the recovered corpus is actually this
        // long, but the two parsers must not diverge on the day one is.
        let src = b"ABCDEFGHI {x} S 1 p
";
        let f = SpecFile::parse("T.MSG", src).expect("parses");
        assert_eq!(f.options()[0].name, b"ABCDEFGHI".to_vec());
        assert_eq!(f.messages().len(), 1, "scan and MsgFile must agree on the message count");
    }

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
