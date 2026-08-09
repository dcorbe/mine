//! Telnet IAC filter: a byte pipe, not a line reader (Task 7).
//!
//! GSBL (`crates/mbbs/src/gsbl.rs::Channel::take`) owns the line discipline:
//! echo, backspace as `\x08 \x08`, the input translate table, the `maxinl`
//! limit, and raising `CRSTG` on `\r`. This filter only removes telnet IAC
//! command sequences; every other byte -- including `\r`, `\n`, `0x08`,
//! `0x7f`, and ANSI escapes -- passes through unchanged. A filter that ate
//! the CR would leave the module waiting forever; one that edited the line
//! would double-echo every keystroke.

const IAC: u8 = 255;
const SB: u8 = 250;
const SE: u8 = 240;

/// Strips telnet IAC sequences from a byte stream fed in arbitrary chunks.
#[derive(Default)]
pub struct Filter {
    held: Vec<u8>,
}

impl Filter {
    /// The data bytes in `chunk`, with telnet commands removed. A sequence
    /// that has only partly arrived is held until the rest turns up.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);

        let mut out = Vec::new();
        let mut i = 0;
        while i < self.held.len() {
            if self.held[i] != IAC {
                out.push(self.held[i]);
                i += 1;
                continue;
            }

            // self.held[i] == IAC: the verb byte decides the shape, and
            // without it we cannot tell them apart yet.
            let Some(&verb) = self.held.get(i + 1) else {
                break;
            };
            match verb {
                // Escaped 0xFF: one literal byte of data.
                IAC => {
                    out.push(IAC);
                    i += 2;
                }
                // Subnegotiation runs to the next unescaped IAC SE.
                SB => match Self::subnegotiation_end(&self.held[i..]) {
                    Some(len) => i += len,
                    None => break,
                },
                // Three-byte command (WILL/WONT/DO/DONT/...).
                _ => {
                    if self.held.len() < i + 3 {
                        break;
                    }
                    i += 3;
                }
            }
        }

        self.held.drain(..i);
        out
    }

    /// The length of `IAC SB ... IAC SE` at the start of `buf`, or `None`
    /// while it is still arriving. An `IAC IAC` inside the payload is data
    /// and does not end the subnegotiation.
    fn subnegotiation_end(buf: &[u8]) -> Option<usize> {
        let mut i = 2;
        while i + 1 < buf.len() {
            if buf[i] == IAC {
                if buf[i + 1] == SE {
                    return Some(i + 2);
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;

    /// Feeding the same bytes one at a time must give the same answer as
    /// feeding them at once. TCP segments where it likes, and a filter that
    /// only ever sees whole sequences is a filter that has never been tested.
    fn both_ways(input: &[u8], expected: &[u8]) {
        let mut whole = Filter::default();
        assert_eq!(whole.feed(input), expected, "fed whole");

        let mut split = Filter::default();
        let mut out = Vec::new();
        for &byte in input {
            out.extend(split.feed(&[byte]));
        }
        assert_eq!(out, expected, "fed one byte at a time");
    }

    #[test]
    fn data_passes_through_untouched() {
        both_ways(b"north\r", b"north\r");
    }

    #[test]
    fn a_three_byte_command_is_removed() {
        // IAC DO SGA in the middle of a command.
        both_ways(b"no\xff\xfd\x03rth\r", b"north\r");
    }

    #[test]
    fn an_escaped_ff_is_one_literal_byte() {
        both_ways(b"a\xff\xffb", b"a\xffb");
    }

    #[test]
    fn a_subnegotiation_is_removed_whole() {
        // IAC SB NAWS 0 80 0 24 IAC SE
        both_ways(b"x\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0y", b"xy");
    }

    #[test]
    fn an_escaped_ff_inside_a_subnegotiation_is_not_its_end() {
        both_ways(b"x\xff\xfa\x1f\xff\xff\xff\xf0y", b"xy");
    }

    /// The carriage return must survive. It is what raises CRSTG in GSBL, and
    /// a filter that ate it would leave the module waiting forever.
    #[test]
    fn line_endings_and_control_bytes_are_not_touched() {
        both_ways(b"\x08look\r\n\x1b[0m", b"\x08look\r\n\x1b[0m");
    }

    /// A sequence that has only half arrived is held, not emitted.
    #[test]
    fn a_partial_sequence_is_held_until_the_rest_arrives() {
        let mut f = Filter::default();
        assert_eq!(f.feed(b"a\xff"), b"a");
        assert_eq!(f.feed(b"\xfd"), b"");
        assert_eq!(f.feed(b"\x03b"), b"b");
    }
}
