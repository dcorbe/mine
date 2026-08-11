//! The transport's translation layer: adapt the host's byte-faithful output
//! for whatever sits on the other end of the socket.
//!
//! `Host`'s output is byte-for-byte what the genuine board sent — proven at
//! `crates/mbbs/tests/ifansi_oracle.rs` against 214 `re/oracle/` captures.
//! Everything that adapts that stream for a particular client happens here,
//! and nowhere else: not in `conn.rs`, not upstream in `mbbs`.
//!
//! **Per-port, not fixed.** The operator picks a [`Stack`] per listening
//! port, because not every client wants the same adaptation: a modern telnet
//! client wants CP437 transcoded to UTF-8 ([`Stack::modern`]); a period DOS
//! terminal, or anything that already speaks CP437 on the wire, wants its
//! bytes left alone ([`Stack::raw`]).

use mud_core::cp437;

/// Telnet's `IAC` byte (RFC 854) — coincides with CP437's non-breaking
/// space, 0xFF. [`Stack::raw`] doubles it so a strict telnet client does not
/// mistake the character for the start of a command.
const IAC: u8 = 0xFF;

/// A configurable translation stack between the host's faithful output and
/// one socket.
///
/// `outbound` takes `&mut self` even though neither variant below needs any
/// state yet: a later stage of this translation layer rewrites ANSI
/// sequences that can straddle two `Out::Bytes` chunks (a split `ESC[` /
/// `2J`, for instance), and recognising that requires carrying the tail of
/// one call over into the next. Giving `outbound` mutable access now means
/// that addition does not have to change every call site.
pub struct Stack {
    transcode: bool,
}

impl Stack {
    /// CP437 -> UTF-8 transcoding, for a modern terminal.
    pub fn modern() -> Self {
        Stack { transcode: true }
    }

    /// The host's bytes as-is, save for telnet framing: only `IAC` (0xFF)
    /// is doubled, so CP437's non-breaking space is not read as the start
    /// of a telnet command.
    pub fn raw() -> Self {
        Stack { transcode: false }
    }

    /// Adapt one chunk of the host's output for this connection's client.
    ///
    /// Returns `Vec<u8>`, not `String`: [`Stack::raw`] can produce bytes
    /// that are not valid UTF-8 (CP437's upper half), so a `String` return
    /// type would be a lie for that variant.
    pub fn outbound(&mut self, bytes: &[u8]) -> Vec<u8> {
        if self.transcode {
            cp437::decode(bytes).into_bytes()
        } else {
            let mut out = Vec::with_capacity(bytes.len());
            for &b in bytes {
                out.push(b);
                if b == IAC {
                    out.push(b);
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chunk of CP437 box drawing, decoded through `modern()`, matches
    /// `cp437::decode` directly -- this is meant to be a pure move, not a
    /// reimplementation.
    #[test]
    fn modern_round_trips_box_drawing_like_cp437_decode() {
        let box_drawing: Vec<u8> = vec![0xC9, 0xCD, 0xCD, 0xBB, 0xBA, 0x20, 0xC8, 0xCD, 0xBC];
        let mut stack = Stack::modern();
        let got = stack.outbound(&box_drawing);
        let want = cp437::decode(&box_drawing).into_bytes();
        assert_eq!(got, want);
    }

    /// The same chunk through `raw()` comes out byte-identical: no telnet
    /// framing byte (0xFF) appears in box-drawing characters, so nothing
    /// should be doubled.
    #[test]
    fn raw_is_byte_identical_for_bytes_with_no_iac() {
        let box_drawing: Vec<u8> = vec![0xC9, 0xCD, 0xCD, 0xBB, 0xBA, 0x20, 0xC8, 0xCD, 0xBC];
        let mut stack = Stack::raw();
        let got = stack.outbound(&box_drawing);
        assert_eq!(got, box_drawing);
    }

    /// The trap: CP437 0xFF (non-breaking space) coincides with telnet's
    /// IAC. A raw port must double it so a strict client does not read it
    /// as the start of a telnet command and swallow the next byte.
    #[test]
    fn raw_doubles_0xff() {
        let input = [b'a', 0xFF, b'b'];
        let mut stack = Stack::raw();
        let got = stack.outbound(&input);
        assert_eq!(got, vec![b'a', 0xFF, 0xFF, b'b']);
    }

    /// `modern()` never needed the doubling above because `cp437::decode`
    /// emits UTF-8, which cannot contain a raw 0xFF byte anywhere -- not
    /// even for the input byte that maps to it. Confirms the asymmetry
    /// between the two variants is real, not assumed.
    #[test]
    fn modern_has_no_0xff_byte_to_double() {
        let input = [b'a', 0xFF, b'b'];
        let mut stack = Stack::modern();
        let got = stack.outbound(&input);
        assert!(!got.contains(&0xFF));
    }

    /// The shared-shape trap: every test above calls `outbound` exactly
    /// once with one self-contained chunk. Nothing here proves that two
    /// calls in a row on the same `Stack` behave consistently with each
    /// other -- state carried wrong between calls would pass every test
    /// above and still be broken. `raw()` has no state yet, so two calls
    /// must simply agree with one call split at the boundary.
    #[test]
    fn two_calls_agree_with_one_call_split_at_the_boundary() {
        let input = [b'a', 0xFF, b'b', 0xFF, b'c'];

        let mut one_call = Stack::raw();
        let whole = one_call.outbound(&input);

        let mut two_calls = Stack::raw();
        let mut split = two_calls.outbound(&input[..2]);
        split.extend(two_calls.outbound(&input[2..]));

        assert_eq!(whole, split);
    }
}
