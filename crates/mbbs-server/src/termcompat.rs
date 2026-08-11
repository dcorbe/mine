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

/// `ED 2` — "erase display, whole screen" — as ANSI.SYS's clients saw it on
/// the wire.
const ESC_2J: &[u8] = b"\x1b[2J";

/// `CUP` with no parameters — "cursor position, home" — what ANSI.SYS did
/// on its own after an `ED 2`, and what [`Stack::modern`] adds back for a
/// client that does not.
const ESC_HOME: &[u8] = b"\x1b[H";

/// A configurable translation stack between the host's faithful output and
/// one socket.
///
/// `outbound` takes `&mut self`: the `ESC[2J` -> `ESC[2J ESC[H` rewrite
/// below is a *sequence* match that can straddle two `Out::Bytes` chunks (a
/// split `ESC[` / `2J`, for instance), and recognising that requires
/// carrying how far into the pattern the previous call got. `ed2_match`
/// is that carry-over; it is the only state either variant holds.
pub struct Stack {
    transcode: bool,
    /// Rewrite `ESC[2J` to `ESC[2J ESC[H` on the way out. `true` only for
    /// [`Stack::modern`] -- see that constructor's doc comment for why.
    home_on_clear: bool,
    /// How many bytes of `ESC_2J`, counted from the start, the tail of the
    /// last chunk already matched. `0` outside a match; `ESC_2J.len()` is
    /// never stored, because a completed match injects the home and resets
    /// this to `0` in the same step. Unused (stays `0`) when
    /// `home_on_clear` is `false`.
    ed2_match: usize,
}

impl Stack {
    /// CP437 -> UTF-8 transcoding, and the ANSI.SYS `ESC[2J` home, for a
    /// modern terminal (xterm, tmux, PuTTY, ...).
    ///
    /// **Why the home is here and not upstream, in `Host`.** ANSI.SYS --
    /// the DOS driver every period client ran -- homed the cursor to (1,1)
    /// on `ED 2`; ECMA-48, which every modern client speaks, does not. The
    /// module was written against the DOS behaviour: `fsdbkg`
    /// (`crates/mbbs/src/shims/fsd.rs:787`) emits `ESC[2J` and never homes
    /// -- confirmed in the oracle captures, 8 occurrences of `fsdbkg`'s own
    /// signature, never followed by a home -- and then `fsddsp` paints
    /// every field with an *absolute* `ESC[<row>;<col>f`. Across the whole
    /// oracle corpus `ESC[2J` appears 695 times, of which 282 are followed
    /// by an explicit `ESC[H`; this rewrite is a no-op duplicate for those
    /// 282 (see `explicit_home_after_clear_is_left_alone_not_special_cased`)
    /// and the fix for the other 413, `fsdbkg`'s 8 among them.
    ///
    /// This must stay a transport-layer rewrite, never migrate into
    /// `Host`. The three injected bytes are safe *only* because they are
    /// added downstream of the host, after `crates/mbbs/src/gsbl.rs`'s
    /// `btutsw` has already finished counting columns against what the
    /// host actually emitted. Injecting them upstream would feed `btutsw`
    /// bytes the genuine board never produced and corrupt its column
    /// arithmetic in a way that *looks* like a wrap bug and is not one --
    /// the same trap Task 2b of this plan spent an entire unplanned detour
    /// on for CP437. The oracle boundary (`Host`'s output byte-for-byte
    /// matching a genuine capture) would also simply stop holding.
    ///
    /// **The blast radius is wider than the FSD, deliberately.** Any
    /// `ESC[2J` followed by a *relative* cursor move (`ESC[<n>B`,
    /// `ESC[<n>C`, ...) elsewhere in the module now lands relative to
    /// (1,1) instead of wherever the cursor happened to be sitting when
    /// the screen was cleared. That is what the module was written
    /// against under ANSI.SYS, so it is a fix everywhere it fires, not a
    /// regression confined to the FSD -- but it means a screen painted
    /// differently elsewhere after this change is not a new bug.
    pub fn modern() -> Self {
        Stack {
            transcode: true,
            home_on_clear: true,
            ed2_match: 0,
        }
    }

    /// The host's bytes as-is, save for telnet framing: only `IAC` (0xFF)
    /// is doubled, so CP437's non-breaking space is not read as the start
    /// of a telnet command.
    ///
    /// No `ESC[2J` rewrite here: `raw()`'s clients are period DOS
    /// terminals (or emulators of one, like SyncTERM) that already run
    /// ANSI.SYS or reproduce its behaviour themselves. They home on their
    /// own; adding the bytes here would be a second, redundant home this
    /// stack has no way to tell apart from one the client actually needed.
    pub fn raw() -> Self {
        Stack {
            transcode: false,
            home_on_clear: false,
            ed2_match: 0,
        }
    }

    /// Adapt one chunk of the host's output for this connection's client.
    ///
    /// Returns `Vec<u8>`, not `String`: [`Stack::raw`] can produce bytes
    /// that are not valid UTF-8 (CP437's upper half), so a `String` return
    /// type would be a lie for that variant.
    pub fn outbound(&mut self, bytes: &[u8]) -> Vec<u8> {
        let bytes = if self.home_on_clear {
            self.home_cursor_after_clear(bytes)
        } else {
            bytes.to_vec()
        };

        if self.transcode {
            cp437::decode(&bytes).into_bytes()
        } else {
            let mut out = Vec::with_capacity(bytes.len());
            for &b in &bytes {
                out.push(b);
                if b == IAC {
                    out.push(b);
                }
            }
            out
        }
    }

    /// Rewrite `ESC[2J` to `ESC[2J ESC[H`, carrying a partial match across
    /// calls in `self.ed2_match`.
    ///
    /// **Never buffers.** Every input byte is pushed to `out` the moment
    /// it is seen, whether or not it turns out to be part of a match --
    /// only the *count* of how far into the pattern the tail is carries
    /// over, not the bytes themselves. This is what makes a partial
    /// `ESC[2J` left over when the connection closes harmless: those bytes
    /// already reached the client in the call that received them, exactly
    /// as they would have with no transform at all. There is nothing to
    /// flush and nothing a dropped `Stack` can lose.
    fn home_cursor_after_clear(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for &b in bytes {
            out.push(b);
            if b == ESC_2J[self.ed2_match] {
                self.ed2_match += 1;
                if self.ed2_match == ESC_2J.len() {
                    out.extend_from_slice(ESC_HOME);
                    self.ed2_match = 0;
                }
            } else if b == ESC_2J[0] {
                // Not the byte the match needed, but a valid restart (an
                // `ESC` that starts over, for instance `ESC ESC [ 2 J`).
                self.ed2_match = 1;
            } else {
                self.ed2_match = 0;
            }
        }
        out
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

    // -- ESC[2J homes the cursor (Task 6) --------------------------------

    /// The basic case: `ESC[2J` through `modern()` gains a trailing
    /// `ESC[H`, reproducing what ANSI.SYS did on a screen clear.
    #[test]
    fn modern_homes_cursor_after_esc_2j() {
        let mut stack = Stack::modern();
        let got = stack.outbound(b"\x1b[2J");
        assert_eq!(got, b"\x1b[2J\x1b[H");
    }

    /// The separation the plan requires as an assertion, not an assumption:
    /// the same input through `raw()` and `modern()` must differ in
    /// exactly one way -- the trailing `ESC[H`. `raw()`'s clients emulate
    /// ANSI.SYS themselves and home on their own; adding the bytes there
    /// would be a double-home the client already produced.
    #[test]
    fn modern_and_raw_diverge_by_exactly_the_home_sequence() {
        let input = b"\x1b[2J";

        let mut raw = Stack::raw();
        let raw_got = raw.outbound(input);

        let mut modern = Stack::modern();
        let modern_got = modern.outbound(input);

        assert_eq!(raw_got, input, "raw must not touch ESC[2J at all");

        let mut want_modern = raw_got.clone();
        want_modern.extend_from_slice(b"\x1b[H");
        assert_eq!(
            modern_got, want_modern,
            "modern must differ from raw by exactly a trailing ESC[H"
        );
    }

    /// `ESC[2J` split across two `outbound` calls, at every possible split
    /// point, must still produce the home -- this is why `outbound` takes
    /// `&mut self`.
    #[test]
    fn modern_homes_cursor_when_esc_2j_is_split_across_chunks() {
        let input = b"\x1b[2J";
        for split in 1..input.len() {
            let mut stack = Stack::modern();
            let mut got = stack.outbound(&input[..split]);
            got.extend(stack.outbound(&input[split..]));
            assert_eq!(
                got, b"\x1b[2J\x1b[H",
                "split at byte {split} lost or corrupted the home"
            );
        }
    }

    /// A partial `ESC[2J` left over when the connection closes (no further
    /// bytes ever arrive) must not be silently lost: every byte handed to
    /// `outbound` is written to `out` in that same call, whether or not it
    /// turns out to complete the pattern. Nothing is buffered waiting for
    /// bytes that may never come.
    #[test]
    fn partial_esc_2j_at_end_of_stream_is_not_lost() {
        for prefix_len in 1..=3 {
            let prefix = &b"\x1b[2J"[..prefix_len];
            let mut stack = Stack::modern();
            let got = stack.outbound(prefix);
            assert_eq!(
                got, prefix,
                "a partial sequence must be forwarded, not withheld, at length {prefix_len}"
            );
        }
    }

    /// The 282 places the oracle shows the module already sending its own
    /// explicit home right after the clear: an extra `ESC[H` immediately
    /// before it is harmless (a duplicate home is a no-op), so no special
    /// case is needed. Assert it rather than assume it.
    #[test]
    fn explicit_home_after_clear_is_left_alone_not_special_cased() {
        let mut stack = Stack::modern();
        let got = stack.outbound(b"\x1b[2J\x1b[H");
        assert_eq!(got, b"\x1b[2J\x1b[H\x1b[H");
    }

    /// `ESC[0J`, `ESC[1J` and a parameterless `ESC[J` are different `ED`
    /// forms, not `ESC[2J`; none of them may gain a home.
    #[test]
    fn other_ed_forms_are_not_rewritten() {
        for other in [&b"\x1b[0J"[..], &b"\x1b[1J"[..], &b"\x1b[J"[..]] {
            let mut stack = Stack::modern();
            let got = stack.outbound(other);
            assert_eq!(got, other, "{other:?} must not be treated as ESC[2J");
        }
    }

    /// A second `ESC` right after the first one restarts the match instead
    /// of losing it: `ESC ESC [ 2 J` still gets a home, because the second
    /// `ESC` is itself a valid start of the pattern.
    #[test]
    fn a_leading_esc_that_is_not_the_match_restarts_it() {
        let mut stack = Stack::modern();
        let got = stack.outbound(b"\x1b\x1b[2J");
        assert_eq!(got, b"\x1b\x1b[2J\x1b[H");
    }

    /// The shared-shape assumption every test above makes: `ESC[2J`
    /// appears once, and any chunk boundary falls strictly inside or
    /// strictly outside a match. None of them puts a chunk boundary
    /// exactly where a match *completes* and a fresh match starts in the
    /// very next byte -- the one place a match-state reset that ran one
    /// byte late, or leaked into the next call, would go unnoticed. Two
    /// back-to-back clears, split at every position, must each get their
    /// own home.
    #[test]
    fn back_to_back_clears_split_at_every_position_each_get_a_home() {
        let input = b"\x1b[2J\x1b[2J";
        let want = b"\x1b[2J\x1b[H\x1b[2J\x1b[H".to_vec();

        for split in 0..=input.len() {
            let mut stack = Stack::modern();
            let mut got = stack.outbound(&input[..split]);
            got.extend(stack.outbound(&input[split..]));
            assert_eq!(got, want, "split at byte {split} desynced the match state");
        }
    }
}
