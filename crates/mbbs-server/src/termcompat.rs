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
//!
//! **Both directions, same [`Stack`].** `outbound` (host -> client) has
//! translated CP437 to UTF-8 since before this plan; `inbound` (client ->
//! host) does the reverse -- UTF-8 to CP437 -- for exactly the same reason
//! and exactly the same clients: a modern telnet client types UTF-8, and a
//! period client (or an emulator of one, like SyncTERM) already types
//! CP437. `inbound` belongs on `Stack`, not as a free function, for the
//! same reason `home_on_clear` does: it needs to differ between `modern`
//! and `raw`, and it needs carry-over state across calls (see `pending`).

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
    /// Bytes of an incomplete UTF-8 sequence carried over from the tail of
    /// the previous `inbound` call -- the same kind of carry-over
    /// `ed2_match` is for `outbound`, for the same reason: a client's typed
    /// multi-byte character can land split across two TCP reads exactly
    /// like a bare `ESC[2J` can. Bounded to at most 3 bytes:
    /// `std::str::from_utf8` only reports an incomplete-at-the-end error
    /// for a valid *lead* byte with fewer than its required continuation
    /// bytes on hand, and the longest UTF-8 sequence is 4 bytes. Unused
    /// (stays empty) when `transcode` is `false`.
    pending: Vec<u8>,
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
            pending: Vec::new(),
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
            pending: Vec::new(),
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
            expand_c0_glyphs(&cp437::decode(&bytes)).into_bytes()
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

    /// Adapt one chunk of bytes typed by this connection's client, for the
    /// host: UTF-8 -> CP437, [`Stack::outbound`]'s reverse. Only
    /// [`Stack::modern`] does this; [`Stack::raw`] returns `bytes`
    /// unchanged, because its client already sends CP437 on the wire -- see
    /// `raw_inbound_leaves_a_cp437_clients_high_bit_bytes_alone` below for
    /// what transcoding it anyway would do to that client's high-bit bytes.
    ///
    /// **ASCII is unaffected**, which is why nothing noticed this gap
    /// existed until now: every ASCII byte is already both its own one-byte
    /// UTF-8 encoding and its own CP437 byte, so a session that never types
    /// outside ASCII sees no difference between a `Stack` that does this
    /// and one that silently drops it on the floor.
    ///
    /// **This must run after `crate::iac::Filter::feed`, never before.**
    /// `cp437::encode` can *synthesize* a `0xFF` byte -- CP437's
    /// non-breaking space -- out of an ordinary typed character no
    /// different from any other (see `mud_core::cp437`'s `HIGH` table,
    /// last entry). `0xFF` also happens to be telnet's `IAC` (RFC 854). If
    /// this ran before the IAC filter saw the client's real bytes, a typed
    /// non-breaking space would look exactly like the start of a genuine
    /// telnet command and the filter would silently eat whatever character
    /// followed it -- the same `0xFF`/`IAC` collision `Stack::raw`'s IAC
    /// doubling exists to prevent outbound, now arriving from the other
    /// direction. `crates/mbbs-server/src/conn.rs`'s `pump` calls
    /// `Filter::feed` first for exactly this reason; see its
    /// `iac_filter_runs_before_inbound_transcode` test, which is worth more
    /// than this paragraph.
    ///
    /// **Invalid UTF-8 does not panic.** A raw-bytes client, or a scripted
    /// test, can send anything; malformed sequences are decoded lossily,
    /// the same substitution `String::from_utf8_lossy` makes -- one
    /// `U+FFFD` per malformed sequence, however many raw bytes it spanned.
    /// `cp437::encode` maps `U+FFFD` to `?`, outside the codepage like any
    /// other character it cannot represent, so every malformed sequence
    /// costs the module exactly one byte -- predictable, because the
    /// module counts bytes.
    ///
    /// **Carry-over.** A multi-byte character can arrive split across two
    /// reads; the unconsumed tail is held in `self.pending` (bounded to at
    /// most 3 bytes, see its doc comment) rather than guessed at or
    /// discarded. A `pending` tail that never resolves -- the connection
    /// closes mid-character -- is simply lost with it, the same as any
    /// other buffered state a dropped connection abandons.
    pub fn inbound(&mut self, bytes: &[u8]) -> Vec<u8> {
        if !self.transcode {
            return bytes.to_vec();
        }

        self.pending.extend_from_slice(bytes);

        let mut text = String::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(valid) => {
                    text.push_str(valid);
                    self.pending.clear();
                    break;
                }
                Err(e) => {
                    let valid_up_to = e.valid_up_to();
                    // Sound, not merely convenient: `valid_up_to` is
                    // exactly the length of a prefix `from_utf8` already
                    // proved is valid UTF-8, so this can never be the
                    // unwrap-on-attacker-input this method's doc promises
                    // not to do.
                    text.push_str(std::str::from_utf8(&self.pending[..valid_up_to]).unwrap());
                    match e.error_len() {
                        // A definite malformed sequence of `len` bytes:
                        // one replacement character, then keep scanning
                        // whatever is left of `pending` in this same call.
                        Some(len) => {
                            text.push('\u{FFFD}');
                            self.pending.drain(..valid_up_to + len);
                        }
                        // The tail is a valid lead byte with too few
                        // continuation bytes on hand *so far* -- it may
                        // still complete once the next chunk arrives.
                        // Leave it in `pending` and stop; do not guess.
                        None => {
                            self.pending.drain(..valid_up_to);
                            break;
                        }
                    }
                }
            }
        }

        cp437::encode(&text)
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

/// Expand CP437's C0-range video glyphs into their Unicode equivalents, for
/// [`Stack::modern`]'s outbound path only.
///
/// **The problem this fixes.** CP437 gives every byte `0x00`-`0x1F` a
/// printable glyph in the IBM PC's text-mode font -- smiley faces, card
/// suits, arrows, musical notes -- because on real DOS hardware a byte
/// written to video memory is just a font index, with no ASCII control
/// meaning at all. `mud_core::cp437::decode` maps every byte `< 0x80` to
/// itself (see that module's doc comment: this matches Python's `cp437`
/// *text* codec, which treats these bytes as controls, not glyphs -- verify
/// with `python3 -c "print(repr(bytes([0x11]).decode('cp437')))"`, which
/// prints `'\x11'`, not `'◄'`). On a modern terminal that byte either fires
/// a real control action (`0x07` rings the bell) or is consumed with zero
/// width, where DOS drew one column. Everything after it on the line then
/// lands one column short of where the module's FSD painting code (fixed
/// absolute `ESC[<row>;<col>f` addressing) put it.
///
/// **The mechanism is general; the scope translated here is not, and that
/// is deliberate.** Every byte `0x00`-`0x1F` has *a* CP437 glyph, but this
/// function translates exactly one of them: `0x11`. An earlier version of
/// this fix translated 21 of the 32 -- everything except a hand-picked
/// exclusion list -- on the reasoning that "other screens and other modules
/// will use the rest of the range." That reasoning does not hold: a full
/// scan of the module's text corpus (every `*.MSG`, `*.MCV` and `*.MDF` in
/// `tmp/`) for C0 bytes other than TAB/LF/CR found
///
/// ```text
/// 0x11 x3      cp437 ◄    files: ['WCCTEXT.MSG']
/// 0x1B x3089   ESC        files: WCCTEXT/WCCMMUD/WCCMMHLP/WCCMMPLS.MSG
/// ```
///
/// `0x11` is the *only* C0 glyph byte anywhere in the module's static text.
/// (`re/oracle/`'s 120 `.raw` captures are silent on the runtime cases
/// below: zero `0x01` bytes, zero `[HP=` prompts -- they cannot be cited
/// either way.) Nothing else in the corpus is evidence for a glyph, and
/// runtime output demonstrated the opposite: translating the speculative
/// 21-byte set caused two live regressions on the very first session that
/// exercised it --
///
/// 1. The in-game prompt started ending in a visible `☺`. MajorMUD emits
///    `0x01` at the end of `[HP=28/MA=8]:` as a runtime protocol marker,
///    not text; it was invisible before the 21-byte version and the fix
///    made it render (see
///    `modern_leaves_the_prompt_marker_byte_untranslated` below).
/// 2. A stat-sheet field (Armour Class) came out right-aligned, consistent
///    with a newly-visible glyph inserted before the value.
///
/// So a C0 byte in this range is not reliably a glyph -- it can just as
/// easily be a protocol marker or other runtime-generated control byte,
/// and there is no way to tell the two apart except by measuring actual
/// module data. Widening this map again needs the same kind of evidence
/// `0x11` has (a byte position in `tmp/*.MSG` immediately bracketed by
/// glyph-only context, corroborated by a live capture), not "the rest of
/// the range is probably fine too."
///
/// `tmp/WCCTEXT.MSG`'s 3 occurrences of `0x11` sit each immediately after
/// an SGR sequence and immediately before a run of `0xC4` (─) -- the Point
/// Cost Chart's `◄──────┤` connector rows -- and a live capture of that
/// chart on port 2323 has exactly 3 rows misaligned, matching.
///
/// **Why this lives here, not in `mud_core::cp437`.** `cp437::decode` is
/// shared with `mud-client` and `mud-server` -- callers with no stake in
/// how *this* transport's FSD renders on *this* port. The defect was
/// created by `Stack::modern`'s outbound translation (the raw port hands
/// the same byte straight to a client that already draws its own CP437
/// font and is unaffected), so the fix stays where the defect was made,
/// same reasoning the per-port `Stack` split itself was built on.
///
/// **Why this runs after `cp437::decode`, not before or merged into it.**
/// This operates on the decoded `char`s, not the raw CP437 bytes: a C0
/// byte decodes to the literal control character (`0x11` -> `'\u{11}'`)
/// today, so mapping specific `char`s here is exactly equivalent to
/// mapping the bytes that produced them, without needing to know anything
/// about multi-byte UTF-8 layout. Running it on raw bytes instead (before
/// `cp437::decode`) would require re-deriving UTF-8 boundary logic this
/// function has no reason to duplicate. Running it before
/// `home_cursor_after_clear` (which matches literal `ESC[2J` bytes and
/// carries partial-match state across calls) is not an option either: that
/// matcher must see the host's original bytes, unmodified, or an
/// `ESC[2J` split by a translated byte landing mid-pattern could desync
/// its `ed2_match` counter. The order in `outbound` --
/// `home_cursor_after_clear` (raw bytes) -> `cp437::decode` (bytes ->
/// chars) -> `expand_c0_glyphs` (chars -> chars) -- keeps each stage
/// working on the representation it was designed for.
///
/// **Scope is a data question, re-asked every time it changes.** See
/// [`c0_glyph`]'s doc comment for the one byte translated today and the
/// standard a new one would have to meet.
fn expand_c0_glyphs(text: &str) -> String {
    text.chars().map(|c| c0_glyph(c).unwrap_or(c)).collect()
}

/// The C0-byte -> video-glyph map itself, as a `char -> char` function so
/// [`expand_c0_glyphs`] can fold it over decoded text. Returns `None` for
/// every byte other than `0x11`.
///
/// The full range this *could* cover is `0x00`-`0x1F` -- CP437 gives all 32
/// of them a glyph -- but only `0x11` is translated, because it is the only
/// one with measured evidence in the module's own data (see
/// `expand_c0_glyphs`'s doc comment for the corpus scan). Every other C0
/// byte keeps its control/identity meaning by default, not by an
/// individually-argued exclusion: with no evidence a byte is glyph content,
/// the safe assumption is that it is not, because two of them turned out to
/// be runtime protocol markers the moment this was tested live (`0x01` in
/// the `[HP=.../MA=...]:` prompt, and whatever produced the Armour Class
/// misalignment). `0x1B` ESC gets the same treatment as every other
/// untranslated byte here now, not a special case -- it was never going to
/// have glyph evidence, since translating it would destroy the escape
/// sequences this transport exists to carry, but the reasoning that keeps
/// it out is the same "no evidence, so no" as everything else in the range.
///
/// If a future byte earns a place here, it needs `0x11`'s kind of evidence:
/// a position in `tmp/*.MSG` (or another shipped module's text data)
/// bracketed by context that is unambiguously glyph, not control -- ideally
/// corroborated by a live capture the way the Point Cost Chart's 3
/// misaligned rows corroborated `0x11`. "The rest of the range probably
/// has similar uses" is exactly the reasoning that put `0x01` in front of a
/// live player as a smiley face; it is not sufficient on its own a second
/// time.
fn c0_glyph(c: char) -> Option<char> {
    Some(match c {
        '\u{11}' => '◄', // BLACK LEFT-POINTING POINTER -- the Point Cost Chart's connectors
        _ => return None,
    })
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

    // -- inbound: UTF-8 -> CP437 (Task 7) --------------------------------

    /// The basic case: a typed UTF-8 accented character comes out as its
    /// single CP437 byte. 'é' is U+00E9, UTF-8 `0xC3 0xA9`, CP437 `0x82`.
    #[test]
    fn modern_inbound_transcodes_utf8_to_cp437() {
        let mut stack = Stack::modern();
        let got = stack.inbound(&[0xC3, 0xA9]);
        assert_eq!(got, vec![0x82]);
    }

    /// The design reason `inbound` differs by `Stack`, not by chance: a
    /// client that already speaks CP437 on the wire (a period DOS
    /// terminal, SyncTERM, MegaMUD) sends single CP437 bytes, not UTF-8.
    /// `raw()` must leave them alone.
    #[test]
    fn raw_inbound_leaves_bytes_alone() {
        let cp437_e_acute = [0x82u8]; // 'é' in CP437, already one byte
        let mut stack = Stack::raw();
        assert_eq!(stack.inbound(&cp437_e_acute), vec![0x82]);
    }

    /// The separation test: what would go wrong if `raw`'s client were
    /// wired to `modern` instead. `0x82` alone is a UTF-8 *continuation*
    /// byte with no lead byte before it -- invalid on its own -- so
    /// `modern`'s decoder replaces it with one `U+FFFD`, which
    /// `cp437::encode` maps to `?`. This is why the two stacks are not
    /// interchangeable: a SyncTERM client wired to a modern port would see
    /// every accented character it typed turn into a question mark, not
    /// pass through as the byte it actually sent.
    #[test]
    fn raw_inbound_leaves_a_cp437_clients_high_bit_bytes_alone() {
        let cp437_e_acute = [0x82u8];

        let mut raw = Stack::raw();
        assert_eq!(raw.inbound(&cp437_e_acute), vec![0x82]);

        let mut modern = Stack::modern();
        assert_eq!(
            modern.inbound(&cp437_e_acute),
            vec![b'?'],
            "modern must not be handed a client that already speaks CP437"
        );
    }

    /// The blind spot this task's own analysis calls out: ASCII is
    /// identical UTF-8 and CP437, so ASCII-only input cannot distinguish
    /// `modern` from `raw`, or a working `inbound` from one that does
    /// nothing at all. This test documents the trap rather than proving
    /// anything on its own -- the two tests above, which use a real
    /// high-bit byte, are what actually separates the stacks.
    #[test]
    fn ascii_inbound_is_identical_through_both_stacks() {
        let input = b"hello world 123";
        let mut modern = Stack::modern();
        let mut raw = Stack::raw();
        assert_eq!(modern.inbound(input), raw.inbound(input));
    }

    /// A 2-byte UTF-8 character split at its one interior point -- the
    /// lead byte in one `inbound` call, the continuation byte in the next
    /// -- still produces the single CP437 byte, not two garbled halves.
    #[test]
    fn modern_inbound_handles_2byte_char_split_across_calls() {
        let utf8 = [0xC3u8, 0xA9u8]; // 'é'
        let mut stack = Stack::modern();
        let mut got = stack.inbound(&utf8[..1]);
        got.extend(stack.inbound(&utf8[1..]));
        assert_eq!(got, vec![0x82]);
    }

    /// The same for a 3-byte character, split at every interior point.
    /// '≡' is U+2261, UTF-8 `0xE2 0x89 0xA1`, CP437 `0xF0`.
    #[test]
    fn modern_inbound_handles_3byte_char_split_across_calls() {
        let utf8 = [0xE2u8, 0x89u8, 0xA1u8];
        for split in 1..utf8.len() {
            let mut stack = Stack::modern();
            let mut got = stack.inbound(&utf8[..split]);
            got.extend(stack.inbound(&utf8[split..]));
            assert_eq!(got, vec![0xF0], "split at byte {split} corrupted the character");
        }
    }

    /// The same 3-byte character fed one byte per call -- three calls, not
    /// two -- so the carry-over is proven to survive more than one hop.
    #[test]
    fn modern_inbound_handles_3byte_char_one_byte_per_call() {
        let utf8 = [0xE2u8, 0x89u8, 0xA1u8];
        let mut stack = Stack::modern();
        let mut got = Vec::new();
        for &b in &utf8 {
            got.extend(stack.inbound(&[b]));
        }
        assert_eq!(got, vec![0xF0]);
    }

    /// A truncated lead byte at the very end of a chunk -- as if the
    /// connection then closed before the character completed -- is held
    /// as valid-so-far, not immediately guessed at or replaced. This is
    /// the "does a buffering implementation only pass when given a
    /// resolving follow-up call" trap: nothing ever resolves this one.
    #[test]
    fn modern_inbound_holds_a_truncated_lead_byte_rather_than_guessing() {
        let mut stack = Stack::modern();
        let got = stack.inbound(&[0xC3]); // lead byte of 'é'; the rest never arrives
        assert!(got.is_empty(), "nothing should be emitted while the sequence might still complete");
    }

    /// A lone continuation byte -- never a valid lead -- does not panic
    /// and costs the module exactly one byte: `?`, same as any other
    /// unmappable character.
    #[test]
    fn modern_inbound_replaces_invalid_utf8_with_one_question_mark() {
        let mut stack = Stack::modern();
        let got = stack.inbound(&[0x80]); // continuation byte, no lead
        assert_eq!(got, vec![b'?']);
    }

    /// The malformed byte does not swallow what follows it: an invalid
    /// byte immediately followed by plain ASCII must not lose the ASCII.
    #[test]
    fn modern_inbound_recovers_after_invalid_byte() {
        let mut stack = Stack::modern();
        let got = stack.inbound(&[0x80, b'X']);
        assert_eq!(got, vec![b'?', b'X']);
    }

    /// The shared-shape trap every test above shares: the malformed byte
    /// always sits at the very start of the buffer, where `valid_up_to`
    /// (how much of `pending` was valid before the error) is always `0` --
    /// so a mutant that drains `..len` instead of the correct
    /// `..valid_up_to + len` passes every one of them, because `0 + len ==
    /// len`. Measured: it did, until this test was added. Typing a real
    /// character before the mistake -- 'é', then a stray continuation
    /// byte, then 'X' -- puts something ahead of the error and is the one
    /// case that tells the two apart.
    #[test]
    fn modern_inbound_replaces_invalid_byte_after_a_valid_prefix() {
        let mut stack = Stack::modern();
        let got = stack.inbound(&[0xC3, 0xA9, 0x80, b'X']); // 'é', then garbage, then 'X'
        assert_eq!(got, vec![0x82, b'?', b'X']);
    }

    /// Every possible byte value, all in one chunk: must not panic. A
    /// scripted test or a raw-bytes client can send anything.
    #[test]
    fn modern_inbound_does_not_panic_on_arbitrary_bytes() {
        let mut stack = Stack::modern();
        let garbage: Vec<u8> = (0u8..=255).collect();
        let got = stack.inbound(&garbage);
        assert!(!got.is_empty());
    }

    // -- C0 glyph expansion (Task 3, live-session-defects; narrowed after --
    // -- live regressions, see termcompat.rs's `c0_glyph` doc comment)   --
    //
    // CP437 gives every byte 0x00-0x1F a printable glyph in the DOS
    // text-mode font -- arrows, card suits, musical notes -- distinct from
    // what the same byte means as an ASCII control code. `cp437::decode`
    // (shared with `mud-client` and `mud-server`, see its own doc comment)
    // deliberately does not know about this: it maps every byte < 0x80 to
    // itself, so on a modern terminal a CP437 glyph byte that also happens
    // to be a real control code either fires that control (BEL rings) or
    // is swallowed with zero width (most others) -- where DOS drew a
    // one-column glyph. Bytes after it on the line then land one column
    // short.
    //
    // Only byte 0x11 is translated. It is the only C0 byte with measured
    // glyph evidence: `tmp/WCCTEXT.MSG` has exactly 3 occurrences, always
    // immediately after an SGR sequence and immediately before a run of
    // 0xC4 (─) box-drawing bytes -- the Point Cost Chart's `◄──────┤`
    // connectors -- and a live capture of that screen on port 2323 has
    // exactly 3 misaligned rows to match. A full scan of every `*.MSG`,
    // `*.MCV` and `*.MDF` in `tmp/` for C0 bytes outside TAB/LF/CR found
    // nothing else: 0x11 x3 (cp437 ◄) and 0x1B x3089 (ESC, correctly never
    // translated). An earlier version of this function translated 21 of
    // the 32 C0 bytes on the unmeasured assumption that other modules would
    // use the rest of the range; live testing immediately produced two
    // regressions that prove the assumption false -- a runtime protocol
    // marker (0x01, at the end of the `[HP=28/MA=8]:` prompt) rendering as
    // a visible ☺, and a stat-sheet field shifting out of alignment. See
    // `modern_leaves_the_prompt_marker_byte_untranslated` below for the
    // regression test that pins the first of those.

    /// The exact defect from the live session, reproduced byte-for-byte:
    /// `WCCTEXT.MSG`'s own SGR-then-0x11-then-0xC4-run-then-0xB4 sequence,
    /// through `Stack::modern`.
    #[test]
    fn modern_expands_the_point_cost_chart_connector_arrow() {
        let input: &[u8] = b"\x1b[1;30m\x11\xc4\xc4\xc4\xc4\xc4\xc4\xb4";
        let mut stack = Stack::modern();
        let got = stack.outbound(input);
        assert_eq!(got, "\x1b[1;30m◄──────┤".as_bytes());
    }

    /// The shared-shape check: every other test in this section hands
    /// `outbound` at most one occurrence of the translated byte per call.
    /// An implementation bug that translates only the first occurrence it
    /// finds per call (an early-return, or a `.find()` where a `.map()`
    /// belongs) would pass every other test in this file and still be
    /// broken. Two occurrences, one call, must both come out translated.
    #[test]
    fn modern_translates_every_glyph_byte_in_one_call_not_just_the_first() {
        let mut stack = Stack::modern();
        let got = stack.outbound(&[0x11, b'x', 0x11]);
        assert_eq!(got, "◄x◄".as_bytes());
    }

    /// The shared-shape attack on the old test battery: every prior
    /// "stays a control" test here (and the regression test above, for
    /// 0x01 specifically) only ever checked bytes drawn from the *original*
    /// 11-byte exclusion list -- never the 20 bytes the 21-byte version
    /// used to translate. A bug that left one of those 20 mappings in
    /// `c0_glyph` (an incomplete narrowing) would have passed every other
    /// test in this file, the 0x01 regression test included, since none of
    /// them exercises byte 0x02, say. This test closes that gap directly:
    /// every byte in the full C0 range except 0x11 -- both the
    /// always-excluded bytes and the ones this task removed -- must come
    /// out of `modern()` exactly as it went in, all in one call.
    #[test]
    fn modern_never_translates_any_c0_byte_except_0x11() {
        let controls: Vec<u8> = (0x00u8..=0x1F).filter(|&b| b != 0x11).collect();
        let mut stack = Stack::modern();
        let got = stack.outbound(&controls);
        assert_eq!(got, controls);
    }

    /// The task's own acceptance case: an `ESC[...]` sequence that
    /// contains no C0 glyph byte is completely unaffected -- not merely
    /// "still valid", byte-identical.
    #[test]
    fn modern_leaves_esc_sequences_with_no_c0_glyph_bytes_untouched() {
        let input: &[u8] = b"\x1b[0;7m\x1b[4;20fHello, Adventurer\x1b[0m";
        let mut stack = Stack::modern();
        let got = stack.outbound(input);
        assert_eq!(got, input.to_vec());
    }

    /// The task's other acceptance case: the raw port -- a period client
    /// that renders CP437 itself -- must still see byte 0x11 exactly as
    /// the host sent it, not the 3-byte UTF-8 expansion `modern()` uses.
    #[test]
    fn raw_leaves_c0_glyph_bytes_untouched() {
        let mut stack = Stack::raw();
        let got = stack.outbound(&[0x11]);
        assert_eq!(got, vec![0x11]);
    }

    /// The shared-shape check: every test above hands `outbound` either a
    /// lone C0 byte or a chunk with no `ESC[2J` in it, so none of them
    /// proves glyph expansion composes correctly with `home_on_clear` in
    /// the same call -- a wiring bug that ran expansion on the wrong
    /// stage (say, before `home_cursor_after_clear` sees the raw bytes,
    /// or that fed the injected `ESC[H` through the glyph map) would pass
    /// every test above and still be broken. `ESC[2J` immediately
    /// followed by a glyph byte must produce both the home and the glyph,
    /// undisturbed by each other.
    #[test]
    fn modern_home_on_clear_and_c0_glyph_expansion_compose_in_one_call() {
        let mut stack = Stack::modern();
        let got = stack.outbound(b"\x1b[2J\x11");
        assert_eq!(got, "\x1b[2J\x1b[H◄".as_bytes());
    }

    /// The same composition, split across two `outbound` calls right at
    /// the `ESC[2J` / glyph-byte boundary -- proving `ed2_match`'s
    /// carry-over state and the (stateless) glyph expansion do not step
    /// on each other across chunks either.
    #[test]
    fn modern_home_on_clear_and_c0_glyph_expansion_compose_across_chunks() {
        let mut stack = Stack::modern();
        let mut got = stack.outbound(b"\x1b[2J");
        got.extend(stack.outbound(&[0x11]));
        assert_eq!(got, "\x1b[2J\x1b[H◄".as_bytes());
    }

    /// The regression a live session found: MajorMUD emits `0x01` at the
    /// end of the `[HP=28/MA=8]:` prompt as a runtime protocol marker, not
    /// text. The original (over-broad, 21-byte) version of this function
    /// translated it to `☺` and made it visible on the modern port; `0x11`
    /// is the only C0 byte with measured glyph evidence in this module's
    /// text data (see `c0_glyph`'s doc comment), so `0x01` -- and every
    /// other C0 byte -- must reach the client exactly as the host sent it.
    #[test]
    fn modern_leaves_the_prompt_marker_byte_untranslated() {
        let mut stack = Stack::modern();
        let got = stack.outbound(b"[HP=28/MA=8]:\x01");
        assert_eq!(got, b"[HP=28/MA=8]:\x01".to_vec());
    }

    /// `inbound` is the reverse direction (client -> host, UTF-8 -> CP437)
    /// and must not know anything about C0 glyph expansion, which is an
    /// outbound-only, video-font concept. A client that types (or pastes)
    /// a literal U+25C4 is not asking for CP437 byte 0x11 -- `cp437::HIGH`
    /// (the only table `encode` consults) has no entry for it, so it maps
    /// to `?` exactly like any other character outside the codepage. This
    /// pins that `inbound` was not accidentally wired to the same map.
    #[test]
    fn inbound_is_unaffected_by_c0_glyph_expansion() {
        let mut stack = Stack::modern();
        let got = stack.inbound("◄".as_bytes());
        assert_eq!(got, vec![b'?']);
    }
}
