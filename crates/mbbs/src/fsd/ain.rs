//! `AIN.C`: the ANSI X3.64 keystroke-sequence to keystroke-code translator.
//!
//! A remote terminal spells "up arrow" `ESC [ A`, three bytes arriving one at a
//! time. The FSD wants the one number an IBM PC keyboard would have produced,
//! `72 * 256`, so it can switch on it. [`Ainscb::ainchr`] is the four-state
//! machine that turns the former into the latter, a direct port of `AIN.C:30`.
//!
//! # It is not an ANSI-only component
//!
//! The obvious reading of the name is that this belongs to full-screen mode.
//! It does not. `fsdego` calls `ainbeg()` outside its `amode` branch
//! (`FSDBBS.C:217-218`), and `fsdchi` routes *every* inbound byte through
//! `ainchr` before `fsdinc` ever sees one, with no mode test at all
//! (`FSDBBS.C:349-356`). A line-mode session on the genuine host is therefore
//! decoded exactly as hard as a full-screen one, and the difference shows: a
//! bare `ESC` is swallowed here (`AIN.C:40-44`) rather than delivered, so
//! quitting an FSD session takes **two** of them -- the second lands on
//! `WT4BKT`'s default arm (`AIN.C:54-57`), which hands back the offending
//! character and resets. Before this module existed one `ESC` reached
//! `fsdinc` and quit the session on the spot.
//!
//! # Return convention
//!
//! Three distinct meanings share one `i16`, exactly as the C shares one `int`:
//!
//! | value | meaning |
//! |---|---|
//! | `0` | consumed; nothing to deliver yet |
//! | `1..=255`, or negative | an ordinary byte, passed through |
//! | `scancode * 256` | a decoded special key |
//!
//! Nothing distinguishes "a real NUL arrived" from "consumed"; the original
//! does not either (`fsdchi`'s `if ((c=ainchr(c)) != 0)` drops both), and a
//! NUL is not a keystroke any terminal sends for its own sake.
//!
//! # Why `i16` and not `u16`
//!
//! Borland's `int` is 16 bits and signed, so `i16` is the C's own type and
//! reproduces its two visible consequences for free. The first is here: `char
//! c` is signed too, so a byte with the high bit set arrives *negative* and
//! the pass-through arms return it that way -- see [`Ainscb::ainchr`]. The
//! second is [`super::fsdinc`]'s, where `CTRLPGUP` (`132 * 256` = 33792)
//! overflows a signed 16-bit int and compares equal to `-31744`.
//!
//! Every code this module can itself emit fits comfortably: the largest is
//! `CRSRDN` at `80 * 256` = 20480.

/// AIN session state codes, `AIN.H:57-61`.
pub mod state {
    /// Waiting for `ESC`. The resting state, and what [`super::Ainscb::ainbeg`]
    /// installs.
    pub const WT4ESC: u8 = 0;

    /// Waiting for `[` (ANSI) or `O` (VT100 function key).
    pub const WT4BKT: u8 = 1;

    /// Waiting for the actual ANSI code letter.
    pub const WT4ALP: u8 = 2;

    /// Waiting for the actual VT100 function-key letter.
    pub const WT4LTO: u8 = 3;
}

/// `ESC`, `GCOMM.H:181`. Plain 27 -- unlike every other key here it is not a
/// scancode pair, which is what lets it pass through as an ordinary byte.
const ESC: u8 = 27;

/// Cursor up, `GCOMM.H:173`.
pub const CRSRUP: i16 = 72 * 256;

/// Cursor down, `GCOMM.H:174`.
pub const CRSRDN: i16 = 80 * 256;

/// Cursor left, `GCOMM.H:175`.
pub const CRSRLF: i16 = 75 * 256;

/// Cursor right, `GCOMM.H:176`.
pub const CRSRRT: i16 = 77 * 256;

/// Home, `GCOMM.H:169`.
pub const HOME: i16 = 71 * 256;

/// End, `GCOMM.H:170`.
pub const END: i16 = 79 * 256;

/// `F1`, `GCOMM.H:155`. `F2`..`F8` follow at one scancode apiece.
pub const F1: i16 = 59 * 256;

/// Shift-Tab, `GCOMM.H:177`.
///
/// # Not produced here
///
/// [`Ainscb::ainchr`] has no arm that emits this, nor [`DEL`]: no ANSI or
/// VT100 sequence in `AIN.C`'s tables maps to either. They are here because
/// `fsdinc`'s switch names them (`FSD.C:1904`, `:1920`) and the port keeps
/// the C's arms even where this crate's own decoder cannot reach them -- the
/// genuine host also takes keystrokes from a local console via `getchc()`,
/// which can. Deleting the arms would be a silent narrowing.
pub const BAKTAB: i16 = 15 * 256;

/// The `Del` key as a scancode, `GCOMM.H` (`(83*256)`). Distinct from the
/// ASCII `0x7F` byte, which `fsdinc` handles in the same arm. See [`BAKTAB`]
/// for why this exists despite being unreachable through [`Ainscb::ainchr`].
pub const DEL: i16 = 83 * 256;

/// Ctrl-Home, `GCOMM.H:183` (`119*256`). See [`BAKTAB`] for why this exists
/// despite [`Ainscb::ainchr`] having no arm that produces it -- `fsdinc`'s
/// `FSDAPT` case (`FSD.C:1663`) names it directly.
pub const CTRLHOME: i16 = 119 * 256;

/// Ctrl-End, `GCOMM.H:182` (`117*256`). See [`CTRLHOME`].
pub const CTRLEND: i16 = 117 * 256;

/// Ctrl-PgDn, `GCOMM.H:185` (`118*256`). See [`CTRLHOME`].
pub const CTRLPGDN: i16 = 118 * 256;

/// Ctrl-PgUp, `GCOMM.H:184` (`132*256` = 33792). See [`CTRLHOME`] for why
/// this exists at all.
///
/// # It overflows a signed 16-bit `int`, on purpose
///
/// `132*256` is 33792, past `i16::MAX` (32767) -- the module docs already
/// flag this as the second of the two places this crate's `i16` choice for a
/// keystroke shows its C ancestry (`char c` sign-extending is the first).
/// Two's-complement wraparound turns 33792 into -31744, which is exactly
/// what Borland's own 16-bit `int` would have held and exactly what
/// `fsdinc`'s `case CTRLPGUP:` label compares against on the real host --
/// so this is written as the wrapped value directly rather than as
/// `132 * 256`, which does not compile (`i16` overflow is a hard error in a
/// const, even though the real machine's arithmetic wrapped silently).
pub const CTRLPGUP: i16 = -31744;

/// The `ESC O <letter>` function-key table, `AIN.C:88-116`.
///
/// Transcribed rather than computed, because it is **not** alphabetical:
/// `P Q W x t u q r` maps to `F1`..`F8` in that order. `F3` is `W` where a
/// tidier scheme would have said `R`, and the last five are lowercase. This is
/// what a DEC VT100 keypad actually sends; there is no rule to derive.
const FUNCTION_KEYS: [(u8, i16); 8] = [
    (b'P', F1),
    (b'Q', F1 + 256),
    (b'W', F1 + 2 * 256),
    (b'x', F1 + 3 * 256),
    (b't', F1 + 4 * 256),
    (b'u', F1 + 5 * 256),
    (b'q', F1 + 6 * 256),
    (b'r', F1 + 7 * 256),
];

/// An ANSI input session control block: one byte of state. `AIN.H:51-53`.
///
/// The original keeps this inside `struct fsdbbs` and reaches it through the
/// global `ainscb` pointer, which `fsdchi` swaps in and back out around every
/// call (`FSDBBS.C:344-355`) so that nested sessions on other channels are not
/// disturbed. Here it is an ordinary value that the caller owns per channel,
/// which is the same thing without the global.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ainscb {
    state: u8,
}

impl Ainscb {
    /// `ainbeg()`, `AIN.C:24-28`: begin an ANSI input translation session.
    ///
    /// Note what this does *not* do: there is no matching `ainend`, and the
    /// state is one byte, so beginning a session is only ever "forget any
    /// half-finished escape sequence." `fsdego` calls it for both modes.
    pub fn ainbeg(&mut self) {
        self.state = state::WT4ESC;
    }

    /// The state code, for tests and assertions that care where a partial
    /// sequence left the machine.
    #[must_use]
    pub fn state(&self) -> u8 {
        self.state
    }

    /// `ainchr()`, `AIN.C:30-120`: feed one incoming byte, get one keystroke.
    ///
    /// See the module docs for the return convention. The parameter is a `u8`
    /// rather than the C's `char` because that is what comes off the wire, but
    /// the C's signedness is modelled where it is observable: every `case`
    /// label in the function is a 7-bit ASCII constant, so the sign cannot
    /// change *which* arm runs, but it does change what the two pass-through
    /// arms return. A byte of `0xE9` comes back as `-23`, and it is
    /// `fsdchi`'s `c &= eurmsk` (`FSDBBS.C:352-354`, `eurmsk` being `0x7F` for
    /// a U.S. board) that folds it back into a byte -- as `0x69`, `'i'`, which
    /// is the high-bit stripping that mask is *for*. Doing the mask here
    /// instead would put it on the special keys too, and `CRSRUP & 0x7F` is 0.
    pub fn ainchr(&mut self, c: u8) -> i16 {
        // The C's `char c` sign-extends into the `int` it returns.
        let passthrough = i16::from(c as i8);

        match self.state {
            state::WT4BKT => match c {
                b'[' => {
                    self.state = state::WT4ALP;
                    0
                }
                b'O' => {
                    self.state = state::WT4LTO;
                    0
                }
                // `AIN.C:54-57`. This is the arm a second `ESC` lands on, and
                // the reason `ESC ESC` delivers one `ESC`.
                _ => {
                    self.state = state::WT4ESC;
                    passthrough
                }
            },

            state::WT4ALP => {
                let rc = match c {
                    // `C` is *right* and `D` is *left* (`AIN.C:67-72`). They
                    // are the way round the ANSI standard says, not the way
                    // round the alphabet suggests.
                    b'A' => CRSRUP,
                    b'B' => CRSRDN,
                    b'C' => CRSRRT,
                    b'D' => CRSRLF,
                    b'H' | b'f' => HOME,
                    b'K' => END,
                    _ => {
                        // `AIN.C:80-83`: digits and `;` are parameter bytes.
                        // They return 0 *without* leaving this state, so a
                        // parameterised sequence keeps accumulating -- and
                        // then its final byte falls to the line below and is
                        // discarded. `ESC [ 5 ~`, which many real terminals
                        // send for PgUp, therefore delivers nothing at all.
                        // That is the original's behaviour and inventing a
                        // mapping for it would be a divergence, not a fix.
                        //
                        // The C writes `isdigit(c)` on a signed char, which is
                        // undefined for the negative values a high-bit byte
                        // produces; Borland's table lookup returns 0 there in
                        // practice, which is what `is_ascii_digit` does for
                        // the same bytes.
                        if c.is_ascii_digit() || c == b';' {
                            return 0;
                        }
                        0
                    }
                };
                self.state = state::WT4ESC;
                rc
            }

            state::WT4LTO => {
                let rc = FUNCTION_KEYS
                    .iter()
                    .find(|&&(letter, _)| letter == c)
                    .map_or(0, |&(_, code)| code);
                self.state = state::WT4ESC;
                rc
            }

            // `WT4ESC`, and -- per the C's `default:` falling straight into
            // `case WT4ESC:` (`AIN.C:37-39`) -- any state byte that is not one
            // of the four. Resetting it first is a no-op in the reachable
            // case and a repair in the unreachable one.
            _ => {
                self.state = state::WT4ESC;
                if c != ESC {
                    return passthrough;
                }
                self.state = state::WT4BKT;
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole byte string, returning every non-zero code it produced.
    fn feed(scb: &mut Ainscb, bytes: &[u8]) -> Vec<i16> {
        bytes
            .iter()
            .map(|&b| scb.ainchr(b))
            .filter(|&code| code != 0)
            .collect()
    }

    #[test]
    fn plain_ascii_passes_through_untouched() {
        // AIN.H's own worked example: "HELLO" in, "HELLO" out.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, b"HELLO"), vec![72, 69, 76, 76, 79]);
        assert_eq!(scb.state(), state::WT4ESC, "no sequence was ever started");
    }

    #[test]
    fn a_lone_esc_delivers_nothing_and_arms_the_decoder() {
        // The whole reason this module changes line mode's behaviour.
        let mut scb = Ainscb::default();
        assert_eq!(scb.ainchr(ESC), 0, "swallowed, not delivered");
        assert_eq!(scb.state(), state::WT4BKT);
    }

    #[test]
    fn esc_esc_delivers_one_esc() {
        // `AIN.C:54-57`: the second ESC is the "offending character" the
        // default arm hands back. This is why quitting an FSD session on the
        // genuine host takes ESC ESC, and it is the landed line-mode
        // divergence this module corrects.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, &[ESC, ESC]), vec![27]);
        assert_eq!(scb.state(), state::WT4ESC, "and the machine is reset");
    }

    #[test]
    fn the_four_arrow_keys_decode_with_c_right_and_d_left() {
        // Getting C/D backwards is the obvious slip and would be invisible
        // until a player's cursor walked the wrong way, so name all four.
        for (bytes, expected, name) in [
            (b"\x1b[A", CRSRUP, "up"),
            (b"\x1b[B", CRSRDN, "down"),
            (b"\x1b[C", CRSRRT, "right"),
            (b"\x1b[D", CRSRLF, "left"),
        ] {
            let mut scb = Ainscb::default();
            assert_eq!(feed(&mut scb, bytes), vec![expected], "ESC [ {name}");
        }
        assert_eq!(CRSRRT, 77 * 256, "right is scancode 77");
        assert_eq!(CRSRLF, 75 * 256, "left is scancode 75");
    }

    #[test]
    fn home_has_two_spellings_and_end_has_one() {
        // `AIN.C:73-79`: 'H' and 'f' share an arm; 'K' is END alone.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, b"\x1b[H"), vec![HOME]);
        assert_eq!(feed(&mut scb, b"\x1b[f"), vec![HOME]);
        assert_eq!(feed(&mut scb, b"\x1b[K"), vec![END]);
    }

    #[test]
    fn the_function_key_table_is_not_alphabetical() {
        // Transcribed from `AIN.C:88-116`, deliberately spelled out here so
        // that a "tidying" edit to FUNCTION_KEYS fails rather than silently
        // remapping someone's keyboard.
        for (letter, n) in [
            (b'P', 1),
            (b'Q', 2),
            (b'W', 3),
            (b'x', 4),
            (b't', 5),
            (b'u', 6),
            (b'q', 7),
            (b'r', 8),
        ] {
            let mut scb = Ainscb::default();
            let got = feed(&mut scb, &[ESC, b'O', letter]);
            assert_eq!(
                got,
                vec![(59 + n - 1) * 256],
                "ESC O {} is F{n}",
                letter as char
            );
        }
    }

    #[test]
    fn an_unknown_function_key_letter_delivers_nothing() {
        // `AIN.C:114-115`: default arm, rc=0, reset.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, &[ESC, b'O', b'Z']), Vec::<i16>::new());
        assert_eq!(scb.state(), state::WT4ESC);
    }

    #[test]
    fn a_parameterised_sequence_is_discarded_entirely() {
        // ESC [ 5 ~ -- PgUp on a great many real terminals. The digits hold
        // the machine in WT4ALP (`AIN.C:80-83`) and '~' then falls to the
        // default arm, which returns 0. Nothing is delivered.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, b"\x1b[5~"), Vec::<i16>::new());
        assert_eq!(scb.state(), state::WT4ESC);

        // Multi-parameter form, with the ';' arm exercised too.
        assert_eq!(feed(&mut scb, b"\x1b[1;5R"), Vec::<i16>::new());
        assert_eq!(scb.state(), state::WT4ESC);
    }

    #[test]
    fn digits_hold_the_state_rather_than_resetting_it() {
        // The discrimination the previous test can't make on its own: if
        // digits reset to WT4ESC instead of staying in WT4ALP, `ESC [ 5 ~`
        // would still deliver nothing -- but '~' would then pass through as
        // ordinary text. Pin the state directly.
        let mut scb = Ainscb::default();
        scb.ainchr(ESC);
        scb.ainchr(b'[');
        assert_eq!(scb.ainchr(b'5'), 0);
        assert_eq!(scb.state(), state::WT4ALP, "still consuming parameters");
        assert_eq!(scb.ainchr(b';'), 0);
        assert_eq!(scb.state(), state::WT4ALP);
    }

    #[test]
    fn esc_then_an_ordinary_letter_delivers_the_letter_not_the_esc() {
        // `AIN.C:54-57` again, and worth its own test because `AIN.H`'s prose
        // says otherwise: the header claims ESC + non-'[' is "passed through
        // by returning the oddball value 0x0100 plus whatever the non-[ was."
        // The code does no such thing -- it returns the character alone. The
        // code is what shipped; the comment is stale.
        let mut scb = Ainscb::default();
        assert_eq!(feed(&mut scb, &[ESC, b'x']), vec![i16::from(b'x')]);
        assert_ne!(feed(&mut Ainscb::default(), &[ESC, b'x']), vec![0x100 + 120]);
    }

    #[test]
    fn a_high_bit_byte_passes_through_sign_extended() {
        // Faithful to `char c` being signed on Borland. The caller's
        // `c &= eurmsk` is what makes this a byte again, and this test exists
        // so that whoever moves that mask in here finds out.
        let mut scb = Ainscb::default();
        assert_eq!(scb.ainchr(0xE9), -23);
        assert_eq!(-23i16 & 0x7F, 0x69, "what fsdchi's eurmsk mask makes of it");
    }

    #[test]
    fn ainbeg_abandons_a_half_finished_sequence() {
        let mut scb = Ainscb::default();
        scb.ainchr(ESC);
        assert_eq!(scb.state(), state::WT4BKT);
        scb.ainbeg();
        assert_eq!(scb.state(), state::WT4ESC);
        // And the 'A' that would have completed it is now just an 'A'.
        assert_eq!(scb.ainchr(b'A'), i16::from(b'A'));
    }

    #[test]
    fn an_out_of_range_state_byte_resets_rather_than_panicking() {
        // The C's `default:` arm (`AIN.C:37-38`). Unreachable through this
        // API, but the arm exists and costs nothing to keep honest.
        let mut scb = Ainscb { state: 99 };
        assert_eq!(scb.ainchr(b'A'), i16::from(b'A'));
        assert_eq!(scb.state(), state::WT4ESC);
    }

    #[test]
    fn every_code_this_module_emits_fits_a_signed_16_bit_int() {
        // The `i16` choice is only safe because ainchr's outputs are all
        // below 32768. CTRLPGUP (132*256) is not, but nothing here emits it.
        for code in [CRSRUP, CRSRDN, CRSRLF, CRSRRT, HOME, END, F1] {
            assert!(code > 0, "{code} did not overflow into negative");
        }
        assert_eq!(CRSRDN, 20480, "the largest code ainchr can produce");
    }

    #[test]
    fn the_ctrl_navigation_keys_have_the_right_scancodes_including_the_overflowed_one() {
        // Transcribed straight from GCOMM.H:182-185, not derived: getting any
        // one of these wrong is invisible until fsdinc's FSDAPT arm compares
        // a real keystroke against the wrong constant and silently no-ops.
        assert_eq!(CTRLEND, 117 * 256);
        assert_eq!(CTRLHOME, 119 * 256);
        assert_eq!(CTRLPGDN, 118 * 256);
        // CTRLPGUP alone overflows i16 -- 132*256 = 33792, and two's
        // complement wraparound is what a real Borland `int` would have
        // done. Checked against the wide computation rather than trusted as
        // a bare literal, so a future edit that "fixes" the sign is caught.
        assert_eq!(i32::from(CTRLPGUP), 132 * 256 - 65536);
    }
}
