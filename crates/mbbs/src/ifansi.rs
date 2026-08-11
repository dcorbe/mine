//! The `ESC[[ansi|ascii]` construct: IF-ANSI.
//!
//! Undocumented in the recovered Galacticomm sources (searched, absent from
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/`); the name and the only
//! recovered implementation come from MBBSEmu's `ProcessIfANSI`, mirrored in
//! this repo at
//! `docs/mirrors/github-mbbsemu-MBBSEmu/MBBSEmu/HostProcess/ExportedModules/ExportedModuleBase.cs:857-936`.
//! This module is a from-scratch port of that algorithm, not a transliteration
//! of the C# -- see "Where this differs from `ProcessIfANSI`" below for the
//! one place that matters.
//!
//! # Shape
//!
//! `ESC [ [ <ansi form> | <ascii form> ]`
//!
//! - `ESC[[` opens the construct. This is deliberately confusable with an
//!   ordinary CSI sequence such as `ESC[1;37m` -- the two are told apart by
//!   the third byte, exactly as `ProcessIfANSI` does it (`ExportedModuleBase.cs:874,881`):
//!   `ESC[` followed by another `[` is IF-ANSI, anything else is left alone.
//! - An unescaped `|` separates the ANSI form from the ASCII form.
//! - An unescaped `]` closes the construct.
//! - `~` escapes an immediately following `|`, `]`, or `~` so it can appear
//!   literally inside a form; the `~` itself is consumed and never emitted.
//!
//! [`process`] emits exactly one of the two forms -- discarding the other
//! form, the punctuation, and the `~` escapes -- and passes every other byte
//! through unchanged. Real fixtures pulled out of `WCCMMUD.DLL`:
//!
//! ```text
//! \x1b[[\x1b[1;37m| \x08 \x08 \x08 \x08]         ansi: ESC[1;37m   ascii: " \b \b \b \b"
//! \x1b[[\x1b[79D\x1b[K| \x08 \x08 \x08 \x08]     ansi: ESC[79D ESC[K
//! ```
//!
//! The ANSI form sets colour or clears the line properly; the ASCII form
//! fakes the same effect on a dumb terminal by backspacing over it.
//!
//! # The branch `ProcessIfANSI` never takes
//!
//! `ProcessIfANSI` accepts an `isAnsi` parameter and never reads it -- the
//! body always emits the ANSI form, and its caller, `FormatOutput`, calls it
//! without the argument at all. Every one of the 214 `re/oracle/` captures is
//! an ANSI session, so nothing in the oracle can tell "always ANSI" apart
//! from "ANSI because the session is ANSI".
//!
//! [`process`] implements the branch for real: the caller passes the
//! channel's actual ANSI flag (`Connection::ansi`, `crates/mbbs/src/users.rs:156`)
//! and gets the ASCII form back when it is false. As of this module's
//! introduction the ASCII branch is unreachable through `mbbs-server` --
//! `crates/mbbs-server/src/conn.rs:132` connects every channel as ANSI -- so
//! it is exercised by this module's own unit tests rather than by the oracle.
//! That is a gap in the harness, not in the code: a non-ANSI channel is a
//! real MajorBBS configuration this host does not happen to offer yet.
//!
//! # Where this differs from `ProcessIfANSI`: unterminated input
//!
//! `ProcessIfANSI` bounds-checks nothing. Three ways malformed module output
//! reaches it unpunished today and would not survive a direct port:
//!
//! 1. `ESC[[` with fewer than two more bytes in the buffer -- `inputSpan[i + 2]`
//!    is simply read past the end of the span.
//! 2. A form whose *first* character is an unescaped `|`, `]`, or `~` --
//!    `substringSpan[j - 1]` at `j == 0` is `substringSpan[-1]`.
//! 3. A construct with no closing `]` before the input ends -- this one
//!    happens not to crash (the search loops terminate on `substringEnd`/`i`
//!    reaching `inputSpan.Length`), but it relies on the same unchecked
//!    indexing as the other two, not on anything that guarantees safety.
//!
//! This host's rule, matching every other shim in this crate (see the module
//! doc on `crates/mbbs/src/lib.rs`, "A shim that lies is worse than one that
//! refuses"): malformed *module* output must not take the *board* down.
//! `mbbs16`'s watchdog does not reach code running on the host side of a
//! call, so an index panic here would kill the process for every connected
//! player over a single bad string, not just the channel that triggered it.
//! [`process`] therefore bounds-checks every index and defines an answer for
//! each of the three cases above, rather than reproducing the crash:
//!
//! - **Case 1** (truncated opener): if the input ends before `ESC[[`'s third
//!   byte is even present to inspect, it is indistinguishable from an
//!   ordinary, harmless `ESC[...` sequence that also happens to be cut off --
//!   so it is left alone. The `ESC` (and, if present, the following `[`) are
//!   copied through literally, one byte at a time, exactly as an ordinary
//!   truncated CSI code already is (this module never touches those).
//!   *But* if all three opener bytes (`ESC[[`) are present and only the
//!   *content* runs out, the opener is no longer ambiguous -- see case 3.
//! - **Case 2** (leading special character in a form): read the "preceding
//!   byte" relative to the *extracted form*, not the original buffer. This
//!   is not merely the bounds-safe version of `ProcessIfANSI`'s check, it is
//!   the *semantically correct* one: an escape's `~` has to be payload
//!   *inside* the form for it to mean anything, and there is no room inside
//!   the form before its own first character. So position 0 of a form can
//!   never be "the char after a `~`", which is exactly what treating
//!   out-of-range as "not escaped" says. See [`emit_form`].
//! - **Case 3** (no closing `]`, or no separating `|` at all): a form is only
//!   ever emitted when it is bounded by real, present delimiters on *both*
//!   sides. A dangling ANSI or ASCII form -- one whose closing `|` or `]`
//!   never arrives before the input does -- is dropped instead of emitted
//!   half-finished. A truncated escape sequence left on the wire (say, the
//!   module was cut off mid `ESC[1;37` with no final letter) can make a
//!   terminal treat the *next* legitimate output as parameters to that
//!   dangling CSI, which corrupts far more of the screen than the missing
//!   fragment itself would. Silence is the safer failure. See [`process`]'s
//!   `None` arms for the exact rule, and its tests for what each of the four
//!   combinations (both delimiters present / only `|` / neither) produces.
//!
//! None of this is reachable through `mbbs-server` today either -- the
//! module only ever emits well-formed constructs, which is exactly why the
//! 269 occurrences in `WCCMMUD.DLL` all round-trip through [`process`] and
//! zero of them are why this section exists. It exists because "the host
//! never sends garbage" is a claim about `WCCMMUD.DLL`, not a bound this
//! function can assume of every module that will ever run under it.

/// Resolve one IF-ANSI construct's chosen form, applying the `~` escape.
///
/// `form` is the raw bytes between the construct's delimiters (between
/// `ESC[[` and the `|`, or between the `|` and the `]`) -- already known to
/// be complete, since [`process`] never calls this on a form it could not
/// bound on both sides. An unescaped `|`, `]`, or `~` is IF-ANSI's own
/// syntax and contributes nothing to the output; `~` immediately before one
/// of those three makes it literal, and the `~` itself is consumed.
///
/// The escape lookback is relative to `form`, not the surrounding buffer --
/// see the module doc, "Where this differs from `ProcessIfANSI`", case 2, for
/// why that is the correct rule and not just the safe one.
fn emit_form(out: &mut Vec<u8>, form: &[u8]) {
    for (j, &c) in form.iter().enumerate() {
        match c {
            b'|' | b']' | b'~' => {
                if j > 0 && form[j - 1] == b'~' {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
    }
}

/// Find the first unescaped `target` byte in `input` at or after `start`.
///
/// A byte at index `k` counts as escaped when `input[k - 1] == b'~'`. Unlike
/// [`emit_form`]'s lookback, this one reads the *original* buffer rather than
/// a form slice, so it is always in range: the byte immediately before
/// `start` is always real input here (either the second `[` of `ESC[[`, or
/// the separating `|` itself), never a slice boundary manufactured by the
/// caller. Returns `None` if `target` never appears, unescaped, before
/// `input` ends.
fn find_unescaped(input: &[u8], start: usize, target: u8) -> Option<usize> {
    let mut j = start;
    while j < input.len() {
        if input[j] == target && input[j - 1] != b'~' {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Resolve every `ESC[[ansi|ascii]` construct in `input`, keeping the ANSI
/// form when `ansi` is true and the ASCII form otherwise; every other byte,
/// including ordinary `ESC[...` colour codes, passes through unchanged.
///
/// This is `ProcessIfANSI` (`ExportedModuleBase.cs:857-936`), reimplemented
/// with the branch it declares but never takes, and with bounds checks on
/// every index it does not have. See the module doc for both.
///
/// Returns an owned `Vec<u8>` rather than borrowing because the result is
/// always the same length as `input` or shorter (a construct's punctuation
/// and unchosen form are strictly removed, nothing is ever added), and
/// callers hand the result straight to `append`, which wants an owned buffer
/// to write into `prfbuf` anyway.
pub fn process(input: &[u8], ansi: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != 0x1B {
            out.push(b);
            i += 1;
            continue;
        }

        // Ordinary CSI (`ESC[` not followed by a second `[`), or an ESC this
        // host cannot classify because the buffer ends right here: pass the
        // ESC through and let whatever follows it be handled byte-by-byte on
        // later iterations, same as an ordinary colour code always is.
        let second = input.get(i + 1).copied();
        let third = input.get(i + 2).copied();
        if second != Some(b'[') || third != Some(b'[') {
            out.push(b);
            i += 1;
            continue;
        }

        // `ESC[[` -- unambiguously an IF-ANSI opener, all three bytes present.
        let form_start = i + 3;
        match find_unescaped(input, form_start, b'|') {
            None => {
                // No separator anywhere before the input ends: this
                // construct is not just missing its close, its ANSI form
                // was never bounded on the right either. Drop it whole --
                // see the module doc, case 3.
                i = input.len();
            }
            Some(sep) => match find_unescaped(input, sep + 1, b']') {
                None => {
                    // Separator found, closer missing: the ANSI form *is*
                    // fully bounded (by `ESC[[` and `|`), so it is safe to
                    // emit; the ASCII form is the dangling one and is
                    // dropped instead.
                    if ansi {
                        emit_form(&mut out, &input[form_start..sep]);
                    }
                    i = input.len();
                }
                Some(close) => {
                    if ansi {
                        emit_form(&mut out, &input[form_start..sep]);
                    } else {
                        emit_form(&mut out, &input[sep + 1..close]);
                    }
                    i = close + 1;
                }
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `ESC[[` anywhere: every byte, including an ordinary colour code,
    /// survives untouched. This is the "third byte" distinction
    /// (`ExportedModuleBase.cs:874`) exercised directly.
    #[test]
    fn passthrough_no_ifansi_unchanged() {
        let input = b"hello \x1b[1;37mworld\x1b[0m!";
        assert_eq!(process(input, true), input);
        assert_eq!(process(input, false), input);
    }

    /// The plan's own worked example: `ESC[1;37m` on the ANSI branch, the
    /// space/backspace fakery on the ASCII branch.
    #[test]
    fn basic_construct_ansi_and_ascii() {
        let input = b"\x1b[[\x1b[1;37m| \x08 \x08 \x08 \x08]";
        assert_eq!(process(input, true), b"\x1b[1;37m");
        assert_eq!(process(input, false), b" \x08 \x08 \x08 \x08");
    }

    /// The real `WCCMMUD.DLL` fixture backing "49,143 `ESC[79D`, paired with
    /// 49,143 `ESC[K`" in the plan's evidence table.
    #[test]
    fn real_fixture_79d_k() {
        let input = b"\x1b[[\x1b[79D\x1b[K| \x08 \x08 \x08 \x08]";
        assert_eq!(process(input, true), b"\x1b[79D\x1b[K");
    }

    /// Two constructs back to back, with ordinary text before, between, and
    /// after -- nothing bleeds from one construct's resolution into the
    /// next, and plain text is untouched.
    #[test]
    fn two_constructs_back_to_back_with_text_between() {
        let input = b"A\x1b[[\x1b[31m|R]B\x1b[[\x1b[32m|G]C";
        assert_eq!(process(input, true), b"A\x1b[31mB\x1b[32mC");
        assert_eq!(process(input, false), b"ARBGC");
    }

    /// `~|` inside a form yields a literal `|` and does not end the ANSI
    /// form early.
    #[test]
    fn tilde_escapes_pipe_inside_form() {
        let input = b"\x1b[[a~|b|ascii]";
        assert_eq!(process(input, true), b"a|b");
    }

    /// `~]` inside a form yields a literal `]` and does not close the
    /// construct early.
    #[test]
    fn tilde_escapes_bracket_inside_form() {
        let input = b"\x1b[[a~]b|ascii]tail";
        assert_eq!(process(input, true), b"a]btail");
    }

    /// `~~` yields exactly one literal `~`.
    #[test]
    fn tilde_escapes_tilde() {
        let input = b"\x1b[[a~~b|ascii]";
        assert_eq!(process(input, true), b"a~b");
    }

    /// Text after the closing `]` is ordinary text again, not consumed by
    /// the construct.
    #[test]
    fn text_after_closing_bracket_preserved() {
        let input = b"\x1b[[ansi|ascii]tail text";
        assert_eq!(process(input, true), b"ansitail text");
    }

    /// A form whose very first character is an unescaped special byte (here
    /// `]`, which does not end the ANSI-form search -- only an unescaped `|`
    /// does) must not panic. Case 2 in the module doc: position 0 can never
    /// be "escaped", so the leading `]` is dropped like any other unescaped
    /// syntax byte and the rest of the form is emitted normally.
    #[test]
    fn leading_special_char_in_form_no_panic() {
        let input = b"\x1b[[]xyz|rest]";
        assert_eq!(process(input, true), b"xyz");
    }

    /// A form that *opens* with a `~`-escaped special character -- the pair
    /// itself sits at the very start of the form, so resolving it exercises
    /// the same zero-index lookback as the previous test, just on the path
    /// that must emit a byte rather than drop one.
    #[test]
    fn tilde_escapes_bracket_at_form_start_no_panic() {
        let input = b"\x1b[[~]ok|ascii]";
        assert_eq!(process(input, true), b"]ok");
    }

    /// `ESC[[` as the very last three bytes of the input: the opener is
    /// complete and unambiguous, but there is no content, no separator, and
    /// no closer left to find. Case 3: dropped whole, no panic.
    #[test]
    fn truncated_opener_at_eof_consumed_silently() {
        let input = b"before\x1b[[";
        assert_eq!(process(input, true), b"before");
    }

    /// `ESC` or `ESC[` alone at the end of the input is ambiguous with an
    /// ordinary, harmlessly-truncated colour code -- it is not yet known to
    /// be an IF-ANSI opener, so it passes through literally instead of being
    /// consumed. Case 1 in the module doc.
    #[test]
    fn truncated_csi_prefix_passthrough() {
        assert_eq!(process(b"before\x1b", true), b"before\x1b");
        assert_eq!(process(b"before\x1b[", true), b"before\x1b[");
    }

    /// A construct with a separator but no closing `]`: the ANSI form is
    /// fully bounded (`ESC[[` ... `|`) and safe to emit even though the
    /// ASCII form trails off unterminated.
    #[test]
    fn unterminated_missing_close_ansi_mode_emits_complete_form() {
        let input = b"x\x1b[[\x1b[1;37m|abcdef";
        assert_eq!(process(input, true), b"x\x1b[1;37m");
    }

    /// Same input, ASCII branch: the form that branch would need is the
    /// unterminated one, so nothing is emitted for the construct at all.
    #[test]
    fn unterminated_missing_close_ascii_mode_emits_nothing_for_form() {
        let input = b"x\x1b[[\x1b[1;37m|abcdef";
        assert_eq!(process(input, false), b"x");
    }

    /// No unescaped `|` anywhere after the opener: neither form is ever
    /// bounded, so the whole construct -- opener included -- is dropped.
    #[test]
    fn unterminated_missing_separator_dropped_entirely() {
        let input = b"x\x1b[[no separator here at all";
        assert_eq!(process(input, true), b"x");
        assert_eq!(process(input, false), b"x");
    }
}
