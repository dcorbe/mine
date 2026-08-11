//! The `ESC[[ansi|ascii]` construct: IF-ANSI.
//!
//! Undocumented in the recovered Galacticomm sources (searched, absent from
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/`); the name and the only
//! recovered implementation come from MBBSEmu's `ProcessIfANSI`, mirrored in
//! this repo at
//! `docs/mirrors/github-mbbsemu-MBBSEmu/MBBSEmu/HostProcess/ExportedModules/ExportedModuleBase.cs:857-937`.
//! This module is a from-scratch port of that algorithm, not a
//! transliteration of the C# -- see "Where this differs from
//! `ProcessIfANSI`" below. There is more than one place that matters; an
//! earlier revision of this doc claimed bounds-checking was "the one place
//! that matters" and that claim was false (Important finding #2 in the
//! commit that fixed this paragraph) -- read the whole section.
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
//! # Fixed: two lookbacks, one escape rule
//!
//! An earlier revision of this module (`38b57ee`) implemented [`emit_form`]
//! and [`find_unescaped`] as two independent stateless one-byte lookbacks:
//! each decided whether `input[k]` was "escaped" by checking `input[k - 1]
//! == b'~'` on its own, with no memory of whether that preceding `~` had
//! *already* been consumed as the escapee half of an earlier pair. Reading
//! `~` left to right, pairwise, means a `~` that just finished escaping the
//! byte after it is spent -- it cannot also escape the byte after *that*.
//! The lookback had no way to know it was spent, so it did not enforce that:
//!
//! - `a~~~b`: the first `~` escapes the second (`~` -> literal `~`), leaving
//!   an unpaired third `~` before `b`, which is syntax and contributes
//!   nothing. Correct answer: `a~b`. The lookback let the *second* `~` --
//!   already spent pairing with the first -- also escape the third, yielding
//!   `a~~b`.
//! - `a~~|b`: same reasoning, but the byte after the unpaired-syntax `~` is
//!   a real, unescaped `|`. `find_unescaped` used the identical lookback and
//!   made the identical mistake, reporting the `|` as escaped when it was
//!   not -- which meant *no* separator was found at all, and the whole
//!   surrounding construct (plus, before the fix below, everything after
//!   it) was dropped.
//!
//! Both call sites now share [`next_token`], a single forward-only scan:
//! walk the buffer one token at a time, where a token is either an ordinary
//! byte or a `~`-plus-escapee pair, and always advance by exactly how much
//! that token consumed. A spent `~` is never revisited, because the scan
//! only ever looks *forward* from a token boundary -- there is no lookback
//! left to disagree with itself. See [`next_token`]'s doc for the exact
//! rule, and `double_tilde_then_real_separator_is_not_mistaken_for_escaped`
//! / `triple_tilde_does_not_reuse_a_consumed_escaper` /
//! `four_tildes_are_two_independent_pairs` in the test module for the fixed
//! behaviour.
//!
//! `ExportedModuleBase.cs:900-917` (the C# form-resolution loop) has this
//! identical flaw -- it is also a backward lookback, `substringSpan[j - 1]
//! == '~'`, with the same inability to tell a spent `~` from a fresh one.
//! This is a deliberate non-reproduction, not an oversight: see "Where this
//! differs from `ProcessIfANSI`" below.
//!
//! # Where this differs from `ProcessIfANSI`: unterminated input
//!
//! `ProcessIfANSI` bounds-checks nothing. Four ways malformed module output
//! reach it unpunished today and would not survive a direct port. In .NET,
//! `ReadOnlySpan<byte>` indexing is bounds-checked, so each of these is an
//! unhandled `IndexOutOfRangeException` -- a crash -- not a silent
//! out-of-bounds read:
//!
//! 1. `ESC[[` with fewer than two more bytes in the buffer -- `inputSpan[i + 2]`
//!    throws.
//! 2. A form whose *first* character is an unescaped `|`, `]`, or `~` --
//!    `substringSpan[j - 1]` at `j == 0` throws.
//! 3. A construct with no closing `]` before the input ends -- this one
//!    happens not to throw (the search loops terminate on `substringEnd`/`i`
//!    reaching `inputSpan.Length`), but it relies on the same unchecked
//!    indexing as the other two, not on anything that guarantees safety.
//! 4. The global `~~` check at `:867` (see the next section) reads
//!    `inputSpan[i + 1]` unconditionally once `inputSpan[i] == '~'` -- a `~`
//!    as the very last byte of the input throws.
//!
//! This host's rule, matching every other shim in this crate (see the module
//! doc on `crates/mbbs/src/lib.rs`, "A shim that lies is worse than one that
//! refuses"): malformed *module* output must not take the *board* down.
//! `mbbs16`'s watchdog does not reach code running on the host side of a
//! call, so an index panic here would kill the process for every connected
//! player over a single bad string, not just the channel that triggered it.
//! [`process`] therefore bounds-checks every index and defines an answer for
//! each of the first three cases above (case 4 does not arise -- see the
//! next section), rather than reproducing the crash:
//!
//! - **Case 1** (truncated opener): if the input ends before `ESC[[`'s third
//!   byte is even present to inspect, it is indistinguishable from an
//!   ordinary, harmless `ESC[...` sequence that also happens to be cut off --
//!   so it is left alone. The `ESC` (and, if present, the following `[`) are
//!   copied through literally, one byte at a time, exactly as an ordinary
//!   truncated CSI code already is (this module never touches those).
//!   *But* if all three opener bytes (`ESC[[`) are present and only the
//!   *content* runs out, the opener is no longer ambiguous -- see case 3.
//! - **Case 2** (leading special character in a form): [`next_token`] never
//!   looks backward at all, so there is no "preceding byte" to read out of
//!   range in the first place -- see [`next_token`]'s doc. This is not
//!   merely the bounds-safe version of `ProcessIfANSI`'s check, it is the
//!   *semantically correct* one: an escape's `~` has to be payload *inside*
//!   the form for it to mean anything, and there is no room inside the form
//!   before its own first character. So position 0 of a form can never be
//!   "the char after a `~`", which is exactly what a forward-only scan says
//!   by construction.
//! - **Case 3** (no closing `]`, or no separating `|` at all): a *form* is
//!   only ever emitted when it is bounded by real, present delimiters on
//!   *both* sides -- a dangling ANSI or ASCII form, one whose closing `|` or
//!   `]` never arrives before the input does, is never emitted
//!   half-finished. But the raw bytes that would have made up that
//!   unbounded form are not thereby escape-sequence content: they are prose
//!   that happened to follow a stray opener (or a stray separator), and
//!   [`process`] emits them as plain text rather than discarding them.
//!
//!   This is narrower than it sounds: it is *only* safe because IF-ANSI
//!   syntax bytes (`|`, `]`, `~`) never survive into the output on their
//!   own -- an unresolved form's `|`/`]`/`~` bytes are simply passed through
//!   raw, exactly as ordinary punctuation would be, and any `ESC[...`
//!   sequence embedded in that raw tail is left untouched because
//!   [`process`] never re-scans a byte it has already committed to the
//!   output buffer. Compare this to the reasoning this replaced: a
//!   truncated escape sequence left dangling on the wire (say, the module
//!   was cut off mid `ESC[1;37` with no final letter) really can make a
//!   terminal treat the *next* legitimate output as parameters to that
//!   dangling CSI -- but that hazard is about an *actually incomplete*
//!   terminal escape code, which is not what a merely-unbounded IF-ANSI form
//!   is. Silently eating unrelated trailing prose to guard against a
//!   different, unrelated failure mode was the bug (Important finding #1);
//!   see [`process`]'s `None` arms for the exact rule, and its tests --
//!   `stray_opener_in_prose_drops_only_the_opener`,
//!   `unterminated_missing_close_ansi_mode_emits_form_and_trailing_text`,
//!   `unterminated_missing_close_ascii_mode_emits_trailing_text_only`,
//!   `unterminated_missing_separator_drops_opener_but_keeps_trailing_text` --
//!   for what each of the four delimiter combinations now produces.
//!
//! None of this is reachable through `mbbs-server` today either -- the
//! module only ever emits well-formed constructs, which is exactly why the
//! 269 occurrences in `WCCMMUD.DLL` all round-trip through [`process`] and
//! zero of them are why this section exists. It exists because "the host
//! never sends garbage" is a claim about `WCCMMUD.DLL`, not a bound this
//! function can assume of every module that will ever run under it.
//!
//! # Where this differs from `ProcessIfANSI`: two deliberate divergences
//!
//! Bounds-checking (above) is not the only place this module departs from
//! `ProcessIfANSI` -- it is simply the only place the *previous* revision of
//! this doc mentioned, and that was an incomplete (and, in its "the one
//! place that matters" framing, false) claim. Two further divergences,
//! verified against the C# source and against the running Rust, are
//! deliberate and are not bugs to fix:
//!
//! - **`ExportedModuleBase.cs:866-869` collapses `~~` -> `~` globally**, for
//!   *every* byte in the input stream, not just inside an IF-ANSI form:
//!   `if (inputSpan[i] == '~' && inputSpan[i + 1] == '~') i++;` runs on the
//!   `inputSpan[i] != 0x1B` branch of the main loop, which is every byte
//!   that is not part of an escape sequence at all. [`process`] does not
//!   replicate this: `~` has meaning only inside a form's delimiters, and
//!   nowhere else. `a~~b` typed as ordinary game text is two literal tildes
//!   followed by `b`, not one -- replicating the global collapse would
//!   corrupt any ordinary prose that happens to contain a double tilde, for
//!   the sake of matching a construct (IF-ANSI) that was never present in
//!   that text to begin with. Locked in by
//!   `double_tilde_outside_construct_is_unchanged`.
//! - **`ExportedModuleBase.cs:874` writes `ESC` only when it is followed by
//!   `[`**: `if (inputSpan[i] == 0x1B && inputSpan[i + 1] == '[' &&
//!   inputSpan[i + 2] != '[')`. A bare `ESC` not starting *any* CSI sequence
//!   -- followed by neither `[` nor end-of-input -- fails every branch of
//!   `ProcessIfANSI`'s `i`-loop and is silently dropped: `X\x1bQY` becomes
//!   `XQY` in C#. [`process`] preserves it: `X\x1bQY` stays `X\x1bQY`,
//!   because the only condition under which this module treats `ESC` as
//!   "part of something else" is when a second `[` is truly next (IF-ANSI)
//!   or plausibly next (an ordinary CSI code, including one cut off before
//!   its `[`, per case 1 above). A bare `ESC` that starts nothing is just a
//!   byte, and dropping a byte the module actually sent is data loss this
//!   host does not accept from any shim (same rationale as the bounds-check
//!   rule above, restated: a shim that lies is worse than one that refuses --
//!   here, "lies" means "silently discards").
//!
//! Both are intentional: this module's behaviour is right in both cases and
//! the C#'s is not something a from-scratch port should aim to reproduce.

/// Interpret one position of IF-ANSI's `~` escape syntax, left to right.
///
/// `pos` must be the start of a token -- either `0`, or `pos` from a
/// previous call plus the `consumed` it returned. Given that, this decides
/// what `input[pos]` (and possibly `input[pos + 1]`) mean, without ever
/// looking backward: a `~` immediately followed by `|`, `]`, or `~` is one
/// escape pair, consumed together; anything else is a single byte.
///
/// Returns `(consumed, resolved)`. `consumed` is `2` for an escape pair, `1`
/// otherwise. `resolved` is `Some(byte)` for literal content -- an ordinary
/// byte, or the escapee half of a pair, emitted as itself -- and `None` for
/// IF-ANSI's own syntax: an unescaped `|`, `]`, or a `~` that is not the
/// escaper half of a pair (either because nothing follows it, or because
/// what follows it is not `|`, `]`, or `~`). Syntax bytes contribute nothing
/// to the output.
///
/// This is the *only* place that decides escapedness, and both
/// [`emit_form`] and [`find_unescaped`] are built on it -- see the module
/// doc, "Fixed: two lookbacks, one escape rule", for why a single forward
/// scan is load-bearing here and a backward lookback is not: advancing by
/// `consumed` means a `~` that was just spent pairing with the byte after it
/// is never visited again as a token start, so it can never be reread as the
/// escaper for the *next* byte too.
fn next_token(input: &[u8], pos: usize) -> (usize, Option<u8>) {
    debug_assert!(pos < input.len(), "next_token called past the end of input");
    let c = input[pos];
    if c == b'~' {
        if let Some(&next) = input.get(pos + 1)
            && matches!(next, b'|' | b']' | b'~')
        {
            return (2, Some(next));
        }
        // Lone or trailing `~`: nothing eligible follows it to escape, so
        // it is IF-ANSI syntax like any other unescaped `~` -- dropped, not
        // emitted. (This is also what a `~~` pair's *first* `~` becomes:
        // never inspected on its own, because the pair consumes it as part
        // of `consumed == 2` before a later call could ever land on it.)
        return (1, None);
    }
    if matches!(c, b'|' | b']') {
        return (1, None); // unescaped syntax byte
    }
    (1, Some(c))
}

/// Resolve one IF-ANSI construct's chosen form, applying the `~` escape.
///
/// `form` is the raw bytes between the construct's delimiters (between
/// `ESC[[` and the `|`, or between the `|` and the `]`) -- already known to
/// be complete, since [`process`] never calls this on a form it could not
/// bound on both sides. Built entirely on [`next_token`]: walk `form` left
/// to right one token at a time, and emit whatever each token resolves to.
///
/// Scanning `form` rather than the surrounding buffer is what makes case 2
/// in the module doc's "Where this differs from `ProcessIfANSI`" section
/// correct rather than merely bounds-safe: a token can never start at a
/// negative offset, because there is no such thing as "the byte before
/// `form[0]`" -- it is simply outside the slice `next_token` ever sees.
fn emit_form(out: &mut Vec<u8>, form: &[u8]) {
    let mut j = 0;
    while j < form.len() {
        let (consumed, resolved) = next_token(form, j);
        if let Some(b) = resolved {
            out.push(b);
        }
        j += consumed;
    }
}

/// Find the first unescaped `target` byte (`|` or `]`) in `input` at or
/// after `start`.
///
/// Built on [`next_token`]: walk `input` left to right one token at a time,
/// starting at `start`, and report the position of the first token that is
/// both single-byte (`consumed == 1`) and IF-ANSI syntax (`resolved ==
/// None`) whose byte is `target`. A `target` byte that is instead the
/// escapee half of a `~`-pair resolves to `Some`, not `None`, so it is
/// walked past like any other literal content -- it is never considered a
/// separator or closer, which is exactly the property the two-copies bug
/// broke (see the module doc).
///
/// `start` need not be positive and `input[start - 1]` is never read --
/// unlike the version this replaced, there is no backward-lookback
/// precondition to violate here. Returns `None` if `target` never appears,
/// unescaped, before `input` ends.
fn find_unescaped(input: &[u8], start: usize, target: u8) -> Option<usize> {
    debug_assert!(matches!(target, b'|' | b']'), "target must be `|` or `]`");
    let mut j = start;
    while j < input.len() {
        let (consumed, resolved) = next_token(input, j);
        if resolved.is_none() && input[j] == target {
            return Some(j);
        }
        j += consumed;
    }
    None
}

/// Resolve every `ESC[[ansi|ascii]` construct in `input`, keeping the ANSI
/// form when `ansi` is true and the ASCII form otherwise; every other byte,
/// including ordinary `ESC[...` colour codes, passes through unchanged.
///
/// This is `ProcessIfANSI` (`ExportedModuleBase.cs:857-937`), reimplemented
/// with the branch it declares but never takes, and with bounds checks on
/// every index it does not have. See the module doc for both, and for the
/// two further, deliberate divergences beyond bounds-checking.
///
/// Returns an owned `Vec<u8>` rather than borrowing because the result is
/// always the same length as `input` or shorter (every byte in `out` is
/// copied from `input`, some are dropped as punctuation or an unchosen
/// form, and none are ever added or duplicated), and callers hand the
/// result straight to `append`, which wants an owned buffer to write into
/// `prfbuf` anyway.
///
/// Nesting (an `ESC[[...]` construct embedded inside another one's form) is
/// not part of IF-ANSI's spec and is unreachable through `WCCMMUD.DLL`; this
/// function has no notion of construct depth and does not attempt to detect
/// or reject it -- see `nested_construct_is_a_known_unsupported_limitation`
/// in the test module for the exact (unsupported, not corrected) behaviour
/// this produces, kept as a locked-in regression test rather than a silent
/// "works by accident."
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
                // construct's ANSI form was never bounded on the right, so
                // it can never be resolved. Only the `ESC[[` opener --
                // which really was the start of an escape attempt -- is
                // dropped; everything after it never became part of any
                // form, so it is not escape-sequence content to discard.
                // It survives as plain text. See the module doc, case 3.
                out.extend_from_slice(&input[form_start..]);
                i = input.len();
            }
            Some(sep) => match find_unescaped(input, sep + 1, b']') {
                None => {
                    // Separator found, closer missing: the ANSI form *is*
                    // fully bounded (by `ESC[[` and `|`), so it is emitted
                    // when selected. The ASCII form is not bounded on
                    // either branch -- there is no closer to bound it
                    // against -- so, like the no-separator case above, its
                    // raw bytes are not resolved-form content on *either*
                    // branch; they survive as trailing text regardless of
                    // `ansi`.
                    if ansi {
                        emit_form(&mut out, &input[form_start..sep]);
                    }
                    out.extend_from_slice(&input[sep + 1..]);
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

    /// Critical bug #1 (found by execution, `38b57ee` review): a `~~` pair
    /// followed immediately by an unescaped `|` inside the ANSI form. The
    /// `~~` is one consumed escape (a literal `~`), which means the `|`
    /// right after it is a *real*, unescaped separator -- not the escapee
    /// half of a second pair reusing the same `~`. The old stateless
    /// one-byte lookback (`x[j-1] == b'~'`) could not tell the difference:
    /// it saw `input[sep-1] == b'~'` and wrongly called the separator
    /// escaped, found no separator at all, and dropped the entire
    /// construct plus everything after it.
    #[test]
    fn double_tilde_then_real_separator_is_not_mistaken_for_escaped() {
        let input = b"\x1b[[a~~|b]TAIL";
        assert_eq!(process(input, true), b"a~TAIL");
    }

    /// Critical bug #2 (found by execution): three consecutive `~` inside a
    /// form. Read pairwise left to right, `~~` is one literal `~` and the
    /// third, unpaired `~` is dangling syntax that contributes nothing --
    /// `a~~~b` -> `a~b`. The old `emit_form` decided escapedness with a
    /// backward lookback at each `~` individually, so the *second* `~`
    /// (already spent pairing with the first) could be reused as the
    /// escaper for the third, yielding the wrong `a~~b`.
    #[test]
    fn triple_tilde_does_not_reuse_a_consumed_escaper() {
        let input = b"\x1b[[a~~~b|ascii]";
        assert_eq!(process(input, true), b"a~b");
    }

    /// Four consecutive `~` is two independent pairs: `a~~~~b` -> `a~~b`,
    /// not `a~~~b` (the old buggy result, per the finding's own worked
    /// example).
    #[test]
    fn four_tildes_are_two_independent_pairs() {
        let input = b"\x1b[[a~~~~b|ascii]";
        assert_eq!(process(input, true), b"a~~b");
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
    /// ASCII form trails off unterminated. `abcdef` was never part of any
    /// resolved form (there is no closer to bound it against), so it is not
    /// escape-sequence content to drop -- it is plain trailing text and
    /// survives, same as it would if the construct were never there.
    ///
    /// CHANGED from the original Task 1 landing (`38b57ee`), which asserted
    /// `x\x1b[1;37m` here -- i.e. that `abcdef` was silently discarded. That
    /// was the bug in Important finding #1: this arm did `i = input.len()`
    /// without emitting the unconsumed tail. See the module doc, "Where
    /// this differs from `ProcessIfANSI`", case 3.
    #[test]
    fn unterminated_missing_close_ansi_mode_emits_form_and_trailing_text() {
        let input = b"x\x1b[[\x1b[1;37m|abcdef";
        assert_eq!(process(input, true), b"x\x1b[1;37mabcdef");
    }

    /// Same input, ASCII branch: the form that branch would need is the
    /// unterminated one, so no *form* is emitted for the construct -- but
    /// `abcdef` is still plain trailing text, independent of which branch
    /// is active, and survives.
    ///
    /// CHANGED from `38b57ee`, which asserted `x` here (dropping `abcdef`).
    /// See the previous test and Important finding #1.
    #[test]
    fn unterminated_missing_close_ascii_mode_emits_trailing_text_only() {
        let input = b"x\x1b[[\x1b[1;37m|abcdef";
        assert_eq!(process(input, false), b"xabcdef");
    }

    /// No unescaped `|` anywhere after the opener: neither form is ever
    /// bounded, so the `ESC[[` opener itself is dropped (it really was the
    /// start of an escape attempt) -- but everything after it is prose that
    /// happens to follow a stray opener, not escape-sequence content, and
    /// survives untouched on both branches.
    ///
    /// CHANGED from `38b57ee`, which asserted `x` here for both branches
    /// (dropping the entire tail, including plain text with no `~`, `|`, or
    /// `]` in it at all). See Important finding #1: the module's own stated
    /// rationale for dropping unterminated content -- a dangling CSI
    /// fragment could swallow later output -- does not apply to prose that
    /// was never part of any escape sequence.
    #[test]
    fn unterminated_missing_separator_drops_opener_but_keeps_trailing_text() {
        let input = b"x\x1b[[no separator here at all";
        assert_eq!(process(input, true), b"xno separator here at all");
        assert_eq!(process(input, false), b"xno separator here at all");
    }

    /// The exact fixture from Important finding #1: a stray `ESC[[` in the
    /// middle of ordinary game text, with no separator ever following.
    /// Everything before and after the dropped opener survives.
    #[test]
    fn stray_opener_in_prose_drops_only_the_opener() {
        let input = b"you see a door.\x1b[[and then nothing";
        assert_eq!(
            process(input, true),
            b"you see a door.and then nothing".as_slice()
        );
    }

    /// `~~` outside any `ESC[[...]` construct is ordinary text -- the `~`
    /// escape is IF-ANSI form syntax and has no meaning anywhere else in the
    /// stream. Locks in Minor finding #6 and the deliberate divergence from
    /// `ProcessIfANSI` documented as Important finding #2: `ExportedModuleBase.cs:866-869`
    /// collapses `~~` -> `~` for *every* byte in the stream, which this host
    /// does not replicate because it would corrupt ordinary prose.
    #[test]
    fn double_tilde_outside_construct_is_unchanged() {
        let input = b"a~~b";
        assert_eq!(process(input, true), input);
        assert_eq!(process(input, false), input);
    }

    /// An explicit empty ANSI form: the separator immediately follows the
    /// opener, so the ANSI form is the empty slice between them. Already
    /// correct before this fix; Minor finding #6 asks to lock it in.
    #[test]
    fn empty_ansi_form() {
        let input = b"\x1b[[|ascii]";
        assert_eq!(process(input, true), b"");
        assert_eq!(process(input, false), b"ascii");
    }

    /// Nesting is not part of IF-ANSI's spec and unreachable through
    /// `WCCMMUD.DLL` (Important finding #3): `find_unescaped` has no notion
    /// of construct depth, so an inner `ESC[[...]` embedded in an outer
    /// form's content is not recognized as nested -- it is just more bytes
    /// to scan through looking for the *outer* construct's own `|` and `]`.
    /// Here that means the outer separator search stops at the *inner*
    /// construct's `|`, and the outer closer search stops at the inner
    /// construct's `]`, splicing the two forms together and leaking the
    /// inner `ESC[[` and the un-consumed `b|ascii]` as raw output. This is
    /// a named known limitation, not a bug fix -- this test locks in the
    /// current (unsupported) behaviour so a future change to it is a
    /// deliberate, visible decision rather than a silent regression.
    #[test]
    fn nested_construct_is_a_known_unsupported_limitation() {
        let input = b"\x1b[[a\x1b[[nested|n2]b|ascii]";
        assert_eq!(process(input, true), b"a\x1b[[nestedb|ascii]".as_slice());
    }
}
