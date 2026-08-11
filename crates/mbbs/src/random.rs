//! What MajorBBS's random numbers were made of.
//!
//! Two things live here, and both are recovered rather than invented: an
//! *algorithm*, from surviving source, and a *generator*, from surviving
//! machine code.
//!
//! # `genrdn` is a port
//!
//! [`between`] is `BBSUTILS.C:49` line for line -- the source survives, so this
//! is a translation rather than a reconstruction. Its oddities are the
//! original's: the upper bound is exclusive ("between min/max-1", says the
//! comment), a zero `max` answers zero before anything else happens, and an
//! empty range answers its own lower bound, which is outside the range the name
//! promises.
//!
//! # `rand` is disassembled out of the host binary itself
//!
//! **There is no `MAJORBBS.DLL`, and looking for one is the mistake.** The
//! 16-bit host is `MAJORBBS.EXE`: an NE *executable* whose module name is
//! `MAJORBBS` and which exports ~1,230 ordinals, which is what a module's
//! imports resolve against. Search `archive/` for a `.dll` and you conclude the
//! host binary was lost; it was not.
//!
//! Four versions are extracted to `re/hosts/` (gitignored, re-extractable), and
//! `rand` is intact in all four -- byte-identical but for where each build's
//! `RANDSEED` landed. **`wg200` and `wg101` are the version-matched ones**,
//! MajorMUD 1.11p being a Worldgroup module:
//!
//! ```text
//! MAJORBBS-wg200.EXE   @0x422a2   1996-03   <- matches MajorMUD
//! MAJORBBS-wg101.EXE   @0x420a2   1995-07   <- matches MajorMUD
//! MAJORBBS-eng201.EXE  @0x422c8   1996-06
//! MAJORBBS-mbbstd.EXE  @0x3c028   1993-08
//! ```
//!
//! Disassembled from `wg200`, which is the copy MajorMUD would have called:
//!
//! ```text
//! srand:
//!   8b 46 06            mov ax,[bp+6]          ; the 16-bit argument
//!   c7 06 0c 1b 00 00   mov word [0x1b0c],0    ; RANDSEED high := 0  -- zero-extended
//!   a3 0a 1b            mov [0x1b0a],ax        ; RANDSEED low  := it
//!
//! rand:
//!   8b 0e 0c 1b   mov cx,[0x1b0c]    ; RANDSEED, high half
//!   8b 1e 0a 1b   mov bx,[0x1b0a]    ; RANDSEED, low half
//!   ba 5a 01      mov dx,0x015a      ; \  0x015A4E35
//!   b8 35 4e      mov ax,0x4e35      ; /  = 22695477
//!   e8 b4 ff      call <long multiply>
//!   05 01 00      add ax,1           ; \  + 1
//!   83 d2 00      adc dx,0           ; /
//!   89 16 0c 1b   mov [0x1b0c],dx    ; \  store the new state
//!   a3 0a 1b      mov [0x1b0a],ax    ; /
//!   a1 0c 1b      mov ax,[0x1b0c]    ; return the HIGH word -- i.e. state >> 16
//!   25 ff 7f      and ax,0x7fff      ; masked to RAND_MAX
//! ```
//!
//! So `state = state * 22695477 + 1` returning `(state >> 16) & 0x7fff`, from a
//! seed zero-extended into the low half -- which is line for line
//! [`Random::new`] and [`Random::rand`] below. The `+ 1` increment, the *high*
//! half being the half handed back, the mask, and the zero-extension are each
//! read off an instruction rather than assumed. Those are exactly the details a
//! from-memory reconstruction of "the Borland LCG" gets wrong.
//!
//! Three unrelated period binaries carry the identical function, which is what
//! first established it before the host was located and is worth keeping as
//! corroboration: Galacticomm's own `wg300/WGDOS/REGDISK/INSTALL.EXE`, TTI's
//! `TTICWD.DLL`, and an Infinetwork addon.
//!
//! # What is still not pinned, and it is not the generator
//!
//! One thing, and it is not about this file: **the seed is the wall clock.**
//! MajorMUD calls `srand(time(NULL))` six calls into initialisation, so no two
//! boots of the *real* host produced the same numbers either. Nothing here
//! makes a world reproducible; that is a question about the clock.
//!
//! Note also that the meter cannot see any of this. Initialisation reaches the
//! same 8,546 calls and the same next stop under this generator, under the ANSI
//! LCG, and under a xorshift -- so the call count pins that `genrdn` *works*
//! and nothing about which numbers it returns. The tests below are the only
//! thing that pins those.

use std::fmt;

/// The largest number [`Random::rand`] can return.
///
/// 32767, and this is read off the instruction rather than inferred from
/// `RAND_MAX` being `0x7fff` on a 16-bit compiler: the recovered `rand` ends in
/// a literal `and ax,0x7fff` (`25 ff 7f`) in all three binaries. See the module
/// docs.
///
/// It is also the one property of the generator a module could *observe*, which
/// is why it would have mattered even without the disassembly: `lngrnd` takes a
/// `long` `max`, and `rand()%max` for a `max` above 32768 cannot exceed 32767 on
/// the first draw. A wider generator would answer numbers the original could
/// not produce.
pub const RAND_MAX: u16 = 0x7fff;

/// How many times [`between`]'s loop may go round before the host gives up.
///
/// Generous by a wide margin: reaching a `min` takes one pass with probability
/// `1 - min/max`, so ten thousand consecutive failures does not happen to a
/// working generator. It is here for the one that is not working.
const PATIENCE: u32 = 10_000;

/// `genrdn` or `lngrnd` could not reach the number it was asked for.
///
/// The loop `rnum += rand()%(max-rnum)` makes progress only when the generator
/// gives it something, and one that returns the same value forever would go
/// round forever. This runs on the *host* side of a module call, where
/// [`mbbs16`]'s watchdog does not reach, so an unbounded loop would hang the
/// process without saying anything -- which is the one outcome this crate never
/// accepts.
///
/// # Why the bounds are `i32` for a routine whose own are `i16`
///
/// [`between`] and [`between_long`] are the same algorithm over `int` and
/// `long` -- `BBSUTILS.C:49-66` and `:76-93` are the same nine statements with
/// the type changed -- so they share this one error rather than carrying a
/// near-identical pair. An `i16` bound widens into an `i32` field exactly, so
/// `genrdn`'s numbers survive it unchanged; the reverse would not, which is why
/// the widening goes this way round. `routine` is what keeps the message honest
/// about which of the two ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Runaway {
    /// `"genrdn"` or `"lngrnd"` -- the name the module actually called.
    pub routine: &'static str,
    pub min: i32,
    pub max: i32,
}

impl fmt::Display for Runaway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { routine, min, max } = self;
        write!(
            f,
            "{routine}({min}, {max}): {PATIENCE} draws never reached {min}, \
             so the generator is not generating"
        )
    }
}

/// Borland's `rand`, and the seed `srand` starts it from.
///
/// The state is a full 32 bits and only the top half is ever handed out. That
/// is what keeps the low bit usable -- an LCG's low bits of *state* are famously
/// periodic, but the returned value's bits are bits 16 and up, which are not.
/// Measured: 200,000 draws of `genrdn(0, 2)` gave `[99998, 100002]`, and the raw
/// low bit changed 100,028 times in 200,000 rather than the 199,999 an
/// alternating bit would give. A coin flip in MajorMUD is a fair one.
#[derive(Debug, Clone)]
pub struct Random {
    state: u32,
}

impl Random {
    /// Start from `seed`, as `srand` does.
    ///
    /// `RANDSEED` is a `long` and `srand` takes an `unsigned`, so the 16 bits
    /// the module supplies are the low half and the rest is zero. That is read
    /// off the host rather than inferred: `MAJORBBS.EXE` wg200 does
    /// `mov word [RANDSEED+2],0` before storing the argument into
    /// `[RANDSEED]`. Zeroed, not sign-extended.
    pub fn new(seed: u16) -> Self {
        Self {
            state: u32::from(seed),
        }
    }

    /// One number in `[0, RAND_MAX]`.
    pub fn rand(&mut self) -> u16 {
        self.state = self.state.wrapping_mul(22695477).wrapping_add(1);
        ((self.state >> 16) as u16) & RAND_MAX
    }

    /// `int genrdn(int min, int max)`.
    ///
    /// # Errors
    ///
    /// See [`Runaway`].
    pub fn genrdn(&mut self, min: i16, max: i16) -> Result<i16, Runaway> {
        between(&mut || self.rand(), min, max)
    }

    /// `long lngrnd(long min, long max)`.
    ///
    /// Draws from the same generator `genrdn` does -- there is one `RANDSEED`
    /// in the host and both routines call the same `rand` (measured: both
    /// relocate to segment 1 offset 0x2017). A module interleaving the two
    /// therefore sees one stream, not two.
    ///
    /// # Errors
    ///
    /// See [`Runaway`].
    pub fn lngrnd(&mut self, min: i32, max: i32) -> Result<i32, Runaway> {
        between_long(&mut || self.rand(), min, max)
    }
}

impl Default for Random {
    /// Seeded zero, which is what a host that has not been told anything has.
    ///
    /// `srand` is called six calls into MajorMUD's initialisation, so nothing
    /// real draws from this one -- but a generator that panicked until seeded
    /// would be a worse answer than one that starts somewhere.
    fn default() -> Self {
        Self::new(0)
    }
}

/// `genrdn`, over any source of numbers.
///
/// Taking the generator as an argument rather than reading `self` is what makes
/// [`Runaway`] reachable from a test: no seed makes the real generator stand
/// still, so the guard would otherwise be unprovable code.
///
/// **This never answers a negative number for a sane range**, and that is
/// structural rather than lucky. `next()` is masked to [`RAND_MAX`], so
/// `next() as i16` is always in `0..=32767` -- never negative, and never
/// `i16::MIN`, so `%` can neither take the sign of a negative dividend nor
/// overflow on `i16::MIN % -1`. `rnum` therefore starts at zero or above and
/// the loop only ever adds a non-negative remainder. A negative answer requires
/// `min < 0` *and* `min >= max`, which is the degenerate second branch handing
/// back its own argument -- exactly as the C does. Swept: every `(min, max)`
/// pair over a 613-value grid spanning `i16::MIN` to `i16::MAX`, and no
/// negative ever came out of the draw.
///
/// # Errors
///
/// See [`Runaway`].
pub fn between(next: &mut dyn FnMut() -> u16, min: i16, max: i16) -> Result<i16, Runaway> {
    // Both of the source's early exits, in its order. The `ASSERT(min <= max)`
    // between them is not reconstructible -- `galastfail` does not survive, and
    // what it does depends on an `astmode` global whose default does not either
    // -- but it cannot change the answer: every mode that returns at all
    // returns into the line below.
    if max == 0 {
        return Ok(0);
    }
    if min >= max {
        return Ok(min);
    }

    // `next()` is at most RAND_MAX, so it always fits an i16 and is never
    // negative; `%` therefore cannot make `rnum` negative either, and
    // `max - rnum` cannot overflow. Inside the loop `rnum < min < max`, so the
    // divisor is at least 2 and never zero.
    let mut rnum = (next() as i16) % max;
    for _ in 0..PATIENCE {
        if rnum >= min {
            return Ok(rnum);
        }
        rnum += (next() as i16) % (max - rnum);
    }
    Err(Runaway {
        routine: "genrdn",
        min: i32::from(min),
        max: i32::from(max),
    })
}

/// `lngrnd`, over any source of numbers. `BBSUTILS.C:76-93`.
///
/// [`between`] in `long` arithmetic, and that is not a family resemblance --
/// the two functions are the same nine statements with `int` changed to `long`
/// and `addrdn` changed to `addlng`. This is written out rather than shared
/// with [`between`] through a generic because the one place they *do* differ is
/// the interesting one, and a generic would hide it: see "The width is the
/// whole behaviour" below.
///
/// # Measured against the host, not inferred from the C alone
///
/// The archive has the C (`BBSUTILS.C:76-93`), and the compiled host agrees
/// with it -- but not obviously. `lngrnd` is ordinal 390 at segment 13 offset
/// 230 of `MAJORBBS-mbbstd.EXE`, and its two relocated `lcall`s resolve to
/// `rand` (segment 1 offset 0x2017, ordinal 486) and `lmod@`/`f_lmod@`
/// (segment 1 offset 0x1ce2, ordinals 655/667) -- Borland's long-modulo
/// helper, which is what `rand()%max` compiles to when `max` is a `long`. The
/// `cwd` between them is the `int`-to-`long` promotion of `rand`'s result.
///
/// The disassembly also settles a question the C would have left open. Its
/// early exit compiles to a bare **equality** test (`cmp`/`jne` on each half,
/// `FSD`-style, at offsets 0x104-0x10c) where the C says `if (min >= max)`.
/// That is not a divergence and the port follows the **C**: `ASSERT(min <= max)`
/// sits immediately above it (`BBSUTILS.C:84`), so Borland was entitled to fold
/// `>=` into `==`. `genrdn` compiles to exactly the same equality test from
/// exactly the same source, which is what proves the folding rather than
/// leaving it a guess about one function.
///
/// # The width is the whole behaviour
///
/// `rand()` answers `0..=RAND_MAX` whatever the caller's types are, so
/// `rand()%max` for any `max` above 32768 **is just `rand()`** -- the modulo
/// cannot bite. That is the one property a `long` version has and an `int`
/// version cannot, and it is exactly why [`RAND_MAX`]'s own doc comment calls
/// this the single observable property of the generator. A `lngrnd(0, 1000000)`
/// therefore never answers above 32767 on its first draw, and reaches larger
/// numbers only by the loop's repeated addition -- which it does only when
/// `min` demands it.
///
/// # Errors
///
/// See [`Runaway`].
pub fn between_long(next: &mut dyn FnMut() -> u16, min: i32, max: i32) -> Result<i32, Runaway> {
    // Both early exits, in the source's own order, exactly as `between` takes
    // them -- see that function on why the unreconstructible `ASSERT(min <= max)`
    // between them cannot change the answer.
    if max == 0 {
        return Ok(0);
    }
    if min >= max {
        return Ok(min);
    }

    // `next()` is at most RAND_MAX, so widening it to i32 is exact and never
    // negative; `%` therefore cannot make `rnum` negative and `max - rnum`
    // cannot overflow an i32 (both operands are non-negative here and `max` is
    // at most i32::MAX). Inside the loop `rnum < min < max`, so the divisor is
    // at least 2 and never zero -- the same argument `between` makes, and it
    // survives the widening because it rests on the ordering, not the width.
    let mut rnum = i32::from(next()) % max;
    for _ in 0..PATIENCE {
        if rnum >= min {
            return Ok(rnum);
        }
        rnum += i32::from(next()) % (max - rnum);
    }
    Err(Runaway {
        routine: "lngrnd",
        min,
        max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generator that has run out of ideas. The one input that makes
    /// `genrdn`'s loop go round forever, which is the only way to reach the
    /// guard.
    fn stuck() -> impl FnMut() -> u16 {
        || 0
    }

    #[test]
    fn the_upper_bound_is_exclusive_and_the_lower_one_is_not() {
        // "Create a random number between min/max-1", says BBSUTILS.C:49, and
        // it means it: `rand()%max` cannot reach `max`, and neither can any
        // number of `+= rand()%(max-rnum)` after it.
        let mut r = Random::new(1);
        for _ in 0..10_000 {
            let n = r.genrdn(5, 9).expect("a number");
            assert!((5..9).contains(&n), "{n} is outside 5..9");
        }
    }

    #[test]
    fn every_value_in_the_range_comes_up() {
        // A generator that answered a constant would pass the bounds test
        // above. This is what says it is a generator.
        let mut r = Random::new(1);
        let mut seen = [false; 4];
        for _ in 0..10_000 {
            seen[usize::from(r.genrdn(5, 9).expect("a number") as u16 - 5)] = true;
        }
        assert_eq!(seen, [true; 4]);
    }

    #[test]
    fn a_zero_maximum_is_zero_rather_than_an_error() {
        // The first line of the routine, before even the assertion.
        let mut r = Random::new(1);
        assert_eq!(r.genrdn(0, 0), Ok(0));
        assert_eq!(r.genrdn(7, 0), Ok(0), "min is not consulted");
    }

    #[test]
    fn an_empty_range_answers_its_own_lower_bound() {
        // Which is outside the range the name promises, and is what the source
        // does. `ASSERT(min <= max)` fires first on the real host and changes
        // nothing about the answer.
        let mut r = Random::new(1);
        assert_eq!(r.genrdn(9, 9), Ok(9));
        assert_eq!(r.genrdn(12, 4), Ok(12));
    }

    #[test]
    fn a_negative_lower_bound_is_clamped_away_rather_than_honoured() {
        // The one place the eight lines differ from `min + rand()%(max-min)`,
        // which is otherwise the same distribution. `rand()%max` is never
        // negative, so it already satisfies a negative `min` and the loop never
        // runs. Simplifying this routine to one modulo would answer -5..=2 here.
        let mut r = Random::new(1);
        for _ in 0..1000 {
            let n = r.genrdn(-5, 3).expect("a number");
            assert!((0..3).contains(&n), "{n} is outside 0..3");
        }
    }

    #[test]
    fn the_same_seed_is_the_same_sequence() {
        // The whole point of `srand` storing anything.
        let draw = |seed| {
            let mut r = Random::new(seed);
            (0..20).map(|_| r.rand()).collect::<Vec<_>>()
        };
        assert_eq!(draw(40615), draw(40615));
        assert_ne!(draw(40615), draw(40616));
    }

    #[test]
    fn nothing_ever_comes_back_wider_than_a_borland_int() {
        // RAND_MAX is 32767 on a 16-bit compiler, and it is the one property of
        // the generator a module could observe -- through `lngrnd`, whose `max`
        // is a `long`. See the plan.
        let mut r = Random::new(40615);
        for _ in 0..100_000 {
            assert!(r.rand() <= RAND_MAX);
        }
    }

    #[test]
    fn the_long_upper_bound_is_exclusive_and_the_lower_one_is_not() {
        // BBSUTILS.C:76-93 is BBSUTILS.C:49-66 with the type changed, so every
        // promise the int version makes the long version makes too.
        let mut r = Random::new(1);
        for _ in 0..10_000 {
            let n = r.lngrnd(5, 9).expect("a number");
            assert!((5..9).contains(&n), "{n} is outside 5..9");
        }
    }

    #[test]
    fn a_zero_long_maximum_is_zero_and_an_empty_long_range_is_its_lower_bound() {
        let mut r = Random::new(1);
        assert_eq!(r.lngrnd(0, 0), Ok(0));
        assert_eq!(r.lngrnd(7, 0), Ok(0), "min is not consulted");
        assert_eq!(r.lngrnd(9, 9), Ok(9));
        assert_eq!(r.lngrnd(12, 4), Ok(12), "min >= max, per the C's own >=");
    }

    #[test]
    fn a_range_wider_than_rand_max_cannot_exceed_it_on_the_first_draw() {
        // The one property `lngrnd` has that `genrdn` cannot: `rand()` answers
        // 0..=32767 whatever the argument types are, so `rand()%max` for a max
        // above 32768 is just `rand()` -- the modulo never bites. With min 0 the
        // loop never runs, so the whole routine is that single draw and nothing
        // above RAND_MAX can ever come out, however wide the range.
        //
        // This is the assertion that would fail against a "wider generator", and
        // RAND_MAX's own doc comment calls it the single observable property of
        // the generator for exactly that reason.
        let mut r = Random::new(1);
        for _ in 0..20_000 {
            let n = r.lngrnd(0, 1_000_000).expect("a number");
            assert!(
                (0..=i32::from(RAND_MAX)).contains(&n),
                "{n} is above RAND_MAX, so the draw was not one rand()"
            );
        }
    }

    #[test]
    fn a_wide_range_reaches_past_rand_max_only_by_accumulating() {
        // The complement of the test above: a `min` beyond RAND_MAX is
        // unreachable in one draw, so the loop's `rnum += rand()%(max-rnum)` is
        // the only thing that can satisfy it. If the loop were dropped this
        // would answer something below 100_000 every time.
        let mut r = Random::new(1);
        for _ in 0..2_000 {
            let n = r.lngrnd(100_000, 1_000_000).expect("a number");
            assert!(
                (100_000..1_000_000).contains(&n),
                "{n} is outside 100_000..1_000_000"
            );
        }
    }

    #[test]
    fn the_long_routine_and_the_int_one_agree_on_a_range_that_fits_both() {
        // Same source, same generator, same stream -- so over a range an i16 can
        // hold, the two must produce identical sequences draw for draw. This is
        // what says `between_long` is a port of the same nine statements rather
        // than a lookalike that happens to land in range.
        let mut a = Random::new(12345);
        let mut b = Random::new(12345);
        for i in 0..5_000 {
            let wide = a.lngrnd(-40, 300).expect("a number");
            let narrow = b.genrdn(-40, 300).expect("a number");
            assert_eq!(wide, i32::from(narrow), "diverged at draw {i}");
        }
    }

    #[test]
    fn a_stuck_generator_is_refused_for_the_long_routine_and_named_as_such() {
        // The Runaway guard is shared, so the routine name is the only thing
        // telling the operator which of the two actually ran.
        assert_eq!(
            between_long(&mut stuck(), 5, 9),
            Err(Runaway {
                routine: "lngrnd",
                min: 5,
                max: 9
            })
        );
        let said = format!(
            "{}",
            between_long(&mut stuck(), 5, 9).expect_err("refused")
        );
        assert!(said.starts_with("lngrnd("), "{said}");
    }

    #[test]
    fn a_generator_that_never_moves_is_refused_rather_than_spun_on() {
        // `rnum += rand()%(max-rnum)` with a generator stuck at zero adds
        // nothing, forever. On the host side of a call there is no watchdog, so
        // an unbounded loop here hangs the process with no diagnostic.
        assert_eq!(
            between(&mut stuck(), 5, 9),
            Err(Runaway {
                routine: "genrdn",
                min: 5,
                max: 9
            })
        );
    }

    #[test]
    fn the_refusal_says_what_was_asked_for() {
        let e = between(&mut stuck(), 5, 9).expect_err("refused");
        let said = format!("{e}");
        assert!(said.contains('5') && said.contains('9'), "{said}");
    }
}
