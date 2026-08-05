//! Borland's `printf`, over a 16-bit module's arguments.
//!
//! `spr`, `sprintf`, `prf` and `shocst` are all one engine and a different
//! destination, so this is written once and a bug here is a bug in all of them.
//!
//! # Where the arguments are
//!
//! cdecl pushes right to left, so a varargs routine's arguments sit above its
//! call frame in declaration order and the format string is the only one whose
//! position is known. Everything after it is found by *reading the format
//! string* -- there is no other record of how many there are or how wide each
//! is. A conversion that consumes the wrong number of words does not fail; it
//! shifts every argument after it, and the output looks like data.
//!
//! A `v`-spelled routine is handed an [`Args::List`] instead: a `va_list`
//! pointing at the *caller's* frame, whose words are laid out identically. The
//! walk below cannot tell the difference and must not have to.
//!
//! Widths follow from the model Galacticomm built with, which is Borland's
//! **huge**: an `int` is one word, a `long` two, and `char *` is *far* and
//! therefore two. `%Ns` and `%Fs` say so explicitly and are honoured, because a
//! near pointer read as a far one would eat the next argument as its selector.
//!
//! # A conversion this does not know is an error
//!
//! Not a passthrough and not an empty string. An unimplemented conversion has
//! already consumed the wrong number of arguments by the time anyone notices,
//! so it stops the module instead -- the same rule as everything else here.

use mbbs16::{FarPtr, Machine};

use crate::shims::ShimError;

/// Where a `printf` walk reads its arguments from.
///
/// `printf` and `vprintf` are one engine over two argument sources, and the
/// only thing that differs between them is where word `n` of the variadic list
/// is found. Naming the source rather than passing a word index keeps that the
/// *only* difference: every conversion, width and pointer rule below is written
/// once, and both spellings get the same one.
#[derive(Debug, Clone, Copy)]
pub enum Args {
    /// The outstanding call's own stack, from argument word `first` on.
    ///
    /// What `prf`, `spr`, `sprintf`, `fprintf`, `shocst` and `prfmsg` have: the
    /// variadic arguments follow the fixed ones in the same frame. `first`
    /// counts argument *words* and not arguments, because a far `char *` is two
    /// of them and a near one is not.
    Call { first: usize },

    /// A `va_list`: consecutive words from a far pointer into module memory.
    ///
    /// Borland's `va_list` is `void *`, which under the huge model is far, and
    /// `va_start` sets it to the address just past the last fixed argument --
    /// so it points into the *caller's* frame in `SS` and the words behind it
    /// are laid out exactly as [`Args::Call`]'s are.
    List { at: FarPtr },
}

impl Args {
    /// Word `n` of the variadic list, counting from its first word.
    ///
    /// # Errors
    ///
    /// If a `va_list` names nothing of the module's, or walks off the end of
    /// what it names. Neither can happen to [`Args::Call`]: those words are the
    /// frame the host was called through.
    ///
    /// # Panics
    ///
    /// [`Args::Call`] panics if the module is not stopped at a call, since that
    /// is where its arguments are. [`Args::List`] does not need a frame at all.
    fn word(self, machine: &Machine, n: usize) -> Result<u16, ShimError> {
        match self {
            Self::Call { first } => Ok(machine.arg_u16(first + n)),
            Self::List { at } => {
                // A `va_list` that walks past 0xffff has left its segment,
                // which no legitimate one does -- and wrapping the offset would
                // read the front of the segment as though it were the back.
                let offset = usize::from(at.offset)
                    .checked_add(n * 2)
                    .and_then(|offset| u16::try_from(offset).ok())
                    .ok_or_else(|| {
                        ShimError::Failed(format!("a va_list at {at} ran off word {n}"))
                    })?;
                let word = machine.resolve(
                    FarPtr {
                        offset,
                        selector: at.selector,
                    },
                    2,
                )?;
                Ok(u16::from_le_bytes([word[0], word[1]]))
            }
        }
    }

    /// Words `n` and `n + 1` as one 32-bit value, low half first.
    ///
    /// A `long`, and also the shape a far pointer arrives in. Which of the two
    /// a given argument is depends on the format string, so the choice belongs
    /// to the walk.
    fn long(self, machine: &Machine, n: usize) -> Result<u32, ShimError> {
        Ok(u32::from(self.word(machine, n)?) | (u32::from(self.word(machine, n + 1)?) << 16))
    }

    /// Words `n` and `n + 1` as a far pointer: offset first, then selector.
    fn far(self, machine: &Machine, n: usize) -> Result<FarPtr, ShimError> {
        Ok(FarPtr {
            offset: self.word(machine, n)?,
            selector: self.word(machine, n + 1)?,
        })
    }
}

/// One `%...` conversion, as parsed.
#[derive(Debug, Default, Clone, Copy)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    long: bool,
    /// Set by `%N`: this pointer is one word, an offset into the module's own
    /// `DGROUP`, rather than the two-word far pointer the huge model defaults
    /// to. Getting it backwards eats the next argument as a selector.
    near: bool,
}

/// Format `template` with the arguments `args` names.
///
/// Returns the bytes, and how many argument words the walk consumed -- which is
/// what a test needs to check that a conversion took the width it should. A
/// conversion that consumes the wrong number does not fail; it shifts every
/// argument after it, and the output looks like data.
///
/// # Errors
///
/// If the format string or a `%s` argument names memory outside the module's
/// segments, if a `va_list` walks off its own segment, or if the format asks
/// for a conversion this does not implement.
///
/// # Panics
///
/// If `args` is [`Args::Call`] and the module is not stopped at a call, since
/// that is where those arguments are.
pub fn format(
    machine: &Machine,
    template: FarPtr,
    args: Args,
) -> Result<(Vec<u8>, usize), ShimError> {
    let template = machine.read_cstr(template)?.to_vec();
    let mut out = Vec::new();
    let mut arg = 0usize;
    let mut rest = template.as_slice();

    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'%' {
            out.push(byte);
            continue;
        }

        let (spec, conv, tail) = parse(rest, machine, args, &mut arg)?;
        rest = tail;

        match conv {
            b'%' => out.push(b'%'),
            b'c' => {
                // A `char` promotes to `int` before it is pushed, so it arrives
                // as a whole word and the low half is the character.
                let value = args.word(machine, arg)? as u8;
                arg += 1;
                pad(&mut out, &[value], &spec);
            }
            b's' => {
                let at = pointer(machine, args, spec.near, arg)?;
                arg += if spec.near { 1 } else { 2 };
                let text = machine.read_cstr(at)?;
                let text = &text[..spec.precision.unwrap_or(text.len()).min(text.len())];
                pad(&mut out, text, &spec);
            }
            b'p' => {
                let at = pointer(machine, args, false, arg)?;
                arg += 2;
                let text = format!("{:04X}:{:04X}", at.selector, at.offset);
                pad(&mut out, text.as_bytes(), &spec);
            }
            b'd' | b'i' => {
                let (value, size) = signed(machine, args, &spec, arg)?;
                arg += size;
                out.extend_from_slice(&integer(value.unsigned_abs(), value < 0, 10, false, &spec));
            }
            b'u' => {
                let (value, size) = unsigned(machine, args, &spec, arg)?;
                arg += size;
                out.extend_from_slice(&integer(value, false, 10, false, &spec));
            }
            b'o' => {
                let (value, size) = unsigned(machine, args, &spec, arg)?;
                arg += size;
                out.extend_from_slice(&integer(value, false, 8, false, &spec));
            }
            b'x' | b'X' => {
                let (value, size) = unsigned(machine, args, &spec, arg)?;
                arg += size;
                out.extend_from_slice(&integer(value, false, 16, conv == b'X', &spec));
            }
            other => {
                // `%f`, `%e`, `%g` and `%n` land here. Each has already been
                // given the wrong number of argument words by the time this
                // returns, so there is nothing to carry on with.
                return Err(ShimError::Failed(format!(
                    "%{} is a conversion the host does not implement",
                    other as char
                )));
            }
        }
    }

    Ok((out, arg))
}

/// Parse everything between the `%` and the conversion letter.
///
/// `*` takes its value from the argument list, which is why this needs to
/// advance `arg` as it goes.
fn parse<'a>(
    mut rest: &'a [u8],
    machine: &Machine,
    args: Args,
    arg: &mut usize,
) -> Result<(Spec, u8, &'a [u8]), ShimError> {
    let mut spec = Spec::default();

    loop {
        let Some((&byte, tail)) = rest.split_first() else {
            return Err(ShimError::Failed("a format string ends in %".to_owned()));
        };
        match byte {
            b'-' => spec.left = true,
            b'+' => spec.plus = true,
            b' ' => spec.space = true,
            b'#' => spec.alt = true,
            b'0' => spec.zero = true,
            _ => break,
        }
        rest = tail;
    }

    if rest.first() == Some(&b'*') {
        // A negative width means left-aligned, which is how C spells it.
        let n = args.word(machine, *arg)? as i16;
        *arg += 1;
        if n < 0 {
            spec.left = true;
        }
        spec.width = n.unsigned_abs() as usize;
        rest = &rest[1..];
    } else {
        let (n, tail) = digits(rest);
        spec.width = n.unwrap_or(0);
        rest = tail;
    }

    if rest.first() == Some(&b'.') {
        rest = &rest[1..];
        if rest.first() == Some(&b'*') {
            spec.precision = Some(args.word(machine, *arg)? as usize);
            *arg += 1;
            rest = &rest[1..];
        } else {
            let (n, tail) = digits(rest);
            spec.precision = Some(n.unwrap_or(0));
            rest = tail;
        }
    }

    loop {
        match rest.first() {
            Some(b'l' | b'L') => spec.long = true,
            Some(b'h') => spec.long = false,
            Some(b'F') => spec.near = false,
            Some(b'N') => spec.near = true,
            _ => break,
        }
        rest = &rest[1..];
    }

    let Some((&conv, tail)) = rest.split_first() else {
        return Err(ShimError::Failed(
            "a format string ends in a conversion with no letter".to_owned(),
        ));
    };
    Ok((spec, conv, tail))
}

fn digits(rest: &[u8]) -> (Option<usize>, &[u8]) {
    let end = rest.iter().position(|b| !b.is_ascii_digit()).unwrap_or(0);
    if end == 0 {
        return (None, rest);
    }
    let n = rest[..end]
        .iter()
        .fold(0usize, |acc, b| acc * 10 + usize::from(b - b'0'));
    (Some(n), &rest[end..])
}

/// The pointer at argument word `at`.
fn pointer(machine: &Machine, args: Args, near: bool, at: usize) -> Result<FarPtr, ShimError> {
    if near {
        // A near pointer is an offset into the module's own globals, which is
        // the segment its `DS` names.
        Ok(FarPtr {
            offset: args.word(machine, at)?,
            selector: machine.data_selector(),
        })
    } else {
        args.far(machine, at)
    }
}

fn signed(
    machine: &Machine,
    args: Args,
    spec: &Spec,
    at: usize,
) -> Result<(i64, usize), ShimError> {
    if spec.long {
        Ok((i64::from(args.long(machine, at)? as i32), 2))
    } else {
        Ok((i64::from(args.word(machine, at)? as i16), 1))
    }
}

fn unsigned(
    machine: &Machine,
    args: Args,
    spec: &Spec,
    at: usize,
) -> Result<(u64, usize), ShimError> {
    if spec.long {
        Ok((u64::from(args.long(machine, at)?), 2))
    } else {
        Ok((u64::from(args.word(machine, at)?), 1))
    }
}

/// Render a number with its flags, precision and width.
fn integer(value: u64, negative: bool, base: u64, upper: bool, spec: &Spec) -> Vec<u8> {
    let mut digits = Vec::new();
    let mut n = value;
    while n > 0 {
        let d = (n % base) as u8;
        digits.push(match d {
            0..=9 => b'0' + d,
            _ if upper => b'A' + d - 10,
            _ => b'a' + d - 10,
        });
        n /= base;
    }
    if digits.is_empty() {
        // A precision of zero prints nothing at all for a zero value, which is
        // the one case where an empty field is correct rather than a bug.
        if spec.precision != Some(0) {
            digits.push(b'0');
        }
    }
    digits.reverse();

    while digits.len() < spec.precision.unwrap_or(0) {
        digits.insert(0, b'0');
    }

    let mut prefix = Vec::new();
    if negative {
        prefix.push(b'-');
    } else if base == 10 && spec.plus {
        prefix.push(b'+');
    } else if base == 10 && spec.space {
        prefix.push(b' ');
    }
    if spec.alt {
        match base {
            8 if digits.first() != Some(&b'0') => prefix.push(b'0'),
            16 if value != 0 => prefix.extend_from_slice(if upper { b"0X" } else { b"0x" }),
            _ => {}
        }
    }

    let body = prefix.len() + digits.len();
    let mut out = Vec::with_capacity(spec.width.max(body));

    // Zero-padding goes after the sign and any `0x`, and a precision turns it
    // off -- the precision already said how many digits there are to be.
    if spec.zero && !spec.left && spec.precision.is_none() && spec.width > body {
        out.extend_from_slice(&prefix);
        out.resize(spec.width - digits.len(), b'0');
        out.extend_from_slice(&digits);
        return out;
    }

    if !spec.left {
        out.resize(spec.width.saturating_sub(body), b' ');
    }
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&digits);
    if spec.left {
        out.resize(out.len().max(spec.width), b' ');
    }
    out
}

/// Place `text` in a field of `spec.width`.
fn pad(out: &mut Vec<u8>, text: &[u8], spec: &Spec) {
    let fill = spec.width.saturating_sub(text.len());
    if !spec.left {
        out.extend(std::iter::repeat_n(b' ', fill));
    }
    out.extend_from_slice(text);
    if spec.left {
        out.extend(std::iter::repeat_n(b' ', fill));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// One case: a format string, the argument words, and what should come out.
    fn check(template: &str, args: &[u16], expect: &str) {
        let mut f = Fixture::new();
        let at = f.text(template);
        f.call(args);
        let (bytes, _) = format(&f.machine, at, Args::Call { first: 0 }).expect("formatted");
        assert_eq!(String::from_utf8_lossy(&bytes), expect, "{template:?}");
    }

    /// The rendering, and the argument word the walk stopped at.
    fn walk(f: &Fixture, template: FarPtr) -> (String, usize) {
        let (bytes, next) =
            format(&f.machine, template, Args::Call { first: 0 }).expect("formatted");
        (String::from_utf8_lossy(&bytes).into_owned(), next)
    }

    #[test]
    fn text_with_no_conversions_comes_through_unchanged() {
        check("MajorMUD is now online.", &[], "MajorMUD is now online.");
        check("100%% done", &[], "100% done");
    }

    #[test]
    fn an_int_is_one_word_and_signed() {
        check("%d", &[7], "7");
        check("%d", &[(-1234i16) as u16], "-1234");
        check("%u", &[(-1i16) as u16], "65535");
        check("%d and %d", &[1, 2], "1 and 2");
    }

    #[test]
    fn a_long_is_two_words_low_half_first() {
        // The one that shifts everything after it when it is got wrong: read as
        // an int, `%ld` leaves the high half to be read as the next argument.
        let value: u32 = 0x0001_86a0; // 100,000
        check(
            "%ld then %d",
            &[value as u16, (value >> 16) as u16, 42],
            "100000 then 42",
        );
        check("%ld", &[0x6780, 0xffff], "-39040");
    }

    #[test]
    fn a_string_is_a_far_pointer_and_therefore_two_words() {
        let mut f = Fixture::new();
        let template = f.text("<%s>");
        let text = f.text("Newhaven");
        f.call(&Fixture::far(text));
        assert_eq!(walk(&f, template).0, "<Newhaven>");
    }

    #[test]
    fn a_string_leaves_the_next_argument_where_it_belongs() {
        // Two words for the pointer, then the int. Consuming one would print
        // the selector as a number and read the int as garbage.
        let mut f = Fixture::new();
        let template = f.text("%s has %d");
        let text = f.text("a kobold");
        f.call(&[text.offset, text.selector, 12]);
        assert_eq!(walk(&f, template).0, "a kobold has 12");
    }

    #[test]
    fn a_near_string_is_one_word_in_the_modules_own_data_segment() {
        let mut f = Fixture::new();
        let template = f.text("%Ns/%d");
        let at = FarPtr {
            offset: 0x0100,
            selector: f.machine.data_selector(),
        };
        f.machine.write(at, b"gold\0").expect("fits");
        f.call(&[at.offset, 9]);
        assert_eq!(walk(&f, template).0, "gold/9");
    }

    #[test]
    fn bases_and_their_alternate_forms() {
        check("%x %X", &[0xbeef, 0xbeef], "beef BEEF");
        check("%#x", &[0x2a], "0x2a");
        // C drops the `0x` for a zero value, since `0x0` is not what `%#x`
        // means by "the alternate form of zero".
        check("%#x", &[0], "0");
        check("%o %#o", &[8, 8], "10 010");
    }

    #[test]
    fn width_precision_and_the_flags() {
        check("[%5d]", &[42], "[   42]");
        check("[%-5d]", &[42], "[42   ]");
        check("[%05d]", &[42], "[00042]");
        check("[%05d]", &[(-42i16) as u16], "[-0042]");
        check("[%+d] [% d]", &[7, 7], "[+7] [ 7]");
        check("[%.5d]", &[42], "[00042]");
        check("[%8.5d]", &[42], "[   00042]");
        check("[%.0d]", &[0], "[]");
    }

    #[test]
    fn a_star_takes_its_width_from_the_arguments() {
        check("[%*d]", &[6, 42], "[    42]");
        // A negative star width is how C spells left-aligned.
        check("[%*d]", &[(-6i16) as u16, 42], "[42    ]");
    }

    #[test]
    fn a_star_precision_truncates_a_string() {
        let mut f = Fixture::new();
        let template = f.text("[%.*s]");
        let text = f.text("Newhaven");
        f.call(&[3, text.offset, text.selector]);
        assert_eq!(walk(&f, template).0, "[New]");
    }

    #[test]
    fn a_precision_truncates_a_string_and_a_width_pads_it() {
        let mut f = Fixture::new();
        let template = f.text("[%.4s][%8s][%-8s]");
        let text = f.text("Ranger");
        let args: Vec<u16> = std::iter::repeat_n(Fixture::far(text), 3)
            .flatten()
            .collect();
        f.call(&args);
        assert_eq!(walk(&f, template).0, "[Rang][  Ranger][Ranger  ]");
    }

    #[test]
    fn a_char_arrives_promoted_to_an_int() {
        check("%c%c", &[u16::from(b'h'), u16::from(b'i')], "hi");
        check("[%3c]", &[u16::from(b'x')], "[  x]");
    }

    #[test]
    fn a_pointer_prints_as_selector_and_offset() {
        check("%p", &[0x1234, 0x00af], "00AF:1234");
    }

    #[test]
    fn the_walk_reports_where_it_stopped() {
        let mut f = Fixture::new();
        let template = f.text("%d %ld %c");
        f.call(&[1, 2, 0, u16::from(b'z')]);
        assert_eq!(walk(&f, template), ("1 2 z".to_owned(), 4));
    }

    #[test]
    fn a_conversion_the_host_does_not_implement_is_an_error() {
        // Not a passthrough and not an empty field. By the time `%f` is
        // reached its four words have already not been consumed, so every
        // argument after it would be read from the wrong place.
        let mut f = Fixture::new();
        let template = f.text("%f");
        f.call(&[0, 0, 0, 0]);
        assert!(format(&f.machine, template, Args::Call { first: 0 }).is_err());
    }

    #[test]
    fn a_format_string_that_ends_in_a_percent_is_an_error() {
        let mut f = Fixture::new();
        let template = f.text("all done %");
        f.call(&[]);
        assert!(format(&f.machine, template, Args::Call { first: 0 }).is_err());
    }

    #[test]
    fn a_va_list_reads_the_words_a_frame_walk_would() {
        // The same format string and the same words as
        // `a_string_leaves_the_next_argument_where_it_belongs`, from a pointer
        // instead of from the stack -- and note there is no `f.call` at all.
        // A `va_list` walk needs no outstanding frame, which is exactly what
        // makes it usable from a routine whose own frame holds something else.
        let mut f = Fixture::new();
        let template = f.text("%s has %d");
        let text = f.text("a kobold");
        let list = f.words(&[text.offset, text.selector, 12]);

        let (bytes, next) =
            format(&f.machine, template, Args::List { at: list }).expect("formatted");
        assert_eq!(String::from_utf8_lossy(&bytes), "a kobold has 12");
        assert_eq!(next, 3, "two words for the far pointer and one for the int");
    }

    #[test]
    fn a_va_list_and_a_frame_render_the_same_arguments_the_same_way() {
        // Every argument width in one string: a far pointer, a long, a
        // promoted char and an int. If the two sources ever disagree it will be
        // about a width, so the check is worth making over all of them at once.
        let words = |f: &mut Fixture| {
            let text = f.text("gold");
            vec![
                text.offset,
                text.selector,
                0x86a0,
                0x0001,
                u16::from(b'x'),
                42,
            ]
        };

        let mut f = Fixture::new();
        let template = f.text("%s|%ld|%c|%05d");
        let args = words(&mut f);
        f.call(&args);
        let framed = format(&f.machine, template, Args::Call { first: 0 }).expect("formatted");

        let mut g = Fixture::new();
        let template = g.text("%s|%ld|%c|%05d");
        let args = words(&mut g);
        let list = g.words(&args);
        let listed = format(&g.machine, template, Args::List { at: list }).expect("formatted");

        assert_eq!(framed, listed);
        assert_eq!(String::from_utf8_lossy(&framed.0), "gold|100000|x|00042");
    }

    #[test]
    fn a_va_list_naming_nothing_is_an_error() {
        // Not an empty field and not a zero. A null `va_list` is a module bug,
        // and the host's rule everywhere else is that a pointer it cannot
        // follow stops the module rather than inventing what was behind it.
        let mut f = Fixture::new();
        let template = f.text("%d");
        let at = FarPtr::NULL;
        assert!(format(&f.machine, template, Args::List { at }).is_err());
    }

    #[test]
    fn a_va_list_that_walks_off_its_segment_is_an_error() {
        // The failure a bounds check exists for: the list is real and the first
        // conversion reads it, and the second runs past the end of what it
        // names. Reading two bytes of nothing there would put a number in the
        // output that no argument ever held.
        let mut f = Fixture::new();
        let template = f.text("%d %d");
        let selector = f.machine.alloc_segment(2).expect("a one-word segment");
        let at = FarPtr {
            offset: 0,
            selector,
        };
        f.machine.write(at, &7u16.to_le_bytes()).expect("fits");

        assert!(format(&f.machine, template, Args::List { at }).is_err());
    }
}
