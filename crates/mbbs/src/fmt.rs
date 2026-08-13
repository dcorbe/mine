//! Borland's `printf`, over a module's arguments.
//!
//! `spr`, `sprintf`, `prf`, `fprintf`, `shocst` and `prfmsg` are all one
//! engine and a different destination, so this is written once and a bug
//! here is a bug in all of them.
//!
//! # Where the arguments are
//!
//! cdecl pushes right to left, so a varargs routine's arguments sit above its
//! call frame in declaration order and the format string is the only one whose
//! position is known. Everything after it is found by *reading the format
//! string* -- there is no other record of how many there are or how wide each
//! is. A conversion that consumes the wrong number of bytes does not fail; it
//! shifts every argument after it, and the output looks like data.
//!
//! A `v`-spelled routine is handed a `va_list` instead: a pointer into the
//! *caller's* frame, whose bytes are laid out identically. The walk below
//! cannot tell the difference and must not have to.
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
//!
//! # Generic core, `Wg16` facade
//!
//! [`format_call`] and [`format_va_list`] are `fn<A: Abi>`: they read the
//! format string and every argument through [`Call<A>`], the same handle a
//! converted shim already holds, and touch memory through [`Call::mem`]
//! rather than a whole `&mut Machine`. Nothing here needs a word-index
//! parameter the way [`Args::Call`]'s old `first` field did -- a `Call<A>`
//! *is* a cursor already standing wherever the fixed arguments left off (see
//! `crates/mbbs/src/abi.rs`'s "Why `Call` owns its frame"), so the generic
//! walk just keeps reading through it. That is the design's own predicted
//! improvement over the word-index scheme, and it holds without
//! qualification: nothing about the walk below cares whether `A` is `Wg16`
//! or a future `Wg32`, because [`Abi::INT_WIDTH`]/[`Abi::LONG_WIDTH`]/
//! [`Abi::PTR_WIDTH`] are exactly the widths [`Call::int`]/[`Call::long`]/
//! [`Call::ptr`] already advance by.
//!
//! `format` itself stays [`Wg16`]-concrete, under its original name and
//! (almost -- see its own doc comment) its original signature, because six
//! call sites across four other files (`msg::prfmsg`, `text::spr`/`sprintf`/
//! `vsprintf`/`prf`, `system::shocst`/`catastro`, and `stream::fprintf` if it
//! is not converted) still hold a whole `&mut Machine` and construct the
//! word-indexed [`Args`] this crate used before `Call` existed. Converting
//! those is each file's own task, not this one's -- see the module doc
//! comment on why `fmt.rs` alone was worth doing first regardless: every one
//! of those six routines was blocked on this file, and now none of them are.

use mbbs_machine::ptr::ModulePtr;

use crate::abi::{Abi, Call};
use crate::shims::ShimError;

/// One `%...` conversion, as parsed.
///
/// `pub(crate)` so [`integer`] can be driven from outside a `%` conversion --
/// see its doc comment.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    long: bool,
    /// Set by `%N`: this pointer is one argument word, an offset into the
    /// module's own `DGROUP`, rather than the two-word far pointer the huge
    /// model defaults to. Getting it backwards eats the next argument as a
    /// selector.
    near: bool,
}

/// Where the varargs after the format string come from, once a source is
/// picked: either wherever [`Call<A>`]'s own position stands, or a `va_list`
/// walked on demand.
///
/// Not [`Args`]: that type is the *word-indexed* compatibility shape the
/// `Wg16` facade still hands its unconverted callers' choices through. This
/// one is what the shared walk in [`walk`] actually reads from, and it is
/// deliberately not `pub` -- nothing outside this file has any argument
/// source but a live `Call<A>`, and [`format_va_list`] builds this variant
/// internally rather than asking a caller to.
enum Vararg<A: Abi> {
    /// Keep reading through `call`'s own position. What every routine here
    /// has except a `v`-spelled one.
    Call,

    /// A `va_list`: consecutive bytes from a pointer into the *caller's*
    /// frame, resolved on demand rather than copied up front -- unlike
    /// `Call`'s own frame, nothing bounds how large the segment behind a
    /// `va_list` is before the format string says how far to walk it, so
    /// copying it all in advance would be copying memory that is not this
    /// call's to claim.
    List { at: A::Ptr, pos: u16 },
}

impl<A: Abi> Vararg<A> {
    /// The next argument as a C `int`.
    fn int(&mut self, call: &mut Call<A>) -> Result<A::Int, ShimError> {
        match self {
            Self::Call => Ok(call.int()),
            Self::List { at, pos } => {
                let bytes = Self::list_take(call.mem(), *at, pos, A::INT_WIDTH)?;
                Ok(A::int_from_bytes(&bytes))
            }
        }
    }

    /// The next argument as a C `long`.
    fn long(&mut self, call: &mut Call<A>) -> Result<u32, ShimError> {
        match self {
            Self::Call => Ok(call.long()),
            Self::List { at, pos } => {
                let bytes = Self::list_take(call.mem(), *at, pos, A::LONG_WIDTH)?;
                Ok(A::long_from_bytes(&bytes))
            }
        }
    }

    /// The next argument as a far/flat pointer, in this ABI's own
    /// representation.
    fn ptr(&mut self, call: &mut Call<A>) -> Result<A::Ptr, ShimError> {
        match self {
            Self::Call => Ok(call.ptr()),
            Self::List { at, pos } => {
                let bytes = Self::list_take(call.mem(), *at, pos, A::PTR_WIDTH)?;
                Ok(A::ptr_from_bytes(&bytes))
            }
        }
    }

    /// Resolve `width` bytes at `*pos` past `at`, in module memory, and
    /// advance `pos` past them.
    ///
    /// An associated function rather than a free one so `A` is fixed by
    /// `Self` at every call site above -- `A::Mem`/`A::Ptr` alone do not
    /// determine `A` for type inference, since an associated-type projection
    /// is not invertible.
    ///
    /// # Errors
    ///
    /// If `*pos + width` would not fit in a `u16` -- a `va_list` that has
    /// walked past 0xffff has left its segment, which no legitimate one
    /// does, and wrapping the offset would read the front of the segment as
    /// though it were the back -- or if `at` names nothing of the module's,
    /// or the read would leave what it names.
    fn list_take(mem: &A::Mem, at: A::Ptr, pos: &mut u16, width: usize) -> Result<Vec<u8>, ShimError> {
        let next = usize::from(*pos)
            .checked_add(width)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| {
                ShimError::Failed(format!("a va_list at {at} ran off by {width} bytes"))
            })?;
        let ptr = A::ptr_offset(at, *pos);
        let bytes = ptr
            .resolve(mem, width)
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        *pos = next;
        Ok(bytes)
    }
}

/// Format `template` with the varargs that follow it, read through `call`
/// from wherever its position currently stands.
///
/// The generic replacement for [`Args::Call`]: a converted shim reads its
/// fixed arguments off `call` with [`Call::int`]/[`Call::ptr`]/[`Call::long`]
/// exactly as it always would, and by the time it reaches the format
/// string's varargs, `call`'s position already marks where they begin --
/// there is nothing left to tell this function beyond that.
///
/// Returns the bytes, and how many bytes of `call`'s frame the walk consumed
/// past its starting position -- what a test needs to check that a
/// conversion took the width it should. A conversion that consumes the wrong
/// number does not fail; it shifts every argument after it, and the output
/// looks like data.
///
/// # Errors
///
/// If the format string or a `%s` argument names memory outside the module's
/// reach, or if the format asks for a conversion this does not implement.
pub fn format_call<A: Abi>(
    call: &mut Call<A>,
    template: A::Ptr,
) -> Result<(Vec<u8>, usize), ShimError> {
    walk(call, template, &mut Vararg::Call)
}

/// Format `template` with the varargs a `va_list` at `at` names.
///
/// The generic replacement for [`Args::List`]. `at` points into the
/// *caller's* frame -- `va_start` sets it to the word past the last fixed
/// argument, so the bytes behind it are laid out exactly as [`format_call`]'s
/// own are -- and are read through `call.mem()` on demand, not through
/// `call`'s own position: a `va_list` names someone else's frame, not this
/// call's.
///
/// # Errors
///
/// As [`format_call`], plus if the `va_list` walks off its own segment or
/// names nothing of the module's.
pub fn format_va_list<A: Abi>(
    call: &mut Call<A>,
    template: A::Ptr,
    at: A::Ptr,
) -> Result<(Vec<u8>, usize), ShimError> {
    walk(call, template, &mut Vararg::List { at, pos: 0 })
}

/// The shared walk both public entry points -- and the `Wg16` facade -- run.
/// Everything conversion-specific lives here exactly once, which is the
/// whole reason [`Vararg`] exists: the only thing that differs between a
/// `Call`-sourced and a `va_list`-sourced format is where word `n` of the
/// variadic list comes from, and naming that source rather than threading a
/// word offset keeps every conversion, width and pointer rule below written
/// once for both.
fn walk<A: Abi>(
    call: &mut Call<A>,
    template: A::Ptr,
    args: &mut Vararg<A>,
) -> Result<(Vec<u8>, usize), ShimError> {
    let template = template
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let mut out = Vec::new();
    let mut consumed = 0usize;
    let mut rest = template.as_slice();

    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'%' {
            out.push(byte);
            continue;
        }

        let (spec, conv, tail) = parse(rest, call, args, &mut consumed)?;
        rest = tail;

        match conv {
            b'%' => out.push(b'%'),
            b'c' => {
                // A `char` promotes to `int` before it is pushed, so it
                // arrives as a whole argument and the low byte is the
                // character.
                let value = Into::<u32>::into(args.int(call)?) as u8;
                consumed += A::INT_WIDTH;
                pad(&mut out, &[value], &spec);
            }
            b's' => {
                let at = pointer(call, args, spec.near)?;
                consumed += if spec.near { A::INT_WIDTH } else { A::PTR_WIDTH };
                let text = at
                    .read_cstr(call.mem())
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                let text = &text[..spec.precision.unwrap_or(text.len()).min(text.len())];
                pad(&mut out, text, &spec);
            }
            b'p' => {
                let at = pointer(call, args, false)?;
                consumed += A::PTR_WIDTH;
                pad(&mut out, format!("{at}").as_bytes(), &spec);
            }
            b'd' | b'i' => {
                let (value, size) = signed(call, args, &spec)?;
                consumed += size;
                out.extend_from_slice(&integer(value.unsigned_abs(), value < 0, 10, false, &spec));
            }
            b'u' => {
                let (value, size) = unsigned(call, args, &spec)?;
                consumed += size;
                out.extend_from_slice(&integer(value, false, 10, false, &spec));
            }
            b'o' => {
                let (value, size) = unsigned(call, args, &spec)?;
                consumed += size;
                out.extend_from_slice(&integer(value, false, 8, false, &spec));
            }
            b'x' | b'X' => {
                let (value, size) = unsigned(call, args, &spec)?;
                consumed += size;
                out.extend_from_slice(&integer(value, false, 16, conv == b'X', &spec));
            }
            other => {
                // `%f`, `%e`, `%g` and `%n` land here. Each has already been
                // given the wrong number of argument bytes by the time this
                // returns, so there is nothing to carry on with.
                return Err(ShimError::Failed(format!(
                    "%{} is a conversion the host does not implement",
                    other as char
                )));
            }
        }
    }

    Ok((out, consumed))
}

/// Parse everything between the `%` and the conversion letter.
///
/// `*` takes its value from the argument list, which is why this needs
/// `call`/`args` and advances `consumed` as it goes.
fn parse<'a, A: Abi>(
    mut rest: &'a [u8],
    call: &mut Call<A>,
    args: &mut Vararg<A>,
    consumed: &mut usize,
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
        let n = Into::<u32>::into(args.int(call)?) as i16;
        *consumed += A::INT_WIDTH;
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
            spec.precision = Some(Into::<u32>::into(args.int(call)?) as usize);
            *consumed += A::INT_WIDTH;
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

/// The pointer the next argument names.
fn pointer<A: Abi>(call: &mut Call<A>, args: &mut Vararg<A>, near: bool) -> Result<A::Ptr, ShimError> {
    if near {
        // A near pointer is one argument word: an offset into the module's
        // own globals, which is the segment `Abi::data_ptr` names -- see its
        // own doc comment for why this could not be built from anything else
        // in `Abi`.
        let raw = Into::<u32>::into(args.int(call)?) as u16;
        Ok(A::ptr_offset(A::data_ptr(call.cpu), raw))
    } else {
        args.ptr(call)
    }
}

fn signed<A: Abi>(
    call: &mut Call<A>,
    args: &mut Vararg<A>,
    spec: &Spec,
) -> Result<(i64, usize), ShimError> {
    if spec.long {
        Ok((i64::from(args.long(call)? as i32), A::LONG_WIDTH))
    } else {
        Ok((
            i64::from(Into::<u32>::into(args.int(call)?) as i16),
            A::INT_WIDTH,
        ))
    }
}

fn unsigned<A: Abi>(
    call: &mut Call<A>,
    args: &mut Vararg<A>,
    spec: &Spec,
) -> Result<(u64, usize), ShimError> {
    if spec.long {
        Ok((u64::from(args.long(call)?), A::LONG_WIDTH))
    } else {
        Ok((u64::from(Into::<u32>::into(args.int(call)?)), A::INT_WIDTH))
    }
}

/// Render a number with its flags, precision and width.
///
/// `pub(crate)`: this is the one place a `long` becomes decimal digits and a
/// sign, and `shims::text::l2as` reuses it rather than formatting a second
/// time -- this module's own doc comment (top of file) is the reason why. A
/// converter that disagreed with `%ld` on so much as `i32::MIN` would be the
/// exact bug that comment warns about.
pub(crate) fn integer(value: u64, negative: bool, base: u64, upper: bool, spec: &Spec) -> Vec<u8> {
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
    use crate::abi::Wg16;
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

    /// A [`Call<Wg16>`] over the outstanding call's frame -- the same two
    /// lines `crate::shims::call` builds, repeated here so this module's
    /// tests need no dependency on `crate::shims`.
    fn call(f: &mut Fixture) -> Call<'_, Wg16> {
        let frame = f.machine.arg_frame().to_vec();
        Call::new(&mut f.machine, &frame)
    }

    /// One case: a format string, the argument words, and what should come
    /// out -- through [`format_call`] directly. Was, until `Args`/`format`
    /// (the word-indexed `Wg16` compatibility facade) were deleted: their
    /// last non-test callers converted in `shims::system`/`shims::msg`, and
    /// this helper's own `Args::Call { first: 0 }` was doing nothing
    /// `format_call` does not already do for a `Call` positioned at the
    /// start of its frame -- see [`walk`], which already exercised the same
    /// generic entry point and is now what this delegates to.
    fn check(template: &str, args: &[u16], expect: &str) {
        let mut f = Fixture::new();
        let at = f.text(template);
        f.call(args);
        let (rendered, _) = walk(&mut f, at);
        assert_eq!(rendered, expect, "{template:?}");
    }

    /// The rendering, and the bytes the walk stopped at, through
    /// [`format_call`] -- the generic entry point every converted shim
    /// (`shims::text::spr`/`sprintf`/`prf`, `shims::msg::prfmsg`,
    /// `shims::system::shocst`/`catastro`, ...) now calls directly.
    fn walk(f: &mut Fixture, template: FarPtr) -> (String, usize) {
        let mut call = call(f);
        let (bytes, next) = format_call(&mut call, template).expect("formatted");
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
        assert_eq!(walk(&mut f, template).0, "<Newhaven>");
    }

    #[test]
    fn a_string_leaves_the_next_argument_where_it_belongs() {
        // Two words for the pointer, then the int. Consuming one would print
        // the selector as a number and read the int as garbage.
        let mut f = Fixture::new();
        let template = f.text("%s has %d");
        let text = f.text("a kobold");
        f.call(&[text.offset, text.selector, 12]);
        assert_eq!(walk(&mut f, template).0, "a kobold has 12");
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
        assert_eq!(walk(&mut f, template).0, "gold/9");
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
        assert_eq!(walk(&mut f, template).0, "[New]");
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
        assert_eq!(walk(&mut f, template).0, "[Rang][  Ranger][Ranger  ]");
    }

    #[test]
    fn a_char_arrives_promoted_to_an_int() {
        check("%c%c", &[u16::from(b'h'), u16::from(b'i')], "hi");
        check("[%3c]", &[u16::from(b'x')], "[  x]");
    }

    #[test]
    fn a_pointer_prints_as_selector_and_offset() {
        // Lower case: `%p` now defers to `A::Ptr`'s own `Display` (see
        // `format`'s doc for why the generic walk cannot reconstruct
        // `FarPtr`'s fields by hand) rather than reimplementing the same
        // `seg:off` rendering `mbbs_machine::m16::FarPtr::fmt` already gives -- one
        // place that decides how a pointer prints, not two that could
        // disagree. WCCMMUD.DLL's decompiled sources have no `%p` conversion
        // at all (`grep -c %p` over `WCCMMUD_named.c` is 0), so nothing
        // measured depends on the case that changed.
        check("%p", &[0x1234, 0x00af], "00af:1234");
    }

    #[test]
    fn the_walk_reports_how_many_bytes_it_consumed() {
        let mut f = Fixture::new();
        let template = f.text("%d %ld %c");
        f.call(&[1, 2, 0, u16::from(b'z')]);
        // 2 (int) + 4 (long) + 2 (int, promoted char) = 8 bytes.
        assert_eq!(walk(&mut f, template), ("1 2 z".to_owned(), 8));
    }

    #[test]
    fn a_conversion_the_host_does_not_implement_is_an_error() {
        // Not a passthrough and not an empty field. By the time `%f` is
        // reached its arguments have already not been consumed, so every
        // argument after it would be read from the wrong place.
        let mut f = Fixture::new();
        let template = f.text("%f");
        f.call(&[0, 0, 0, 0]);
        let mut c = call(&mut f);
        assert!(format_call(&mut c, template).is_err());
    }

    #[test]
    fn a_format_string_that_ends_in_a_percent_is_an_error() {
        let mut f = Fixture::new();
        let template = f.text("all done %");
        f.call(&[]);
        let mut c = call(&mut f);
        assert!(format_call(&mut c, template).is_err());
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

        // Not `call(&mut f)`: that helper reads `Machine::arg_frame`, which
        // panics with no outstanding call. An empty frame is enough --
        // `format_va_list` never reads through `Call`'s own position, only
        // through `Call::mem`, which this still has.
        let mut call = Call::<Wg16>::new(&mut f.machine, &[]);
        let (bytes, next) = format_va_list(&mut call, template, list).expect("formatted");
        assert_eq!(String::from_utf8_lossy(&bytes), "a kobold has 12");
        assert_eq!(next, 6, "four bytes for the far pointer, two for the int");
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
        let mut c = call(&mut f);
        let framed = format_call(&mut c, template).expect("formatted");

        let mut g = Fixture::new();
        let template = g.text("%s|%ld|%c|%05d");
        let args = words(&mut g);
        let list = g.words(&args);
        // Not `call(&mut g)`: a `va_list` walk needs no outstanding frame --
        // see `a_va_list_reads_the_words_a_frame_walk_would`'s own comment.
        let mut c = Call::<Wg16>::new(&mut g.machine, &[]);
        let listed = format_va_list(&mut c, template, list).expect("formatted");

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
        let mut c = Call::<Wg16>::new(&mut f.machine, &[]);
        assert!(format_va_list(&mut c, template, at).is_err());
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

        let mut c = Call::<Wg16>::new(&mut f.machine, &[]);
        assert!(format_va_list(&mut c, template, at).is_err());
    }

    /// [`format_call`], exercised directly with no `Wg16` `Args` in sight --
    /// the shape a converted `fprintf` (or any future converted printf
    /// routine) actually calls.
    #[test]
    fn format_call_reads_straight_through_a_calls_own_position() {
        let mut f = Fixture::new();
        let template = f.text("%s has %d gold");
        let who = f.text("rangerdan");
        f.call(&[who.offset, who.selector, 1234]);

        let mut call = call(&mut f);
        let (bytes, consumed) = format_call(&mut call, template).expect("formatted");
        assert_eq!(String::from_utf8_lossy(&bytes), "rangerdan has 1234 gold");
        assert_eq!(consumed, 6, "four bytes for the far pointer, two for the int");
    }

    /// The same proof [`crate::abi`]'s own tests make for `Call::ptr`/`int`/
    /// `long`: a fixed argument consumed *before* the vararg walk begins
    /// leaves `call`'s position exactly where the format string's own
    /// arguments start, with no word-index needed to say so.
    #[test]
    fn format_call_starts_wherever_the_fixed_arguments_left_the_call() {
        let mut f = Fixture::new();
        let template = f.text("%d");
        f.call(&[0xdead, 7]); // a fixed word, then the one vararg.

        let mut call = call(&mut f);
        let _ = call.int(); // consume the fixed argument, as a real shim would.
        let (bytes, consumed) = format_call(&mut call, template).expect("formatted");
        assert_eq!(String::from_utf8_lossy(&bytes), "7");
        assert_eq!(consumed, 2);
    }
}
