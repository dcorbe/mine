//! One format engine, behind `sprintf`, `fprintf` and `vsprintf`.
//!
//! All three walk a format string pulling arguments from a cursor; they differ
//! only in where the cursor starts and where the result goes. On 32-bit cdecl a
//! `va_list` *is* a pointer into the caller's argument frame, so `vsprintf`'s
//! third argument and `sprintf`'s implicit varargs are the same thing reached
//! two ways -- which is why [`ArgCursor`] has two sources and one `next_u32`.
//!
//! # Only the conversions this program uses
//!
//! Measured by scanning `wccmmutl.exe`'s own `DATA` section for format strings:
//! **153 of them, using `%d %s %X %x %u %c %%`** with width, precision, the `0`
//! and `-` flags, and the `l` length modifier. There is **no floating point at
//! all** -- not one `%f`, `%e` or `%g` in the binary.
//!
//! So this engine has no float support, and that is a measured bound rather
//! than a shortcut. Implementing the whole of C's `printf` here would be work
//! no input asks for, and float formatting in particular is where a
//! hand-rolled implementation quietly disagrees with the original in the last
//! digit.
//!
//! An unrecognised conversion is emitted **literally**, which is what a real
//! `printf` does with `%q` and is the behaviour least likely to be mistaken for
//! success: the wrong text appears on screen rather than a plausible number.

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

/// Where a format call's variable arguments come from.
pub enum ArgSource<'a> {
    /// `sprintf`/`fprintf`: the arguments are stack slots of the call that is
    /// currently suspended, starting at `base`.
    Frame { machine: &'a Machine, base: usize },
    /// `vsprintf`: the caller has already reduced them to a `va_list`, which on
    /// this ABI is a bare pointer to the first of them.
    VaList { at: u32 },
}

/// A walking read-head over a call's variable arguments.
///
/// Every argument is fetched as a 32-bit word because that is what cdecl
/// promotes to: a `char` argument arrives as an `int`, and a `short` does too.
/// The conversion decides how to *interpret* the word, never how wide it is.
pub struct ArgCursor<'a> {
    source: ArgSource<'a>,
    next: usize,
}

impl<'a> ArgCursor<'a> {
    pub fn new(source: ArgSource<'a>) -> Self {
        Self { source, next: 0 }
    }

    /// The next argument, or zero once they run out.
    ///
    /// Zero rather than a panic for a format string with more conversions than
    /// arguments: that is a bug in the *guest*, and a host that aborted would
    /// turn the program's bug into the host's crash. C reads whatever is on the
    /// stack there; this reads a deterministic zero, which is at least
    /// reproducible.
    pub fn next_u32(&mut self, mem: &Memory) -> u32 {
        let index = self.next;
        self.next += 1;
        match &self.source {
            ArgSource::Frame { machine, base } => machine.arg_u32(mem.stack(), base + index),
            ArgSource::VaList { at } => {
                let off = u32::try_from(index * 4).unwrap_or(u32::MAX);
                Flat32Ptr(at.wrapping_add(off))
                    .resolve(mem, 4)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
            }
        }
    }
}

/// One conversion's flags, width and precision.
#[derive(Default, Debug, Clone, Copy)]
struct Spec {
    left: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
}

impl Spec {
    /// Pad `body` to the requested width.
    ///
    /// **Zero-padding goes after the sign, not before it**: `%05d` of `-42` is
    /// `-0042`, never `00-42`. That is the detail a naive "pad the whole string
    /// with zeros" gets wrong, and it only shows on negative numbers.
    ///
    /// A `-` flag beats a `0` flag, as C says, because there is nowhere to put
    /// zeros on the right of a number.
    fn pad(self, body: Vec<u8>, sign: Option<u8>) -> Vec<u8> {
        let signed_len = body.len() + usize::from(sign.is_some());
        let fill = self.width.saturating_sub(signed_len);
        let mut out = Vec::with_capacity(self.width.max(signed_len));
        if self.left {
            if let Some(s) = sign {
                out.push(s);
            }
            out.extend_from_slice(&body);
            out.extend(std::iter::repeat_n(b' ', fill));
        } else if self.zero {
            if let Some(s) = sign {
                out.push(s);
            }
            out.extend(std::iter::repeat_n(b'0', fill));
            out.extend_from_slice(&body);
        } else {
            out.extend(std::iter::repeat_n(b' ', fill));
            if let Some(s) = sign {
                out.push(s);
            }
            out.extend_from_slice(&body);
        }
        out
    }
}

/// Render `fmt`, pulling arguments from `args`.
///
/// Bytes in and bytes out: a format string in this program is CP437 text, not
/// UTF-8, and decoding it here would corrupt every box-drawing character on its
/// way to the screen.
pub fn render(mem: &Memory, fmt: &[u8], args: &mut ArgCursor) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len() + 16);
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i]);
            i += 1;
            continue;
        }
        let start = i;
        i += 1;

        let mut spec = Spec::default();
        // Flags. Only `-` and `0` are measured in this binary; the others are
        // accepted so that an unmeasured format string degrades to the right
        // text rather than to a literal `%`.
        while i < fmt.len() {
            match fmt[i] {
                b'-' => spec.left = true,
                b'0' => spec.zero = true,
                b'+' | b' ' | b'#' => {}
                _ => break,
            }
            i += 1;
        }
        // Width.
        if i < fmt.len() && fmt[i] == b'*' {
            spec.width = args.next_u32(mem) as usize;
            i += 1;
        } else {
            let mut w = 0usize;
            let mut any = false;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                w = w.saturating_mul(10) + usize::from(fmt[i] - b'0');
                any = true;
                i += 1;
            }
            if any {
                spec.width = w;
            }
        }
        // Precision.
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            if i < fmt.len() && fmt[i] == b'*' {
                spec.precision = Some(args.next_u32(mem) as usize);
                i += 1;
            } else {
                let mut p = 0usize;
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    p = p.saturating_mul(10) + usize::from(fmt[i] - b'0');
                    i += 1;
                }
                spec.precision = Some(p);
            }
        }
        // Length modifier. Every argument is a 32-bit word on this ABI whatever
        // this says, so it is consumed and discarded -- but it must be
        // consumed, or `%ld` renders as a literal `l` followed by the number.
        while i < fmt.len() && matches!(fmt[i], b'h' | b'l' | b'L') {
            i += 1;
        }

        let Some(&conv) = fmt.get(i) else {
            // A format string ending mid-conversion. Emit what was there.
            out.extend_from_slice(&fmt[start..]);
            break;
        };
        i += 1;

        match conv {
            b'%' => out.push(b'%'),
            b'c' => {
                #[allow(clippy::cast_possible_truncation)]
                let ch = args.next_u32(mem) as u8;
                out.extend_from_slice(&spec.pad(vec![ch], None));
            }
            b's' => {
                let at = args.next_u32(mem);
                let mut s = string_at(mem, at);
                if let Some(p) = spec.precision {
                    s.truncate(p);
                }
                out.extend_from_slice(&spec.pad(s, None));
            }
            b'd' | b'i' => {
                #[allow(clippy::cast_possible_wrap)]
                let v = args.next_u32(mem) as i32;
                let sign = (v < 0).then_some(b'-');
                let digits = v.unsigned_abs().to_string().into_bytes();
                out.extend_from_slice(&spec.pad(with_precision(digits, spec), sign));
            }
            b'u' => {
                let v = args.next_u32(mem);
                let digits = v.to_string().into_bytes();
                out.extend_from_slice(&spec.pad(with_precision(digits, spec), None));
            }
            b'x' | b'X' => {
                let v = args.next_u32(mem);
                let digits = if conv == b'x' {
                    format!("{v:x}")
                } else {
                    format!("{v:X}")
                }
                .into_bytes();
                out.extend_from_slice(&spec.pad(with_precision(digits, spec), None));
            }
            b'o' => {
                let v = args.next_u32(mem);
                let digits = format!("{v:o}").into_bytes();
                out.extend_from_slice(&spec.pad(with_precision(digits, spec), None));
            }
            b'p' => {
                let v = args.next_u32(mem);
                out.extend_from_slice(format!("{v:08X}").as_bytes());
            }
            // Unrecognised: emit the whole thing literally. See the module doc.
            _ => out.extend_from_slice(&fmt[start..i]),
        }
    }
    out
}

/// A numeric conversion's precision is a *minimum digit count*, padded with
/// leading zeros -- unlike `%s`, where it is a maximum length. Confusing the
/// two truncates numbers.
fn with_precision(digits: Vec<u8>, spec: Spec) -> Vec<u8> {
    match spec.precision {
        Some(p) if p > digits.len() => {
            let mut out = vec![b'0'; p - digits.len()];
            out.extend_from_slice(&digits);
            out
        }
        _ => digits,
    }
}

/// The bytes of a `%s` argument.
///
/// **A null pointer renders as nothing, deliberately.** C leaves it undefined
/// and implementations disagree -- some print `(null)`, some crash. Printing
/// nothing is the choice least likely to be mistaken for real data in a report
/// this program is generating, and it is tested rather than incidental. An
/// unreadable non-null pointer is treated the same way, because the alternative
/// is taking the host down in the middle of formatting an error message.
fn string_at(mem: &Memory, at: u32) -> Vec<u8> {
    if at == 0 {
        return Vec::new();
    }
    Flat32Ptr(at)
        .read_cstr(mem)
        .map_or_else(|_| Vec::new(), <[u8]>::to_vec)
}

