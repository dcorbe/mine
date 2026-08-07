//! Strings, numbers and the print buffer.
//!
//! Everything here is a leaf: it computes, and it touches no host state a
//! module can observe later except the memory it was pointed at. `prf` and
//! `clrprf` are the exception that proves it -- they move `prfptr`, which is a
//! host global the module reads back.
//!
//! Signatures from `GCOMM.H`. Semantics from Galacticomm's own use of them
//! where the header does not say: `GALFILUT.C:73` passes `stzcpy`'s result
//! straight to `checkdir`, which is how we know it returns the destination and
//! not the terminator.

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::fmt::{Args, format};
use crate::shims::ShimError;

/// Bytes in one of `spr`'s rotating buffers.
pub const SPR_BYTES: u16 = 1024;

/// How many buffers `spr` rotates through.
///
/// Four, and it is observable: `prf("%s and %s", spr(...), spr(...))` needs
/// both results alive at once, and a module that nests more than four deep
/// gets the oldest one back. Galacticomm's own rotating-buffer idiom is
/// `cycle=((cycle+1)&3)` (`GALFILUT.C:73`), and MBBSEmu independently reads the
/// same count out of the binary.
pub const SPR_BUFFERS: usize = 4;

/// `char *spr(char *fmat, ...)` -- format into a buffer the host owns.
///
/// The module keeps the pointer, so the buffer has to outlive the call and the
/// rotation has to be wide enough that the next few calls do not tread on it.
pub fn spr(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (text, _) = format(machine, machine.arg_far(0), Args::Call { first: 2 })?;
    let at = host.next_spr_buffer();
    write_cstr(machine, at, &text, SPR_BYTES)?;
    Ok(Ret::Far(at))
}

/// `int sprintf(char *buf, char *fmat, ...)` -- format into the caller's
/// buffer, and return how many bytes that took.
///
/// How big the buffer is, only the caller knows. The bounds check is the
/// segment's, which is the only limit the host can see.
pub fn sprintf(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let buffer = machine.arg_far(0);
    let template = machine.arg_far(2);
    let (text, _) = format(machine, template, Args::Call { first: 4 })?;
    fill(machine, buffer, &text)?;
    Ok(Ret::U16(text.len() as u16))
}

/// `int vsprintf(char *buf, const char *fmat, va_list ap)` -- format into the
/// caller's buffer from an argument list it was handed, and return how many
/// bytes that took.
///
/// [`sprintf`] with the arguments somewhere else, and deliberately nothing
/// more: both go through the same [`crate::fmt::format`], so a conversion that
/// is right in one is right in the other.
///
/// Borland's `va_list` is `void *`, far under the huge model, which is why both
/// of MajorMUD's call sites clean six words rather than five. What it points at
/// is the caller's own frame in `SS` -- `va_start` is `lea ax,[bp+0x0a]` at
/// `seg 32:0x0b79`, the word past the last fixed argument -- so the words
/// behind it are laid out exactly as this routine's own would be.
pub fn vsprintf(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let buffer = machine.arg_far(0);
    let template = machine.arg_far(2);
    let list = machine.arg_far(4);
    let (text, _) = format(machine, template, Args::List { at: list })?;
    fill(machine, buffer, &text)?;
    Ok(Ret::U16(text.len() as u16))
}

/// `void prf(char *fmat, ...)` -- append to the channel's output.
///
/// `prfbuf` and `prfptr` are `char *` globals, not the buffer (`GCOMM.H:449`).
/// **`prfptr` is read back out of module memory every time**, never remembered:
/// the module moves it itself, and a host that cached it would append over
/// whatever the module had written.
pub fn prf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (text, _) = format(machine, machine.arg_far(0), Args::Call { first: 2 })?;
    append(machine, host, &text)?;
    Ok(Ret::Void)
}

/// Put `text` where `prfptr` points, and move `prfptr` past it.
///
/// Shared with `prfmsg`, which is this and a template that came out of a
/// message file rather than out of the module.
pub fn append(machine: &mut Machine, host: &mut Host, text: &[u8]) -> Result<(), ShimError> {
    let at = host
        .globals()
        .pointer(machine, "prfptr")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let end = host.prf_end();
    if usize::from(at.offset) + text.len() + 1 > usize::from(end) {
        return Err(ShimError::Failed(format!(
            "prf would put {} bytes past the end of a {end}-byte buffer",
            text.len()
        )));
    }

    write_cstr(machine, at, text, end - at.offset)?;
    let moved = FarPtr {
        offset: at.offset + text.len() as u16,
        selector: at.selector,
    };
    host.globals()
        .write(machine, "prfptr", &moved.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// `void clrprf(void)` -- throw away whatever `prf` has queued.
pub fn clrprf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let start = host
        .globals()
        .pointer(machine, "prfbuf")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    machine.write(start, &[0])?;
    host.globals()
        .write(machine, "prfptr", &start.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(Ret::Void)
}

/// `char *stzcpy(char *dst, char *src, unsigned num)` -- copy, bounded,
/// always terminated.
///
/// Not `strncpy`. `num` is the size of the destination, so at most `num - 1`
/// characters are copied and the NUL always fits; `strncpy` would copy `num`
/// and leave an unterminated buffer, which is the bug this routine exists to
/// avoid.
pub fn stzcpy(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let src = machine.arg_far(2);
    let num = machine.arg_u16(4);

    if num == 0 {
        // Nowhere to put even the terminator. Copying nothing is the only
        // thing that cannot overrun.
        return Ok(Ret::Far(dst));
    }
    let text = machine.read_cstr(src)?;
    let take = text.len().min(usize::from(num) - 1);
    let text = text[..take].to_vec();

    write_cstr(machine, dst, &text, num)?;
    Ok(Ret::Far(dst))
}

/// `char *strcpy(char *dst, char *src)`.
pub fn strcpy(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let text = machine.read_cstr(machine.arg_far(2))?.to_vec();
    let len = text.len() as u16 + 1;
    write_cstr(machine, dst, &text, len)?;
    Ok(Ret::Far(dst))
}

/// `unsigned strlen(char *s)`.
pub fn strlen(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let text = machine.read_cstr(machine.arg_far(0))?;
    Ok(Ret::U16(text.len() as u16))
}

/// `void rmvwht(char *string)` -- remove every whitespace character, in place.
///
/// See [`strings::rmvwht`](crate::strings::rmvwht), which is the transcription;
/// this is only the read and the write-back. The result is never longer than
/// what was read, so the original's capacity always holds it.
pub fn rmvwht(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let at = machine.arg_far(0);
    let text = machine.read_cstr(at)?.to_vec();
    let tight = crate::strings::rmvwht(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr(machine, at, &tight, capacity)?;
    Ok(Ret::Void)
}

/// `char *skpwht(char *cp)` -- past the leading spaces.
///
/// The answer is a pointer *into* the caller's own buffer, so the selector is
/// the one that arrived. See [`strings::skpwht`](crate::strings::skpwht) for
/// why a tab does not count.
pub fn skpwht(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let cp = machine.arg_far(0);
    let text = machine.read_cstr(cp)?;
    let n = crate::strings::skpwht(text) as u16;
    Ok(Ret::Far(at(cp, n)))
}

/// `char *skpwrd(char *cp)` -- past this word, to the space that ends it.
pub fn skpwrd(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let cp = machine.arg_far(0);
    let text = machine.read_cstr(cp)?;
    let n = crate::strings::skpwrd(text) as u16;
    Ok(Ret::Far(at(cp, n)))
}

/// `int depad(char *cp)` -- strip trailing whitespace, answer how much went.
pub fn depad(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let at = machine.arg_far(0);
    let text = machine.read_cstr(at)?.to_vec();
    let (kept, removed) = crate::strings::depad(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr(machine, at, &text[..kept], capacity)?;
    Ok(Ret::U16(removed))
}

/// `void parsin(void)` -- parse `input` into `margv[]`.
///
/// **Not in the v6 host source.** `MAJORBBS.C`'s `getin()` folds this
/// parsing inline; the routine `WCCMMUD.DLL` imports is Worldgroup's own,
/// split out at
/// `archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3376`:
///
///
/// Four things this does that a from-scratch splitter would not, and each is
/// load-bearing:
///
/// 1. **It fills `margn[]`, not just `margv[]`.** `margn[i]` points at the NUL
///    that replaced word `i`'s separator. [`rstrin`] already reads `margn` to
///    put the spaces back, at **every** exit -- including the early `return`
///    inside the inner loop, which is the common case: a line with no
///    trailing whitespace never reaches the function's tail at all.
/// 2. **It sets `inplen`** to the offset of the last word's terminator from
///    the start of `input`.
/// 3. **It zeroes the tail of `input`** past the last word -- but only on the
///    path that falls through to the function's end. That path is reached
///    only when the line has trailing whitespace after its last word; the
///    early return does not run it, because there is nothing stale left to
///    clear when the word ended at the buffer's own terminator.
/// 4. **On an empty line it sets `margv[0]` to an empty string, not to
///    null.** The module reads `margv[0]` unguarded, so this host keeps one
///    NUL byte of its own for the purpose -- see [`Host::empty`].
pub fn parsin(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let input = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    let size = usize::from(
        host.globals()
            .size("input")
            .ok_or_else(|| ShimError::Failed("input is not placed".into()))?,
    );
    let margv = host
        .globals()
        .address("margv")
        .ok_or_else(|| ShimError::Failed("margv is not placed".into()))?;
    let margn = host
        .globals()
        .address("margn")
        .ok_or_else(|| ShimError::Failed("margn is not placed".into()))?;

    let mut buf = machine.resolve(input, size)?.to_vec();

    let mut margv_ends: Vec<u16> = Vec::new(); // offsets into `buf`
    let mut margn_ends: Vec<u16> = Vec::new(); // offsets into `buf`

    // `inpptr = input - 1`. Every step below pre-increments before testing,
    // exactly as the C does, which is not a stylistic match: after a
    // separator is overwritten with a NUL, the outer loop's own
    // `while (*++inpptr == ' ')` has to step *past* that NUL before it looks
    // at anything, or it reads the byte it just wrote and mistakes it for the
    // end of the line.
    let mut i: isize = -1;

    loop {
        // `while (*++inpptr == ' ') {}`
        loop {
            i += 1;
            if buf.get(i as usize) != Some(&b' ') {
                break;
            }
        }
        // `if (*inpptr == '\0') { break; }`
        if buf.get(i as usize).copied().unwrap_or(0) == 0 {
            break;
        }
        // `margv[margc] = inpptr;`
        margv_ends.push(i as u16);

        // `while (*++inpptr != ' ') { if (*inpptr == '\0') { ...; return; } }`
        loop {
            i += 1;
            match buf.get(i as usize).copied() {
                Some(b' ') => break,
                None | Some(0) => {
                    // The early return. A word that runs straight into the
                    // buffer's own terminator, with no separator of its own
                    // to turn into one -- so `setmem` never runs, and
                    // nothing past this NUL is touched.
                    margn_ends.push(i as u16);
                    return write_parse(
                        machine,
                        host,
                        input,
                        margv,
                        margn,
                        &buf,
                        &margv_ends,
                        &margn_ends,
                        i as u16,
                    );
                }
                Some(_) => {}
            }
        }
        // `*inpptr = '\0'; margn[margc++] = inpptr;`
        buf[i as usize] = 0;
        margn_ends.push(i as u16);
    }

    let inplen = match margn_ends.last().copied() {
        Some(last) => {
            for byte in &mut buf[usize::from(last)..] {
                *byte = 0;
            }
            last
        }
        None => 0,
    };
    write_parse(
        machine,
        host,
        input,
        margv,
        margn,
        &buf,
        &margv_ends,
        &margn_ends,
        inplen,
    )
}

/// The tail every exit of [`parsin`] shares: write the (possibly modified)
/// input buffer back, then `margc`, `inplen`, `margv[]` and `margn[]`.
#[allow(clippy::too_many_arguments)]
fn write_parse(
    machine: &mut Machine,
    host: &mut Host,
    input: FarPtr,
    margv: FarPtr,
    margn: FarPtr,
    buf: &[u8],
    margv_ends: &[u16],
    margn_ends: &[u16],
    inplen: u16,
) -> Result<Ret, ShimError> {
    machine.write(input, buf)?;

    let margc = margv_ends.len() as u16;
    host.globals()
        .write(machine, "margc", &margc.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write(machine, "inplen", &inplen.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if margc == 0 {
        let empty = host.empty_string();
        machine.write(margv, &empty.to_bytes())?;
        return Ok(Ret::Void);
    }

    for (n, &at) in margv_ends.iter().enumerate() {
        let word = FarPtr {
            offset: input.offset + at,
            selector: input.selector,
        };
        let slot = FarPtr {
            offset: margv.offset + n as u16 * 4,
            selector: margv.selector,
        };
        machine.write(slot, &word.to_bytes())?;
    }
    for (n, &at) in margn_ends.iter().enumerate() {
        let end = FarPtr {
            offset: input.offset + at,
            selector: input.selector,
        };
        let slot = FarPtr {
            offset: margn.offset + n as u16 * 4,
            selector: margn.selector,
        };
        machine.write(slot, &end.to_bytes())?;
    }
    Ok(Ret::Void)
}

/// `void rstrin(void)` -- put back the separators that parsing overwrote.
///
/// MajorBBS tokenises a command line in place: each separator becomes a `\0`,
/// `margv` points at the words and `margn` at where each one ended.
/// `MAJORBBS.H:384` says so -- "array of ptrs to word ends, for rstrin()" --
/// and this walks that array writing a space back at each.
///
/// **The bound is `margc - 1` and the comparison is signed**, which is why a
/// `margc` of zero writes nothing rather than looping 65,535 times. Read off
/// `seg 4:0x5bde` in `MAJORBBS.EXE`; the routine sets up no `bp` frame at all,
/// which is what settles that it takes no arguments -- the whole of its input
/// is these two globals.
pub fn rstrin(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let margc = host
        .globals()
        .word(machine, "margc")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let margn = host
        .globals()
        .address("margn")
        .ok_or_else(|| ShimError::Failed("margn is not placed".into()))?;

    for i in 0..(margc - 1).max(0) as u16 {
        let slot = FarPtr {
            offset: margn.offset + i * 4,
            selector: margn.selector,
        };
        // `resolve` is how this crate reads raw bytes out of module memory --
        // `read_cstr` is for strings and there is no buffer-filling `read`.
        let bytes = machine.resolve(slot, 4)?;
        let end = FarPtr {
            offset: u16::from_le_bytes([bytes[0], bytes[1]]),
            selector: u16::from_le_bytes([bytes[2], bytes[3]]),
        };
        machine.write(end, b" ")?;
    }
    Ok(Ret::Void)
}

/// `long atol(char *s)`.
///
/// Leading whitespace, an optional sign, then digits until something that is
/// not one. No error: C says the value is undefined on overflow and Borland
/// wraps, so this wraps.
pub fn atol(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let text = machine.read_cstr(machine.arg_far(0))?;
    let mut rest = text;

    while rest.first().is_some_and(u8::is_ascii_whitespace) {
        rest = &rest[1..];
    }
    let negative = match rest.first() {
        Some(b'-') => {
            rest = &rest[1..];
            true
        }
        Some(b'+') => {
            rest = &rest[1..];
            false
        }
        _ => false,
    };

    let mut value = 0i32;
    while let Some(&byte) = rest.first().filter(|b| b.is_ascii_digit()) {
        value = value.wrapping_mul(10).wrapping_add(i32::from(byte - b'0'));
        rest = &rest[1..];
    }
    if negative {
        value = value.wrapping_neg();
    }
    Ok(Ret::U32(value as u32))
}

/// `int sameas(char *stg1,char *stg2)` -- equal, ignoring case.
///
/// **1 is equal**, which is the opposite of [`strcmp`] and the reason this
/// family is worth reading twice. See
/// [`strings::sameas`](crate::strings::sameas).
pub fn sameas(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let a = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let b = machine.read_cstr(machine.arg_far(2))?;
    Ok(Ret::U16(crate::strings::sameas(&a, b).into()))
}

/// `int sameto(char *shorts,char *longs)` -- a prefix test, short one first.
pub fn sameto(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let shorts = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let longs = machine.read_cstr(machine.arg_far(2))?;
    Ok(Ret::U16(crate::strings::sameto(&shorts, longs).into()))
}

/// `int samein(char *shorts,char *longs)` -- a substring test, short one first.
pub fn samein(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let shorts = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let longs = machine.read_cstr(machine.arg_far(2))?;
    Ok(Ret::U16(crate::strings::samein(&shorts, longs).into()))
}

/// `char *lastwd(char *string)` -- the last word, in the caller's own buffer.
///
/// See [`strings::lastwd`](crate::strings::lastwd). It writes nothing, and the
/// selector it answers is the one that arrived.
pub fn lastwd(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let s = machine.arg_far(0);
    let n = crate::strings::lastwd(machine.read_cstr(s)?) as u16;
    Ok(Ret::Far(at(s, n)))
}

/// `void sortstgs(char *stgs[],int num)` -- sort an array of `char *` in place.
///
/// `num` is a signed `int` and the original's `gap = num / 2` is tested with a
/// signed compare, so **anything below two returns before the array is read**.
/// That is why a `num` of zero with a null array is not an error here either --
/// the real one never dereferences it.
///
/// The pointers move; the strings do not. See
/// [`strings::sortstgs`](crate::strings::sortstgs) for why the sort is
/// transcribed rather than delegated.
pub fn sortstgs(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let array = machine.arg_far(0);
    let num = machine.arg_u16(2) as i16;
    if num < 2 {
        return Ok(Ret::Void);
    }
    let num = usize::from(num as u16);

    let slots = machine.resolve(array, num * 4)?.to_vec();
    let mut items: Vec<(FarPtr, Vec<u8>)> = Vec::with_capacity(num);
    for slot in slots.chunks_exact(4) {
        let ptr = FarPtr::from_bytes([slot[0], slot[1], slot[2], slot[3]]);
        items.push((ptr, machine.read_cstr(ptr)?.to_vec()));
    }
    crate::strings::sortstgs(&mut items, |a, b| crate::strings::strcmp(&a.1, &b.1));

    let out: Vec<u8> = items.iter().flat_map(|(ptr, _)| ptr.to_bytes()).collect();
    machine.write(array, &out)?;
    Ok(Ret::Void)
}

/// `char *strtok(char *s,char *delim)` -- the next token, destructively.
///
/// Ordinal 585, `seg 1:0x24f4`. Three things worth naming:
///
/// * **The state is the host's.** A non-null `s` sets it, a null `s` continues
///   from it, and nothing the module can address holds it. See
///   [`Host::strtok`].
/// * **It writes into the caller's string**, putting a terminator over the
///   delimiter that ended each token. What it answers is a pointer into that
///   same buffer.
/// * **A run of delimiters is one gap**, because the leading-delimiter skip and
///   the token scan are separate loops; a string of nothing else answers
///   `NULL`.
///
/// The original walks a byte at a time through `les bx,[0x18a8]`. Reading the
/// remainder once with [`Machine::read_cstr`] is the same bytes and one bounds
/// check -- and it is what turns a cursor left dangling by a `galfree` into
/// [`ShimError::BadPointer`] rather than a token made of rubbish.
pub fn strtok(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let s = machine.arg_far(0);
    let delims = machine.read_cstr(machine.arg_far(2))?.to_vec();
    if s != FarPtr::NULL {
        host.strtok = s;
    }

    let cursor = host.strtok;
    let rest = machine.read_cstr(cursor)?;
    let Some(start) = rest.iter().position(|b| !delims.contains(b)) else {
        // Nothing but delimiters. The cursor ends on the terminator, so every
        // later call answers NULL too.
        host.strtok = at(cursor, rest.len() as u16);
        return Ok(Ret::Far(FarPtr::NULL));
    };
    let token_len = rest[start..].len();
    let ends_at = rest[start..].iter().position(|b| delims.contains(b));

    let token = at(cursor, start as u16);
    match ends_at {
        Some(n) => {
            let end = at(token, n as u16);
            machine.write(end, &[0])?;
            host.strtok = at(end, 1);
        }
        None => host.strtok = at(token, token_len as u16),
    }
    Ok(Ret::Far(token))
}

/// `char *strchr(char *s,int c)`.
///
/// Ordinal 572, `seg 1:0xcf62`. Two things the prototype hides. `c` arrives as
/// an `int` and is compared as `mov bl,[bp+0xa]`, so **only its low byte
/// counts**. And the scan compares each byte *before* it tests for the end
/// (`lodsb / cmp al,bl / jz ... / and al,al / jnz`), so `strchr(s, 0)` answers
/// a pointer to the terminator rather than `NULL`.
pub fn strchr(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let s = machine.arg_far(0);
    let want = machine.arg_u16(2) as u8;
    let text = machine.read_cstr(s)?;

    if want == 0 {
        return Ok(Ret::Far(at(s, text.len() as u16)));
    }
    Ok(match text.iter().position(|&b| b == want) {
        Some(i) => Ret::Far(at(s, i as u16)),
        None => Ret::Far(FarPtr::NULL),
    })
}

/// `char *strstr(char *hay,char *needle)`.
///
/// Ordinal 584, `seg 1:0x2896`. **An empty needle answers the haystack** --
/// the routine's first instruction after the frame is `cmp byte [es:bx],0` on
/// the needle, and the path it takes returns `hay` **without reading it**, so
/// the check comes before the haystack does here too. A needle that is not
/// there answers `NULL`.
pub fn strstr(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let hay = machine.arg_far(0);
    let needle = machine.read_cstr(machine.arg_far(2))?.to_vec();
    if needle.is_empty() {
        return Ok(Ret::Far(hay));
    }
    let text = machine.read_cstr(hay)?;

    if needle.len() > text.len() {
        return Ok(Ret::Far(FarPtr::NULL));
    }
    let found = (0..=text.len() - needle.len()).find(|&i| text[i..].starts_with(&needle));
    Ok(match found {
        Some(i) => Ret::Far(at(hay, i as u16)),
        None => Ret::Far(FarPtr::NULL),
    })
}

/// `char *strcat(char *dst,char *src)`.
///
/// Ordinal 571, `seg 1:0x26d0`. How much room `dst` has, only the caller knows,
/// so the bound is the segment's -- the same limit [`fill`] applies to
/// `sprintf`, and for the same reason.
pub fn strcat(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let end = machine.read_cstr(dst)?.len() as u16;
    let text = machine.read_cstr(machine.arg_far(2))?.to_vec();
    fill(machine, at(dst, end), &text)?;
    Ok(Ret::Far(dst))
}

/// `char *strncat(char *dst,char *src,int maxlen)`.
///
/// Ordinal 580, `seg 1:0x236a`: `strlen`, `strlen`, clamp to `maxlen`, `movmem`,
/// then a terminator the routine writes itself at `dst[dstlen + n]`. So at most
/// `maxlen + 1` bytes land past the end of `dst` and -- unlike [`strncpy`] --
/// the result is always terminated.
pub fn strncat(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let end = machine.read_cstr(dst)?.len() as u16;
    let max = usize::from(machine.arg_u16(4));
    let text = machine.read_cstr(machine.arg_far(2))?;
    let text = text[..text.len().min(max)].to_vec();
    fill(machine, at(dst, end), &text)?;
    Ok(Ret::Far(dst))
}

/// `char *strncpy(char *dst,char *src,unsigned n)`.
///
/// Ordinal 582, `seg 1:0x2815`, and **not** [`stzcpy`] -- which is
/// Galacticomm's answer to this routine's one flaw. `strncpy` copies at most
/// `n` bytes and pads the rest of `n` with NUL, so a source of `n` characters
/// or more leaves the destination **unterminated**. Exactly `n` bytes are
/// written every time, which is what makes the bound checkable at all.
///
/// **The source need not be terminated.** `repne scasb` is issued with
/// `cx = n`, so the scan reads at most `n` bytes and stops; a blank-padded
/// fixed-width field with no NUL in it is precisely what this routine is for,
/// and refusing one would stop a module the real host served.
pub fn strncpy(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let n = usize::from(machine.arg_u16(4));
    if n == 0 {
        // All three `rep` prefixes are no-ops, so the original dereferences
        // neither pointer. Same reason `stzcpy` returns early on a zero.
        return Ok(Ret::Far(dst));
    }

    // What the scan could touch. `n` bytes if they are all inside the segment;
    // otherwise the original only got away with it because a terminator
    // stopped it first, and `read_cstr` is the reader that insists on one.
    let src = machine.arg_far(2);
    let text = match machine.resolve(src, n) {
        Ok(bytes) => bytes,
        Err(_) => machine.read_cstr(src)?,
    };
    let take = text
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(text.len())
        .min(n);

    let mut out = vec![0u8; n];
    out[..take].copy_from_slice(&text[..take]);
    machine.write(dst, &out)?;
    Ok(Ret::Far(dst))
}

/// `int strcmp(char *s1,char *s2)` -- **0 is equal**, unlike [`sameas`].
///
/// See [`strings::strcmp`](crate::strings::strcmp): the result is the unsigned
/// byte difference, not a sign, and MajorMUD's 48 sites test it both ways.
pub fn strcmp(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let a = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let b = machine.read_cstr(machine.arg_far(2))?;
    Ok(Ret::U16(crate::strings::strcmp(&a, b) as u16))
}

/// `int toupper(int c)`.
///
/// **Not a macro here.** Borland's macro is `_toupper`; `toupper` is a real
/// routine in the runtime, which is why `WCCMMUD.DLL` has 530 *call sites* for
/// ordinal 604 rather than 530 inlined subtractions.
///
/// Two things the prototype does not say, both read off `seg 1:0x54a9`. `-1` is
/// compared *before* the ctype table is indexed and returned unchanged, so EOF
/// survives as a full word. Everything else is `mov al,cl; mov ah,0` -- cut to
/// its low byte and zero-extended back -- so `toupper(0x161)` is `toupper('a')`
/// and answers `0x41`, not `0x141`.
pub fn toupper(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    Ok(Ret::U16(fold(machine.arg_u16(0), crate::strings::toupper)))
}

/// `int tolower(int c)` -- [`toupper`]'s mirror, and the routine `sameas`,
/// `sameto` and `samein` fold with.
pub fn tolower(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    Ok(Ret::U16(fold(machine.arg_u16(0), crate::strings::tolower)))
}

/// The `int` wrapper both case-folding routines share: EOF through untouched,
/// everything else truncated to a byte and zero-extended back.
fn fold(c: u16, by: fn(u8) -> u8) -> u16 {
    /// What `cmp cx,0xffff` compares against, and the one argument that is not
    /// truncated.
    const EOF: u16 = -1i16 as u16;

    if c == EOF {
        EOF
    } else {
        u16::from(by(c as u8))
    }
}

/// Put `text` and its terminator where a caller's `char *` points.
///
/// How big the buffer is, only the caller knows -- `sprintf` and `vsprintf` are
/// told an address and nothing else. The bounds check is therefore the
/// segment's, which is the only limit the host can see, and it is one check
/// because the terminator goes out in the same write as the text. That is not
/// only tidier: computing the terminator's own address means adding to a `u16`
/// offset, and a buffer near the end of its segment wraps that addition round
/// to the front.
///
/// [`write_cstr`] is the other half of this pair, for the buffers this host
/// owns and whose capacity it therefore knows enough to refuse.
///
/// # Errors
///
/// If the text and its terminator do not fit in the segment `at` names.
fn fill(machine: &mut Machine, at: FarPtr, text: &[u8]) -> Result<(), ShimError> {
    let mut bytes = text.to_vec();
    bytes.push(0);
    machine.write(at, &bytes)?;
    Ok(())
}

/// A pointer `n` bytes into the string `ptr` names.
///
/// The one piece of arithmetic every routine here that answers a `char *` does,
/// and the reason it does not need checking: **`ptr.offset + n` never passes
/// the terminator of a string that has already been read**. A successful
/// [`Machine::read_cstr`] puts that terminator inside the segment, a segment is
/// at most 64 KiB, and so the sum is at most `0xffff`. That covers `n` taken
/// from a string's length and equally the
/// `at(end, 1)` in [`strtok`], where `end` is a delimiter -- strictly before
/// the terminator, so one past it still is not past.
///
/// The selector is the caller's own. Rebuilding it from anywhere else would
/// hand the module an address into the wrong segment.
fn at(ptr: FarPtr, n: u16) -> FarPtr {
    FarPtr {
        offset: ptr.offset + n,
        selector: ptr.selector,
    }
}

/// Write `text` and its terminator at `at`, refusing to exceed `capacity`.
pub fn write_cstr(
    machine: &mut Machine,
    at: FarPtr,
    text: &[u8],
    capacity: u16,
) -> Result<(), ShimError> {
    if text.len() + 1 > usize::from(capacity) {
        return Err(ShimError::Failed(format!(
            "{} bytes and a terminator will not fit in {capacity}",
            text.len()
        )));
    }
    let mut bytes = text.to_vec();
    bytes.push(0);
    machine.write(at, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn lastwd_answers_a_pointer_into_the_callers_own_string() {
        let mut f = Fixture::new();
        let s = f.text("SHORT MESSAGES LONG");
        let Ret::Far(p) = f.invoke(lastwd, &Fixture::far(s)).expect("ok") else {
            panic!("lastwd returns char *");
        };
        assert_eq!(p.selector, s.selector);
        assert_eq!(f.read(p), "LONG");
        assert_eq!(f.read(s), "SHORT MESSAGES LONG", "and changes nothing");
    }

    #[test]
    fn lastwd_leaves_the_trailing_padding_where_it_found_it() {
        let mut f = Fixture::new();
        let s = f.text("go north  ");
        let Ret::Far(p) = f.invoke(lastwd, &Fixture::far(s)).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "north  ", "skipped, not stripped");
    }

    #[test]
    fn sortstgs_rewrites_the_array_of_pointers_in_place() {
        let mut f = Fixture::new();
        let pear = f.text("pear");
        let apple = f.text("apple");
        let fig = f.text("fig");
        let array = f.words(&[
            pear.offset,
            pear.selector,
            apple.offset,
            apple.selector,
            fig.offset,
            fig.selector,
        ]);

        assert!(matches!(
            f.invoke(sortstgs, &[array.offset, array.selector, 3]),
            Ok(Ret::Void)
        ));
        let bytes = f.machine.resolve(array, 12).expect("readable").to_vec();
        let got: Vec<FarPtr> = bytes
            .chunks_exact(4)
            .map(|c| FarPtr::from_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(
            got,
            vec![apple, fig, pear],
            "the pointers moved, not the text"
        );
    }

    #[test]
    fn sortstgs_of_fewer_than_two_reads_nothing_at_all() {
        // `gap = num/2` under a signed compare, so 1, 0 and any negative return
        // before the array is touched. That is why a null array is not an
        // error here -- the real one never dereferences it either.
        let mut f = Fixture::new();
        for num in [0u16, 1, (-4i16) as u16] {
            assert!(matches!(f.invoke(sortstgs, &[0, 0, num]), Ok(Ret::Void)));
        }
    }

    #[test]
    fn sortstgs_refuses_a_slot_that_names_nothing() {
        // The array itself is readable and one of the strings in it is not.
        // Sorting by a comparison the host cannot make is exactly the
        // plausible answer this crate refuses.
        let mut f = Fixture::new();
        let one = f.text("only");
        let array = f.words(&[one.offset, one.selector, 0, 0]);
        assert!(
            f.invoke(sortstgs, &[array.offset, array.selector, 2])
                .is_err()
        );
    }

    #[test]
    fn sortstgs_refuses_an_array_that_leaves_its_segment() {
        let mut f = Fixture::new();
        let one = f.text("only");
        let array = f.words(&[one.offset, one.selector]);
        // Two pointers named, one present, and the rest of the segment is not
        // the module's to claim.
        assert!(
            f.invoke(sortstgs, &[array.offset, array.selector, 900])
                .is_err()
        );
    }

    #[test]
    fn strtok_walks_a_line_and_then_says_there_is_no_more() {
        // The state is the host's -- `MAJORBBS.EXE` keeps one far pointer at
        // `DGROUP:0x18a8` and no module can see it -- so the later calls pass
        // NULL and the host has to remember where it got to.
        let mut f = Fixture::new();
        let line = f.text("go  north now");
        let delim = f.text(" ");
        let first = [line.offset, line.selector, delim.offset, delim.selector];
        let again = [0, 0, delim.offset, delim.selector];

        let Ret::Far(one) = f.invoke(strtok, &first).expect("ok") else {
            panic!("strtok returns char *");
        };
        assert_eq!(f.read(one), "go");

        let Ret::Far(two) = f.invoke(strtok, &again).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(two), "north", "a run of two spaces is one gap");

        let Ret::Far(three) = f.invoke(strtok, &again).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(three), "now");

        assert_eq!(
            f.invoke(strtok, &again).expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
        assert_eq!(
            f.invoke(strtok, &again).expect("ok"),
            Ret::Far(FarPtr::NULL),
            "and it stays exhausted"
        );
    }

    #[test]
    fn strtok_writes_a_terminator_over_the_delimiter_it_consumed() {
        // It is destructive, and the module depends on that: the token it
        // answers is a pointer into the caller's own buffer, terminated in
        // place by `mov byte [es:bx],0x0`.
        let mut f = Fixture::new();
        let line = f.text("a,b");
        let delim = f.text(",");

        f.invoke(
            strtok,
            &[line.offset, line.selector, delim.offset, delim.selector],
        )
        .expect("ok");
        assert_eq!(
            f.machine.resolve(line, 4).expect("readable"),
            b"a\0b\0",
            "the comma became a terminator"
        );
    }

    #[test]
    fn strtok_of_nothing_but_delimiters_answers_null() {
        let mut f = Fixture::new();
        let line = f.text(",,,");
        let delim = f.text(",");
        assert_eq!(
            f.invoke(
                strtok,
                &[line.offset, line.selector, delim.offset, delim.selector]
            )
            .expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn strtok_restarts_when_it_is_given_a_string() {
        let mut f = Fixture::new();
        let first = f.text("a b");
        let second = f.text("c d");
        let delim = f.text(" ");

        f.invoke(
            strtok,
            &[first.offset, first.selector, delim.offset, delim.selector],
        )
        .expect("ok");
        let Ret::Far(p) = f
            .invoke(
                strtok,
                &[second.offset, second.selector, delim.offset, delim.selector],
            )
            .expect("ok")
        else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "c", "a non-null string replaces the cursor");
    }

    #[test]
    fn strtok_with_no_delimiters_answers_the_whole_string() {
        // The delimiter walk is `while (*p != 0)`, so an empty set exits at
        // once and nothing is ever a delimiter: one token, the whole line.
        let mut f = Fixture::new();
        let line = f.text("go north");
        let empty = f.text("");
        let Ret::Far(p) = f
            .invoke(
                strtok,
                &[line.offset, line.selector, empty.offset, empty.selector],
            )
            .expect("ok")
        else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "go north");
        assert_eq!(
            f.invoke(strtok, &[0, 0, empty.offset, empty.selector])
                .expect("ok"),
            Ret::Far(FarPtr::NULL),
            "and then there is no more"
        );
    }

    #[test]
    fn strtok_with_no_previous_call_refuses_rather_than_inventing_a_token() {
        // The real one reads through whatever `DGROUP:0x18a8` happens to hold.
        // Here that starts null, and a pointer naming nothing is an error.
        let mut f = Fixture::new();
        let delim = f.text(" ");
        assert!(
            f.invoke(strtok, &[0, 0, delim.offset, delim.selector])
                .is_err()
        );
    }

    #[test]
    fn strchr_finds_a_byte_or_answers_null() {
        let mut f = Fixture::new();
        let s = f.text("go north");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'n')])
                .expect("ok"),
            Ret::Far(at(s, 3))
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'z')])
                .expect("ok"),
            Ret::Far(FarPtr::NULL),
            "absent is NULL, not the terminator"
        );
    }

    #[test]
    fn strchr_of_nul_answers_the_terminator_and_ignores_the_high_byte() {
        // `mov bl,[bp+0xa]` -- only the low byte of the `int` is compared --
        // and the scan tests each byte before it checks for the end, so
        // searching for `\0` finds it rather than failing.
        let mut f = Fixture::new();
        let s = f.text("abc");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0]).expect("ok"),
            Ret::Far(at(s, 3))
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0xff62])
                .expect("ok"),
            Ret::Far(at(s, 1)),
            "0xff62 is searched for as 'b'"
        );
    }

    #[test]
    fn strstr_finds_a_run_and_an_empty_needle_finds_the_start() {
        let mut f = Fixture::new();
        let hay = f.text("go north now");
        let needle = f.text("north");
        let empty = f.text("");
        let missing = f.text("south");
        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];

        assert_eq!(
            f.invoke(strstr, &pair(hay, needle)).expect("ok"),
            Ret::Far(at(hay, 3))
        );
        assert_eq!(
            f.invoke(strstr, &pair(hay, empty)).expect("ok"),
            Ret::Far(hay),
            "the routine's first test is on the needle"
        );
        assert_eq!(
            f.invoke(strstr, &pair(hay, missing)).expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
        assert_eq!(
            f.invoke(strstr, &pair(needle, hay)).expect("ok"),
            Ret::Far(FarPtr::NULL),
            "a needle longer than the haystack"
        );
    }

    #[test]
    fn strcat_appends_and_returns_the_destination() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector];
        assert_eq!(f.invoke(strcat, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.read(dst), "go north");
    }

    #[test]
    fn strncpy_pads_to_n_and_does_not_terminate_a_full_buffer() {
        // The difference from `stzcpy`, which is Galacticomm's answer to this
        // routine: `stzcpy` always terminates and `strncpy` does not.
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let src = f.text("abcdefgh");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 4];

        assert_eq!(f.invoke(strncpy, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(
            f.machine.resolve(dst, 8).expect("readable"),
            b"abcd####",
            "four copied, no terminator, and the rest of the buffer untouched"
        );
    }

    #[test]
    fn strncpy_fills_the_whole_of_n_when_the_source_is_shorter() {
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let src = f.text("ab");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 6];

        f.invoke(strncpy, &args).expect("ok");
        assert_eq!(
            f.machine.resolve(dst, 8).expect("readable"),
            b"ab\0\0\0\0##",
            "six bytes written, the last four of them NUL"
        );
    }

    #[test]
    fn strncpy_does_not_require_the_source_to_be_terminated() {
        // `repne scasb` with `cx = n` reads **at most n bytes**. A source with
        // no terminator in it is the case this routine exists for -- a
        // blank-padded fixed-width field -- and refusing one would stop a
        // module the real host served.
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let scratch = dst.selector;

        // Six non-zero bytes hard against the end of a 4,096-byte segment, so
        // there is no terminator between the source and the end of what it
        // names.
        let src = FarPtr {
            offset: 4090,
            selector: scratch,
        };
        f.machine.write(src, &[b'x'; 6]).expect("fits exactly");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 4];
        assert_eq!(f.invoke(strncpy, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.machine.resolve(dst, 8).expect("readable"), b"xxxx####");
    }

    #[test]
    fn strncpy_of_nothing_touches_neither_pointer() {
        // `rep` with `cx = 0` is a no-op three times over, so the original
        // dereferences nothing at all -- the same reason `stzcpy` returns
        // early on a `num` of zero.
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(strncpy, &[0, 0, 0, 0, 0]).expect("wrote nothing"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn strncpy_still_refuses_a_source_it_would_have_to_read_past() {
        // The other half of the same rule: the scan is bounded by `n`, so an
        // `n` that reaches past the end of the source's segment with no
        // terminator in the way is a read the original could not have made
        // either.
        let mut f = Fixture::new();
        let dst = f.buffer(64);
        let src = FarPtr {
            offset: 4090,
            selector: dst.selector,
        };
        f.machine.write(src, &[b'x'; 6]).expect("fits exactly");
        assert!(
            f.invoke(
                strncpy,
                &[dst.offset, dst.selector, src.offset, src.selector, 32]
            )
            .is_err()
        );
    }

    #[test]
    fn strncat_clamps_the_source_and_terminates_it_itself() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("northwards");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 5];
        assert_eq!(f.invoke(strncat, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.read(dst), "go north", "five of the source, then a NUL");
    }

    #[test]
    fn strncat_clamps_unsigned_despite_its_int_prototype() {
        // The clamp is `cmp ax,[bp+0xe] / jna` -- an UNSIGNED compare, though
        // `GCOMM.H` calls the argument an `int`. Reading it signed would make
        // a large `maxlen` negative and clamp the copy to nothing.
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 0x8000];
        f.invoke(strncat, &args).expect("ok");
        assert_eq!(f.read(dst), "go north", "0x8000 is 32,768, not -32,768");
    }

    #[test]
    fn strncat_of_nothing_writes_only_a_terminator_already_there() {
        // `maxlen` of zero copies nothing, and the terminator the routine
        // writes itself goes at `dst[dstlen + n]` -- which with `n` of zero is
        // the terminator `dst` already had. So nothing past the string moves,
        // and in particular the byte *after* it is not cleared.
        let mut f = Fixture::new();
        let dst = f.bytes(b"go \0##", false);
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 0];
        f.invoke(strncat, &args).expect("ok");
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"go \0##");
    }

    #[test]
    fn strchr_on_an_empty_string_finds_only_its_terminator() {
        let mut f = Fixture::new();
        let s = f.text("");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0]).expect("ok"),
            Ret::Far(s),
            "the terminator is at offset zero"
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'a')])
                .expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn the_writers_refuse_to_run_off_the_end_of_a_segment() {
        // How much room a destination has, only the caller knows -- so the
        // only bound the host can apply is the segment's, and it must be an
        // error rather than a truncated copy or a wrapped offset.
        let mut f = Fixture::new();
        let src = f.text("overlong");
        let scratch = src.selector;
        let near_end = FarPtr {
            offset: 4090,
            selector: scratch,
        };
        f.machine.write(near_end, b"go\0").expect("still inside");

        assert!(
            f.invoke(
                strncpy,
                &[
                    near_end.offset,
                    near_end.selector,
                    src.offset,
                    src.selector,
                    100
                ]
            )
            .is_err(),
            "100 bytes at 4090 leaves a 4096-byte segment"
        );
        assert!(
            f.invoke(
                strcat,
                &[near_end.offset, near_end.selector, src.offset, src.selector]
            )
            .is_err(),
            "and so does `go` plus `overlong`"
        );
        assert!(
            f.invoke(
                strncat,
                &[
                    near_end.offset,
                    near_end.selector,
                    src.offset,
                    src.selector,
                    100
                ]
            )
            .is_err(),
            "and so does appending a clamped copy of it"
        );
    }

    #[test]
    fn strcmp_returns_the_difference_and_zero_for_equal() {
        let mut f = Fixture::new();
        let short = f.text("kobold");
        let long = f.text("koboldy");
        let same = f.text("kobold");
        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];

        assert_eq!(
            f.invoke(strcmp, &pair(short, long)).expect("ok"),
            Ret::U16((-121i16) as u16),
            "the terminator against 'y'"
        );
        assert_eq!(
            f.invoke(strcmp, &pair(long, short)).expect("ok"),
            Ret::U16(121)
        );
        assert_eq!(
            f.invoke(strcmp, &pair(short, same)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn the_same_family_answers_one_for_equal_not_strcmps_zero() {
        // `sameas` is 1 for equal; `strcmp` is 0 for equal. Returning the
        // wrong sense compiles, runs, and diverges 500 sites later.
        let mut f = Fixture::new();
        let long = f.text("LONG");
        let lower = f.text("long");
        let longer = f.text("longer");

        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];
        assert_eq!(
            f.invoke(sameas, &pair(long, lower)).expect("ok"),
            Ret::U16(1)
        );
        assert_eq!(
            f.invoke(sameas, &pair(long, longer)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn sameto_takes_the_prefix_first_and_samein_takes_the_needle_first() {
        let mut f = Fixture::new();
        let long = f.text("long");
        let longer = f.text("longer");
        let ong = f.text("ONG");

        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];
        assert_eq!(
            f.invoke(sameto, &pair(long, longer)).expect("ok"),
            Ret::U16(1),
            "sameto(shorts, longs): `longer` begins with `long`"
        );
        assert_eq!(
            f.invoke(sameto, &pair(longer, long)).expect("ok"),
            Ret::U16(0),
            "and not the other way round"
        );
        assert_eq!(
            f.invoke(samein, &pair(ong, longer)).expect("ok"),
            Ret::U16(1),
            "samein(shorts, longs): `ONG` is inside `longer`"
        );
        assert_eq!(
            f.invoke(samein, &pair(longer, ong)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn the_same_family_refuses_a_pointer_naming_nothing() {
        let mut f = Fixture::new();
        let s = f.text("x");
        for shim in [sameas, sameto, samein] {
            assert!(f.invoke(shim, &[s.offset, s.selector, 0, 0]).is_err());
            assert!(f.invoke(shim, &[0, 0, s.offset, s.selector]).is_err());
        }
    }

    #[test]
    fn toupper_folds_a_letter_and_leaves_everything_else() {
        let mut f = Fixture::new();
        for (input, want) in [
            (u16::from(b'a'), u16::from(b'A')),
            (u16::from(b'A'), u16::from(b'A')),
            (u16::from(b'7'), u16::from(b'7')),
            (0, 0),
        ] {
            assert_eq!(f.invoke(toupper, &[input]).expect("folded"), Ret::U16(want));
        }
        assert_eq!(
            f.invoke(tolower, &[u16::from(b'Z')]).expect("folded"),
            Ret::U16(u16::from(b'z'))
        );
    }

    #[test]
    fn toupper_passes_eof_through_and_truncates_everything_else() {
        // `cmp cx,0xffff` happens before the table is indexed, so EOF is the
        // one argument that survives as a full word. Every other `int` is cut
        // to its low byte: `toupper(0x161)` is `toupper('a')`.
        let mut f = Fixture::new();
        assert_eq!(f.invoke(toupper, &[0xffff]).expect("EOF"), Ret::U16(0xffff));
        assert_eq!(f.invoke(tolower, &[0xffff]).expect("EOF"), Ret::U16(0xffff));
        assert_eq!(f.invoke(toupper, &[0x161]).expect("cut"), Ret::U16(0x41));
        assert_eq!(f.invoke(tolower, &[0xff41]).expect("cut"), Ret::U16(0x61));
    }

    #[test]
    fn case_folding_agrees_with_the_ctype_table_the_host_placed() {
        // Two sources of case-folding is a bug waiting to happen. The module
        // indexes `_ctype` itself -- it imports it as the `__CTYPE` datum --
        // and the real `toupper` reads that same table. This sweeps all 256
        // bytes and asserts the transcription and the placed bytes agree, so
        // that a change to either is caught here rather than 500 sites later.
        let f = Fixture::new();
        let at = f
            .host
            .globals()
            .address("_ctype")
            .expect("_ctype is placed");
        let table = f.machine.resolve(at, 257).expect("257 bytes").to_vec();
        for c in 0..=255u8 {
            let bits = table[usize::from(c) + 1];
            assert_eq!(
                bits & 0x08 != 0,
                crate::strings::toupper(c) != c,
                "_IS_LOW disagrees about {c:#04x}"
            );
            assert_eq!(
                bits & 0x04 != 0,
                crate::strings::tolower(c) != c,
                "_IS_UPP disagrees about {c:#04x}"
            );
        }
    }

    #[test]
    fn stzcpy_truncates_and_always_terminates() {
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("Newhaven");

        // Five bytes of room means four characters and the NUL. `strncpy`
        // would put five characters and no NUL, which is the difference.
        let args = [dst.offset, dst.selector, src.offset, src.selector, 5];
        assert_eq!(f.invoke(stzcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "Newh");
    }

    #[test]
    fn stzcpy_returns_the_destination() {
        // `GALFILUT.C:73` passes the result straight to `checkdir`, so it is
        // the string that was written and not its terminator.
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("hi");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 16];
        assert_eq!(f.invoke(stzcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "hi");
    }

    #[test]
    fn stzcpy_with_no_room_writes_nothing() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"keep", true);
        let src = f.text("overwrite me");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 0];
        f.invoke(stzcpy, &args).expect("copied nothing");
        assert_eq!(f.read(dst), "keep", "not even a terminator fits in zero");
    }

    #[test]
    fn strcpy_and_strlen() {
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("kobold");
        let args = [dst.offset, dst.selector, src.offset, src.selector];
        assert_eq!(f.invoke(strcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "kobold");

        let mut f = Fixture::new();
        let at = f.text("kobold");
        assert_eq!(
            f.invoke(strlen, &Fixture::far(at)).expect("ok"),
            Ret::U16(6)
        );
    }

    #[test]
    fn atol_reads_a_long_out_of_a_string() {
        let cases = [
            ("100000", 100_000i32),
            ("  -42abc", -42),
            ("+7", 7),
            ("", 0),
            ("not a number", 0),
        ];
        for (text, expect) in cases {
            let mut f = Fixture::new();
            let at = f.text(text);
            assert_eq!(
                f.invoke(atol, &Fixture::far(at)).expect("parsed"),
                Ret::U32(expect as u32),
                "{text:?}"
            );
        }
    }

    #[test]
    fn spr_rotates_far_enough_to_keep_four_results_alive() {
        // `prf("%s and %s", spr(...), spr(...))` needs both, so the rotation
        // is observable. Four calls must land in four different places, and
        // the fifth must come back to the first.
        let mut f = Fixture::new();
        let template = f.text("%d");
        let mut seen = Vec::new();
        for n in 0..=SPR_BUFFERS {
            let args = [template.offset, template.selector, n as u16];
            let Ret::Far(at) = f.invoke(spr, &args).expect("formatted") else {
                panic!("spr returns a pointer");
            };
            seen.push(at);
        }

        let mut offsets: Vec<u16> = seen[..SPR_BUFFERS].iter().map(|p| p.offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), SPR_BUFFERS, "{seen:?}");
        assert_eq!(seen[SPR_BUFFERS], seen[0], "the fifth reuses the first");

        // And the fourth is still readable after the fifth overwrote the first.
        assert_eq!(f.read(seen[3]), "3");
    }

    #[test]
    fn sprintf_writes_into_the_callers_buffer_and_returns_the_length() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        let template = f.text("%s/%d");
        let text = f.text("gold");
        let args = [
            dst.offset,
            dst.selector,
            template.offset,
            template.selector,
            text.offset,
            text.selector,
            9,
        ];
        assert_eq!(f.invoke(sprintf, &args).expect("ok"), Ret::U16(6));
        assert_eq!(f.read(dst), "gold/9");
    }

    #[test]
    fn prf_appends_and_clrprf_starts_over() {
        let mut f = Fixture::new();
        let template = f.text("<%d>");

        f.invoke(prf, &[template.offset, template.selector, 1])
            .expect("first");
        f.invoke(prf, &[template.offset, template.selector, 2])
            .expect("second");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<1><2>", "the second call appends");

        f.invoke(clrprf, &[]).expect("cleared");
        assert_eq!(f.read(buffer), "");
        assert_eq!(
            f.host
                .globals()
                .pointer(&f.machine, "prfptr")
                .expect("prfptr"),
            buffer,
            "clrprf puts prfptr back at the start"
        );
    }

    #[test]
    fn prf_reads_prfptr_back_rather_than_remembering_it() {
        // The module moves `prfptr` itself -- it writes into the buffer and
        // advances the pointer without telling anyone. A host that remembered
        // where it last wrote would append over that, and the damage would
        // show up as scrambled output much later.
        let mut f = Fixture::new();
        let template = f.text("%d");
        f.invoke(prf, &[template.offset, template.selector, 1])
            .expect("first");

        let buffer = f.host.globals().prf_buffer();
        let moved = FarPtr {
            offset: buffer.offset + 8,
            selector: buffer.selector,
        };
        f.host
            .globals()
            .write(&mut f.machine, "prfptr", &moved.to_bytes())
            .expect("moved");

        f.invoke(prf, &[template.offset, template.selector, 2])
            .expect("second");
        assert_eq!(f.read(moved), "2", "prf wrote where prfptr now points");
        assert_eq!(f.read(buffer), "1", "and left the earlier text alone");
    }

    #[test]
    fn prf_refuses_to_run_past_the_end_of_the_buffer() {
        let mut f = Fixture::new();
        let template = f.text("%s");
        let long = f.bytes(&vec![b'x'; 2000], true);

        // Twice over is more than the 4 KiB buffer holds. The real one would
        // simply write past it.
        f.invoke(
            prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        )
        .expect("the first fits");
        let second = f.invoke(
            prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        );
        assert!(second.is_ok(), "two of these still fit");

        let third = f.invoke(
            prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        );
        assert!(third.is_err(), "the third would overrun");
    }

    #[test]
    fn rmvwht_rewrites_the_callers_buffer_in_place() {
        // It returns void, so the only observable effect is the buffer.
        let mut f = Fixture::new();
        let at = f.text("  the quick brown fox  ");
        assert!(matches!(f.invoke(rmvwht, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"thequickbrownfox");
    }

    #[test]
    fn rmvwht_handles_a_string_that_is_entirely_whitespace() {
        let mut f = Fixture::new();
        let at = f.text(" \t\r\n ");
        f.invoke(rmvwht, &Fixture::far(at)).expect("void");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"");
    }

    #[test]
    fn skpwht_answers_a_pointer_into_the_string_it_was_given() {
        // The return is a far pointer, and its selector must be the caller's --
        // a shim that rebuilt it from somewhere else would hand back an address
        // into the wrong segment and the module would read rubbish.
        let mut f = Fixture::new();
        let at = f.text("   abc");
        let Ret::Far(p) = f.invoke(skpwht, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwht returns char *");
        };
        assert_eq!(p.selector, at.selector);
        assert_eq!(p.offset, at.offset + 3);
        assert_eq!(f.machine.read_cstr(p).expect("a string"), b"abc");
    }

    #[test]
    fn skpwht_stops_at_a_tab_because_the_original_tests_one_byte() {
        let mut f = Fixture::new();
        let at = f.text("\tabc");
        let Ret::Far(p) = f.invoke(skpwht, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwht returns char *");
        };
        assert_eq!(p.offset, at.offset, "a tab is not 0x20");
    }

    #[test]
    fn skpwrd_answers_the_space_that_ended_the_word() {
        let mut f = Fixture::new();
        let at = f.text("word rest");
        let Ret::Far(p) = f.invoke(skpwrd, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwrd returns char *");
        };
        assert_eq!(p.offset, at.offset + 4);
        assert_eq!(f.machine.read_cstr(p).expect("a string"), b" rest");
    }

    #[test]
    fn depad_truncates_the_buffer_and_returns_the_count() {
        let mut f = Fixture::new();
        let at = f.text("text   ");
        let Ret::U16(n) = f.invoke(depad, &Fixture::far(at)).expect("a count") else {
            panic!("depad returns an int");
        };
        assert_eq!(n, 3, "three characters went");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"text");
    }

    #[test]
    fn depad_leaves_a_string_that_needs_nothing_alone() {
        let mut f = Fixture::new();
        let at = f.text("  text");
        let Ret::U16(n) = f.invoke(depad, &Fixture::far(at)).expect("a count") else {
            panic!("depad returns an int");
        };
        assert_eq!(n, 0, "leading padding is not padding");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"  text");
    }

    #[test]
    fn rstrin_puts_back_the_separators_that_parsing_replaced() {
        // `margn` holds pointers to where each word ended -- the bytes that
        // were spaces before the parser wrote NULs over them. `rstrin` restores
        // margc-1 of them, which is one per gap between margc words.
        let mut f = Fixture::new();
        let line = f.text("look\0at\0this");
        let margn = f.host.globals().address("margn").expect("margn");

        // Two separators, at offsets 4 and 7.
        let ends = [line.offset + 4, line.offset + 7];
        for (i, off) in ends.iter().enumerate() {
            let slot = mbbs16::FarPtr {
                offset: margn.offset + (i as u16) * 4,
                selector: margn.selector,
            };
            let bytes = [
                off.to_le_bytes()[0],
                off.to_le_bytes()[1],
                line.selector.to_le_bytes()[0],
                line.selector.to_le_bytes()[1],
            ];
            f.machine.write(slot, &bytes).expect("margn slot");
        }
        f.host
            .globals()
            .write(&mut f.machine, "margc", &3u16.to_le_bytes())
            .expect("margc");

        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(line).expect("a string"), b"look at this");
    }

    #[test]
    fn rstrin_with_nothing_parsed_writes_nothing() {
        // The original's bound is `margc - 1` under a SIGNED compare, so a
        // margc of zero writes nothing. Unsigned, it would loop 65,535 times
        // and scribble over whatever margn happened to contain.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "margc", &0u16.to_le_bytes())
            .expect("margc");
        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));
    }

    /// A far pointer, read out of module memory at `at`.
    fn read_ptr(machine: &mbbs16::Machine, at: FarPtr) -> FarPtr {
        let bytes = machine.resolve(at, 4).expect("readable");
        FarPtr::from_bytes(bytes.try_into().expect("4 bytes"))
    }

    /// The `n`th slot of `margv` or `margn`, each an array of far pointers.
    fn slot(base: FarPtr, n: u16) -> FarPtr {
        FarPtr {
            offset: base.offset + n * 4,
            selector: base.selector,
        }
    }

    #[test]
    fn parsin_splits_the_input_buffer_into_margv() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 3);
        let margv = f.host.globals().address("margv").expect("margv");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 0))), "get");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 1))), "all");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 2))), "gold");
    }

    #[test]
    fn parsin_collapses_runs_of_separators() {
        // "get   all" is two arguments, not four -- the three spaces between
        // them are one gap, not three empty ones.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get   all")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 2);
        let margv = f.host.globals().address("margv").expect("margv");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 0))), "get");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 1))), "all");
    }

    #[test]
    fn parsin_on_an_empty_line_points_margv_zero_at_an_empty_string() {
        // The module reads `margv[0]` unguarded, so it must be a readable
        // pointer -- never null, and never a stack temporary that stops being
        // valid after this call returns.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);
        let margv = f.host.globals().address("margv").expect("margv");
        let at = read_ptr(&f.machine, slot(margv, 0));
        assert_ne!(at, FarPtr::NULL, "margv[0] must not be null");
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"");
    }

    #[test]
    fn parsin_records_where_each_word_ended_so_rstrin_can_undo_it() {
        // margn[i] is the NUL that replaced word i's separator -- offset 3 for
        // the space after "get", offset 7 for the one after "all".
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        let margn = f.host.globals().address("margn").expect("margn");
        let end0 = read_ptr(&f.machine, slot(margn, 0));
        let end1 = read_ptr(&f.machine, slot(margn, 1));
        assert_eq!(end0.offset - input.offset, 3);
        assert_eq!(end1.offset - input.offset, 7);
    }

    #[test]
    fn rstrin_puts_back_exactly_what_parsin_took_apart() {
        // The round trip, and the test that catches a `parsin` which is
        // self-consistent but disagrees with the `rstrin` already shipped:
        // parse "get all gold", call `rstrin`, and read `input` back as one
        // string.
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));
        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));

        assert_eq!(f.machine.read_cstr(input).expect("a string"), b"get all gold");
    }

    #[test]
    fn parsin_sets_inplen_to_the_length_it_consumed() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        // The offset of the terminating NUL from the start of `input` -- the
        // early-return path inside the inner loop is what sets this, since
        // "gold" has no trailing space.
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 12);
    }

    #[test]
    fn parsin_zeros_the_tail_of_input_past_trailing_whitespace_and_stale_bytes() {
        // Reachable only through the *outer* tail -- `if (margc != 0) { ...
        // setmem(...) }` -- and not through the inner loop's early return,
        // because trailing spaces after the last word mean the terminating
        // NUL is only found once the outer loop resumes skipping spaces.
        // `input` is 256 bytes and nothing clears it between commands, so a
        // shorter line leaves the previous, longer one sitting past its own
        // terminator; a `parsin` that forgot the `setmem` would leave that
        // stale tail for the module to read as though it were part of this
        // line.
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        let size = usize::from(f.host.globals().size("input").expect("input"));
        let mut buf = vec![0xffu8; size];
        buf[..7].copy_from_slice(b"gold   ");
        buf[7] = 0;
        f.machine.write(input, &buf).expect("input with a stale tail");

        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 1);
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 4);
        let bytes = f.machine.resolve(input, size).expect("readable");
        assert_eq!(&bytes[..4], b"gold");
        assert!(
            bytes[4..].iter().all(|&b| b == 0),
            "trailing spaces and everything stale past them are zeroed"
        );
    }

    #[test]
    fn vsprintf_formats_from_the_list_it_is_handed() {
        let mut f = Fixture::new();
        let out = f.buffer(64);
        let template = f.text("%s the %s, level %d");
        let who = f.text("rangerdan");
        let what = f.text("Ranger");
        let list = f.words(&[who.offset, who.selector, what.offset, what.selector, 21]);

        let ret = f
            .invoke(
                vsprintf,
                &[
                    out.offset,
                    out.selector,
                    template.offset,
                    template.selector,
                    list.offset,
                    list.selector,
                ],
            )
            .expect("formatted");

        assert_eq!(f.read(out), "rangerdan the Ranger, level 21");
        assert!(matches!(ret, Ret::U16(30)), "{ret:?}");
    }

    #[test]
    fn vsprintf_terminates_what_it_wrote() {
        // The buffer starts full of a byte that is not a terminator, so a
        // missing NUL would be visible rather than papered over by a fixture
        // that happened to hand out zeroed memory.
        let mut f = Fixture::new();
        let out = f.bytes(&[b'#'; 16], false);
        let template = f.text("%d");
        let list = f.words(&[7]);

        f.invoke(
            vsprintf,
            &[
                out.offset,
                out.selector,
                template.offset,
                template.selector,
                list.offset,
                list.selector,
            ],
        )
        .expect("formatted");

        assert_eq!(f.read(out), "7");
    }

    #[test]
    fn vsprintf_refuses_a_list_it_cannot_follow() {
        let mut f = Fixture::new();
        let out = f.buffer(16);
        let template = f.text("%d");
        let args = [
            out.offset,
            out.selector,
            template.offset,
            template.selector,
            0,
            0,
        ];
        assert!(f.invoke(vsprintf, &args).is_err());
    }
}
