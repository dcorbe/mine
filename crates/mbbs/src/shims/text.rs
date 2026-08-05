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
    let at = machine.arg_far(0);
    let text = machine.read_cstr(at)?;
    let n = crate::strings::skpwht(text) as u16;
    Ok(Ret::Far(FarPtr {
        offset: at.offset + n,
        selector: at.selector,
    }))
}

/// `char *skpwrd(char *cp)` -- past this word, to the space that ends it.
pub fn skpwrd(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let at = machine.arg_far(0);
    let text = machine.read_cstr(at)?;
    let n = crate::strings::skpwrd(text) as u16;
    Ok(Ret::Far(FarPtr {
        offset: at.offset + n,
        selector: at.selector,
    }))
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
        assert_eq!(
            f.machine.read_cstr(at).expect("a string"),
            b"thequickbrownfox"
        );
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
        assert_eq!(
            f.machine.read_cstr(line).expect("a string"),
            b"look at this"
        );
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
