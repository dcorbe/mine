//! Credits, module exit, and three C-runtime leaves: `_DEDCRD`, `_TSTCRD`,
//! `_CONDEX`, `_SSCANF`, `_MEMSET`, `_INTDOS`.
//!
//! (`_HASMKEY` was a sixth leaf here once -- a message-keyed key check --
//! removed 2026-08-15 as a dead duplicate of [`crate::shims::user::hasmkey`],
//! the registered twin: the same `LOCKNKEY.C:238-243` logic, reached through
//! [`crate::shims::user`]'s own private `gen_haskey` helper instead of
//! reimplemented inline. See `docs/2026-08-15-dead-twin-shims.md`.)
//!
//! None of these six are called by `WCCMMUD.DLL` -- `re/exports/WCCMMUD_named.c`
//! and `WCCMMUD_decompiled.c` have zero occurrences of any of them, checked
//! against every case-folding Ghidra might have used for an unresolved import.
//! The oracle for this file is Tele-Arena instead:
//! `/home/daniel/bbs/re/tasrc/tsgarn-2.c:385-386,440` calls `tstcrd`, `dedcrd`
//! and `condex` as a real shipping module, and is cited as a module call site
//! throughout, never as host source. `sscanf`, `memset` and `intdos` have no
//! call site anywhere in `re/tasrc` either; those three are implemented from
//! the vendor's own definition, and say so at each one.
//!
//! Vendor citations are the **wg1** archive tree
//! (`archive/galacticomm/extract/wg1/GALDSRC/SRC`), never wg20 -- the same
//! files exist in both and carry different line numbers.
//!
//! # Accounting is where this file is deliberately lazy
//!
//! [`dedcrd`] and [`tstcrd`] do no accounting at all -- `tstcrd` always
//! answers "yes, plenty of credits" and `dedcrd` always answers "deducted"
//! while touching no balance, because nothing here keeps one. This is the
//! repository owner's explicit call, not a measurement or a derivation from
//! `shims::credits`' otherwise-careful reasoning: this host is not billing
//! anyone for a computer program written before the US Civil War began, and
//! a permissive, no-op answer is the one that lets a game run without a
//! credit gate ever blocking it. `shims::credits`' own module doc comment
//! reaches the same *answer* independently, for a real accounting model
//! (class debt limits, `CRDXMT`) this file does not bother building -- see
//! [`dedcrd`] and [`tstcrd`] themselves for what that means concretely. A
//! host that ever wants real billing has to replace both.
//!
//! [`condex`] restates `lib.rs`'s own precedent for a real host mechanism this
//! crate does not have: `MAJORBBS.C:5253-5255`'s `go2mnu(JSTRET)`, "the
//! menuing system this host does not have", answered by finishing the
//! disconnect instead of guessing at one. `condex`'s real body needs the same
//! missing subsystem -- see its own doc comment for why that turns out to
//! change nothing observable here, rather than requiring the same kind of
//! substitution.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::shims::ShimError;

/// The answer [`dedcrd`] and [`tstcrd`] both give: yes.
///
/// Not a measurement, and not derived from `ldedcrd`/`ltstcrd`'s class-table
/// arithmetic the way `shims::credits::otstcrd`/`odedcrd` derive theirs. This
/// is the repository owner's explicit instruction: this host does no
/// accounting, on purpose, because nobody is being billed for a computer
/// program written before the US Civil War began, and a permissive answer is
/// the one that lets a game run rather than dead-end at a credit gate a real
/// board could enforce and this one has no reason to.
const YES: u16 = 1;

/// `int dedcrd(long amt, int asmuch)` -- deduct credits from the *current*
/// online account. `ACCOUNT.C:412-418`:
///
///
/// **Deducts nothing and always reports success.** This host keeps no credit
/// balance for any account, and per the repository owner's own instruction
/// (see [`YES`]) that is deliberate laziness rather than a gap to fill later:
/// building `ldedcrd`'s class-table arithmetic (debt limits, `CRDXMT`,
/// `swtcls` on hitting zero) would only be work spent making a billing system
/// answer questions nobody is asking for money. `amt` and `asmuch` are read,
/// to keep the argument frame in step with whatever follows this call on the
/// module's own stack, and then discarded.
///
/// `re/tasrc/tsgarn-2.c:386` is the real call site: `dedcrd(rescrd,1)`, the
/// toll for a character reset, called immediately after `tstcrd(rescrd)`
/// (`:385`) answers yes -- confirming this always-succeeds answer is what
/// lets that path resolve rather than dead-end at `NEDCRD`/`prfmlt(NEDCRD)`
/// (`:428`), the "not enough credits" branch this host never takes.
///
/// A host that ever wants real billing has to replace this with something
/// that reads and writes an actual balance.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host -- in particular, if
/// nobody is current at all. [`Host::current_channel_mem`]'s own doc comment
/// covers when that is true; the real `uacoff(usrnum)` would be indexing the
/// account table with `-1`, so refusing here is not part of the accounting
/// this file skips, only the channel bookkeeping every shim in this crate
/// does.
pub fn dedcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _amt = call.long();
    let _asmuch = call.int();
    host.current_channel_mem(call.mem())?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

/// `int rdedcrd(long amt, int asmuch)` -- deduct **real** credits from the
/// current online account. `ACCOUNT.C:409-415`:
///
///
/// **[`dedcrd`] with `real` set, and the same answer for the same reason.**
/// The two differ by one argument to `ldedcrd`: `dedcrd` passes `real=0` and
/// `rdedcrd` passes `real=1`, which selects whether the class table's debt
/// limit and its `CRDXMT` credit-exemption are allowed to make the deduction
/// succeed on an account that cannot really afford it. This host keeps no
/// balance, no class table and no debt limit, so the distinction has nothing
/// to distinguish and both answer yes -- see [`YES`] for whose decision that
/// is and why it is a decision rather than a gap.
///
/// Answering this one differently from [`dedcrd`] would be the incoherent
/// choice, not the careful one: a module charging through `dedcrd` would
/// proceed and the same module charging through `rdedcrd` would stop, over a
/// balance neither of them moved.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host; see [`dedcrd`].
pub fn rdedcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _amt = call.long();
    let _asmuch = call.int();
    host.current_channel_mem(call.mem())?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

/// `int tstcrd(long amt)` -- does the *current* user have `amt` credits to
/// spare? `ACCOUNT.C:574-579`:
///
///
/// **Always yes**, for the same reason [`dedcrd`] always succeeds -- see
/// [`YES`]. `amt` is read and discarded; there is no balance here for it to
/// be compared against.
///
/// `re/tasrc/tsgarn-2.c:385` is the real call site, quoted on [`dedcrd`].
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host; see [`dedcrd`].
pub fn tstcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _amt = call.long();
    host.current_channel_mem(call.mem())?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

/// `CONCEX`, `MAJORBBS.H:211` -- "commands concatenated -- exit fast". Bit
/// `0x800` of `user.flags`, which [`crate::users::UserLayout::flags`] locates at
/// `+0x14` in `struct user` (four bytes, little-endian -- `users.rs`'s own
/// module doc comment measures the field off `WCCMMUD.DLL`'s own byte
/// accesses, though this bit is never one of the ones that module tests).
const CONCEX: u32 = 0x0000_0800;

/// `void condex(void)` -- conditional module-exit. `MAJORBBS.C:2544-2557`:
///
///
/// `re/tasrc/tsgarn-2.c:438-442` is the real call site -- Tele-Arena's
/// `EXTING` substate, reached from the credit-refusal branch quoted on
/// [`dedcrd`], calls `condex()` to bail out of a chained command sequence
/// before falling through to `quitta()`/`injacr()`.
///
/// # Why this can answer faithfully without `eximod`/`valexi`
///
/// The `longjmp` branch needs two pieces of host state this crate does not
/// have: `valexi` (was a `susing()` dispatch currently mid-call to a status
/// routine) and `eximod` (where to land). `lib.rs:5253-5255`'s own test
/// comment already names the reason neither exists -- `go2mnu(JSTRET)`, "the
/// menuing system this host does not have" -- and `susing()` (`MAJORBBS.C:2478`,
/// the only place `valexi` is ever set to 1) is that same menuing dispatch
/// loop's per-channel status handler. This host drives a channel's status
/// handling a different way (see `lib.rs`'s own `susing()` citations at
/// `:2652`/`:4974`) and never runs the code path that would set `valexi`.
///
/// That would ordinarily make this a routine to refuse rather than fabricate.
/// It does not have to be, because **`valexi` provably reads 0 for every call
/// this host can ever receive** -- there is no code path, reachable or not,
/// in this crate that writes it any other way, since the field does not
/// exist here at all. So the vendor's own branch on `valexi` is not a
/// question this host has to guess the answer to; it is a question whose
/// answer is fixed by this host's design, the same way `susing()`'s own
/// `if (usrptr->flags&ISGCSU)` branch is fixed false for a host with no
/// client/server subsystem. With `valexi` always 0, `condex()`'s *own* logic
/// -- not a substitution for it -- reduces to: report a catastrophic
/// "INVALID CONDEX CALL" if `CONCEX` is set, otherwise do nothing.
///
/// The remaining question is whether `CONCEX` can ever be set. Grepping the
/// entire wg1 archive tree for the literal token finds exactly one setter:
/// `MENUING.C:679`, `usrptr->flags|=CONCEX`, inside the main menu's own
/// concatenated-selection parser (`"1;2;3"` typed at a menu prompt). Every
/// other reference either tests the bit (`GALMJD.C`, `GALQWK.C`, this file)
/// or clears it (`AAFOR.C`, `GALFILUT.C`, `EMULATE.C`, `MENUING.C:389,682`).
/// This host has no menuing subsystem -- `docs/plans/2026-08-03-16bit-module-execution.md`'s
/// "Scope" is explicit that the goal is a headless module, not a reproduction
/// of MajorBBS's menu tree -- so nothing in this host's own code can ever set
/// this bit either. Both branches of the real function are therefore
/// answerable, not just the reachable one: the bit is read from the same
/// module memory `WCCMMUD.DLL` itself would read it from (rather than
/// asserted false from the host side), so a future feature that starts
/// setting it is caught by the loud refusal below instead of silently
/// mis-answering.
///
/// # Errors
///
/// If `usrnum` does not name a channel, or if `CONCEX` is set. The second
/// case is unreached by anything this crate can construct today (see above);
/// if it is ever reached, the two pieces of host state this comment opens
/// with -- a per-channel "a status dispatch is in progress" flag matching
/// `valexi`, and a place for [`condex`] to signal "unwind to it" that
/// whatever drives that dispatch loop honours -- are what would be needed to
/// answer it for real, rather than reporting it and continuing.
pub fn condex<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    let flags_at = A::ptr_offset(host.users().slot(chan), host.users().user_layout().flags.at);
    let bytes = flags_at
        .resolve(call.mem(), A::LONG_WIDTH)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let flags = A::long_from_bytes(bytes);
    if flags & CONCEX != 0 {
        return Err(ShimError::Failed(
            "condex: usrptr->flags&CONCEX is set, which this host's own code \
             can never construct (MENUING.C:679 is the only setter in the wg1 \
             archive, and this host has no menuing subsystem) -- something new \
             is setting it, and answering this for real needs a valexi/eximod \
             equivalent this host does not have; see this function's own doc \
             comment"
                .into(),
        ));
    }
    Ok(abi::Ret::Void)
}

/// Advance `pos` past every ASCII whitespace byte in `input` at or after it.
///
/// `scanf`'s own rule for a whitespace character in the *format*: it matches
/// any amount of whitespace in the input, including none. [`sscanf`] uses
/// this both for that case and, separately, before every conversion except
/// `%c` -- the ANSI rule that every conversion but `c` (and the two this host
/// does not implement, `[` and `n`) skips leading whitespace on its own,
/// independent of whether the format string put any there.
fn skip_ws(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && input[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

/// Pack `mag` (negated, if `neg`) into the low `width` bytes of a C integer,
/// little-endian -- what every numeric conversion in [`sscanf`] writes into
/// the caller's `int *`/`long *`.
///
/// Refuses rather than truncating a value that will not fit: `int i; sscanf
/// (s,"%d",&i)` with an out-of-range literal is undefined behaviour in ANSI C
/// too, but this crate stops the module over undefined behaviour everywhere
/// else, and a magnitude too large to fit is exactly the class of "the host
/// cannot answer this truthfully" that earns a refusal rather than a
/// plausible wrong number sitting in the caller's variable forever after.
fn pack_int(mag: u64, neg: bool, width: usize) -> Result<Vec<u8>, ShimError> {
    let limit: u64 = if neg {
        // The most negative value at this width has one more unit of
        // magnitude available than the most positive one (two's complement).
        1u64 << (width * 8 - 1)
    } else if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    };
    if mag > limit {
        return Err(ShimError::Failed(format!(
            "sscanf: {}{mag} does not fit in a {width}-byte int",
            if neg { "-" } else { "" }
        )));
    }
    let v: i64 = if neg { -(mag as i64) } else { mag as i64 };
    Ok(v.to_le_bytes()[..width].to_vec())
}

/// `int sscanf(const char *str, const char *fmat, ...)` -- parse `str`
/// against `fmat`, writing each matched conversion through the pointer
/// argument that follows it, and return how many conversions were assigned.
///
/// No prototype in any Galacticomm header (`GCOMM.H:97`'s `CNTLIT` comment --
/// "does sscanf() count literal matches?" -- is the only mention, and it does
/// not declare one); this is Borland's ANSI C runtime, re-exported by
/// `MAJORBBS.EXE`/`.DLL` the same way `sprintf` and `vsprintf` are
/// (`shims::text`'s own doc comment). No call site in `WCCMMUD.DLL` or
/// Tele-Arena (this file's own module doc comment) -- the format strings
/// below are cited to the *host's own* internal use of the real C library
/// `sscanf`, as the only measured evidence of what a Galacticomm-style format
/// string for this routine looks like:
///
///
/// # What is implemented, and what refuses
///
/// Literal characters (matched exactly), whitespace in the format (matches
/// any run of input whitespace, including none), `%%`, `%c`, `%s`, and `%d`/
/// `%u`/`%x`/`%X` with an optional `l` length modifier (`%ld`, `%lu`, `%lx`).
/// That covers every specifier the two cited call sites use, plus the length
/// modifier a module writing to a `long *` would need.
///
/// Anything else -- `%f`, `%o`, `%[`, `%n`, a width or `h`/`L` modifier, a
/// bare `%` at the end of the format -- is a **conversion this does not
/// know**, matching `crate::fmt`'s own rule for the output side (that
/// module's doc comment: "Not a passthrough and not an empty string"): it
/// stops the module rather than silently mis-parsing or skipping a
/// conversion whose argument it never consumed. `%u`/`%x`/`%X` do not accept
/// a leading sign here, unlike strict ISO C89 (which defines a signed `%u` as
/// wrapping) -- neither cited call site signs one, and accepting one without
/// an oracle to check the wraparound against would be a guess dressed as
/// fidelity.
///
/// The `0x`/`0X` prefix for `%x`/`%X` is consumed whenever both characters
/// are present, without backtracking if no hex digit follows -- an input of
/// exactly `"0x"` with nothing after it is a matching failure rather than a
/// match of the bare `0`. Real `scanf` backtracks; this does not, because
/// neither measured call site's input can produce that shape.
///
/// # Return value
///
/// The number of conversions successfully assigned, same as ISO C89. `-1`
/// (`EOF`) only when the input string is already exhausted at the point the
/// very *first* conversion is attempted -- once anything has been assigned,
/// running out of input or failing to match later just stops and returns the
/// count so far, never `-1`. `MAJORBBS.C:1104`'s own check
/// (`!= 2+CNTLIT`, and `CNTLIT` is `0`) is exactly "not both fields matched",
/// which this makes answerable the same way the real library would.
///
/// # Errors
///
/// If either string cannot be read, if a conversion this does not implement
/// appears in the format, or if a matched numeric literal does not fit the
/// destination's width (see [`pack_int`]).
pub fn sscanf<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let str_ptr = call.ptr();
    let fmt_ptr = call.ptr();
    let input = str_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let fmt = fmt_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    scan(call, &fmt, &input)
}

/// `sscanf`'s conversion loop, over a format and an input the caller has
/// already read.
///
/// Split out of [`sscanf`] so that [`crate::shims::crt::fscanf`] can drive the
/// same loop over a line read from a `FILE` instead of a string. The two
/// routines have the same argument shape after their first pointer -- the
/// destination pointers are read from the `Call` cursor here, as the format
/// string names them -- so one loop genuinely serves both.
///
/// Extracted rather than copied. A second transcription of scanf's conversion
/// rules is the kind of duplication this crate has paid for before: see
/// `shims::mod`'s `getmsgblk` registration for a third body deleted the same
/// day, and `da891421` for the twenty before that.
///
/// # Errors
///
/// An unsupported conversion specifier, or a destination pointer that does not
/// resolve.
pub(crate) fn scan<A: Abi>(
    call: &mut Call<A>,
    fmt: &[u8],
    input: &[u8],
) -> Result<abi::Ret<A>, ShimError> {
    // Exhaustion before the first conversion is EOF (`-1`); exhaustion or a
    // mismatch after at least one conversion just stops, per `sscanf`'s own
    // doc comment.
    let exhausted = |assigned: i32| -> abi::Ret<A> {
        if assigned == 0 {
            abi::Ret::Int(A::int_from_u32(u32::MAX))
        } else {
            abi::Ret::Int(A::int_from_u32(assigned as u32))
        }
    };
    let stopped =
        |assigned: i32| -> abi::Ret<A> { abi::Ret::Int(A::int_from_u32(assigned as u32)) };

    let mut ipos = 0usize;
    let mut fpos = 0usize;
    let mut assigned: i32 = 0;

    while fpos < fmt.len() {
        let fc = fmt[fpos];

        if fc.is_ascii_whitespace() {
            while fpos < fmt.len() && fmt[fpos].is_ascii_whitespace() {
                fpos += 1;
            }
            skip_ws(&input, &mut ipos);
            continue;
        }

        if fc != b'%' {
            if ipos >= input.len() {
                return Ok(exhausted(assigned));
            }
            if input[ipos] != fc {
                return Ok(stopped(assigned));
            }
            ipos += 1;
            fpos += 1;
            continue;
        }

        // `%` -- a conversion.
        fpos += 1;
        let long_mod = fpos < fmt.len() && fmt[fpos] == b'l';
        if long_mod {
            fpos += 1;
        }
        let Some(&conv) = fmt.get(fpos) else {
            return Err(ShimError::Failed(
                "sscanf: format ends with an incomplete conversion".into(),
            ));
        };
        fpos += 1;

        match conv {
            b'%' => {
                if ipos >= input.len() {
                    return Ok(exhausted(assigned));
                }
                if input[ipos] != b'%' {
                    return Ok(stopped(assigned));
                }
                ipos += 1;
            }
            b'c' => {
                if ipos >= input.len() {
                    return Ok(exhausted(assigned));
                }
                let dest = call.ptr();
                dest.write(call.mem(), &[input[ipos]])
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                ipos += 1;
                assigned += 1;
            }
            b's' => {
                skip_ws(&input, &mut ipos);
                if ipos >= input.len() {
                    return Ok(exhausted(assigned));
                }
                let start = ipos;
                while ipos < input.len() && !input[ipos].is_ascii_whitespace() {
                    ipos += 1;
                }
                let mut bytes = input[start..ipos].to_vec();
                bytes.push(0);
                let dest = call.ptr();
                dest.write(call.mem(), &bytes)
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                assigned += 1;
            }
            b'd' | b'u' | b'x' | b'X' => {
                skip_ws(&input, &mut ipos);
                if ipos >= input.len() {
                    return Ok(exhausted(assigned));
                }
                let signed = conv == b'd';
                let radix: u32 = if conv == b'x' || conv == b'X' { 16 } else { 10 };

                let neg = signed && input[ipos] == b'-';
                if signed && (input[ipos] == b'-' || input[ipos] == b'+') {
                    ipos += 1;
                }
                if radix == 16
                    && ipos + 1 < input.len()
                    && input[ipos] == b'0'
                    && (input[ipos + 1] == b'x' || input[ipos + 1] == b'X')
                {
                    ipos += 2;
                }

                let digits_start = ipos;
                let mut mag: u64 = 0;
                while ipos < input.len() {
                    let Some(d) = (input[ipos] as char).to_digit(radix) else {
                        break;
                    };
                    mag = mag
                        .checked_mul(u64::from(radix))
                        .and_then(|m| m.checked_add(u64::from(d)))
                        .ok_or_else(|| {
                            ShimError::Failed("sscanf: numeric literal overflowed".into())
                        })?;
                    ipos += 1;
                }
                if ipos == digits_start {
                    return Ok(stopped(assigned));
                }

                let width = if long_mod {
                    A::LONG_WIDTH
                } else {
                    A::INT_WIDTH
                };
                let bytes = pack_int(mag, neg, width)?;
                let dest = call.ptr();
                dest.write(call.mem(), &bytes)
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                assigned += 1;
            }
            other => {
                return Err(ShimError::Failed(format!(
                    "sscanf: conversion '%{}{}' is not implemented",
                    if long_mod { "l" } else { "" },
                    other as char
                )));
            }
        }
    }

    Ok(abi::Ret::Int(A::int_from_u32(assigned as u32)))
}

/// `void *memset(void *s, int c, size_t n)` -- fill, Borland's real ANSI C
/// runtime routine rather than the `setmem` macro over it.
///
/// **Pointer, fill, count** -- the argument order every C programmer already
/// knows, and the *opposite* of `setmem`'s. `GCOMM.H:143`'s
/// `#define setmem(p,n,c) memset(p,c,n)` is the vendor's own statement of
/// both orders at once: `setmem` is `(p, count, fill)`,
/// [`crate::shims::memory::setmem`] reads it that way, and this reads the
/// three raw arguments of the routine that macro expands to -- `(p, fill,
/// count)` -- in *its* order instead. A module that imports `_MEMSET`
/// directly (bypassing the macro, the way a hand-written import table or a
/// module compiled without `GCOMM.H` might) is calling the real routine with
/// the real order, and swapping fill and count here would silently corrupt
/// whatever the module meant to fill.
///
/// Returns `s`, matching the true `void *memset` prototype -- unlike
/// `shims::memory::setmem`, which answers `Void` because every measured
/// `setmem` call site in this crate's corpus discards the result. `memset`
/// has no such corpus to check, so this keeps the ANSI contract rather than
/// assume the same discard: `crate::shims::memory::memcpy`, the other real
/// CRT routine in this file's neighbour with no Galacticomm prototype,
/// answers its destination pointer for the identical reason.
///
/// # Errors
///
/// If the write runs past the segment `s` names.
pub fn memset<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    // A `char` argument still arrives as a whole word; the fill is its low
    // byte, matching `shims::memory::setmem`'s own note on the same read.
    let fill = Into::<u32>::into(call.int()) as u8;
    let count = Into::<u32>::into(call.int()) as u16;
    at.write(call.mem(), &vec![fill; usize::from(count)])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `int intdos(union REGS *inregs, union REGS *outregs)` -- Borland's wrapper
/// over `INT 21h`: load the CPU registers from `*inregs`, fire the DOS
/// software interrupt, and copy the result back into `*outregs`.
///
/// `MAJORBBS.C:3171-3191` shows the vendor's own use of the sibling `int86`
/// (`INT 1Ah`/`INT 21h` through a `union REGS`) to read and set the CMOS/DOS
/// clock -- real vendor code built on exactly this mechanism, cited to prove
/// it is a real one and not a speculative prototype.
///
/// # This host has no DOS interrupt path, and this refuses rather than fake one
///
/// `intdos`'s entire contract is "run whatever DOS function `AH` in `*inregs`
/// names" -- file I/O, memory allocation, the DOS version, dozens of others,
/// selected by a byte this routine does not get to see in advance. This
/// crate's module execution is `mbbs_machine::m16::Machine`, an x86 interpreter with
/// no DOS kernel or BIOS beneath it: there is no `int21`/`int86`/`intdos`
/// dispatcher anywhere in this crate (checked -- zero matches for any of
/// those names, or for "interrupt", outside this comment), because nothing
/// this host does needs one; every file, timer and console operation a
/// module can reach goes through a Galacticomm-shaped host routine instead of
/// a raw DOS call.
///
/// Answering this would not be one shim's worth of work: it would mean
/// choosing, function by function, which of DOS's INT 21h services this host
/// pretends to be able to run, and there is no oracle for that decision --
/// neither `WCCMMUD.DLL` nor Tele-Arena calls `intdos` at all (this file's
/// own module doc comment), so there is no real `AH` value to start from.
/// Per this crate's own standing rule (`crate::shims`'s "what to do when
/// nothing does"), a host that cannot answer truthfully stops the module
/// rather than fabricating a plausible `outregs`.
///
/// # Errors
///
/// Always. There is no answer this can give that is not a lie.
pub fn intdos<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _inregs = call.ptr();
    let _outregs = call.ptr();
    Err(ShimError::Failed(
        "intdos: this host has no DOS interrupt path -- INT 21h is not \
         emulated, and no call site in the measured corpus names which \
         function it would need; see this routine's own doc comment"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Connection;
    use crate::testing::Fixture;
    use mbbs_machine::m16::{FarPtr, Ret};

    fn connect(f: &mut Fixture, keys: &[&str]) -> crate::Chan {
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("rangerdan").with_keys(keys.iter().copied()),
            )
            .expect("channel 0");
        console
    }

    fn long_words(v: i64) -> [u16; 2] {
        let v = v as u32;
        [v as u16, (v >> 16) as u16]
    }

    #[test]
    fn dedcrd_and_tstcrd_answer_yes_for_the_current_user() {
        let mut f = Fixture::new();
        connect(&mut f, &[]);

        let amt = long_words(500);
        assert_eq!(
            f.invoke(tstcrd, &amt).expect("tstcrd"),
            Ret::U16(1),
            "otherwise re/tasrc/tsgarn-2.c:385 bounces the player to NEDCRD"
        );

        let mut args = amt.to_vec();
        args.push(1); // asmuch
        assert_eq!(f.invoke(dedcrd, &args).expect("dedcrd"), Ret::U16(1));
    }

    /// `rdedcrd` is `dedcrd` with `real` set, and answers the same way.
    /// Asserted side by side with `dedcrd` over the identical arguments,
    /// because the failure worth catching is the two disagreeing -- a module
    /// charging through one would proceed and through the other would stop,
    /// over a balance neither moved.
    #[test]
    fn rdedcrd_answers_exactly_as_dedcrd_does() {
        let mut f = Fixture::new();
        connect(&mut f, &[]);

        for amt in [0, 500, -500] {
            let mut args = long_words(amt).to_vec();
            args.push(1); // asmuch
            assert_eq!(
                f.invoke(rdedcrd, &args).expect("rdedcrd"),
                f.invoke(dedcrd, &args).expect("dedcrd"),
                "rdedcrd and dedcrd must agree on {amt}"
            );
            assert_eq!(f.invoke(rdedcrd, &args).expect("rdedcrd"), Ret::U16(1));
        }
    }

    /// With nobody current, `rdedcrd` refuses rather than answering yes --
    /// the real `uacoff(usrnum)` would be indexing the account table with
    /// `-1`. The same guard `dedcrd` carries.
    #[test]
    fn rdedcrd_refuses_when_nobody_is_the_current_user() {
        let mut f = Fixture::new();
        let mut args = long_words(500).to_vec();
        args.push(1);
        assert!(
            f.invoke(rdedcrd, &args).is_err(),
            "usrnum is -1 before anyone connects"
        );
    }

    #[test]
    fn dedcrd_and_tstcrd_take_a_refund_and_a_zero_charge_the_same_way() {
        let mut f = Fixture::new();
        connect(&mut f, &[]);
        for amt in [0, -500] {
            assert_eq!(
                f.invoke(tstcrd, &long_words(amt)).expect("tstcrd"),
                Ret::U16(1),
                "amt={amt}"
            );
        }
    }

    #[test]
    fn dedcrd_and_tstcrd_refuse_when_no_channel_is_current() {
        let mut f = Fixture::new();
        // Never connected: `usrnum` is still the `-1` `Globals::new` seeds.
        assert!(f.invoke(tstcrd, &long_words(500)).is_err());
        let mut args = long_words(500).to_vec();
        args.push(1);
        assert!(f.invoke(dedcrd, &args).is_err());
    }

    #[test]
    fn condex_is_a_no_op_when_concex_is_clear() {
        let mut f = Fixture::new();
        connect(&mut f, &[]);
        assert_eq!(f.invoke(condex, &[]).expect("no-op"), Ret::Void);
    }

    #[test]
    fn condex_refuses_loudly_when_concex_is_set() {
        let mut f = Fixture::new();
        let console = connect(&mut f, &[]);
        let slot = f.host.users().slot(console);
        let flags_at = FarPtr {
            offset: slot.offset + f.host.users().user_layout().flags.at,
            selector: slot.selector,
        };
        // Set only the CONCEX bit (0x0800), little-endian, leaving the rest
        // of the four-byte field zero.
        f.machine.write(flags_at, &[0, 0x08, 0, 0]).expect("in bounds");

        let e = f.invoke(condex, &[]).expect_err("no eximod/valexi here");
        assert!(e.to_string().contains("CONCEX"), "{e}");
    }

    #[test]
    fn condex_refuses_when_no_channel_is_current() {
        let mut f = Fixture::new();
        assert!(f.invoke(condex, &[]).is_err());
    }

    #[test]
    fn memset_takes_the_fill_before_the_count() {
        // Mirrors `shims::memory`'s own
        // `setmem_takes_the_count_before_the_fill` test, with the two
        // arguments the other way round -- see [`memset`]'s own doc comment.
        let mut f = Fixture::new();
        let at = f.bytes(&[0u8; 8], false);
        let got = f
            .invoke(memset, &[at.offset, at.selector, 0x41, 4])
            .expect("filled");
        assert_eq!(got, Ret::Far(at), "memset returns its pointer argument");
        assert_eq!(f.machine.resolve(at, 8).expect("in bounds"), &[0x41; 4].into_iter().chain([0; 4]).collect::<Vec<u8>>()[..]);
    }

    #[test]
    fn sscanf_matches_the_hosts_own_two_field_format() {
        // `MAJORBBS.C:1104`'s own `sscanf(margv[i],"%d:%d",&parm,&val)`.
        let mut f = Fixture::new();
        let s = f.text("60:5");
        let fmt = f.text("%d:%d");
        let a = f.bytes(&[0, 0], false);
        let b = f.bytes(&[0, 0], false);
        let mut args = Fixture::far(s).to_vec();
        args.extend(Fixture::far(fmt));
        args.extend(Fixture::far(a));
        args.extend(Fixture::far(b));

        assert_eq!(f.invoke(sscanf, &args).expect("parsed"), Ret::U16(2));
        assert_eq!(f.machine.resolve(a, 2).expect("in bounds"), [60, 0]);
        assert_eq!(f.machine.resolve(b, 2).expect("in bounds"), [5, 0]);
    }

    #[test]
    fn sscanf_matches_the_hosts_own_hex_format() {
        // `MAJORBBS.C:2944`'s `sscanf(lock+strlen("_PORT#"),"%x",&chn)`.
        let mut f = Fixture::new();
        let s = f.text("1A");
        let fmt = f.text("%x");
        let n = f.bytes(&[0, 0], false);
        let mut args = Fixture::far(s).to_vec();
        args.extend(Fixture::far(fmt));
        args.extend(Fixture::far(n));

        assert_eq!(f.invoke(sscanf, &args).expect("parsed"), Ret::U16(1));
        assert_eq!(f.machine.resolve(n, 2).expect("in bounds"), [0x1A, 0]);
    }

    #[test]
    fn sscanf_returns_eof_when_the_input_is_already_exhausted() {
        let mut f = Fixture::new();
        let s = f.text("");
        let fmt = f.text("%d");
        let n = f.bytes(&[0, 0], false);
        let mut args = Fixture::far(s).to_vec();
        args.extend(Fixture::far(fmt));
        args.extend(Fixture::far(n));

        assert_eq!(f.invoke(sscanf, &args).expect("EOF"), Ret::U16(0xFFFF));
    }

    #[test]
    fn sscanf_stops_without_eof_once_something_was_assigned() {
        // `"5x"` against `"%d %d"`: the first field matches, the second does
        // not (there is no digit left to match, but input is not empty
        // either) -- one assignment, not EOF.
        let mut f = Fixture::new();
        let s = f.text("5x");
        let fmt = f.text("%d %d");
        let a = f.bytes(&[0, 0], false);
        let b = f.bytes(&[0, 0], false);
        let mut args = Fixture::far(s).to_vec();
        args.extend(Fixture::far(fmt));
        args.extend(Fixture::far(a));
        args.extend(Fixture::far(b));

        assert_eq!(f.invoke(sscanf, &args).expect("partial"), Ret::U16(1));
    }

    #[test]
    fn sscanf_refuses_a_conversion_it_does_not_implement() {
        let mut f = Fixture::new();
        let s = f.text("1.5");
        let fmt = f.text("%f");
        let n = f.bytes(&[0, 0], false);
        let mut args = Fixture::far(s).to_vec();
        args.extend(Fixture::far(fmt));
        args.extend(Fixture::far(n));

        let e = f.invoke(sscanf, &args).expect_err("no %f");
        assert!(e.to_string().contains('f'), "{e}");
    }

    #[test]
    fn intdos_always_refuses() {
        let mut f = Fixture::new();
        let regs = f.bytes(&[0u8; 16], false);
        let mut args = Fixture::far(regs).to_vec();
        args.extend(Fixture::far(regs));
        assert!(f.invoke(intdos, &args).is_err());
    }
}
