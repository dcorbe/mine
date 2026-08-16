//! The command-concatenation family, `_BGNCNC`/`_ENDCNC`/`_CNCCHR`/`_CNCALL`,
//! plus three unrelated symbols the same corpus census asked for:
//! `_ONSYS`, `_STRUPR`, `_INJOTH`.
//!
//! # The `cnc*` family, cited against **wg1**, never wg20
//!
//! Every routine in `bgncnc`/`endcnc`/`cncchr`/.../`cnclng`'s family lives in
//! one small vendor file, `CNCUTL.C`
//! (`archive/galacticomm/extract/wg1/GALDSRC/SRC/CNCUTL.C`, 238 lines total)
//! -- unlike most of this crate's citations, which point into `MAJORBBS.C`.
//! `MAJORBBS.H:852-866` is where every one of these fifteen routines is
//! declared, in the same order this file (and `CNCUTL.C` itself) states them.
//! wg20 renumbers every one of these lines -- see `crate::shims::gsbl`'s
//! sibling doc comment on why wg1 and not wg20 is cited throughout this
//! crate.
//!
//! It lets a MajorBBS user type several commands on one line
//! (`"n;n;n;l"` to walk three rooms and look, in a MUD): `bgncnc` points a
//! private cursor, `nxtcmd`, at the *first* parsed word (`margv[0]`) and
//! resets the print buffer and the line's separators; each little parser
//! (`cncchr`, `cncint`, `cncwrd`, ...) reads forward from `nxtcmd`, consuming
//! as it goes; `endcnc` re-parses whatever `nxtcmd` still points at as a
//! fresh `input` line (so the *next* semicolon-delimited command gets its own
//! `margc`/`margv`) and reports whether the whole line is exhausted.
//!
//! ## What is already here, and what is not -- the coherence check this
//! task's own instructions ask for
//!
//! The four requested routines (`bgncnc`, `endcnc`, `cncchr`, `cncall`) need
//! exactly four things from the rest of this host, and this host already has
//! every one of them:
//!
//! - `margv`, `margc`, `nxtcmd`, `input` -- placed globals
//!   (`crates/mbbs/src/globals.rs:150-156`), the same ones `getin`/`parsin`
//!   already read and write.
//! - [`crate::shims::text::clrprf_mem`] -- `bgncnc`'s `clrprf()`.
//! - [`crate::shims::text::rstrin`] -- `bgncnc`'s `rstrin()`.
//! - [`crate::shims::text::parsin_mem`] -- `endcnc`'s `parsin()`.
//! - [`crate::shims::text::write_cstr_mem`] -- the bounded write `endcnc`'s
//!   `movmem(nxtcmd,input,strlen(nxtcmd)+1)` needs.
//!
//! **No unimplemented sibling turned out to be necessary.** `cncint`,
//! `cnclon`, `cncuid`, `cncsig`, `cncyesno`, `cncwrd`, `cncbgw`, `morcnc`,
//! `cnchex`, `cncnum` and `cnclng` (`CNCUTL.C:60-238`) are every other member
//! of this family, and not one of `bgncnc`/`endcnc`/`cncchr`/`cncall`'s own
//! bodies calls any of them -- they are siblings *of* this family, not
//! dependencies *within* it. None is added here. (This host also has no
//! `cncchr`/`cncall` caller of its own yet that would need them either --
//! nothing in `crate::shims` calls into the module side of a `cnc*` routine,
//! since only the module calls these, never the host.)
//!
//! ## `maxcat`/`numcat`, and the one gap this task cannot close
//!
//! [`endcnc`] needs `maxcat` (`MAJORBBS.H:528`, set once at startup by
//! `MAJORBBS.C:587`'s `maxcat=numopt(MAXCAT,1,32767)`) and `numcat`
//! (`MAJORBBS.H:389`, already a placed global). `numcat` is real host state
//! this file reads and writes through [`crate::globals::Globals`] like any
//! other global. `maxcat` is not placed at all -- see [`endcnc`]'s own doc
//! comment for why a constant stands in for it, and why that is safe in the
//! only direction that matters.
//!
//! **Left unresolved, and out of this task's reach**: the vendor resets
//! `numcat=0` once per completed input line, in `hdlcri()`
//! (`MAJORBBS.C:2673`, `STATIC`) -- not one of the seven symbols this task
//! covers, and reached only from `Host::poll`'s dispatch loop in `lib.rs`,
//! which this task is not permitted to edit. This host's `numcat` therefore
//! only ever increments, for the life of a channel, and never resets. With
//! `maxcat` standing in at its permissive upper bound (see [`endcnc`]) this
//! is unobservable for a very long time on any one channel, but it is a real
//! divergence and a real channel would eventually reach it. Flagged here
//! rather than silently worked around; fixing it needs a `lib.rs` change
//! this task's own constraints forbid.

use mbbs_machine::ptr::ModulePtr;
#[cfg(test)]
use mbbs_machine::m16::Ret;

use crate::Host;
use crate::abi::{self, Abi, Call, ModuleMem};
use crate::shims::ShimError;
use crate::shims::text;

/// The upper bound `maxcat` would carry if this host parsed a message-file
/// config option -- `numopt(MAXCAT,1,32767)`'s own ceiling
/// (`MAJORBBS.C:587`), used because there is no message-file parser to read
/// a sysop's real setting from. The same gap
/// [`OUTBSZ`](crate::globals::OUTBSZ) documents for `outbsz`, and the same
/// choice: **permissive rather than restrictive**. A lower guess would
/// silently truncate a concatenated command line a real board's default
/// would have allowed to run in full; this one can only ever agree with the
/// real value or be more generous than it, never stricter. In practice a
/// single `input` line (`INPSIZ` bytes) cannot hold anywhere near 32,767
/// semicolon-delimited words, so [`endcnc`]'s `numcat >= MAXCAT` branch is
/// not expected to fire from this constant at all -- `margc == 0` is the
/// termination condition every real line actually reaches.
const MAXCAT: u16 = 32767;

/// `UIDSIZ`, `INC/GCSP.H:27` and `INC/UStructs.h:10` -- `#define UIDSIZ 30`,
/// "user-id size (including trailing zero)". The bound on both [`cncuid`]'s
/// and [`cncwrd`]'s static buffers, each of which stops at `UIDSIZ-1`, so 29
/// characters survive either.
const UIDSIZ: u16 = 30;

/// `SIGSIZ`, `CNCUTL.C:20` -- `#define SIGSIZ 10`, "max size of SIG names
/// (incl. '\0')". Declared in `CNCUTL.C` itself rather than in a header,
/// under a comment calling it a constant "for backward compatibility", so
/// there is no `INC/` citation to prefer over this one.
const SIGSIZ: u16 = 10;

/// `SIGIDC`, `CNCUTL.C:19` -- `#define SIGIDC '/'`, "forum name identifier
/// character". [`cncuid`] hands the line to [`cncsig`] when it starts with
/// one, and [`cncsig`] always writes it back as its answer's first byte
/// whether or not the input carried it.
const SIGIDC: u8 = b'/';

/// The width of [`cncnum`]'s static buffer -- `static CHAR retval[12]`
/// (`CNCUTL.C:215`), a bare literal in the vendor with no name of its own.
/// Eleven characters and a NUL, which is what a sign plus ten digits needs.
const NUMSIZ: u16 = 12;

/// Where each of `CNCUTL.C`'s four function-scope `static` return buffers
/// lives inside the single region [`crate::Host::cnc_statics`] allocates.
///
/// Four disjoint buffers rather than one shared one, because the vendor's are
/// four distinct objects. [`cncuid`] *returns [`cncsig`]'s buffer* on the
/// forum-name path (`CNCUTL.C:83`), so the two cannot overlap; and a module
/// that calls `cncwrd()` while still holding a `cncuid()` result must see
/// both, which is what the original gave it.
const CNCUID_AT: u16 = 0;
const CNCSIG_AT: u16 = CNCUID_AT + UIDSIZ;
const CNCWRD_AT: u16 = CNCSIG_AT + SIGSIZ;
const CNCNUM_AT: u16 = CNCWRD_AT + UIDSIZ;

/// Bytes in the whole static-buffer region: `30+10+30+12`.
const STATICS_LEN: u16 = CNCNUM_AT + NUMSIZ;

/// `SUPIPG`, `MAJORBBS.H:164` -- `#define SUPIPG 3` ("signup in progress").
/// [`onsys`] only counts a channel whose `usrcls` is *above* this: a user
/// mid-signup is not yet "on the system" in the sense a page or a lookup
/// means. The same constant `crate::lib`'s own `usrptr->class > SUPIPG` doc
/// comment (`lib.rs:181-182`) already cites for a different call site.
const SUPIPG: u16 = 3;

/// `NOINJO`, `MAJORBBS.H:200` -- `#define NOINJO 0x00000001L`, bit 0 of
/// `user.flags`'s low byte (`UserLayout::flags` + 0). Set, a channel refuses every
/// injected message; [`injoth`] answers `0` without touching the channel at
/// all.
const NOINJO: u8 = 0x01;

/// `INJOIP`, `MAJORBBS.H:201` -- `#define INJOIP 0x00000002L`, bit 1 of the
/// same byte as [`NOINJO`]. Marks "an `injoth()` operation is in progress"
/// for as long as the injected text sits in the target channel's own output
/// buffer. [`injoth`] sets it on the path that actually injects something.
const INJOIP: u8 = 0x02;

/// `void bgncnc(void)` -- `CNCUTL.C:27-33`:
///
///
/// **Fully implemented.** `nxtcmd=margv[0]` is one global read and one
/// global write: [`crate::globals::Globals::pointer_mem`] on `"margv"`
/// already answers `margv[0]`'s own contents (a global's address *is*
/// `&margv[0]`, per [`crate::globals::Globals::address`]'s own doc comment),
/// and the result is written straight back through `"nxtcmd"`.
///
/// `clrprf()` and `rstrin()` are called through their own `_mem`/`Call<A>`
/// cores rather than re-derived here -- [`text::clrprf_mem`] directly
/// (the established idiom: `shims::output`, `shims::fsd` and
/// `shims::msg` all reach it the same way, never through
/// [`text::clrprf`]'s own `Call<A>`-taking wrapper, per that wrapper's own
/// doc comment), and [`text::rstrin`] by forwarding this call's own `call`
/// and `host` -- safe because `void rstrin(void)` reads no arguments of its
/// own (only `call.mem()`), so there is nothing on `bgncnc`'s zero-argument
/// frame for it to over-read.
///
/// # Errors
///
/// If `margv`, `nxtcmd` or `margn` is not placed (propagated from
/// [`text::rstrin`]), or if a read or write runs off the segment.
pub fn bgncnc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let margv0 = host
        .globals()
        .pointer_mem(call.mem(), "margv")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(call.mem(), "nxtcmd", &A::ptr_to_bytes(margv0))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    text::clrprf_mem(call.mem(), host)?;
    text::rstrin(call, host)?;

    Ok(abi::Ret::Void)
}

/// `int endcnc(void)` -- `CNCUTL.C:35-47`:
///
///
/// **Fully implemented against this host's own `maxcat` gap** -- see this
/// file's own module doc comment for what that gap is and why it cannot be
/// closed here. Everything else is exact:
///
/// - `margc == 0` (nothing left at all, e.g. an already-empty line) answers
///   `1` immediately, without touching `nxtcmd`/`input`/`numcat`.
/// - `movmem(nxtcmd,input,strlen(nxtcmd)+1)` -- copy `nxtcmd`'s remaining
///   text, and its own terminator, over `input`. [`text::write_cstr_mem`] is
///   used rather than a hand-rolled copy: it is the same bounded write
///   `stzcpy`/`strcpy` already trust, and it refuses (loudly) rather than
///   overrunning `input`'s segment if `nxtcmd`'s text somehow did not fit --
///   which it always will, in practice, since `nxtcmd` only ever points
///   inside `input` itself or at the host's own permanent empty string.
/// - `parsin()` -- [`text::parsin_mem`], the exact routine `getin` already
///   calls, re-splitting whatever `movmem` just installed into a fresh
///   `margc`/`margv`/`margn` for the next concatenated command.
/// - `++numcat >= maxcat` -- pre-increment, then compare, exactly as C
///   evaluates it: `numcat` is read, incremented, **written back before the
///   comparison**, and only then compared against [`MAXCAT`].
/// - The final `margc == 0` reads the *freshly reparsed* `margc` -- `parsin`
///   above already overwrote it -- so this answers whether the chunk
///   `movmem` just installed was itself empty (no more concatenated commands
///   remain after this one).
///
/// # Errors
///
/// If `margc`, `nxtcmd`, `input` or `numcat` is not placed, or if a read or
/// write runs off the segment.
pub fn endcnc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let margc = host
        .globals()
        .word_mem(call.mem(), "margc")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    if margc == 0 {
        return Ok(abi::Ret::Int(A::Int::from(1u16)));
    }

    let nxtcmd = host
        .globals()
        .pointer_mem(call.mem(), "nxtcmd")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let text_bytes = nxtcmd
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let input = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    let input_size = host
        .globals()
        .size("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    text::write_cstr_mem::<A>(call.mem(), input, &text_bytes, input_size)?;

    text::parsin_mem(call.mem(), host)?;

    let numcat = host
        .globals()
        .word_mem(call.mem(), "numcat")
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .wrapping_add(1);
    host.globals()
        .write_int_mem(call.mem(), "numcat", u32::from(numcat))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    if numcat >= MAXCAT {
        return Ok(abi::Ret::Int(A::Int::from(1u16)));
    }

    let margc_after = host
        .globals()
        .word_mem(call.mem(), "margc")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let done = if margc_after == 0 { 1u16 } else { 0u16 };
    Ok(abi::Ret::Int(A::Int::from(done)))
}

/// `char cncchr(void)` -- `CNCUTL.C:49-58`:
///
///
/// **Fully implemented.** Reads the one byte `nxtcmd` currently points at,
/// upper-cases it with [`crate::strings::toupper`] (the same fold
/// [`text::toupper`]'s own shim uses), and advances `nxtcmd` past it --
/// **unless** the byte was the string's own terminator, in which case
/// `nxtcmd` is left exactly where it was so a caller that keeps calling
/// `cncchr()` at the end of the line keeps getting `'\0'` back rather than
/// walking off the end of `input`.
///
/// Returned as `abi::Ret::Int`, matching [`text::toupper`]'s own answer
/// shape for a `char`-returning routine -- there is no narrower `Ret`
/// variant, and the module reads back only the low byte regardless.
///
/// # Errors
///
/// If `nxtcmd` is not placed, or the read or write runs off the segment.
pub fn cncchr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let upper = cncchr_mem::<A>(call.mem(), host)?;
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(upper))))
}

/// [`cncchr`]'s core, against memory directly rather than a whole [`Call`].
///
/// Split out because [`cncyesno`] *is* a `cncchr()` call plus a comparison
/// (`CNCUTL.C:117`), and calling the `Call<A>`-taking wrapper from inside
/// another shim would mean handing `cncyesno`'s own zero-argument frame to a
/// routine that has no business reading it. The established idiom in this
/// crate for exactly this -- see [`text::clrprf_mem`] and
/// [`text::parsin_mem`], which `bgncnc` and `endcnc` already reach the same
/// way.
fn cncchr_mem<A: Abi>(mem: &mut A::Mem, host: &Host<A>) -> Result<u8, ShimError> {
    let nxtcmd = host
        .globals()
        .pointer_mem(mem, "nxtcmd")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let byte = nxtcmd
        .resolve(mem, 1)
        .map_err(|e| ShimError::Failed(e.to_string()))?[0];
    let upper = crate::strings::toupper(byte);

    if upper != 0 {
        advance_nxtcmd::<A>(mem, host, nxtcmd, 1)?;
    }

    Ok(upper)
}

/// `char *cncall(void)` -- `CNCUTL.C:161-169`:
///
///
/// **Fully implemented.** Hands back `nxtcmd` exactly as it stood -- a
/// pointer into `input`'s own bytes, not a copy -- and then points `nxtcmd`
/// at [`crate::Host`]'s one permanent empty string (`""` in the vendor is a
/// string-literal constant; this host's equivalent is the same NUL byte
/// [`text::parsin_mem`]'s own empty-`margv[0]` case already reuses, reached
/// here through the crate-visible `Host::empty_string`). A module that reads
/// the returned pointer sees the rest of the line as it was at the moment of
/// the call; a module that calls `cncchr`/`cncall` again afterward sees an
/// already-exhausted line, matching the vendor exactly.
///
/// # Errors
///
/// If `nxtcmd` is not placed, or the read or write runs off the segment.
pub fn cncall<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let retval = host
        .globals()
        .pointer_mem(call.mem(), "nxtcmd")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let empty = host.empty_string();
    host.globals()
        .write_mem(call.mem(), "nxtcmd", &A::ptr_to_bytes(empty))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(retval))
}

/// Where `nxtcmd` points, and the bytes it addresses up to the terminator.
///
/// Every routine below walks the line as a `&[u8]` rather than one
/// `resolve(mem, 1)` per character, so `*nxtcmd == '\0'` becomes "the index
/// reached the end of the slice". The two are the same test: `read_cstr`
/// stops at exactly the NUL the vendor's loops stop at.
fn nxtcmd_rest<A: Abi>(mem: &mut A::Mem, host: &Host<A>) -> Result<(A::Ptr, Vec<u8>), ShimError> {
    let at = host
        .globals()
        .pointer_mem(mem, "nxtcmd")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let bytes = at
        .read_cstr(mem)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    Ok((at, bytes))
}

/// Move `nxtcmd` forward by `by` bytes from `from`.
///
/// The whole family advances the *global*, never a host-side copy of it --
/// `crate::globals`' own module doc is explicit that a Rust-side mirror of a
/// module-memory global is the bug that file is shaped to prevent, and
/// `nxtcmd` is the one every one of these routines shares.
fn advance_nxtcmd<A: Abi>(
    mem: &mut A::Mem,
    host: &Host<A>,
    from: A::Ptr,
    by: u16,
) -> Result<(), ShimError> {
    host.globals()
        .write_mem(mem, "nxtcmd", &A::ptr_to_bytes(A::ptr_offset(from, by)))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// The address of one of `CNCUTL.C`'s four `static` return buffers,
/// allocating the region that holds all four on first use.
///
/// See [`crate::Host::cnc_statics`] for why the storage outlives the call and
/// why that is reproduced rather than improved on.
fn cnc_static<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>, at: u16) -> Result<A::Ptr, ShimError> {
    let base = match host.cnc_statics {
        Some(base) => base,
        None => {
            let base = mem.alloc_region(usize::from(STATICS_LEN)).map_err(|e| {
                ShimError::Failed(format!("cnc: no room for the static return buffers: {e}"))
            })?;
            host.cnc_statics = Some(base);
            base
        }
    };
    Ok(A::ptr_offset(base, at))
}

/// The current language's `yes` and `no` strings, read out of
/// `languages[clingo]`.
///
/// The read [`cncyesno`] opens with, and the one that would have faulted
/// before `languages[0]` became a real record -- see
/// `crate::globals::default_lingo`. The field offsets come from
/// `crate::globals`' own `LINGO_YES`/`LINGO_NO` rather than being restated
/// here, so the code that writes the record and the code that reads it back
/// cannot disagree about where `yes` is.
fn lingo_yes_no<A: Abi>(mem: &mut A::Mem, host: &Host<A>) -> Result<(Vec<u8>, Vec<u8>), ShimError> {
    let clingo = host
        .globals()
        .word_mem(mem, "clingo")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let array = host
        .globals()
        .pointer_mem(mem, "languages")
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // `languages[clingo]`: the array is `struct lingo **`, so the index
    // strides by a pointer, not by a record.
    let stride = u16::try_from(A::PTR_WIDTH).expect("a pointer is not 64 KiB wide");
    let slot = A::ptr_offset(array, clingo.wrapping_mul(stride));
    let record = A::ptr_from_bytes(
        slot.resolve(mem, A::PTR_WIDTH)
            .map_err(|e| ShimError::Failed(format!("languages[{clingo}]: {e}")))?,
    );

    let read = |mem: &mut A::Mem, at: u16| -> Result<Vec<u8>, ShimError> {
        Ok(A::ptr_offset(record, at)
            .read_cstr(mem)
            .map_err(|e| ShimError::Failed(format!("languages[{clingo}]: {e}")))?
            .to_vec())
    };
    let yes = read(mem, crate::globals::LINGO_YES)?;
    let no = read(mem, crate::globals::LINGO_NO)?;
    Ok((yes, no))
}

/// `long cnclon(void)` -- `CNCUTL.C:66-74`:
///
///
/// **Fully implemented**, and one of the three routines here that no corpus
/// module imports -- [`cncint`] calls it, which is reason enough under this
/// host's own rule that a symbol is implemented because it exists in the API.
///
/// **No overflow check, deliberately.** `retval*10+digit` on a 32-bit `long`
/// wraps, and the vendor never tests for it. The arithmetic here is
/// `wrapping_mul`/`wrapping_add` rather than plain `*`/`+` for exactly that
/// reason: Rust's own overflow panic in a debug build would turn the
/// vendor's silent wrap into a crash, which is a *different* behaviour, not
/// a safer one. A module that fed this a 20-digit number got a wrapped
/// answer from the original and gets the same wrapped answer here.
///
/// # Errors
///
/// If `nxtcmd` is not placed, or the read or write runs off the segment.
pub fn cnclon<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Long(cnclon_mem::<A>(call.mem(), host)?))
}

/// [`cnclon`]'s core, so [`cncint`] can be the one-line cast the vendor
/// makes it (`CNCUTL.C:63`) rather than a second copy of the digit loop.
fn cnclon_mem<A: Abi>(mem: &mut A::Mem, host: &Host<A>) -> Result<u32, ShimError> {
    let (at, bytes) = nxtcmd_rest::<A>(mem, host)?;

    let mut retval: u32 = 0;
    let mut consumed: u16 = 0;
    while let Some(&byte) = bytes.get(usize::from(consumed)) {
        if !byte.is_ascii_digit() {
            break;
        }
        retval = retval.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'));
        consumed += 1;
    }

    if consumed > 0 {
        advance_nxtcmd::<A>(mem, host, at, consumed)?;
    }
    Ok(retval)
}

/// `int cncint(void)` -- `CNCUTL.C:60-64`:
///
///
/// **Fully implemented.** The `(int)` cast is [`Abi::int_from_u32`], which is
/// a truncation to 16 bits under `Wg16` and the identity under `Wg32` --
/// exactly what a C cast from `long` to `int` does in each. That is not a
/// detail to leave to chance: `cncint` on `"70000"` answers `4464` to a
/// 16-bit module and `70000` to a 32-bit one, and both are right.
///
/// # Errors
///
/// If `nxtcmd` is not placed, or the read or write runs off the segment.
pub fn cncint<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let value = cnclon_mem::<A>(call.mem(), host)?;
    Ok(abi::Ret::Int(A::int_from_u32(value)))
}

/// `char *cncwrd(void)` -- `CNCUTL.C:133-145`:
///
///
/// **Fully implemented.** Three things this reproduces exactly, each of which
/// a plausible rewrite would get wrong:
///
/// - **The delimiting space is not consumed.** The loop stops *on* the space
///   and leaves `nxtcmd` addressing it, so a caller doing `cncwrd()` twice
///   in a row gets the second word only after something else has stepped
///   over the separator. A version that skipped it would silently change
///   every two-word command in the corpus.
/// - **Only `' '` delimits**, not tab and not any other whitespace. This is
///   not [`crate::strings::is_white`]'s set, and using that set here would
///   be a different routine.
/// - **The whole `UIDSIZ` buffer is zeroed first**, not just terminated, so a
///   module reading past the NUL sees the same zeros the vendor left.
///
/// # Errors
///
/// If `nxtcmd` is not placed, if there is no room for the static buffers, or
/// if a read or write runs off the segment.
pub fn cncwrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (at, bytes) = nxtcmd_rest::<A>(call.mem(), host)?;

    let mut taken: u16 = 0;
    while let Some(&byte) = bytes.get(usize::from(taken)) {
        if byte == b' ' || taken >= UIDSIZ - 1 {
            break;
        }
        taken += 1;
    }

    let buffer = cnc_static::<A>(call.mem(), host, CNCWRD_AT)?;
    let mut out = vec![0u8; usize::from(UIDSIZ)];
    out[..usize::from(taken)].copy_from_slice(&bytes[..usize::from(taken)]);
    buffer
        .write(call.mem(), &out)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if taken > 0 {
        advance_nxtcmd::<A>(call.mem(), host, at, taken)?;
    }
    Ok(abi::Ret::Ptr(buffer))
}

/// `char *cncsig(void)` -- `CNCUTL.C:93-108`:
///
///
/// **Fully implemented**, and the second of the three routines no corpus
/// module imports -- [`cncuid`] calls it.
///
/// **The answer always begins with `'/'`**, whether or not the input did:
/// the vendor consumes a leading slash if there is one and then writes one
/// unconditionally. So `"/talk"` and `"talk"` both answer `"/talk"`. The
/// buffer is `SIGSIZ` and the first byte is spent on the slash, so **eight**
/// characters of the name survive, not nine.
///
/// # Errors
///
/// If `nxtcmd` is not placed, if there is no room for the static buffers, or
/// if a read or write runs off the segment.
pub fn cncsig<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (at, bytes) = nxtcmd_rest::<A>(call.mem(), host)?;

    // The leading slash is consumed if present, and the name starts after it.
    let start = usize::from(bytes.first() == Some(&SIGIDC));
    let mut taken: u16 = 0;
    while let Some(&byte) = bytes.get(start + usize::from(taken)) {
        // `rp-retval < SIGSIZ-1` with `rp` starting at `retval+1`, so the
        // name itself is bounded by `SIGSIZ-2`.
        if byte == b' ' || taken >= SIGSIZ - 2 {
            break;
        }
        taken += 1;
    }

    let buffer = cnc_static::<A>(call.mem(), host, CNCSIG_AT)?;
    let mut out = vec![0u8; usize::from(SIGSIZ)];
    out[0] = SIGIDC;
    out[1..1 + usize::from(taken)].copy_from_slice(&bytes[start..start + usize::from(taken)]);
    buffer
        .write(call.mem(), &out)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let consumed = u16::try_from(start).expect("0 or 1") + taken;
    if consumed > 0 {
        advance_nxtcmd::<A>(call.mem(), host, at, consumed)?;
    }
    Ok(abi::Ret::Ptr(buffer))
}

/// `char *cncuid(void)` -- `CNCUTL.C:77-90`:
///
///
/// **Fully implemented.** Two consequences worth stating, because both look
/// like bugs and are not:
///
/// - **A space does not end a user-ID.** [`isuidc`] counts `' '` as a valid
///   user-ID character, so `cncuid()` on `"rangerdan smith went"` answers
///   `"rangerdan smith went"` (up to 29 characters), not `"rangerdan"`.
///   MajorBBS user-IDs really do contain spaces; this is what makes them
///   parseable at all.
/// - **The answer may be [`cncsig`]'s buffer, not this one.** On a leading
///   `'/'` the vendor returns the other static outright, so the pointer a
///   caller gets back is a different address on that path -- reproduced
///   here rather than smoothed over, since a caller comparing pointers
///   would see the same thing from the original.
///
/// # Errors
///
/// If `nxtcmd` is not placed, if there is no room for the static buffers, or
/// if a read or write runs off the segment.
pub fn cncuid<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (at, bytes) = nxtcmd_rest::<A>(call.mem(), host)?;

    if bytes.first() == Some(&SIGIDC) {
        return cncsig(call, host);
    }

    let mut taken: u16 = 0;
    while let Some(&byte) = bytes.get(usize::from(taken)) {
        if !crate::strings::is_uid_char(byte) || taken >= UIDSIZ - 1 {
            break;
        }
        taken += 1;
    }

    let buffer = cnc_static::<A>(call.mem(), host, CNCUID_AT)?;
    let mut out = vec![0u8; usize::from(UIDSIZ)];
    out[..usize::from(taken)].copy_from_slice(&bytes[..usize::from(taken)]);
    buffer
        .write(call.mem(), &out)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if taken > 0 {
        advance_nxtcmd::<A>(call.mem(), host, at, taken)?;
    }
    Ok(abi::Ret::Ptr(buffer))
}

/// `GBOOL isuidc(int c)` -- `SRC/api/gcommlib/ISUIDC.C:18-30`:
///
///
/// **Fully implemented**, and the third routine here no corpus module
/// imports -- [`cncuid`] calls it.
///
/// **`GBOOL` is `short`, not `int`** (`INC/GCTYPDEF.H:105`:
/// `typedef short GBOOL;`), so this answers 16 bits under both ABIs. Handing
/// it back as [`abi::Ret::Int`] is still right: the values are 0 and 1, and
/// a `short` return travels in the low half of the same register an `int`
/// return does. The distinction is recorded because it is *not* cosmetic
/// elsewhere in this API -- `addcrd`'s third parameter is a `GBOOL` in
/// `INC/USRACC.H` and an `INT` in the later `VCPROJ/` generation.
///
/// The argument is an `int`, and only its low byte is tested -- the same
/// `int`-in, byte-tested shape [`text::toupper`] already has. A caller
/// passing a value above 255 gets `FALSE`, matching a C compiler's own
/// comparison of that `int` against the byte ranges.
///
/// # Errors
///
/// Never. The signature is fallible because every shim's is.
pub fn isuidc<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c: u32 = call.int().into();
    let valid = u32::from(u8::try_from(c).is_ok_and(crate::strings::is_uid_char));
    Ok(abi::Ret::Int(A::int_from_u32(valid)))
}

/// `char cncyesno(void)` -- `CNCUTL.C:111-131`:
///
///
/// **Fully implemented.** The routine that made
/// `crate::globals::default_lingo` a prerequisite: `languages[clingo]` is
/// dereferenced on the first line with no NULL check, and until that record
/// existed this would have faulted inside the calling module rather than
/// here.
///
/// **One character is always consumed** -- the `cncchr()` -- and the *rest*
/// of the word only if it matches. So `"yes please"` leaves `nxtcmd` at
/// `" please"`, while `"yellow"` answers `'Y'` and leaves `"ellow"`, because
/// `"es"` is not a prefix of `"ellow"`. That asymmetry is the vendor's and
/// is why the match is [`crate::strings::sameto`] (a case-insensitive
/// *prefix* test) rather than an equality.
///
/// **Anything else comes back as [`cncchr`] left it**: upper-cased, and one
/// character consumed. A module distinguishing "no" from "not an answer"
/// tests against `'Y'`/`'N'` and not against truthiness.
///
/// # Errors
///
/// If `nxtcmd`, `clingo` or `languages` is not placed, or if a read or write
/// runs off the segment -- which is what a `languages[clingo]` that does not
/// resolve reports as, rather than faulting.
pub fn cncyesno<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (yes, no) = lingo_yes_no::<A>(call.mem(), host)?;
    let mut retval = cncchr_mem::<A>(call.mem(), host)?;

    // `lptr->yes[0]` on an empty string is the terminator, and the vendor
    // compares against it unguarded -- `first().unwrap_or(0)` is that read,
    // not a defence against it.
    for (word, answer) in [(&yes, b'Y'), (&no, b'N')] {
        if retval != crate::strings::toupper(word.first().copied().unwrap_or(0)) {
            continue;
        }
        if word.len() > 1 {
            let (at, rest) = nxtcmd_rest::<A>(call.mem(), host)?;
            if crate::strings::sameto(&word[1..], &rest) {
                let by = u16::try_from(word.len() - 1).expect("a lingo yes/no is 12 bytes");
                advance_nxtcmd::<A>(call.mem(), host, at, by)?;
            }
        }
        retval = answer;
        break;
    }

    Ok(abi::Ret::Int(A::int_from_u32(u32::from(retval))))
}

/// `char morcnc(void)` -- `CNCUTL.C:171-182`:
///
///
/// **Fully implemented.** `maxcat` is [`MAXCAT`], the same constant
/// [`endcnc`] already tests against and for the same reason -- this host has
/// no message-file parser to read a sysop's real setting from.
///
/// **The whitespace skip happens even when there is nothing after it**, so a
/// line ending in trailing blanks leaves `nxtcmd` on its terminator and
/// answers `0`. Unlike [`cncwrd`], this uses the full `isspace` set
/// ([`crate::strings::is_white`]), because the vendor does.
///
/// # Errors
///
/// If `nxtcmd` or `numcat` is not placed, or if a read or write runs off the
/// segment.
pub fn morcnc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let numcat = host
        .globals()
        .word_mem(call.mem(), "numcat")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    if numcat >= MAXCAT {
        return Ok(abi::Ret::Int(A::int_from_u32(0)));
    }

    let (at, bytes) = nxtcmd_rest::<A>(call.mem(), host)?;
    let mut skipped: u16 = 0;
    while let Some(&byte) = bytes.get(usize::from(skipped)) {
        if !crate::strings::is_white(byte) {
            break;
        }
        skipped += 1;
    }
    if skipped > 0 {
        advance_nxtcmd::<A>(call.mem(), host, at, skipped)?;
    }

    let next = bytes.get(usize::from(skipped)).copied().unwrap_or(0);
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(
        crate::strings::toupper(next),
    ))))
}

/// `char *cncnum(void)` -- `CNCUTL.C:212-225`:
///
///
/// **Fully implemented.** Two differences from [`cnclon`] over the same
/// input, both deliberate:
///
/// - **A leading `'-'` is consumed and kept.** `cnclon` stops dead on it and
///   answers zero; `cncnum` answers `"-12"`. A caller wanting a signed
///   number reads this and converts, which is why both exist.
/// - **The buffer is *not* zeroed first.** Unlike every other static here,
///   `cncnum` writes only the digits and a terminator, so bytes beyond the
///   NUL still hold whatever the previous call left. Reproduced exactly: a
///   `setmem` here would be a change, however tidy it looks.
///
/// **The `i < 11` bound counts the sign**, so `"-1234567890"` yields ten
/// digits and the minus, and the eleventh digit is dropped.
///
/// # Errors
///
/// If `nxtcmd` is not placed, if there is no room for the static buffers, or
/// if a read or write runs off the segment.
pub fn cncnum<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (at, bytes) = nxtcmd_rest::<A>(call.mem(), host)?;

    let mut taken: u16 = 0;
    if bytes.first() == Some(&b'-') {
        taken = 1;
    }
    while let Some(&byte) = bytes.get(usize::from(taken)) {
        if !byte.is_ascii_digit() || taken >= NUMSIZ - 1 {
            break;
        }
        taken += 1;
    }

    let buffer = cnc_static::<A>(call.mem(), host, CNCNUM_AT)?;
    text::write_cstr_mem::<A>(call.mem(), buffer, &bytes[..usize::from(taken)], NUMSIZ)?;

    if taken > 0 {
        advance_nxtcmd::<A>(call.mem(), host, at, taken)?;
    }
    Ok(abi::Ret::Ptr(buffer))
}

/// `int onsys(char *uid)` -- `MAJORBBS.C:3009-3031`:
///
///
/// **Fully implemented for its return value; one side effect deliberately
/// not reproduced (named below).** `onsys(uid)` is `onsysn(uid,0)` with
/// `invis` hardcoded off, so this implements exactly that: walk every
/// channel, skip anything whose `usrcls` is not above [`SUPIPG`], compare
/// `uid` against the channel's own `usracc.userid` with
/// [`crate::strings::sameas`] (case-insensitive, the same free function
/// [`crate::shims::text::sameas`] and `crate::shims::echo::instat` both
/// already call through), and -- for a match -- answer `1` unless `INVISB`
/// is set, in which case the loop keeps looking rather than stopping (the
/// vendor's own `if (invis || ...)` has no `else return(0)`, so a match on
/// an invisible channel does not end the search). This is the same shape
/// `crate::shims::echo::instat` already implements for `usrptr->state ==
/// qstate`; this is that same loop with `usrptr->class > SUPIPG` in place of
/// the state comparison, and no `qstate` argument to read.
///
/// **Not reproduced: `onsysn`'s walk leaves `othusn`/`othusp`/`othuap`/
/// `othexp` pointed at the last channel it inspected.** The vendor's `for`
/// loop uses four placed host globals (`othusn`, `othusp`, `othuap`,
/// `othexp` -- all present in `crates/mbbs/src/globals.rs`) as its own loop
/// variables, so a module that calls `onsys()` and then reads `othusp`
/// afterward sees whatever the scan left there -- the matching channel's
/// slot, or one past the last channel if nothing matched.
///
/// **Corrected 2026-08-15 (Task 13/15 of the host-API-surface track): this
/// used to say `othexp` "is not a global this host places at all -- no
/// module in the corpus this host was built against addresses it," which
/// was true when written and is not true now.** RTSLORD-NE (Twilight Lord)
/// imports `OTHEXP` directly, 15 sites (`re/ne_arity.py 826
/// tmp/gapsurvey/tlord_ne/RTSLORD.DLL`), and `crate::shims::user::extoff`
/// (the routine that produces the value the vendor's loop assigns into it)
/// is now implemented too. The comment hardened a true-at-the-time search
/// result into a permanent claim, exactly the pattern
/// `docs/*host-api-surface*` warns is worth checking for on sight. The
/// *conclusion* stands regardless: writing some of the four side-effect
/// globals and silently skipping others would be a worse, harder-to-notice
/// divergence than writing none of them, so this implementation still
/// touches none of `othusn`/`othusp`/`othuap`/`othexp` and leaves whatever
/// the calling module's previous host call already left there. Flagged, not
/// silently assumed away -- now for a real reason (an all-or-nothing
/// side-effect this routine does not reproduce) rather than a stale one (a
/// slot that used not to exist).
///
/// # Errors
///
/// If `uid` is not a valid pointer, or any channel's `usrcls`/`userid`/
/// `flags` cannot be read.
pub fn onsys<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid_ptr = call.ptr();
    let uid = uid_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    for chan in host.users().terms().all() {
        let slot = host.users().slot(chan);
        let usrcls_ptr = A::ptr_offset(slot, host.users().user_layout().usrcls.at);
        let usrcls_bytes = usrcls_ptr
            .resolve(call.mem(), 2)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let usrcls = u16::from_le_bytes([usrcls_bytes[0], usrcls_bytes[1]]);
        if usrcls <= SUPIPG {
            continue;
        }

        let account = host.users().account(chan);
        let userid_ptr = A::ptr_offset(account, host.users().account_layout().userid);
        let userid = userid_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        if !crate::strings::sameas(&uid, userid) {
            continue;
        }

        // `INVISB` is `0x00004000L` (`MAJORBBS.H:214`): bit 6 of `FLAGS + 1`,
        // the same per-byte addressing `crate::shims::echo::instat` already
        // measures against and `crates/mbbs/src/users.rs`'s own master-flag
        // test confirms for a different bit of the same field.
        let flags1 = A::ptr_offset(slot, host.users().user_layout().flags.at + 1);
        let byte = flags1
            .resolve(call.mem(), 1)
            .map_err(|e| ShimError::Failed(e.to_string()))?[0];
        if byte & 0x40 == 0 {
            return Ok(abi::Ret::Int(A::Int::from(1u16)));
        }
    }
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `char *strupr(char *s)` -- uppercase a string in place, ASCII only, and
/// return the same pointer.
///
/// **Borland's C runtime, not Galacticomm's.** No header under
/// `archive/galacticomm/extract/wg1/GALDSRC` declares it -- the same absence
/// [`crate::shims::memory::memcpy`]'s own doc comment records for `memcpy`
/// and `memcmp` -- every call site simply calls it, e.g.
/// `archive/galacticomm/extract/wg1/GALDSRC/SRC/AAEML.C:2860`:
/// `stlcpy(efvda->tmpadr,strupr(cncwrd()),DLNMSZ)`, and `:2928`:
/// `stlcpy(tmpkey,strupr(cncwrd()),KEYSIZ)`. `WCCMMUD.DLL` still imports it
/// off `MAJORBBS`'s own export table (`re/isv_union_symbols.tsv`: ordinal
/// 348 is actually `_INJOTH`, not this one, but the same table carries
/// `strupr` the identical way it carries `memcpy`/`memcmp`/`strcmp` --
/// Borland-runtime routines `MAJORBBS.EXE` re-exports for every DLL that
/// links against it), consistent with every other C-runtime routine this
/// crate's own `shims::mod` registration table already lists under
/// `MAJORBBS` rather than inventing a runtime-only DLL for them.
///
/// The transform is [`crate::strings::toupper`], the exact per-byte fold
/// [`text::toupper`]/`sameas`/`sameto`/`samein` already share -- ASCII
/// `a`-`z` only, nothing locale-aware, matching what Borland's own `strupr`
/// did under a `char` that is always one byte regardless of `A`.
///
/// **Length never changes** -- upper-casing does not grow or shrink a
/// string -- so the write always fits back in the space the read just came
/// from: `capacity` is `text.len() + 1`, one byte for the same terminator
/// that was already there.
///
/// # Errors
///
/// If `s` is not a valid pointer, or the read or write runs off the segment.
pub fn strupr<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let original = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let upper: Vec<u8> = original.iter().map(|&b| crate::strings::toupper(b)).collect();
    let capacity = upper.len() as u16 + 1;
    text::write_cstr_mem::<A>(call.mem(), s, &upper, capacity)?;
    Ok(abi::Ret::Ptr(s))
}

/// `int injoth(void)` -- `MAJORBBS.C:3903-3931`, with its fallback,
/// `dftinj`, at `:3933-3939`:
///
///
/// # The `16-bit-only` project note this task asked to verify was wrong
///
/// Project memory (`mbbs-headless-module-scope.md`) recorded
/// `othusp`/`injoth`/`usroff` as "32-bit-only". Checked against the actual
/// corpus census:
///
/// - `re/isv_union_symbols.tsv` (the **16-bit** `MAJORBBS` ordinal table):
///   `MAJORBBS 348 _INJOTH 16 28` -- ordinal 348, imported by **16** 16-bit
///   modules across 28 call sites -- and `MAJORBBS 460 _OTHUSP 21 357` --
///   imported by 21 modules across 357 sites. Both symbols are real,
///   heavily-used 16-bit `MAJORBBS` imports, not 32-bit-only.
/// - `re/isv_union_pe_symbols.tsv` (the 32-bit `WGSERVER` PE export table)
///   separately lists `_injoth` (11 modules) and `_othusp` (12 modules) --
///   so both exist on **both** sides, which is exactly why this task asked
///   for `_INJOTH` as a 16-bit routine in the first place: 16 modules in
///   the 16-bit corpus need it.
/// - `_usroff` is the one symbol of the three that the note's "32-bit-only"
///   claim actually holds for: `re/isv_union_pe_symbols.tsv` lists
///   `WGSERVER _usroff 23 24`, and no `MAJORBBS`/16-bit row for `usroff` (in
///   any casing) exists anywhere in `re/isv_union_symbols.tsv`.
///
/// So the note was two-thirds wrong: `othusp` and `injoth` are both real
/// 16-bit `MAJORBBS` imports (and this crate already places `othusp` as a
/// global for exactly that reason), and only `usroff` is actually
/// 32-bit-only.
///
/// # What is implemented, and what architecturally cannot be
///
/// **This file's own module doc comment inherits `shims::echo`'s standing
/// limit**: *no shim in this crate can call into module code* -- `Call<A>`
/// carries only a raw argument frame and a `&mut A::Cpu`, and `Host<A>`
/// carries no loaded module either, so `module[user[othusn].state]->injrou`
/// -- the vendor's real per-module override -- can be read in principle
/// (nothing stops resolving the pointer) but **can never be called** from in
/// here. `shims::echo::injacr`'s own doc comment establishes the standing
/// alternative for a routine in this exact shape: substitute the *default*
/// behaviour unconditionally rather than fabricate a conditional this shim
/// cannot evaluate honestly.
///
/// So this implementation **always takes the `dftinj()` path** once the
/// `NOINJO` check passes, never the real module's `injrou`. Concretely, for
/// the corpus this host serves that is not even a loss of fidelity: nothing
/// in `re/exports/WCCMMUD_named.c` registers a custom `injrou` for MajorMUD,
/// so the vendor's own conditional would have taken the `dftinj()` branch
/// for that module regardless. A module that *did* register a custom
/// `injrou` would see this host's generic "raw `prfbuf` dumped onto the
/// target channel" behaviour instead of its own formatted one -- a real,
/// named divergence, not a silent one.
///
/// `mltflg`/`prfbuffers`/`nlingo` -- the vendor's per-language buffer
/// rotation -- do not exist in this host at all (no such globals are
/// placed), consistent with this host having no multilingual support
/// anywhere else. `if (mltflg) { ... }` is therefore always the untaken
/// branch here, exactly as it always is on a monolingual board, and the
/// trailing `for (ilingo=0;...)` loop (which only ever rebuilds
/// `prfpointers` from `prfbuffers`) collapses to resetting the one buffer
/// this host has -- [`text::clrprf_mem`], called at the end for the *calling*
/// channel's own print buffer, matching `prfptr=prfbuf=prfpointers[0]`'s
/// observable effect. `savmb=curmbk; ... curmbk=savmb` is dead code under
/// that same collapse (nothing between the save and the restore ever writes
/// `curmbk`), so it is not reproduced.
///
/// `NOINJO`/`INJOIP` are real: the `NOINJO` check gates the whole function
/// exactly as the vendor's does, and the `dftinj()` path sets `INJOIP`
/// exactly as the vendor's does. `btuxmn(othusn,prfbuf)` is
/// [`crate::gsbl::Gsbl::transmit_raw`] -- the same core
/// [`crate::shims::echo::btuxmn`] itself calls -- reading `prfbuf`'s base
/// (not `prfptr`; `dftinj` reads the buffer from its start) as a C string
/// and sending it raw. `btuoes(othusn,1)` is
/// `host.gsbl_mut().channel_mut(chan).oes = true`, the same field
/// `crate::shims::gsbl::btuoes` itself sets.
///
/// # Errors
///
/// If `othusn` does not name a channel of this host, or a read or write runs
/// off the segment.
pub fn injoth<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let othusn = host
        .globals()
        .word_mem(call.mem(), "othusn")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let Some(chan) = host.users().terms().chan(othusn) else {
        return Err(ShimError::Failed(format!(
            "injoth: othusn ({othusn}) names no channel of this host"
        )));
    };

    let slot = host.users().slot(chan);
    let flags0_ptr = A::ptr_offset(slot, host.users().user_layout().flags.at);
    let flags0 = flags0_ptr
        .resolve(call.mem(), 1)
        .map_err(|e| ShimError::Failed(e.to_string()))?[0];

    let retval: u16 = if flags0 & NOINJO != 0 {
        0
    } else {
        // `dftinj()`, unconditionally -- see this routine's own doc comment
        // for why the real `injrou` branch can never be taken from a shim.
        let prfbuf = host
            .globals()
            .pointer_mem(call.mem(), "prfbuf")
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let text_bytes = prfbuf
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        host.gsbl_mut().transmit_raw(chan, &text_bytes);
        host.gsbl_mut().channel_mut(chan).oes = true;

        let new_flags0 = flags0 | INJOIP;
        flags0_ptr
            .write(call.mem(), &[new_flags0])
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        1
    };

    // The vendor's tail loop, collapsed: reset the *calling* channel's own
    // print buffer for continued use. See this routine's own doc comment for
    // why this host's lack of multilingual buffers makes this an exact
    // stand-in rather than an approximation.
    text::clrprf_mem(call.mem(), host)?;

    Ok(abi::Ret::Int(A::Int::from(retval)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

    #[test]
    fn bgncnc_points_nxtcmd_at_margv_zero_and_resets_the_print_buffer() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"look here now")
            .expect("input");
        assert!(matches!(f.invoke(text::parsin, &[]), Ok(Ret::Void)));

        // Leave something in the print buffer so `bgncnc`'s `clrprf()` has
        // something to actually clear.
        //
        // `prfbuf` is a POINTER global, not the buffer itself: `Globals::
        // address("prfbuf")` is the four-byte slot holding the pointer, while
        // `Globals::prf_buffer()` is what it points at. Seeding through the
        // former overwrites the pointer with text -- which is exactly what
        // this test did until the byte `0x65 0x6d` ("me") turned up as a
        // segment selector.
        let prfbuf = f.host.globals().prf_buffer();
        f.machine.write(prfbuf, b"stale\0").expect("seed prfbuf");

        assert!(matches!(f.invoke(bgncnc, &[]), Ok(Ret::Void)));

        let margv = f.host.globals().address("margv").expect("margv");
        let margv0 = FarPtr::from_bytes(
            f.machine
                .resolve(margv, 4)
                .expect("in bounds")
                .try_into()
                .expect("4 bytes"),
        );
        let nxtcmd = f.host.globals().address("nxtcmd").expect("nxtcmd");
        let got = FarPtr::from_bytes(
            f.machine
                .resolve(nxtcmd, 4)
                .expect("in bounds")
                .try_into()
                .expect("4 bytes"),
        );
        assert_eq!(got, margv0, "nxtcmd must equal margv[0]");

        // The WHOLE line, not just the first word. `bgncnc` is
        // `nxtcmd=margv[0]; clrprf(); rstrin();` (CNCUTL.C:27-33), and
        // `rstrin` puts the separators `parsin` overwrote with NULs back --
        // which is the entire point of command concatenation: `nxtcmd` walks
        // the restored line looking for the next command. Asserting `"look"`
        // here would be asserting the state BEFORE `rstrin` ran.
        assert_eq!(
            f.machine.read_cstr(got).expect("readable"),
            b"look here now",
            "rstrin restored the separators, so margv[0] reads the whole line"
        );

        // `clrprf()` ran: the buffer is empty again.
        assert_eq!(f.machine.read_cstr(prfbuf).expect("readable"), b"");
    }

    #[test]
    fn cncchr_uppercases_and_advances_but_stops_at_the_terminator() {
        let mut f = Fixture::new();
        let nxtcmd = f.host.globals().address("nxtcmd").expect("nxtcmd");
        let text_at = f.text("nq");
        f.machine
            .write(nxtcmd, &FarPtr::to_bytes(text_at))
            .expect("nxtcmd seeded");

        let ret = f.invoke(cncchr, &[]).expect("cncchr");
        assert_eq!(ret, Ret::U16(u16::from(b'N')), "upper-cased");
        let advanced = FarPtr::from_bytes(
            f.machine.resolve(nxtcmd, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(f.machine.read_cstr(advanced).expect("readable"), b"q", "advanced one byte");

        let ret = f.invoke(cncchr, &[]).expect("cncchr");
        assert_eq!(ret, Ret::U16(u16::from(b'Q')));

        // Now at the terminator: repeated calls answer 0 and do not advance.
        let ret = f.invoke(cncchr, &[]).expect("cncchr");
        assert_eq!(ret, Ret::U16(0));
        let still = FarPtr::from_bytes(
            f.machine.resolve(nxtcmd, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(f.machine.read_cstr(still).expect("readable"), b"", "did not advance past NUL");
        let ret = f.invoke(cncchr, &[]).expect("cncchr");
        assert_eq!(ret, Ret::U16(0), "still 0, not walking off the string");
    }

    #[test]
    fn cncall_returns_the_rest_and_exhausts_nxtcmd() {
        let mut f = Fixture::new();
        let nxtcmd = f.host.globals().address("nxtcmd").expect("nxtcmd");
        let text_at = f.text("gold and gems");
        f.machine
            .write(nxtcmd, &FarPtr::to_bytes(text_at))
            .expect("nxtcmd seeded");

        let Ret::Far(retval) = f.invoke(cncall, &[]).expect("cncall") else {
            panic!("cncall returns char *");
        };
        assert_eq!(f.machine.read_cstr(retval).expect("readable"), b"gold and gems");

        let now = FarPtr::from_bytes(
            f.machine.resolve(nxtcmd, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(f.machine.read_cstr(now).expect("readable"), b"", "nxtcmd exhausted");
    }

    /// Point `nxtcmd` at `line`, and answer the address of the `nxtcmd`
    /// global itself so [`remaining`] can read it back.
    ///
    /// The same three lines every `cncchr`/`cncall` test above already writes
    /// out by hand; the routines added in Phase 2 need it a dozen more times.
    fn seed(f: &mut Fixture, line: &str) -> FarPtr {
        let nxtcmd = f.host.globals().address("nxtcmd").expect("nxtcmd");
        let at = f.text(line);
        f.machine.write(nxtcmd, &FarPtr::to_bytes(at)).expect("nxtcmd seeded");
        nxtcmd
    }

    /// What is left of the line `nxtcmd` now points at.
    fn remaining(f: &Fixture, nxtcmd: FarPtr) -> Vec<u8> {
        let now = FarPtr::from_bytes(
            f.machine.resolve(nxtcmd, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        f.machine.read_cstr(now).expect("readable").to_vec()
    }

    /// `cncint` is `atoi` over the concatenation pointer: digits are consumed
    /// from `nxtcmd`, which advances past them, and the first non-digit stops
    /// it (`CNCUTL.C:60`, delegating to `cnclon`).
    #[test]
    fn cncint_consumes_digits_and_advances_nxtcmd() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "42rest");

        assert_eq!(f.invoke(cncint, &[]).expect("cncint"), Ret::U16(42));
        assert_eq!(
            remaining(&f, nxtcmd),
            b"rest",
            "nxtcmd advanced past the digits it consumed, and no further"
        );
    }

    /// A leading non-digit yields zero and consumes nothing. This is the case
    /// that distinguishes a real port from a stub returning 0.
    #[test]
    fn cncint_on_a_non_digit_returns_zero_and_consumes_nothing() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "rest");

        assert_eq!(f.invoke(cncint, &[]).expect("cncint"), Ret::U16(0));
        assert_eq!(remaining(&f, nxtcmd), b"rest");
    }

    /// `cnclon` answers a full 32-bit `long` where `cncint` truncates to the
    /// ABI's `int` (`CNCUTL.C:66`). `70000` is the discriminating value: it
    /// does not fit in 16 bits, so a `cncint` that forgot its `(int)` cast
    /// and a `cnclon` that wrongly narrowed would both show up here.
    #[test]
    fn cnclon_answers_the_whole_long_where_cncint_truncates() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "70000 gold");
        assert_eq!(f.invoke(cnclon, &[]).expect("cnclon"), Ret::U32(70_000));
        assert_eq!(remaining(&f, nxtcmd), b" gold", "the space is not consumed");

        // The same input through `cncint` under Wg16: 70000 & 0xffff.
        let mut f = Fixture::new();
        seed(&mut f, "70000");
        assert_eq!(
            f.invoke(cncint, &[]).expect("cncint"),
            Ret::U16(70_000u32 as u16),
            "(int) of a long is a truncation under Wg16, not a saturation"
        );
    }

    /// `cnclon` has no overflow check and the vendor never added one
    /// (`CNCUTL.C:66-74`), so a number past 2^32 wraps rather than
    /// saturating or panicking. Pinned because the natural Rust spelling --
    /// plain `*` and `+` -- would panic in a debug build instead, which is a
    /// different behaviour and not a safer one.
    #[test]
    fn cnclon_wraps_rather_than_checking_for_overflow() {
        let mut f = Fixture::new();
        seed(&mut f, "4294967300"); // 2^32 + 4
        assert_eq!(f.invoke(cnclon, &[]).expect("cnclon"), Ret::U32(4));
    }

    /// `cncwrd` grabs one space-delimited word into a static buffer,
    /// truncating at `UIDSIZ-1` (`CNCUTL.C:133`). The truncation case is what
    /// proves the bound was ported rather than assumed.
    #[test]
    fn cncwrd_grabs_one_word_and_truncates_at_uidsiz() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "hello world");
        let Ret::Far(at) = f.invoke(cncwrd, &[]).expect("cncwrd") else {
            panic!("cncwrd returns char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"hello");
        assert_eq!(
            remaining(&f, nxtcmd),
            b" world",
            "the delimiting space is NOT consumed"
        );

        let mut f = Fixture::new();
        seed(&mut f, &"x".repeat(64));
        let Ret::Far(at) = f.invoke(cncwrd, &[]).expect("cncwrd") else {
            panic!("cncwrd returns char *");
        };
        assert_eq!(
            f.machine.read_cstr(at).expect("readable").len(),
            29,
            "UIDSIZ is 30 including the NUL, so 29 characters survive"
        );
    }

    /// `cncwrd`'s buffer is zeroed in full before the word is written
    /// (`setmem(retval,UIDSIZ,0)`, `CNCUTL.C:139`), so a shorter word after a
    /// longer one leaves no tail of the first behind.
    #[test]
    fn cncwrd_zeroes_its_whole_buffer_between_calls() {
        let mut f = Fixture::new();
        seed(&mut f, "abcdefghij");
        let Ret::Far(at) = f.invoke(cncwrd, &[]).expect("cncwrd") else {
            panic!("char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"abcdefghij");

        seed(&mut f, "ab");
        assert!(matches!(f.invoke(cncwrd, &[]), Ok(Ret::Far(_))));
        let whole = f.machine.resolve(at, usize::from(UIDSIZ)).expect("in bounds").to_vec();
        assert_eq!(&whole[..2], b"ab");
        assert!(
            whole[2..].iter().all(|&b| b == 0),
            "setmem zeroed the whole buffer, so no tail of the longer word survives: {whole:?}"
        );
    }

    /// `cncuid` takes a user-ID, and `isuidc` counts a space as part of one
    /// (`ISUIDC.C:25`) -- so a user-ID does not end at the first blank. That
    /// is the case a reasonable-looking port gets wrong.
    #[test]
    fn cncuid_keeps_spaces_because_a_userid_may_contain_them() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "ranger dan!bang");
        let Ret::Far(at) = f.invoke(cncuid, &[]).expect("cncuid") else {
            panic!("char *");
        };
        assert_eq!(
            f.machine.read_cstr(at).expect("readable"),
            b"ranger dan",
            "the space is a valid user-ID character; the '!' is not"
        );
        assert_eq!(remaining(&f, nxtcmd), b"!bang");
    }

    /// On a leading `'/'`, `cncuid` returns `cncsig`'s answer outright
    /// (`CNCUTL.C:83`) -- a different buffer, and one that always begins with
    /// the slash whether or not the input did.
    #[test]
    fn cncuid_hands_a_leading_slash_to_cncsig() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "/talk about it");
        let Ret::Far(at) = f.invoke(cncuid, &[]).expect("cncuid") else {
            panic!("char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"/talk");
        assert_eq!(remaining(&f, nxtcmd), b" about it");

        // And it really is cncsig's buffer, not cncuid's.
        let mut f = Fixture::new();
        seed(&mut f, "/talk");
        let Ret::Far(sig) = f.invoke(cncsig, &[]).expect("cncsig") else {
            panic!("char *");
        };
        seed(&mut f, "/talk");
        let Ret::Far(uid) = f.invoke(cncuid, &[]).expect("cncuid") else {
            panic!("char *");
        };
        assert_eq!(uid, sig, "CNCUTL.C:83 returns cncsig()'s own static");
    }

    /// `cncsig` writes the `'/'` unconditionally, so a name given without one
    /// comes back with one (`CNCUTL.C:101`). The slash costs a byte of
    /// `SIGSIZ`, so only eight characters of the name survive, not nine.
    #[test]
    fn cncsig_always_leads_with_a_slash_and_truncates_at_eight() {
        let mut f = Fixture::new();
        seed(&mut f, "talk");
        let Ret::Far(at) = f.invoke(cncsig, &[]).expect("cncsig") else {
            panic!("char *");
        };
        assert_eq!(
            f.machine.read_cstr(at).expect("readable"),
            b"/talk",
            "the slash is written whether or not the input carried one"
        );

        let mut f = Fixture::new();
        seed(&mut f, "abcdefghijkl");
        let Ret::Far(at) = f.invoke(cncsig, &[]).expect("cncsig") else {
            panic!("char *");
        };
        assert_eq!(
            f.machine.read_cstr(at).expect("readable"),
            b"/abcdefgh",
            "SIGSIZ is 10: one slash, eight characters and a NUL"
        );
    }

    /// `cncuid` and `cncwrd` return **different** statics (`CNCUTL.C:80`
    /// and `:136`), so a caller holding one while calling the other still
    /// has it. A single shared scratch buffer would pass every test above
    /// and fail this one.
    #[test]
    fn the_static_buffers_do_not_alias_each_other() {
        let mut f = Fixture::new();
        seed(&mut f, "kaimon");
        let Ret::Far(uid) = f.invoke(cncuid, &[]).expect("cncuid") else {
            panic!("char *");
        };
        seed(&mut f, "sword");
        let Ret::Far(wrd) = f.invoke(cncwrd, &[]).expect("cncwrd") else {
            panic!("char *");
        };
        assert_ne!(uid, wrd, "cncuid and cncwrd have separate statics");
        assert_eq!(
            f.machine.read_cstr(uid).expect("readable"),
            b"kaimon",
            "cncwrd must not have clobbered the user-ID the caller still holds"
        );
    }

    /// `cncyesno` maps the current language's yes/no first letters to
    /// `'Y'`/`'N'` and consumes any matching remainder (`CNCUTL.C:111`). It
    /// dereferences `languages[clingo]`, so it is the routine that proves
    /// Task 2.1 landed.
    #[test]
    fn cncyesno_maps_to_upper_y_and_n_through_the_lingo_record() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "yes please");
        assert_eq!(f.invoke(cncyesno, &[]).expect("cncyesno"), Ret::U16(u16::from(b'Y')));
        assert_eq!(
            remaining(&f, nxtcmd),
            b" please",
            "the whole word `yes` was chomped, not just its first letter"
        );

        let nxtcmd = seed(&mut f, "no thanks");
        assert_eq!(f.invoke(cncyesno, &[]).expect("cncyesno"), Ret::U16(u16::from(b'N')));
        assert_eq!(remaining(&f, nxtcmd), b" thanks");

        // Neither word: the raw character comes back, uppercased by cncchr,
        // and only that one character is consumed.
        let nxtcmd = seed(&mut f, "maybe");
        assert_eq!(f.invoke(cncyesno, &[]).expect("cncyesno"), Ret::U16(u16::from(b'M')));
        assert_eq!(remaining(&f, nxtcmd), b"aybe");
    }

    /// The remainder is only chomped when it actually matches: `"yellow"`
    /// answers `'Y'` -- the first letter did match -- but `"es"` is not a
    /// prefix of `"ellow"`, so only the `y` is consumed. This is the
    /// asymmetry `sameto` exists for, and a port using equality instead of a
    /// prefix test would consume nothing anywhere.
    #[test]
    fn cncyesno_only_chomps_the_remainder_when_it_matches() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "yellow");
        assert_eq!(f.invoke(cncyesno, &[]).expect("cncyesno"), Ret::U16(u16::from(b'Y')));
        assert_eq!(remaining(&f, nxtcmd), b"ellow", "`es` is not a prefix of `ellow`");
    }

    /// `morcnc` skips whitespace and answers the next character upper-cased,
    /// or `0` when there is none (`CNCUTL.C:171`). Both halves matter: a port
    /// that forgot the skip answers `' '`, and one that forgot the
    /// end-of-line case answers `' '` there too.
    #[test]
    fn morcnc_skips_whitespace_and_uppercases_what_follows() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "   get gold");
        assert_eq!(f.invoke(morcnc, &[]).expect("morcnc"), Ret::U16(u16::from(b'G')));
        assert_eq!(
            remaining(&f, nxtcmd),
            b"get gold",
            "the blanks were consumed but the character itself was not"
        );

        let nxtcmd = seed(&mut f, "   ");
        assert_eq!(
            f.invoke(morcnc, &[]).expect("morcnc"),
            Ret::U16(0),
            "nothing but trailing blanks means no more commands"
        );
        assert_eq!(remaining(&f, nxtcmd), b"");
    }

    /// `cncnum` keeps a leading sign and bounds the whole answer -- sign
    /// included -- at eleven characters (`CNCUTL.C:212`). The sign is what
    /// separates it from `cnclon`, which stops dead on a `'-'`.
    #[test]
    fn cncnum_keeps_the_sign_and_bounds_at_eleven() {
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "-1234 gold");
        let Ret::Far(at) = f.invoke(cncnum, &[]).expect("cncnum") else {
            panic!("char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"-1234");
        assert_eq!(remaining(&f, nxtcmd), b" gold");

        // Eleven characters including the sign, so ten digits survive.
        let mut f = Fixture::new();
        seed(&mut f, "-123456789012345");
        let Ret::Far(at) = f.invoke(cncnum, &[]).expect("cncnum") else {
            panic!("char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"-1234567890");

        // `cnclon` over the same input stops on the sign and answers zero.
        let mut f = Fixture::new();
        let nxtcmd = seed(&mut f, "-1234");
        assert_eq!(f.invoke(cnclon, &[]).expect("cnclon"), Ret::U32(0));
        assert_eq!(remaining(&f, nxtcmd), b"-1234", "cnclon consumed nothing");
    }

    /// `isuidc` is the predicate `cncuid` walks with (`ISUIDC.C:18`). The
    /// space and the apostrophe are the entries that make it not just
    /// `isalnum`, and the `'!'` is what must still be rejected -- a
    /// predicate tested only on letters passes when it always answers true.
    #[test]
    fn isuidc_accepts_a_space_and_an_apostrophe_but_not_punctuation() {
        let mut f = Fixture::new();
        for c in [b'A', b'z', b'0', b'.', b' ', b',', b'-', b'_', b'\''] {
            assert_eq!(
                f.invoke(isuidc, &[u16::from(c)]).expect("isuidc"),
                Ret::U16(1),
                "{:?} is a valid user-ID character",
                c as char
            );
        }
        for c in [b'!', b'/', b'@', b'#', b'*', 0] {
            assert_eq!(
                f.invoke(isuidc, &[u16::from(c)]).expect("isuidc"),
                Ret::U16(0),
                "{:?} is not a valid user-ID character",
                c as char
            );
        }
        // The two CP437 ranges, at their edges.
        for c in [0x80u8, 0xa5, 0xe0, 0xef] {
            assert_eq!(
                f.invoke(isuidc, &[u16::from(c)]).expect("isuidc"),
                Ret::U16(1),
                "{c:#04x} is inside ISUIDC.C:27-28's high ranges"
            );
        }
        for c in [0xa6u8, 0xdf, 0xf0] {
            assert_eq!(
                f.invoke(isuidc, &[u16::from(c)]).expect("isuidc"),
                Ret::U16(0),
                "{c:#04x} is outside ISUIDC.C:27-28's high ranges"
            );
        }
    }

    #[test]
    fn endcnc_with_nothing_left_answers_one_immediately() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"")
            .expect("input");
        assert!(matches!(f.invoke(text::parsin, &[]), Ok(Ret::Void)));
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);

        let ret = f.invoke(endcnc, &[]).expect("endcnc");
        assert_eq!(ret, Ret::U16(1));
    }

    #[test]
    fn endcnc_reparses_what_nxtcmd_still_points_at_and_counts_numcat() {
        // Simulate `bgncnc` on "look;get gold": nxtcmd lands on "get gold"
        // after the caller's own `cncchr`/`cncall` consumed the ';'.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"look")
            .expect("input");
        assert!(matches!(f.invoke(text::parsin, &[]), Ok(Ret::Void)));

        let nxtcmd = f.host.globals().address("nxtcmd").expect("nxtcmd");
        let rest = f.text("get gold");
        f.machine
            .write(nxtcmd, &FarPtr::to_bytes(rest))
            .expect("nxtcmd points at the next concatenated command");

        assert_eq!(f.host.globals().word(&f.machine, "numcat").expect("numcat"), 0);
        let ret = f.invoke(endcnc, &[]).expect("endcnc");
        // Not the last command, so 0 -- but the reparse already happened.
        assert_eq!(ret, Ret::U16(0));
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 2);

        let margv = f.host.globals().address("margv").expect("margv");
        let margv0 = FarPtr::from_bytes(
            f.machine.resolve(margv, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(f.machine.read_cstr(margv0).expect("readable"), b"get");
        assert_eq!(f.host.globals().word(&f.machine, "numcat").expect("numcat"), 1);
    }

    #[test]
    fn onsys_finds_a_class_above_supipg_and_a_matching_userid() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let zero = f.host.gsbl().terms().chan(0).expect("channel 0");
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");

        f.host
            .connect_state(&mut f.machine, zero, &crate::users::Connection::ansi("kaimon"))
            .expect("channel 0 connected");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");

        // `connect_state` leaves `usrcls` at 0 (`SUPIPG` is 3), so neither
        // channel is "on the system" by `onsys`'s own test until raised.
        let uid = f.text("rangerdan");
        let ret = f.invoke(onsys, &[uid.offset, uid.selector]).expect("onsys");
        assert_eq!(ret, Ret::U16(0), "usrcls is still 0, at or below SUPIPG");

        let slot = f.host.users().slot(one);
        let usrcls = FarPtr {
            offset: slot.offset + f.host.users().user_layout().usrcls.at,
            selector: slot.selector,
        };
        f.machine.write(usrcls, &5u16.to_le_bytes()).expect("in bounds");

        let ret = f.invoke(onsys, &[uid.offset, uid.selector]).expect("onsys");
        assert_eq!(ret, Ret::U16(1), "usrcls 5 is above SUPIPG, and the userid matches");

        let missing = f.text("nobody");
        let ret = f
            .invoke(onsys, &[missing.offset, missing.selector])
            .expect("onsys");
        assert_eq!(ret, Ret::U16(0), "no channel has this userid");
    }

    #[test]
    fn onsys_skips_an_invisible_match_but_keeps_looking() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        let two = f.host.gsbl().terms().chan(2).expect("channel 2");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");
        f.host
            .connect_state(&mut f.machine, two, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 2 connected, same userid, still visible");

        for chan in [one, two] {
            let slot = f.host.users().slot(chan);
            let usrcls = FarPtr {
                offset: slot.offset + f.host.users().user_layout().usrcls.at,
                selector: slot.selector,
            };
            f.machine.write(usrcls, &5u16.to_le_bytes()).expect("in bounds");
        }

        // Mark channel 1 invisible (`INVISB`, bit 6 of `FLAGS + 1`).
        let slot = f.host.users().slot(one);
        let flags1 = FarPtr {
            offset: slot.offset + f.host.users().user_layout().flags.at + 1,
            selector: slot.selector,
        };
        let was = f.machine.resolve(flags1, 1).expect("in bounds")[0];
        f.machine.write(flags1, &[was | 0x40]).expect("in bounds");

        let uid = f.text("rangerdan");
        let ret = f.invoke(onsys, &[uid.offset, uid.selector]).expect("onsys");
        assert_eq!(ret, Ret::U16(1), "channel 1 is invisible, but channel 2 is not");
    }

    #[test]
    fn strupr_uppercases_ascii_in_place_and_returns_the_same_pointer() {
        let mut f = Fixture::new();
        let at = f.text("Get the Gold, Now!");

        let Ret::Far(ret) = f.invoke(strupr, &[at.offset, at.selector]).expect("strupr") else {
            panic!("strupr returns char *");
        };
        assert_eq!(ret, at, "returns the same pointer it was given");
        assert_eq!(
            f.machine.read_cstr(at).expect("readable"),
            b"GET THE GOLD, NOW!"
        );
    }

    #[test]
    fn injoth_runs_dftinj_transmits_raises_oes_and_sets_injoip() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");

        f.host
            .globals()
            .write(&mut f.machine, "othusn", &1u16.to_le_bytes())
            .expect("othusn");

        // Seed the buffer `prfbuf` POINTS AT, not the pointer slot itself --
        // see `bgncnc_points_nxtcmd_at_margv_zero_and_resets_the_print_buffer`
        // for the same trap.
        let prfbuf = f.host.globals().prf_buffer();
        f.machine.write(prfbuf, b"someone pages you\0").expect("seed prfbuf");

        let ret = f.invoke(injoth, &[]).expect("injoth");
        assert_eq!(ret, Ret::U16(1), "NOINJO was clear, dftinj ran");

        assert!(
            f.host.gsbl_mut().channel_mut(one).oes,
            "dftinj's btuoes(othusn,1)"
        );

        let slot = f.host.users().slot(one);
        let flags0 = FarPtr {
            offset: slot.offset + f.host.users().user_layout().flags.at,
            selector: slot.selector,
        };
        let byte = f.machine.resolve(flags0, 1).expect("in bounds")[0];
        assert_ne!(byte & INJOIP, 0, "dftinj's user[othusn].flags|=INJOIP");

        // The calling channel's own print buffer was reset.
        assert_eq!(f.machine.read_cstr(prfbuf).expect("readable"), b"");
    }

    #[test]
    fn injoth_refuses_a_channel_that_set_noinjo() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");

        let slot = f.host.users().slot(one);
        let flags0 = FarPtr {
            offset: slot.offset + f.host.users().user_layout().flags.at,
            selector: slot.selector,
        };
        let was = f.machine.resolve(flags0, 1).expect("in bounds")[0];
        f.machine.write(flags0, &[was | NOINJO]).expect("in bounds");

        f.host
            .globals()
            .write(&mut f.machine, "othusn", &1u16.to_le_bytes())
            .expect("othusn");

        let ret = f.invoke(injoth, &[]).expect("injoth");
        assert_eq!(ret, Ret::U16(0), "NOINJO refuses the injection");
        assert!(!f.host.gsbl_mut().channel_mut(one).oes, "dftinj did not run");
    }
}
