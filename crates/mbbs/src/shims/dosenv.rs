//! `DOSCALLS!DosSetVec`, `PHAPI!DosCreateDSAlias`, `GALME!_oldsend` -- the
//! module's last three non-`MAJORBBS` imports, and none of them is a
//! `MAJORBBS` host routine.
//!
//! `docs/dll-imports.md` (`4163979`/`2ca5c74`/`400368b`, 2026-08-05) already
//! *named* all three: it disassembled every call site, cited the header each
//! comes from, and explained what the real routine does. Nothing here
//! repeats that discovery -- this file re-verifies it independently (see
//! "Independently re-measured" below, which matches byte for byte) and
//! answers the question that doc deliberately left open: whether a module
//! calling these on *this* host would ever reach them, and what this host
//! should therefore do.
//!
//! # `DosSetVec` and `DosCreateDSAlias` share one answer, because they share one call site
//!
//! Both live inside the same 424-byte span: `re/WCCMMUD.DLL` segment 1
//! (NE segment table entry 1: file offset `0x3e00`, length `0x1a8`), offsets
//! `0x00`-`0x1a7`. `DosCreateDSAlias` is the *first* far call the segment
//! makes (fixup at offset `0x17`, one byte into the `9a ff ff 00 00` operand
//! at `0x16`); `DosSetVec` is called twice more, at `0x11d` and `0x139`.
//! Disassembling the whole span (`ndisasm -b16 -o 0`) makes the shape of it
//! unmistakable:
//!
//! ```text
//! 00000000  1E                push ds
//! 00000004  BA0000            mov dx,0x0
//! 00000007  B462              mov ah,0x62         ; DOS: get PSP
//! 00000009  CD21              int 0x21
//! 0000000F  0E                push cs
//! 00000010  68FFFF            push word 0xffff
//! 00000013  687700            push word 0x77
//! 00000016  9AFFFF0000        call far <DosCreateDSAlias>   ; fixup @0x17
//! 0000001B  0BC0              or ax,ax                       ; return code IS tested
//! 0000001D  7402              jz 0x21
//! 0000001F  EB58              jmp 0x79                       ; -> bail out, ax=0
//! ...
//! 0000002C  26C706A4010000    mov word [es:0x1a4],0x0        ; cs:0x1a4 seeded
//! 00000034  B430              mov ah,0x30         ; DOS: get version
//! 00000036  CD21              int 0x21
//! ...
//! 00000113  6A00              push word 0x0                  ; usVecNum 0 (divide-by-zero)
//! 00000116  680A01            push word 0x10a                ; pfnRoutine = cs:0x10a
//! 0000011A  685D00            push word 0x5d                 ; ppfnPrev  = ds:0x5d
//! 0000011D  9AFFFF0000        call far <DosSetVec>            ; fixup @0x11e
//! 00000122  C3                ret                              ; return code NOT tested
//! ...
//! 0000012D  6A00              push word 0x0                  ; usVecNum 0
//! 0000012F  FF365F00          push word [0x5f]                ; the pfnRoutine DosSetVec saved
//! 00000133  FF365D00          push word [0x5d]
//! 00000139  9AFFFF0000        call far <DosSetVec>            ; fixup @0x13a, restore
//! 0000013E  83C404            add sp,0x4                       ; the local, not the arguments
//! ```
//!
//! Every `mov ds,[cs:0x1a4]` in the rest of the span (there are more than a
//! dozen) reads back the value `DosCreateDSAlias` exists to let this code
//! *write*: a code selector (`cs`) is execute-only in protected mode, so the
//! trampoline aliases it with a writable data selector just long enough to
//! poke its own DGROUP selector into a fixed slot at `cs:0x1a4`, and every
//! later routine in the span re-derives `ds` from that slot instead of
//! trusting whatever `ds` happened to hold on entry. That is what a
//! Phar-Lap/Borland **DOS-EXE crt0** does -- get the PSP, get the DOS
//! version, bootstrap DGROUP, walk the environment block, and (on the error
//! path at `0x18e`/`0x194`) write a message with `int 21h ah=0x40` and
//! terminate with `int 21h ah=0x4c`. It is not Worldgroup module logic; it
//! is what the Borland linker puts at the front of *any* Phar-Lap-targeted
//! program, and `DosSetVec`'s pair sits inside it as one piece of that
//! boilerplate: install a handler for vector 0 (divide-by-zero) around the
//! DOS-version/environment arithmetic that follows, restore the previous one
//! before falling into the rest of the crt0.
//!
//! ## Why this host's loader never enters it
//!
//! Four independent facts, not one inference:
//!
//! 1. **The NE header names no entry point.** `re/WCCMMUD.DLL`'s own
//!    `ne_csip` (the header word pair at NE-header offsets `0x14`/`0x16`,
//!    Microsoft's "Windows 3.1 Programmer's Reference, Vol 4" NE spec) reads
//!    `0000:0000` -- measured directly off the file. There is no automatic
//!    entry any generic NE loader convention would jump to; segment 1 offset
//!    0 is reachable only by an explicit far call, and this crate's loader
//!    (`crate::Host::load`) does not make one -- it resolves the module's
//!    own MDF-registered routines (`lonrou`, `huprou`, and the rest) by
//!    address, the same way real `MAJORBBS.EXE` does for an in-process
//!    add-on module, never through a generic crt0/`LibMain` hook meant for a
//!    module launched as its own DOS-extended process.
//! 2. **Nothing inside segment 1 calls into it either.** The only two
//!    targets any of this span's own instructions name are `0x186`
//!    ("write and exit") and `0x143` (an atexit-style list walker) -- no
//!    internal `call 0x0`/`call 0x113` exists. The relocation graph gives
//!    exactly two ways in: the NE header's entry point (absent, see above)
//!    and a far call from *another* segment, which the module's own 22,371
//!    relocation records do not contain (see "Independently re-measured").
//! 3. **The three universal boilerplate imports are identical across four
//!    unrelated modules.** `docs/2026-08-12-module-import-gaps.md`'s own
//!    measurement: `DOSSETVEC` and `DOSCREATEDSALIAS` (with `_DFSTHN`, which
//!    turned out to have a real body reachable through a completely
//!    different call path -- `crate::shims::user::dfsthn`) appear with
//!    *exactly* the same call counts -- 2 and 1 -- in MajorMUD, Lunatix,
//!    Tele-Arena and The Rose: four modules from three different ISVs, whose
//!    only shared property is the Borland/Phar-Lap toolchain that compiled
//!    them. Identical counts across unrelated modules is the signature of
//!    linker-inserted boilerplate, not authored logic -- the same read this
//!    crate's own survey methodology already uses elsewhere.
//! 4. **`crates/mbbs/tests/wccmmud.rs` never mentions any of it.** That file
//!    is 5,000-plus lines of forensic "how far did boot get, and what
//!    blocked it next" narrative against the real `re/WCCMMUD.DLL`, and it
//!    names *every* blocking gap it has hit in that detail. `grep -i
//!    "dossetvec\|doscreatedsalias\|DosSetVec\|Phar Lap\|extender"` against
//!    it returns nothing. A file this thorough about every other gap staying
//!    silent about these three is not proof by itself, but it is exactly
//!    the absence four independent structural facts predict.
//!
//! ## Even in the counterfactual where it *were* entered, the vector table has no reader
//!
//! `mbbs-machine` runs 16-bit code by executing real x86 instructions in
//! compatibility mode, not by interpreting them -- see
//! `mbbs_machine::m16::fault`'s own module doc comment: "A 16-bit module can
//! divide by zero... and none of that should take the host down with it,"
//! recovered by rewriting the interrupted signal context so `sigreturn`
//! lands back in host code. That mechanism is process-wide, ABI-generic, and
//! installed once, independent of whatever any module's own crt0 "remembers"
//! having installed at vector 0 -- there is no table on this host a real
//! `INT 0` trap ever consults to find a module-supplied handler. So even if
//! segment 1 ran, `DosSetVec`'s install/restore pair could not change what
//! this host does on a genuine divide fault; the indirection it manages is
//! structurally unreachable from the CPU's own fault path, not merely
//! unreached today.
//!
//! ## The verdict: documented no-op, for both
//!
//! This is the shape the top-level task brief gives as its own worked
//! example of a legitimate no-op: "installing an interrupt vector nothing
//! will ever raise." Neither routine's return value is trusted for anything
//! [`_oldsend`](oldsend) or later application code depends on (`DosSetVec`'s
//! two sites do not even test `AX`; `DosCreateDSAlias`'s one site does, but
//! only to choose between two branches of dead crt0), so [`dossetvec`] and
//! [`doscreatedsalias`] report success and write [`FarPtr::NULL`] into the
//! out-parameter each API contract promises to fill -- the same
//! nothing-plausible-to-fabricate sentinel [`crate::shims::borland::get_proc_address`]
//! answers with, not a fabricated selector or handler address a caller might
//! go on to dereference. A hard error was considered and rejected: there is
//! no live branch here the way `dfsthn`'s `default:` arm was live in the
//! branch structure that housed it (`crate::shims::user::dfsthn`'s own doc
//! comment) -- this whole call site is unreached, so a refusal here would
//! never fire and would add a trap with no diagnostic value, for code this
//! host's own loader structurally does not run.
//!
//! `DosCreateDSAlias`'s real semantics *are* sourceable and this host *could*
//! answer faithfully -- `archive/galacticomm/extract/phar312/PHAPI.H:351`
//! gives the prototype and mbbs-machine already owns its own LDT, so minting
//! a second writable descriptor over the same base/limit is not a stretch.
//! It is not done here anyway: building it would be real, untestable-by-any-
//! reachable-path work for a call this host's own loader never makes, and
//! that is effort this crate's own principles (incremental, not a local
//! maximum) argue against spending.
//!
//! # `_oldsend` is a different case entirely: real, reachable, and refused
//!
//! Unlike the pair above, `GALME@30`'s two call sites
//! (`re/WCCMMUD.DLL` segment 3 -- a 56 KiB application code segment, not the
//! crt0 -- fixups at offsets `0xa572` and `0xa653`) are ordinary module
//! logic, not linker boilerplate: they sit inside a routine that assembles a
//! 6.x-format message (both sites push `to=NULL` so the callee reads
//! `msg->to`, and both are preceded by other far calls building up the same
//! `oldmsg` structure at `ds:0x28`). `docs/dll-imports.md` already read the
//! purpose off `GMEONL.C:1538`-1553: convert a MajorBBS 6.x `struct oldmsg`
//! into a Worldgroup `struct message` (via `old2new`) and hand it to
//! `simpsnd` for delivery. That is application-visible behaviour a live
//! session can trigger, not a call this host's own loader chooses not to
//! make.
//!
//! ## Which `_oldsend`, settled
//!
//! `crates/mbbs/data/galme_wg101.tsv` line 29 is the shipped WG 1.01
//! `GALME.DLL`'s own NE name table, transcribed byte for byte
//! (`docs/dll-imports.md`'s "Reproducing the tables"): ordinal 30 is
//! `__OLDSEND`, two leading underscores. `crate::exports::c_name` strips
//! *exactly one*, giving `_oldsend` -- matching `GME.H:1268`'s
//! `BOOL _oldsend(struct oldmsg *msg, char *to)`, "backward-compatible to
//! 6.X sendmsg()". This is confirmed by `exports.rs`'s own
//! `galme_ordinal_30_is_the_messaging_engines_6x_compatibility_entry` test.
//! The *other* `_OLDSEND` the task brief warns about is a different symbol
//! in a different, unrelated library: `re/wg33src/LIB/wg2/GALMSG.DEF:10`
//! gives ordinal 30 to `_OLDSEND` (one underscore, so the C name `oldsend`,
//! no leading underscore at all) inside `GALMSG`, the 6.x-era messaging
//! library `_oldsend` exists to be backward-compatible *to*. `WCCMMUD.DLL`
//! does not link `GALMSG` at all -- `GALME` is one of its five linked
//! libraries (`crate::exports`'s own module doc comment); `GALMSG` never
//! appears in its import table, and `re/importgaps.py re/WCCMMUD.DLL`
//! resolves this ordinal to `GALME _oldsend`, never `GALMSG`. Stripping
//! underscores greedily -- `lstrip("_")` rather than removing exactly one --
//! would have answered `oldsend` for both, silently merging two symbols in
//! two libraries into one lookup; `re/ne_exports.py`'s own doc comment names
//! that exact trap.
//!
//! ## The verdict: hard error, not a no-op
//!
//! This host has no GALME/messaging-engine subsystem at all --
//! `grep -rln "GALME\b" crates/mbbs/src/shims/*.rs` finds nothing, no
//! `simpsnd`, no `struct message` store, nothing `_oldsend` could hand a
//! converted message to -- so "faithful" is not available: the semantics
//! are sourced (`GME.H:1268`, `GMEONL.C:1538`), but this host cannot provide
//! them, which is exactly the bar the task brief sets for ruling faithful
//! out. A no-op is not the honest answer either. `_oldsend`'s entire
//! contract is "I sent your message" (`BOOL`, `TRUE` on success) -- a
//! specific, user-visible, data-integrity-bearing claim. Returning `TRUE`
//! without delivering anything tells the player their 6.x-format mail went
//! out when it silently vanished; returning `FALSE` is not honest either, it
//! reports "the messaging engine rejected this" when the true reason is "no
//! messaging engine exists here." Both are the fabricated-but-plausible
//! answer this crate's whole design refuses to give -- the same reasoning
//! `crate::shims::borland::abort` and `crate::shims::user::dfsthn`'s
//! unreproducible branch already apply: a module that believes it succeeded
//! and did not is worse than one this host stops. [`oldsend`] therefore
//! never returns `Ok`.
//!
//! # Independently re-measured
//!
//! Every relocation-record offset and every disassembled byte above was
//! re-derived directly from `re/WCCMMUD.DLL` this session (NE segment-table
//! parse plus `ndisasm -b16`, and a `RELOC_IMPORTORDINAL`/`RELOC_IMPORTNAME`
//! walk keyed on `(DOSCALLS, #89)`, `(GALME, #30)` and `(PHAPI,
//! "DOSCREATEDSALIAS")`), not copied from `docs/dll-imports.md`. They agree
//! with that document's own disassembly byte for byte; nothing here
//! contradicts it, only extends it with the reachability question it left
//! open.

use mbbs_machine::m16::FarPtr;
use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Call, Wg16};

/// `USHORT APIENTRY DosSetVec(USHORT usVecNum, PFN pfnRoutine, PFN FAR *ppfnPrev)`
/// -- install a Phar Lap interrupt-vector handler.
///
/// See this module's own doc comment for the full argument: both of
/// `re/WCCMMUD.DLL`'s call sites sit inside a DOS-EXE crt0 trampoline this
/// host's loader never enters, and even if it did, a real divide-by-zero
/// during that span would already be caught by
/// [`mbbs_machine::m16::fault`]'s process-wide, ABI-generic recovery --
/// nothing on this host ever reads whatever a module "installed" at a
/// vector number. So this answers success and writes
/// [`FarPtr::NULL`] into `*ppfnPrev`, the documented no-op the task brief's
/// own example names ("installing an interrupt vector nothing will ever
/// raise"), rather than a fabricated handler address.
///
/// # Argument order and byte count
///
/// Far pascal (`APIENTRY`): pushed left to right, callee cleans the stack.
/// `usVecNum` is `SEL`-width (`archive/galacticomm/extract/phar312/PHAPI.H:99`,
/// `typedef unsigned short SEL`), `pfnRoutine`/`ppfnPrev` are both `PFN`-width
/// far pointers (`PHAPI.H:105`, `typedef void (pascal _far *PFN)()`) --
/// 2 + 4 + 4 = 10 bytes, `Cleans::Callee(10)`.
///
/// # Errors
///
/// If `*ppfnPrev`'s far pointer does not resolve (a module bug this host can
/// name, not a value this host invented).
pub fn dossetvec(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let _vecnum = call.int();
    let _pfn_routine: FarPtr = call.ptr();
    let ppfn_prev: FarPtr = call.ptr();
    ppfn_prev.write(call.mem(), &FarPtr::NULL.to_bytes())?;
    Ok(abi::Ret::Int(0u16))
}

/// `USHORT APIENTRY DosCreateDSAlias(SEL sel, PSEL aselp)` -- mint a writable
/// data-segment alias over a selector.
///
/// See this module's own doc comment for the full argument: this host
/// *could* answer faithfully (mbbs-machine already owns an LDT), but the
/// one call site this module ever makes is the very first instruction of
/// the same unreachable crt0 trampoline [`dossetvec`] lives in, so this
/// answers success and writes a null `SEL` (`0`, the same "names nothing"
/// convention [`FarPtr::NULL`]'s own doc comment states for a selector) into
/// `*aselp`, rather than spend an LDT descriptor -- or the risk of getting
/// its attributes wrong -- on an alias nothing will ever read through.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `sel` is `SEL`-width (2 bytes,
/// `archive/galacticomm/extract/phar312/PHAPI.H:99`), `aselp` is
/// `PSEL`-width (4 bytes, `PHAPI.H:100`, `typedef unsigned short _far *PSEL`)
/// -- 2 + 4 = 6 bytes, `Cleans::Callee(6)`.
///
/// # Errors
///
/// If `*aselp`'s far pointer does not resolve.
pub fn doscreatedsalias(
    call: &mut Call<Wg16>,
    _host: &mut Host<Wg16>,
) -> Result<abi::Ret<Wg16>, ShimError> {
    let _sel = call.int();
    let aselp: FarPtr = call.ptr();
    aselp.write(call.mem(), &0u16.to_le_bytes())?;
    Ok(abi::Ret::Int(0u16))
}

/// `BOOL _oldsend(struct oldmsg *msg, char *to)` -- send a MajorBBS 6.x-format
/// message through the Worldgroup messaging engine's backward-compatibility
/// entry (`GME.H:1268`, defined `GMEONL.C:1538`).
///
/// See this module's own doc comment for why this is a hard error rather
/// than a no-op: unlike [`dossetvec`]/[`doscreatedsalias`], both of this
/// routine's call sites are reachable application logic, and this host has
/// no messaging-engine subsystem at all to hand a converted message to. A
/// `TRUE` this host fabricated would tell the caller mail went out that
/// silently vanished; a fabricated `FALSE` would misreport why. Neither is
/// the honest answer, so this never returns `Ok`.
///
/// # Argument order and byte count
///
/// Both measured call sites are cdecl, `add sp,0x8` after the call -- caller
/// cleans, two far pointers, `Cleans::Caller`.
///
/// # Errors
///
/// Always. See above.
pub fn oldsend(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let msg: FarPtr = call.ptr();
    let to: FarPtr = call.ptr();
    Err(ShimError::Failed(format!(
        "_oldsend({msg}, {to}): this host has no GALME messaging-engine subsystem -- \
         no simpsnd, no message store -- to hand a converted 6.x message to, and \
         answering TRUE would tell the caller mail was sent that was in fact silently \
         discarded"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs_machine::m16::Ret;

    /// The bug a no-op most easily hides: forgetting to write anything at all,
    /// so the module reads back whatever garbage was already in
    /// `*ppfnPrev`. Seeding it with a value that is neither zero nor a
    /// plausible far pointer makes "the shim never touched it" a distinct,
    /// observable failure from "the shim wrote the documented sentinel."
    #[test]
    fn dossetvec_answers_success_and_writes_a_null_sentinel_into_the_previous_handler_slot() {
        let mut f = Fixture::new();
        let prev = f.words(&[0xdead, 0xbeef]);
        let routine = f.words(&[0x1234, 0x5678]);
        let args = [
            0u16, // usVecNum -- 0, divide-by-zero, the only vector this module ever names
            routine.offset,
            routine.selector,
            prev.offset,
            prev.selector,
        ];

        let ret = f.invoke(dossetvec, &args).expect("dossetvec never refuses");

        assert_eq!(
            ret,
            Ret::U16(0),
            "NO_ERROR -- the return code neither of the module's own call sites tests, \
             but success is the honest shape of a routine that did what it promised"
        );
        assert_eq!(
            f.machine.resolve(prev, 4).expect("prev resolves"),
            &FarPtr::NULL.to_bytes()[..],
            "the out-parameter must be the documented sentinel, not the 0xdead/0xbeef \
             it was seeded with"
        );
    }

    /// The ten-byte frame this test builds is itself part of what is under
    /// test: five words that do not match `Cleans::Callee(10)`'s declared
    /// width would desynchronise every later `usVecNum`/`pfnRoutine`
    /// argument read from where the real far-pascal call sites put them.
    #[test]
    fn dossetvec_reads_exactly_the_five_words_a_far_pascal_call_site_pushes() {
        let mut f = Fixture::new();
        let prev = f.words(&[0, 0]);
        let args = [0u16, 0, 0, prev.offset, prev.selector];

        // A frame one word short would panic inside `Call::take` rather than
        // silently misread -- see `Call::take`'s own doc comment. Reaching
        // `Ok` at all is the assertion.
        f.invoke(dossetvec, &args).expect("five words is the whole frame");
    }

    #[test]
    fn doscreatedsalias_answers_success_and_writes_a_null_selector() {
        let mut f = Fixture::new();
        let aselp = f.words(&[0xbeef, 0]);
        let args = [0x0007u16, aselp.offset, aselp.selector];

        let ret = f
            .invoke(doscreatedsalias, &args)
            .expect("doscreatedsalias never refuses");

        assert_eq!(ret, Ret::U16(0), "NO_ERROR");
        assert_eq!(
            f.machine.resolve(aselp, 2).expect("aselp resolves"),
            &0u16.to_le_bytes()[..],
            "a null SEL, not the 0xbeef it was seeded with"
        );
    }

    #[test]
    fn oldsend_never_answers_ok() {
        let mut f = Fixture::new();
        let msg = f.words(&[0x28, 0x1000]);
        let to = FarPtr::NULL;
        let args = [msg.offset, msg.selector, to.offset, to.selector];

        let err = f
            .invoke(oldsend, &args)
            .expect_err("a fabricated TRUE or FALSE is not available here");

        let text = err.to_string();
        assert!(
            text.contains("simpsnd") || text.contains("messaging"),
            "the refusal should name what is actually missing, not just fail silently: {text}"
        );
    }

    /// Nothing here is a no-op with no mutation to check -- unlike
    /// [`dossetvec`]/[`doscreatedsalias`], every one of `oldsend`'s
    /// observable behaviours (which arguments it reads, that it always
    /// refuses) is exercised above. There is no success path to accidentally
    /// leave untested by mutating it into one.
    #[test]
    fn oldsend_consumes_its_full_eight_byte_cdecl_frame() {
        let mut f = Fixture::new();
        let args = [0u16, 0, 0, 0];
        f.invoke(oldsend, &args)
            .expect_err("four words is the whole frame, and it still refuses");
    }
}
