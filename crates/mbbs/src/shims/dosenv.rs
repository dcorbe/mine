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
use crate::abi::{self, Abi, Call, Wg16};
use crate::shims::Entry;

/// One resolver behind both ABI faces of runtime name resolution --
/// Rose16's Phar Lap `DosGetModHandle`/`DosGetProcAddr`
/// ([`dosgetmodhandle`], [`dosgetprocaddr`]) and Rose32's
/// `KERNEL32!LoadLibraryA`/`FreeLibrary` (`crate::shims::borland::loadlibrarya`,
/// `crate::shims::borland::freelibrary`). Both resolve a host library, and
/// then a routine within it, **by name at runtime** -- something load-time
/// ordinal binding (`shims::mod::entry`'s only caller until now,
/// `Resolver::resolve` at load time) never had to do, because a fixup
/// already names its own target before the module ever runs.
///
/// # What this resolver genuinely shares, and how it was measured
///
/// [`known_library`] and [`resolves`] are the two functions every one of the
/// four faces above calls -- see each one's own doc comment. Both run the
/// caller's raw strings through the same [`super::canonical_dll`] and
/// [`crate::exports::c_name`] that [`crate::shims::entry`] itself applies,
/// so a name reached at runtime and the same name reached through a
/// load-time fixup are answering the identical question against the
/// identical table -- not two independent copies of "does this host
/// implement X" that could silently drift apart.
///
/// Genuinely exercised against a real 32-bit build, not assumed: this task
/// disassembled `tmp/gapsurvey/round2/rose32/RCIROSE.DLL`'s own two call
/// sites for `LoadLibraryA`/`GetProcAddress` (`objdump -d`, thunks at
/// `0x46d534`/`0x46d528`, called from `0x46c30b`/`0x46c324`) and found
/// `push "GALME" ; call LoadLibraryA ; push "_fixadr" ; push <handle> ;
/// call GetProcAddress` -- a real runtime probe, gated behind a flag byte
/// (`cmp byte ds:0x4707f0,1`) the module's own later code checks before
/// ever calling through the resolved pointer (`call dword ptr
/// ds:0x47930c` at `0x429875`). `known_library` correctly answers `GALME`
/// itself is known -- `(GALME, "_oldsend", dosenv::oldsend, ...)` is a real
/// `routines()` entry, registered by an earlier task (see [`oldsend`]'s own
/// doc comment) -- but [`resolves`] answers `false` for `_fixadr`
/// specifically: nothing under `GALME` is named `_fixadr`, and `_oldsend`
/// itself always refuses when called (no messaging-engine subsystem exists
/// behind it), which is a different, narrower fact than "the library name
/// is unrecognised". Either way the module's own flag ends up `0` and the
/// indirect call at `0x429875` never fires -- this host answering honestly
/// keeps the real call site safe regardless of which of the two questions
/// (library known? symbol present?) is the one that actually says no.
///
/// # The one thing this resolver cannot yet do, even for a hit
///
/// **[`resolves`] can tell a caller whether this host implements a named
/// routine. It cannot hand back an address the module can `call far`
/// through and reach it**, and every one of the four faces above is honest
/// about that rather than fabricating one. The reason is structural, not an
/// oversight this task ran out of time for:
///
/// - A module reaches a host routine by executing a far call into
///   [`mbbs_machine::m16::Machine`]'s thunk table (`MAX_THUNKS = 512`,
///   `crates/mbbs-machine/src/m16/mod.rs:156`); the CPU trap that produces
///   `Exit::Call{index}` is driven purely by *which offset* the call
///   landed on, decoded generically, with no notion of "this index means
///   `prfmsg`" baked in anywhere near it.
/// - That meaning lives in an `ImportSite`, and indices are assigned
///   **only at module load**, densely, "in first-encounter order" straight
///   out of the loading module's own relocations
///   (`crates/mbbs-machine/src/m16/ne.rs`'s own `Thunks` doc comment) --
///   never for a symbol nobody's fixups happened to name.
/// - Minting a *new* index at runtime -- which is what handing back a
///   working address for an arbitrary, not-already-imported symbol would
///   need -- means mutating `Machine::next_thunk` and pushing a new
///   `ImportSite`, and both are private to `mbbs_machine::m16::ne`, with no
///   public method anywhere that exposes either. This crate's own
///   `crate::shims::misc` documents the identical shape of gap for the
///   opposite direction (`dfsthn`/`byenow`/`listing` needing `A::Module` to
///   call *into* a module, which no shim has either -- "`Host` never stores
///   a loaded module's own selector/section map"): a [`Call<A>`] carries
///   only `cpu`, never the loaded module, and `Host<A>` keeps its own
///   `loaded_modules` registry private with no accessor a shim can reach.
///
/// So a hit and a miss both write the documented "not found" answer for
/// *the address* today: `NULL`/`ERROR_PROC_NOT_FOUND`, never a fabricated
/// non-null pointer that would fault -- or, worse, silently misdispatch --
/// the moment a module actually called through it. That is squarely inside
/// this crate's sanctioned exception for absence-reporting routines (see
/// `crate::shims::ShimError`'s own doc comment), not a corner this task cut:
/// **[`known_library`]/[`resolves`] still make the *library* and *symbol
/// presence* questions genuinely answerable** (see their own doc comments),
/// which is real, tested, shared behaviour -- only the final "give me
/// something callable" step is blocked, and by exactly one missing public
/// primitive: a way for a shim to reach the executing module's own
/// `ImportSite` table, or a way to mint a new one at runtime. Either would
/// let [`dosgetprocaddr`]/`borland::get_proc_address`'s KERNEL32 sibling
/// progress from "always not-found" to "not-found only for a genuine miss"
/// without changing this resolver's own shape at all.
pub(crate) mod runtime_name {
    use super::Entry;
    use crate::abi::Abi;

    /// Every library [`crate::shims::routines`] serves at least one routine
    /// under, after [`super::canonical_dll`]'s own case-insensitive
    /// aliasing -- computed from the live table rather than a hand-kept
    /// list, so this can never drift out of step with what `entry` itself
    /// would answer.
    ///
    /// Deliberately does **not** also walk `WG16_ROUTINES`/`WG32_ROUTINES`
    /// (`crate::shims::mod`'s `Abi::native` doors): checked directly, every
    /// entry in both of those is already registered under `MAJORBBS` in
    /// `routines()` too (`alctile`/`ptrtile`/the Borland arithmetic helpers/
    /// `_ftol` sit beside dozens of other `MAJORBBS` routines there), so
    /// there is no library identity either table would add. Should a future
    /// task register an ABI-native-only routine under a library `routines()`
    /// never mentions, this note is the reason to revisit this function, not
    /// a silent gap.
    ///
    /// Registered in `routines()`, but not a Worldgroup-family subsystem a
    /// module resolves by name to find out whether it is *present* -- the
    /// question `DosGetModHandle`/`LoadLibraryA` actually ask. `KERNEL32.dll`
    /// carries `getversion`/`get_module_handle`/`get_proc_address`; `DOSCALLS`
    /// carries `dossetvec`; `PHAPI` carries `doscreatedsalias` -- all real
    /// entries `entry`'s own `dll == dll` match would answer `true` for, but
    /// none of them is a module asking "does this *optional* subsystem
    /// exist", the way probing for `GALME`/`GALMSG` is. Excluded here, once,
    /// so a reader of [`distinct_libraries`] does not have to wonder whether
    /// their exclusion was an oversight.
    const NOT_A_WORLDGROUP_PROBE: &[&str] = &[super::super::KERNEL32, "cw3220mt.DLL", crate::exports::DOSCALLS, crate::exports::PHAPI];

    fn distinct_libraries<A: Abi>() -> Vec<&'static str> {
        let mut seen = Vec::new();
        for (dll, _, _, _, _) in super::super::routines::<A>() {
            if !seen.contains(&dll) && !NOT_A_WORLDGROUP_PROBE.contains(&dll) {
                seen.push(dll);
            }
        }
        seen
    }

    /// Whether `name` -- a raw string a module supplied, not yet
    /// canonicalised -- names a library this host serves at least one
    /// routine under. `Some` carries the canonical name back, for a caller
    /// that wants to feed it straight to [`resolves`].
    ///
    /// `GALME` answers `Some("GALME")`: `(GALME, "_oldsend", ...)` is a real
    /// entry (see [`super::oldsend`]'s own doc comment) -- the library
    /// *name* is genuinely registered, even though calling `_oldsend` itself
    /// always refuses because the messaging-engine subsystem behind it does
    /// not exist. Whether a specific *routine* resolves is [`resolves`]'s
    /// own, separate question.
    pub(crate) fn known_library<A: Abi>(name: &str) -> Option<&'static str> {
        let canonical = super::super::canonical_dll(name);
        distinct_libraries::<A>().into_iter().find(|&d| d == canonical)
    }

    /// One opaque, host-minted handle per distinct entry in
    /// [`distinct_libraries`] -- 1-based, so `0` stays free to mean "no
    /// handle" everywhere this crate already uses it that way.
    ///
    /// Not a real address, and not meant to look like one: it is never
    /// dereferenced by anything on this host, only round-tripped back
    /// through [`library_for`] by [`super::dosgetprocaddr`]/
    /// `borland::freelibrary`. `distinct_libraries` is a pure function of
    /// the crate's own `routines()` literal, so the same name always maps
    /// to the same handle within one process, which is all a round trip
    /// needs -- it does not need to survive a restart or agree with any
    /// other host.
    pub(crate) fn handle_for<A: Abi>(name: &str) -> Option<u32> {
        let canonical = known_library::<A>(name)?;
        distinct_libraries::<A>()
            .iter()
            .position(|&d| d == canonical)
            .map(|i| i as u32 + 1)
    }

    /// The inverse of [`handle_for`]: what library a previously-minted
    /// handle names, or `None` for `0` or a value this process never handed
    /// out.
    pub(crate) fn library_for<A: Abi>(handle: u32) -> Option<&'static str> {
        let index = handle.checked_sub(1)?;
        distinct_libraries::<A>().get(index as usize).copied()
    }

    /// Whether this host implements `raw_symbol` under `dll` -- `dll`
    /// already canonical (a [`known_library`] hit), `raw_symbol` a module's
    /// raw string, run through [`crate::exports::c_name`] here so the
    /// comparison is against exactly what [`crate::shims::entry`] itself
    /// would be asked, at load time, for the identical name.
    pub(crate) fn resolves<A: Abi>(dll: &str, raw_symbol: &str) -> bool {
        let symbol = crate::exports::c_name(raw_symbol);
        matches!(crate::shims::entry::<A>(dll, &symbol), Entry::Routine(..))
    }

    /// Encode a small handle into `A::PTR_WIDTH` bytes, least-significant
    /// byte first, and decode it back. The two are each other's exact
    /// inverse for any handle this module ever mints (see [`handle_for`]'s
    /// own doc comment on why that is the only round trip that has to
    /// hold), which is what lets `borland::loadlibrarya`/`freelibrary`
    /// share one encoding without needing to agree on it separately.
    pub(crate) fn ptr_for_handle<A: Abi>(handle: u32) -> A::Ptr {
        let mut bytes = handle.to_le_bytes().to_vec();
        bytes.resize(A::PTR_WIDTH, 0);
        A::ptr_from_bytes(&bytes)
    }

    /// The inverse of [`ptr_for_handle`].
    pub(crate) fn handle_for_ptr<A: Abi>(ptr: A::Ptr) -> u32 {
        let bytes = A::ptr_to_bytes(ptr);
        let mut raw = [0u8; 4];
        let n = bytes.len().min(4);
        raw[..n].copy_from_slice(&bytes[..n]);
        u32::from_le_bytes(raw)
    }
}

/// The OS/2 DosCalls status-code family this Phar Lap API descends from.
/// `archive/galacticomm/extract/phar312/PHAPI.H:587,591` give
/// `DosGetModHandle`/`DosGetProcAddr`'s prototypes but this tree has no
/// surviving header naming their numeric failure codes. `126`/`127` are the
/// standard, widely-documented OS/2 (and later Win32) `ERROR_MOD_NOT_FOUND`/
/// `ERROR_PROC_NOT_FOUND` values this API family is known elsewhere to use --
/// unverified against anything recovered in this repository, and it does not
/// matter for `RCIROSE.DLL`'s own one real call site (`re/WCCMMUD.DLL`-style
/// NE relocation walk against `DOSCALLS #45`/`#47`, segment 33, fixups at
/// segment offsets `0x1AD8`/`0x1AEE`): both of that module's own checks are a
/// bare `or ax,ax` / `jnz` -- nonzero is "failed", and no call site this task
/// found inspects which nonzero value it got.
const ERROR_MOD_NOT_FOUND: u16 = 126;
const ERROR_PROC_NOT_FOUND: u16 = 127;

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
pub fn dossetvec<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _vecnum = call.int();
    let _pfn_routine = call.ptr();
    let ppfn_prev = call.ptr();
    ppfn_prev
        .write(call.mem(), &A::ptr_to_bytes(A::null_ptr()))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
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
pub fn doscreatedsalias<A: Abi>(
    call: &mut Call<A>,
    _host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    let _sel = call.int();
    let aselp = call.ptr();
    aselp
        .write(call.mem(), &0u16.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
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
pub fn oldsend<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msg = call.ptr();
    let to = call.ptr();
    Err(ShimError::Failed(format!(
        "_oldsend({msg}, {to}): this host has no GALME messaging-engine subsystem -- \
         no simpsnd, no message store -- to hand a converted 6.x message to, and \
         answering TRUE would tell the caller mail was sent that was in fact silently \
         discarded"
    )))
}

/// `INT simpsnd(struct message *msg, const CHAR *text, const CHAR *filatt)` --
/// `GME.H:1538`, "simple send msg (non-user specific)" -- returns standard GME
/// status codes. Body: `re/wg33src/SRC/api/galme/GMEONL.C:3918` (Worldgroup
/// 3.3). Exported as `_simpsnd @113` (`re/wg33src/LIB/GALME.DEF:116`).
///
/// The only symbol either 32-bit build imports from GALME, once each --
/// MajorMUD NT (`wccnt7pk` through `wccnt8pj`, unchanged across all thirteen
/// versions) and The Rose 3.0NT.
///
/// # This is answered, not refused, and the vendor is why
///
/// [`oldsend`] above refuses, and this does not. They are not inconsistent:
/// the difference is in what each routine's return type can express.
///
/// `_oldsend` returns `BOOL`. There is no value in `{TRUE, FALSE}` meaning
/// "the messaging engine is not running" -- a fabricated `TRUE` claims mail
/// went out, a fabricated `FALSE` blames the message. Neither is true, so it
/// refuses.
///
/// `simpsnd` returns a GME status code, and the vendor's own body opens by
/// answering precisely our case:
///
/// A host that never initialised a messaging engine has `gmeinit` false, in
/// perpetuity. `GMEERR` is therefore not a plausible zero invented to fill a
/// gap -- it is the documented answer for the exact state this host is in,
/// and the engine's absence *is* the error condition the vendor anticipated.
/// Serving it faithfully needs no GME.
///
/// # Zero would be actively harmful here
///
/// `GME.H:390-394` gives `GMEAGAIN 0`, `GMEOK 1`, `GMEERR -1`. **Zero means
/// "still processing, call again"** -- and the vendor's own shutdown path is
/// `while ((rc=gsndmsg(...)) == GMEAGAIN) {}`. A caller handed 0 by a host
/// with no engine spins forever. This is one of the few places in this crate
/// where the reflexive zero does not merely lie, it hangs the module.
///
/// # Arguments
///
/// Read and discarded rather than ignored, so a bad pointer is still a bad
/// pointer: the real routine `ASSERT`s `msg` and `text` non-NULL before it
/// reaches the `gmeinit` test.
///
/// # Errors
///
/// Never. `GMEERR` is a return value, not a refusal.
pub fn simpsnd<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _msg = call.ptr();
    let _text = call.ptr();
    let _filatt = call.ptr();
    // GMEERR, `GME.H:394`. Not GMEAGAIN (0), which would spin the caller.
    Ok(abi::Ret::Int(A::Int::from(-1i16 as u16)))
}

/// `USHORT APIENTRY DosGetModHandle(PSZ namep, PHMODULE mhandp)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:587` -- resolve a library
/// name to a handle, by name, at runtime.
///
/// See this module's own doc comment ([`runtime_name`]) for the shared
/// mechanism this delegates to and what it can and cannot yet answer.
/// `mhandp` is always written -- `0` on a miss, the same "shim never
/// touched it is a distinct, observable failure from the shim wrote the
/// documented sentinel" discipline [`dossetvec`]'s own doc comment states --
/// never left holding whatever garbage was there before.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `namep` is `PSZ` (far `char *`, 4 bytes,
/// `PHAPI.H:97`), `mhandp` is `PHMODULE` (far pointer to a `HMODULE`, 4
/// bytes, `PHAPI.H:102`) -- 4 + 4 = 8 bytes, `Cleans::Callee(8)`. Confirmed
/// against `RCIROSE.DLL`'s own one real call site (NE segment 33, fixup at
/// segment offset `0x1AD8`, `DOSCALLS #47`): `push ds ; push <namep offset>
/// ; push ss ; lea ax,[bp-2] ; push ax ; call DosGetModHandle` -- two far
/// pointers, in declaration order.
///
/// # Errors
///
/// If `mhandp` does not resolve.
pub fn dosgetmodhandle<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let namep = call.ptr();
    let mhandp = call.ptr();

    let name_bytes = namep.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?.to_vec();
    let name = String::from_utf8_lossy(&name_bytes);

    let handle = runtime_name::handle_for::<A>(&name).unwrap_or(0);
    mhandp
        .write(call.mem(), &(handle as u16).to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if handle == 0 {
        Ok(abi::Ret::Int(A::Int::from(ERROR_MOD_NOT_FOUND)))
    } else {
        Ok(abi::Ret::Int(A::Int::from(0u16)))
    }
}

/// `USHORT APIENTRY DosGetProcAddr(HMODULE mhand, PSZ pnamep, PPFN paddrp)`
/// -- `archive/galacticomm/extract/phar312/PHAPI.H:591` -- resolve a
/// routine within a library [`dosgetmodhandle`] already found a handle for,
/// by name, at runtime.
///
/// See [`runtime_name`]'s own doc comment for why `paddrp` is written
/// `NULL` -- never a fabricated non-null pointer -- whether `mhand` names a
/// library this host does not serve, or names one that does not export
/// `pnamep`, or names one that does export it but this call site cannot yet
/// mint a dispatchable address for it (today, every case: see that doc
/// comment's own accounting). All three collapse to the same wire answer a
/// real `DosGetProcAddr` gives for "not found", which is the routine's own
/// documented failure mode, not a plausible zero invented to paper over an
/// unknown.
///
/// `GALME` is the library `RCIROSE.DLL`'s own 32-bit sibling
/// (`tmp/gapsurvey/round2/rose32/RCIROSE.DLL`) actually probes for at
/// runtime via the KERNEL32 pair (`LoadLibraryA("GALME")` then
/// `GetProcAddress(handle, "_fixadr")`, disassembled for [`runtime_name`]'s
/// own doc comment). `runtime_name::known_library` correctly answers
/// `GALME` itself *is* known -- `(GALME, "_oldsend", oldsend, ...)` is a
/// real `routines()` entry -- but `_fixadr` is not `_oldsend`, so
/// [`runtime_name::resolves`] answers `false` for it regardless; either way
/// the honest wire answer this routine gives is "not found", not a gap this
/// routine papers over.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `mhand` is `HMODULE` (`USHORT`, 2 bytes,
/// `PHAPI.H:101`), `pnamep` is `PSZ` (4 bytes), `paddrp` is `PPFN` (far
/// pointer to a far pointer, 4 bytes) -- 2 + 4 + 4 = 10 bytes,
/// `Cleans::Callee(10)`. Confirmed against `RCIROSE.DLL`'s own one real call
/// site (segment 33, fixup at segment offset `0x1AEE`, `DOSCALLS #45`):
/// `push [bp-2] ; push ds ; push <pnamep offset> ; push 0x0 ; push
/// <paddrp offset> ; call DosGetProcAddr` -- five words, in declaration
/// order.
///
/// # Errors
///
/// If `paddrp` does not resolve.
pub fn dosgetprocaddr<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mhand: u32 = call.int().into();
    let pnamep = call.ptr();
    let paddrp = call.ptr();

    let proc_bytes = pnamep.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?.to_vec();
    let proc_name = String::from_utf8_lossy(&proc_bytes);

    // Always the documented sentinel -- see this function's own doc comment
    // for the three cases that collapse into it today.
    paddrp
        .write(call.mem(), &A::ptr_to_bytes(A::null_ptr()))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let Some(dll) = runtime_name::library_for::<A>(mhand) else {
        return Ok(abi::Ret::Int(A::Int::from(ERROR_MOD_NOT_FOUND)));
    };
    // Computed and not branched on: whether this host implements
    // `proc_name` under `dll` genuinely differs (`resolves` is real,
    // shared, tested behaviour -- see `runtime_name`'s own doc comment),
    // but the *address* answer is `ERROR_PROC_NOT_FOUND` either way today,
    // for the structural reason that doc comment names. Calling it anyway,
    // rather than skipping straight to the shared return, is what makes a
    // future close of that gap a one-line change here (branch on the
    // result) instead of a rediscovery of which function to call.
    let _ = runtime_name::resolves::<A>(dll, &proc_name);
    Ok(abi::Ret::Int(A::Int::from(ERROR_PROC_NOT_FOUND)))
}

/// OS/2's own `ERROR_INVALID_SELECTOR`, checked -- not merely "widely
/// documented" the way [`ERROR_MOD_NOT_FOUND`]/[`ERROR_PROC_NOT_FOUND`]
/// above were -- against a genuine copy of the standard error table this
/// repo's own tree does not carry: OpenWatcom ships the real OS/2 Toolkit
/// headers, and `/opt/watcom/h/os2/bseerr.h:571` on this box gives `490`.
/// The same header's lines 144-145 give `126`/`127` for the two constants
/// above, matching what this file already had -- independent, retroactive
/// confirmation for both, not just a new value.
///
/// What [`dosfreeseg`] and [`dosgetsegdesc`] answer for a selector that
/// names no segment of this module's.
const ERROR_INVALID_SELECTOR: u16 = 490;

/// `archive/galacticomm/extract/phar312/PHAPI.H:196` -- one of the four
/// idealised segment-type constants [`dosgetsegdesc`]'s `attrib` field
/// answers with. The two this host ever has occasion to write; see that
/// function's own doc comment for why `CODE16_NOREAD`/`DATA16_NOWRITE`
/// (`:197`/`:199`) do not appear here.
const CODE16: u16 = 1;
/// `PHAPI.H:197` -- see [`CODE16`].
const DATA16: u16 = 2;

/// `USHORT APIENTRY DosAllocSeg(USHORT size, PSEL selp, USHORT flags)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:565` -- map `size` bytes of
/// writable memory the module can address, and hand back the selector
/// naming it.
///
/// [`mbbs_machine::m16::Machine::alloc_segment`] is this call, essentially
/// as-is: length in, selector out, LDT-backed -- the same primitive
/// [`crate::globals::Globals::new`] already uses to place the module's own
/// globals. `HVSTW` and `HVSXROAD` each import it once (see
/// `crates/mbbs/tests/data/corpus/HVSTW.tsv`/`HVSXROAD.tsv`), and `HVSTW`
/// also imports [`dosfreeseg`] and [`dosgetsegdesc`], which strongly
/// suggests the shape of the real call site: allocate, describe, free.
///
/// `flags` (`GSEL_*`-style sharing bits in the real API) is read and
/// discarded: nothing in this host's segment table distinguishes a
/// "giveable" segment from an ordinary one, and every segment this call
/// makes is already private to this one module's own address space -- there
/// is no second module here `flags` could ever hand it to.
///
/// # Argument order and byte count
///
/// Far pascal (`APIENTRY`), callee cleans. `size` is `USHORT` (2 bytes,
/// `PHAPI.H:99`), `selp` is `PSEL` (far pointer, 4 bytes, `PHAPI.H:100`),
/// `flags` is `USHORT` (2 bytes) -- 2 + 4 + 2 = 8 bytes, `Cleans::Callee(8)`.
///
/// # Errors
///
/// If `size` is zero or larger than a 16-bit segment can address, if the
/// LDT has no free entry, or if `*selp` does not resolve.
pub fn dosallocseg(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let size = call.int();
    let selp = call.ptr();
    let _flags = call.int();

    let selector = call
        .cpu
        .alloc_segment(usize::from(size))
        .map_err(|e| ShimError::Failed(format!("dosallocseg({size}): {e}")))?;

    selp.write(call.mem(), &selector.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(0u16))
}

/// `USHORT APIENTRY DosFreeSeg(SEL sel)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:572` -- release a segment
/// [`dosallocseg`] handed out.
///
/// # Real reclamation, not a documented no-op
///
/// Ruled out deliberately, unlike [`dossetvec`]/[`doscreatedsalias`]'s
/// no-ops earlier in this file: `Segment` (`crates/mbbs-machine/src/m16/
/// seg.rs`) already implements `Drop` -- clearing its LDT entry and, once
/// nothing else shares the mapping, `munmap`-ing it -- so a real free is
/// not new, untested machinery, it is one `Vec::remove` away from teardown
/// this crate already had and already tests
/// (`dropping_a_tiled_region_leaves_no_live_descriptor`). A no-op here
/// would leak one LDT entry (of 8192) and one mapping for as long as the
/// host process runs, for every call this single site makes, with nothing
/// to reveal it wrong until a module that allocates in a loop finally
/// exhausted the LDT -- exactly the failure mode "the byte count that
/// corrupts the *next* call" warns about, at a longer time horizon. Real
/// reclamation costs one function
/// ([`mbbs_machine::m16::Segments::free_segment`]) and removes the
/// question entirely.
///
/// A `sel` naming nothing this module ever allocated -- already freed, or
/// never allocated at all -- answers [`ERROR_INVALID_SELECTOR`] rather than
/// silently succeeding: a module that double-frees or frees a bad selector
/// has a real bug, and papering over it with `NO_ERROR` is the same
/// fabricated-success shape this crate refuses everywhere else.
///
/// **"Never allocated at all" includes the module's own code, stack, data
/// and bridge selectors**, all of which are real, live entries in the same
/// segment table [`dosallocseg`] pushes into and every one of which a
/// module can trivially name (`MOV AX,SS` for its own stack). Those are
/// not merely refused for tidiness: freeing the running module's own stack
/// segment out from under it and then letting execution continue is a
/// host-crashing bug, not a guest one -- see
/// [`mbbs_machine::m16::Segments::free_segment`]'s own doc comment for the
/// allowlist that makes it structurally unreachable, and
/// `crates/mbbs/tests/dosfreeseg_stack_selector_guard.rs` for the
/// regression test that goes through the real dispatch loop to prove it.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `sel` is `SEL` (2 bytes) -- `Cleans::Callee(2)`.
///
/// # Errors
///
/// Never -- an invalid selector is a documented return code
/// ([`ERROR_INVALID_SELECTOR`]), not a host failure.
pub fn dosfreeseg(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let sel = call.int();
    match call.cpu.free_segment(sel) {
        Ok(()) => Ok(abi::Ret::Int(0u16)),
        Err(_) => Ok(abi::Ret::Int(ERROR_INVALID_SELECTOR)),
    }
}

/// `USHORT APIENTRY DosGetSegDesc(SEL sel, PDESC descp)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:361` -- read back the
/// idealised descriptor (`PHAPI.H:181-186`: `ULONG base; ULONG size;
/// USHORT attrib;`) a selector names.
///
/// # What this host answers, and how each field is genuinely derived
///
/// `base` and `size` are read off the same machinery every other far
/// pointer access already trusts, not invented: the mapping
/// [`dosallocseg`] makes really does start at the linear address its own
/// LDT descriptor's `base_addr` field carries
/// (`crates/mbbs-machine/src/m16/seg.rs`'s own `describe`), so resolving
/// one byte at offset 0 through [`mbbs_machine::m16::Machine::resolve`] and
/// reading the returned slice's own pointer back gives that identical
/// address -- there is no second, host-side copy of it that could drift.
/// `size` is [`mbbs_machine::m16::Segments::region_len`], reached through
/// [`mbbs_machine::m16::Machine::mem`].
///
/// `attrib` (`CODE16`/`DATA16`/..., `PHAPI.H:196-199`) answers from a
/// narrower fact this host genuinely tracks: whether `sel` is the module's
/// own scratch code selector
/// ([`mbbs_machine::m16::Machine::code_selector`]) -- [`CODE16`] if so,
/// [`DATA16`] otherwise. Every segment [`dosallocseg`] hands out is
/// non-executable by construction (`Segment::new(len, false)`), so
/// `DATA16` is exactly right for the pairing this routine's one real call
/// site almost certainly makes (describe a segment just allocated,
/// alongside `HVSTW`'s own `dosallocseg`/`dosfreeseg` imports); it is also
/// right for the stack and `DGROUP` selectors. **The one case this cannot
/// distinguish** is one of the loaded NE image's *other* code segments
/// (34, in `WCCMMUD.DLL` alone) -- this host records no per-segment
/// executable flag beyond the one scratch selector it names itself, so
/// such a selector would answer `DATA16` where the true answer is
/// `CODE16`. No corpus call site exercises that case (`dosgetsegdesc` has
/// exactly one site, `HVSTW`), so this is recorded as a known narrowing,
/// not chased further -- the honest alternative to guessing would be
/// refusing every call, which is strictly worse for the one call site this
/// host actually has to serve.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `sel` is `SEL` (2 bytes), `descp` is `PDESC`
/// (far pointer, 4 bytes) -- 2 + 4 = 6 bytes, `Cleans::Callee(6)`.
///
/// # Errors
///
/// Never -- an invalid `sel` is a documented return code
/// ([`ERROR_INVALID_SELECTOR`]) with a zeroed `*descp`, not a host failure.
/// If `*descp` itself does not resolve, that still stops the module: there
/// is nowhere to write the answer at all.
pub fn dosgetsegdesc(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let sel = call.int();
    let descp = call.ptr();
    let at = FarPtr { offset: 0, selector: sel };

    let base = match call.cpu.resolve(at, 1) {
        Ok(bytes) => bytes.as_ptr() as usize as u32,
        Err(_) => {
            descp
                .write(call.mem(), &[0u8; 10])
                .map_err(|e| ShimError::Failed(e.to_string()))?;
            return Ok(abi::Ret::Int(ERROR_INVALID_SELECTOR));
        }
    };
    let size = call.cpu.mem().region_len(at).map_err(|e| {
        ShimError::Failed(format!(
            "dosgetsegdesc: sel {sel:#06x} resolved but region_len disagreed: {e}"
        ))
    })? as u32;
    let attrib = if sel == call.cpu.code_selector() { CODE16 } else { DATA16 };

    let mut desc = Vec::with_capacity(10);
    desc.extend_from_slice(&base.to_le_bytes());
    desc.extend_from_slice(&size.to_le_bytes());
    desc.extend_from_slice(&attrib.to_le_bytes());
    descp
        .write(call.mem(), &desc)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(0u16))
}

/// `USHORT APIENTRY DosGetModName(HMODULE mhand, USHORT buffc, PCHAR buffp)`
/// -- `archive/galacticomm/extract/phar312/PHAPI.H:589` -- the inverse of
/// [`dosgetmodhandle`]: given a handle, answer the library's own name.
///
/// Reached through [`runtime_name::library_for`], the identical lookup
/// [`dosgetprocaddr`] already uses to turn a handle back into a library
/// name -- this is the first caller that hands the name itself back to the
/// module, rather than using it only to look a routine up internally.
///
/// A recognised handle writes its canonical name into `buffp`, truncated to
/// `buffc - 1` bytes if it does not fit, NUL-terminated, and answers
/// `NO_ERROR`. `buffc == 0` writes nothing -- there is no room even for a
/// terminator -- and still answers `NO_ERROR`, since the handle itself was
/// genuinely found; a real `DosGetModName` has no separate "buffer too
/// small" code in this API family to reach for instead
/// (`archive/galacticomm/extract/phar312/PHAPI.H` names none). A handle
/// this process never minted -- `0`, or anything [`runtime_name::handle_for`]
/// did not hand out -- writes nothing and answers [`ERROR_MOD_NOT_FOUND`],
/// the same sentinel [`dosgetmodhandle`] answers for the equivalent miss in
/// the other direction.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `mhand` is `HMODULE` (`USHORT`, 2 bytes,
/// `PHAPI.H:101`), `buffc` is `USHORT` (2 bytes), `buffp` is `PCHAR` (far
/// pointer, 4 bytes) -- 2 + 2 + 4 = 8 bytes, `Cleans::Callee(8)`.
///
/// # Errors
///
/// If `buffc` is nonzero and `buffp` does not resolve.
pub fn dosgetmodname<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mhand: u32 = call.int().into();
    let buffc: u32 = call.int().into();
    let buffp = call.ptr();

    let Some(dll) = runtime_name::library_for::<A>(mhand) else {
        return Ok(abi::Ret::Int(A::Int::from(ERROR_MOD_NOT_FOUND)));
    };

    if buffc > 0 {
        let room = usize::try_from(buffc).unwrap_or(0).saturating_sub(1);
        let mut bytes = dll.as_bytes()[..dll.len().min(room)].to_vec();
        bytes.push(0);
        buffp
            .write(call.mem(), &bytes)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }

    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `USHORT APIENTRY DosLoadModule(PSZ failp, USHORT failc, PSZ modnamep,
/// PHMODULE mhandp)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:594` -- load a named module
/// and hand back its handle, or explain which name failed.
///
/// # The same registry as `DosGetModHandle`, and why that is honest here
///
/// A real `DosLoadModule` differs from [`dosgetmodhandle`] by *doing*
/// something a not-yet-resident module needs before it can be found: it
/// reads the module off disk. This host has no such step for anything
/// `modnamep` could ever legitimately name -- every Worldgroup-family
/// library it can answer for is either compiled into it and answers `true`
/// through [`runtime_name::known_library`], or does not exist here at all,
/// and there is no third state ("known, but not yet loaded") for this call
/// to move a name through. So `DosLoadModule` and `DosGetModHandle` collapse
/// to the identical "is this name known" question against
/// [`runtime_name::handle_for`], which is what makes reusing that registry
/// here honest rather than a shortcut: this host is not pretending to load
/// anything, it is answering the one question it actually can.
///
/// What genuinely differs from [`dosgetmodhandle`] is what a miss writes:
/// `DosLoadModule`'s contract gives it `failp`/`failc` specifically to name
/// the module that could not be found, so a miss here writes the raw name
/// the module asked for into `*failp` (truncated to fit, the same as
/// [`dosgetmodname`]) rather than leaving it untouched.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `failp` is `PSZ` (far pointer, 4 bytes),
/// `failc` is `USHORT` (2 bytes), `modnamep` is `PSZ` (4 bytes), `mhandp` is
/// `PHMODULE` (far pointer, 4 bytes) -- 4 + 2 + 4 + 4 = 14 bytes,
/// `Cleans::Callee(14)`.
///
/// # Errors
///
/// If `modnamep` does not resolve, or `*mhandp` does not resolve.
pub fn dosloadmodule<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let failp = call.ptr();
    let failc: u32 = call.int().into();
    let modnamep = call.ptr();
    let mhandp = call.ptr();

    let name_bytes = modnamep
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    let handle = runtime_name::handle_for::<A>(&name).unwrap_or(0);
    mhandp
        .write(call.mem(), &(handle as u16).to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if handle == 0 {
        if failc > 0 {
            let room = usize::try_from(failc).unwrap_or(0).saturating_sub(1);
            let mut bytes = name.as_bytes()[..name.len().min(room)].to_vec();
            bytes.push(0);
            failp
                .write(call.mem(), &bytes)
                .map_err(|e| ShimError::Failed(e.to_string()))?;
        }
        Ok(abi::Ret::Int(A::Int::from(ERROR_MOD_NOT_FOUND)))
    } else {
        Ok(abi::Ret::Int(A::Int::from(0u16)))
    }
}

/// `USHORT APIENTRY DosAllocRealSeg(ULONG size, PUSHORT parap, PSEL selp)`
/// -- `archive/galacticomm/extract/phar312/PHAPI.H:373` -- allocate
/// conventional (real-mode-addressable, below 1 MiB) memory, and hand back
/// both a real-mode paragraph number (`parap`) and a protected-mode
/// selector (`selp`) aliasing the same physical bytes.
///
/// # Argued refusal: this host has no real-mode address space to alias
///
/// Every segment this host can make -- [`dosallocseg`]'s
/// [`mbbs_machine::m16::Machine::alloc_segment`] among them -- is an
/// anonymous `mmap(MAP_32BIT)` mapping (`crates/mbbs-machine/src/m16/
/// seg.rs`'s own `Mapping::new`): real, addressable memory below 4 GiB, but
/// with no promise of sitting below 1 MiB, and more fundamentally with no
/// real-mode CPU on this host that could ever address it by paragraph
/// number in the first place. `crates/dos` is where that CPU lives -- a KVM
/// real-mode guest, built for exactly this (`crates/dos/src/lib.rs`'s own
/// module doc: "a KVM real-mode runtime that serves DOS doors, and the MBBS
/// host, whose 16-bit modules trap into DOS from protected mode") -- and
/// `crates/mbbs/Cargo.toml` depends on exactly `btrieve`, `libc`,
/// `mbbs-machine`. **No dependency on `crates/dos` exists, and this task
/// does not add one or build a bridge to it.** One call site, in one module
/// (`MBMGEMP`), is not the case that justifies wiring two crates together
/// architecturally and unilaterally.
///
/// A fabricated `parap`/`selp` pair would be actively worse than refusing:
/// `parap` is a real-mode segment paragraph a module may hand to `int 21h`
/// or some other DOS service expecting to read conventional memory through
/// it, and a value this host invented would name nothing there, or worse,
/// something else entirely.
///
/// **What would unblock this**: `crates/mbbs` gaining a dependency on
/// `crates/dos` and a bridge letting a shim allocate (or share) memory in
/// the KVM guest's own low address space, then hand back a paragraph
/// number that guest genuinely honours. Real, cross-crate work, deliberately
/// out of scope here.
///
/// # Argument order and byte count
///
/// Far pascal, callee cleans. `size` is `ULONG` (4 bytes), `parap` is
/// `PUSHORT` (far pointer, 4 bytes), `selp` is `PSEL` (far pointer, 4
/// bytes) -- 4 + 4 + 4 = 12 bytes, `Cleans::Callee(12)`.
///
/// # Errors
///
/// Always. See above.
pub fn dosallocrealseg<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = call.long();
    let _parap = call.ptr();
    let _selp = call.ptr();
    Err(ShimError::Failed(format!(
        "dosallocrealseg({size}): this host has no real-mode address space to alias -- \
         crates/mbbs does not depend on crates/dos, where the one CPU that could ever \
         honour a real-mode paragraph number lives, and one call site in one module does \
         not justify wiring the two crates together unilaterally"
    )))
}

/// `USHORT _far _cdecl DosRealIntr(USHORT int_no, PREGS regsp, REALPTR
/// reserved, SHORT word_count, ...)` --
/// `archive/galacticomm/extract/phar312/PHAPI.H:410` -- raise a real-mode
/// interrupt with a caller-supplied register set, and copy the results
/// back.
///
/// # Argued refusal, for the same structural reason as `DosAllocRealSeg`
///
/// This needs an actual real-mode CPU execution context to raise the
/// interrupt against -- there is no "emulate one instruction's worth of
/// real-mode effect" shortcut for an arbitrary `int_no`, since the whole
/// point of the call is that the module does not know what the interrupt
/// handler does. That CPU is `crates/dos`'s KVM guest, and
/// [`dosallocrealseg`]'s own doc comment already gives the full accounting
/// of why this crate does not reach it: no dependency, no bridge, one call
/// site, deliberately out of scope. See that doc comment for what would
/// unblock this too -- the same missing primitive serves both.
///
/// # Why `Cleans::Caller`, unlike every sibling in this file
///
/// Every other `DOSCALLS`/`PHAPI` routine here is `APIENTRY` (far pascal,
/// callee-cleaned). `DosRealIntr` is declared `_far _cdecl` in the vendor's
/// own header, not `APIENTRY` -- the one routine in this whole family that
/// is not, because it is genuinely variadic (`word_count` extra words
/// follow the four named arguments) and a callee cannot pop a caller-chosen
/// number of bytes it was never told before the call. So this reads only
/// its four fixed, named arguments and refuses without ever touching the
/// variadic tail -- correctly: under `Cleans::Caller` the module cleans its
/// own stack after the call returns regardless of how many of those words
/// this shim read, the same as every `cdecl` routine on this host, so there
/// is nothing to get wrong by not consuming them.
///
/// Since this always refuses, [`Host::run`]'s dispatch loop never reaches
/// [`crate::abi::Abi::resume`] for this call at all (`ShimError` stops the
/// module before any `Cleans` value is applied) -- so this fact is
/// documentation of the real ABI, not a value load-bearing for stack
/// correctness on this host today. It is still the honest one to write
/// down: a future implementation that *did* answer would need to get this
/// right from the start, and a table that already says `Caller` here saves
/// that task from re-deriving it.
///
/// # Argument order and byte count
///
/// `int_no` is `USHORT` (2 bytes), `regsp` is `PREGS` (far pointer, 4
/// bytes), `reserved` is `REALPTR` (`ULONG`, 4 bytes -- not a far pointer;
/// `PHAPI.H:172`, `typedef unsigned long REALPTR`), `word_count` is `SHORT`
/// (2 bytes) -- the four fixed arguments read here. `Cleans::Caller`, per
/// above.
///
/// # Errors
///
/// Always. See above.
pub fn dosrealintr<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let int_no: u32 = call.int().into();
    let _regsp = call.ptr();
    let _reserved = call.long();
    let word_count: u32 = call.int().into();
    Err(ShimError::Failed(format!(
        "dosrealintr(int_no={int_no:#04x}, word_count={word_count}): this host has no \
         real-mode CPU to raise the interrupt against -- crates/mbbs does not depend on \
         crates/dos, where the one guest that could ever honour this call lives; see \
         dosallocrealseg's own doc comment for the full accounting"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    // `Fixture` is `Host<Wg16>`-only (see its own doc comment), so these
    // tests are `Wg16`-concrete by construction and name `FarPtr` for the
    // same reason `testing.rs` itself does. The shims above are generic;
    // only the fixture that drives them is not.
    use mbbs_machine::m16::{FarPtr, Ret};

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

    // -- runtime_name: the pure lookup, tested directly -----------------

    #[test]
    fn known_library_recognises_every_worldgroup_family_dll_this_host_serves_at_least_one_routine_under() {
        use crate::abi::Wg16;
        for dll in ["MAJORBBS", "GALGSBL", "GALMSG", "GALME"] {
            assert_eq!(
                runtime_name::known_library::<Wg16>(dll),
                Some(dll),
                "{dll} has routine-table entries and must be known"
            );
        }
        assert_eq!(
            runtime_name::known_library::<Wg16>("NOSUCHLIBRARY"),
            None,
            "a name nothing registers must not be known"
        );
        assert_eq!(
            runtime_name::known_library::<Wg16>("KERNEL32.dll"),
            None,
            "the DOS extender/compiler runtime is not a Worldgroup-family probe -- \
             see NOT_A_WORLDGROUP_PROBE"
        );
    }

    /// `GALME` is a subtler case than "known or not": `(GALME, "_oldsend",
    /// ...)` is a real `routines()` entry (see [`super::oldsend`]'s own doc
    /// comment), so the *library* resolves -- but `_oldsend` always refuses
    /// when called, because the messaging-engine subsystem behind it does
    /// not exist, and no `_fixadr` entry exists under `GALME` at all. This
    /// is exactly the real call site `RCIROSE.DLL`'s own 32-bit sibling
    /// makes (see [`runtime_name`]'s own module doc comment).
    #[test]
    fn galme_the_library_resolves_but_neither_of_its_two_probed_routines_does() {
        use crate::abi::Wg16;
        assert_eq!(runtime_name::known_library::<Wg16>("GALME"), Some("GALME"));
        assert!(
            !runtime_name::resolves::<Wg16>("GALME", "_fixadr"),
            "nothing under GALME is named _fixadr"
        );
        assert!(
            // `__OLDSEND` (two leading underscores) is GALME's own NE name
            // table spelling for ordinal 30 (see this file's own module doc
            // comment, "Which _oldsend, settled") -- the raw string a real
            // caller supplies, which `c_name` strips to the registered key
            // "_oldsend" (one underscore). Passing the already-canonical
            // "_oldsend" here would get double-stripped to "oldsend" and
            // wrongly answer false -- this is the input `resolves`'s own
            // doc comment documents it expects.
            runtime_name::resolves::<Wg16>("GALME", "__OLDSEND"),
            "__OLDSEND IS registered (as oldsend::<A>) -- it refuses when actually \
             called, which is a different question from whether it resolves"
        );
    }

    #[test]
    fn known_library_canonicalises_a_pe_style_spelling() {
        // The mutation Task 16 names explicitly: skip `canonical_dll` here
        // and this fails, because `routines()` registers the bare
        // "GALGSBL", never "GALGSBL.dll".
        use crate::abi::Wg16;
        assert_eq!(runtime_name::known_library::<Wg16>("GALGSBL.dll"), Some("GALGSBL"));
        assert_eq!(runtime_name::known_library::<Wg16>("galgsbl.DLL"), Some("GALGSBL"));
    }

    #[test]
    fn handle_and_library_round_trip_for_every_known_library() {
        use crate::abi::Wg16;
        for dll in ["MAJORBBS", "GALGSBL", "GALMSG", "GALME"] {
            let handle = runtime_name::handle_for::<Wg16>(dll).expect("a known library mints a handle");
            assert_ne!(handle, 0, "0 stays free for \"no handle\"");
            assert_eq!(runtime_name::library_for::<Wg16>(handle), Some(dll));
        }
        assert_eq!(runtime_name::handle_for::<Wg16>("nonexistent"), None);
        assert_eq!(runtime_name::library_for::<Wg16>(0), None);
        assert_eq!(runtime_name::library_for::<Wg16>(0xffff), None, "never handed out");
    }

    #[test]
    fn resolves_agrees_with_entry_for_a_real_routine_and_a_real_miss() {
        use crate::abi::Wg16;
        assert!(
            runtime_name::resolves::<Wg16>("MAJORBBS", "prfmsg"),
            "prfmsg is implemented -- shims::mlt::prfmsg"
        );
        assert!(
            runtime_name::resolves::<Wg16>("MAJORBBS", "_prfmsg"),
            "c_name strips exactly one leading underscore, so the decorated \
             spelling a module's own relocation table carries must resolve too"
        );
        assert!(
            !runtime_name::resolves::<Wg16>("MAJORBBS", "no_such_routine"),
            "a name nothing registers must not resolve"
        );
    }

    // -- dosgetmodhandle / dosgetprocaddr: the shim bodies ----------------

    #[test]
    fn dosgetmodhandle_resolves_a_known_library_and_writes_a_nonzero_handle() {
        let mut f = Fixture::new();
        let name = f.text("MAJORBBS");
        let mhandp = f.words(&[0xdead]);
        let args = [name.offset, name.selector, mhandp.offset, mhandp.selector];

        let ret = f
            .invoke(dosgetmodhandle, &args)
            .expect("dosgetmodhandle never refuses");

        assert_eq!(ret, Ret::U16(0), "NO_ERROR for a library this host serves");
        let bytes = f.machine.resolve(mhandp, 2).expect("mhandp resolves");
        assert_ne!(
            u16::from_le_bytes([bytes[0], bytes[1]]),
            0xdead,
            "the shim must have written its own answer, not left the seed untouched"
        );
        assert_ne!(u16::from_le_bytes([bytes[0], bytes[1]]), 0, "a real, nonzero handle");
    }

    #[test]
    fn dosgetmodhandle_resolves_the_pe_spelling_through_canonical_dll() {
        let mut f = Fixture::new();
        let name = f.text("GALGSBL.dll");
        let mhandp = f.words(&[0]);
        let args = [name.offset, name.selector, mhandp.offset, mhandp.selector];

        let ret = f
            .invoke(dosgetmodhandle, &args)
            .expect("dosgetmodhandle never refuses");
        assert_eq!(
            ret,
            Ret::U16(0),
            "GALGSBL.dll must canonicalise to GALGSBL, which this host serves"
        );
    }

    #[test]
    fn dosgetmodhandle_answers_error_mod_not_found_for_a_library_this_host_does_not_serve() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCHLIBRARY");
        let mhandp = f.words(&[0xbeef]);
        let args = [name.offset, name.selector, mhandp.offset, mhandp.selector];

        let ret = f
            .invoke(dosgetmodhandle, &args)
            .expect("dosgetmodhandle never refuses");
        assert_eq!(
            ret,
            Ret::U16(ERROR_MOD_NOT_FOUND),
            "nothing in routines() is registered under this name"
        );
        assert_eq!(
            f.machine.resolve(mhandp, 2).expect("mhandp resolves"),
            &0u16.to_le_bytes()[..],
            "the documented zero sentinel, not the 0xbeef it was seeded with"
        );
    }

    #[test]
    fn dosgetprocaddr_answers_error_mod_not_found_for_a_handle_never_minted() {
        let mut f = Fixture::new();
        let name = f.text("prfmsg");
        let paddrp = f.words(&[0xdead, 0xbeef]);
        let args = [0u16, name.offset, name.selector, paddrp.offset, paddrp.selector];

        let ret = f
            .invoke(dosgetprocaddr, &args)
            .expect("dosgetprocaddr never refuses");
        assert_eq!(
            ret,
            Ret::U16(ERROR_MOD_NOT_FOUND),
            "handle 0 was never minted by dosgetmodhandle"
        );
        assert_eq!(
            f.machine.resolve(paddrp, 4).expect("paddrp resolves"),
            &FarPtr::NULL.to_bytes()[..],
            "NULL, not the 0xdead/0xbeef it was seeded with"
        );
    }

    /// The documented gap this file's own `runtime_name` module doc comment
    /// names: `prfmsg` genuinely is implemented, and [`runtime_name::resolves`]
    /// agrees (see the test above), but this call site still cannot mint a
    /// dispatchable address for it -- so the wire answer for a real hit is,
    /// today, indistinguishable from a genuine miss. Written down as a test
    /// rather than left to be rediscovered: closing that gap should make
    /// this assertion fail, on purpose, pointing straight at the doc comment
    /// that explains what changed.
    #[test]
    fn dosgetprocaddr_answers_error_proc_not_found_even_for_a_genuinely_implemented_routine() {
        let mut f = Fixture::new();
        let libname = f.text("MAJORBBS");
        let mhandp = f.words(&[0]);
        f.invoke(
            dosgetmodhandle,
            &[libname.offset, libname.selector, mhandp.offset, mhandp.selector],
        )
        .expect("dosgetmodhandle never refuses");
        let handle_bytes = f.machine.resolve(mhandp, 2).expect("mhandp resolves");
        let handle = u16::from_le_bytes([handle_bytes[0], handle_bytes[1]]);
        assert_ne!(handle, 0, "MAJORBBS must have minted a real handle");

        let proc = f.text("prfmsg");
        let paddrp = f.words(&[0xdead, 0xbeef]);
        let args = [handle, proc.offset, proc.selector, paddrp.offset, paddrp.selector];

        let ret = f
            .invoke(dosgetprocaddr, &args)
            .expect("dosgetprocaddr never refuses");
        assert_eq!(ret, Ret::U16(ERROR_PROC_NOT_FOUND));
        assert_eq!(
            f.machine.resolve(paddrp, 4).expect("paddrp resolves"),
            &FarPtr::NULL.to_bytes()[..],
            "NULL -- never a fabricated non-null pointer -- see this function's own doc comment"
        );
    }

    // -- dosallocseg / dosfreeseg / dosgetsegdesc: real LDT segments --------

    #[test]
    fn dosallocseg_maps_real_writable_memory_and_returns_its_selector() {
        let mut f = Fixture::new();
        let selp = f.words(&[0xdead]);
        let args = [64u16, selp.offset, selp.selector, 0u16];

        let ret = f
            .invoke(dosallocseg, &args)
            .expect("dosallocseg never refuses for a valid size");
        assert_eq!(ret, Ret::U16(0), "NO_ERROR");

        let bytes = f.machine.resolve(selp, 2).expect("selp resolves");
        let selector = u16::from_le_bytes([bytes[0], bytes[1]]);
        assert_ne!(selector, 0xdead, "the shim must have written its own selector");
        assert_ne!(selector, 0, "a real selector, not a null one");

        // Prove it is genuinely writable memory, not merely a
        // plausible-looking number: write through it and read the write back.
        let at = FarPtr { offset: 0, selector };
        f.machine
            .write(at, &[0xaa; 4])
            .expect("a freshly allocated segment must be writable");
        assert_eq!(f.machine.resolve(at, 4).expect("resolves"), &[0xaa; 4]);
    }

    #[test]
    fn dosallocseg_refuses_a_zero_byte_segment() {
        let mut f = Fixture::new();
        let selp = f.words(&[0]);
        let args = [0u16, selp.offset, selp.selector, 0u16];
        f.invoke(dosallocseg, &args)
            .expect_err("a zero-byte segment is nothing to allocate");
    }

    /// The key claim of "real reclamation, not a documented no-op": a
    /// no-op `dosfreeseg` would still resolve here, because it would never
    /// have removed the segment from `Segments` in the first place. This is
    /// the one assertion that distinguishes the two -- mutating the shim
    /// back into `Ok(0)` without calling `free_segment` makes this `resolve`
    /// keep succeeding, and only this assertion catches it.
    #[test]
    fn dosfreeseg_releases_a_real_selector_so_a_later_access_genuinely_fails() {
        let mut f = Fixture::new();
        let selp = f.words(&[0]);
        f.invoke(dosallocseg, &[32u16, selp.offset, selp.selector, 0u16])
            .expect("alloc");
        let bytes = f.machine.resolve(selp, 2).expect("selp resolves");
        let selector = u16::from_le_bytes([bytes[0], bytes[1]]);

        let ret = f
            .invoke(dosfreeseg, &[selector])
            .expect("dosfreeseg never refuses for a real selector");
        assert_eq!(ret, Ret::U16(0), "NO_ERROR");

        let at = FarPtr { offset: 0, selector };
        assert!(
            f.machine.resolve(at, 1).is_err(),
            "the segment must genuinely be gone -- a no-op would still resolve here"
        );
    }

    #[test]
    fn dosfreeseg_answers_error_invalid_selector_for_a_double_free() {
        let mut f = Fixture::new();
        let selp = f.words(&[0]);
        f.invoke(dosallocseg, &[16u16, selp.offset, selp.selector, 0u16])
            .expect("alloc");
        let bytes = f.machine.resolve(selp, 2).expect("selp resolves");
        let selector = u16::from_le_bytes([bytes[0], bytes[1]]);
        f.invoke(dosfreeseg, &[selector]).expect("the first free succeeds");

        let ret = f
            .invoke(dosfreeseg, &[selector])
            .expect("dosfreeseg never refuses, even for a bad selector");
        assert_eq!(
            ret,
            Ret::U16(ERROR_INVALID_SELECTOR),
            "freeing an already-freed selector is exactly the invalid case"
        );
    }

    #[test]
    fn dosgetsegdesc_answers_the_true_base_size_and_data_attrib_for_an_allocated_segment() {
        let mut f = Fixture::new();
        let selp = f.words(&[0]);
        f.invoke(dosallocseg, &[100u16, selp.offset, selp.selector, 0u16])
            .expect("alloc");
        let bytes = f.machine.resolve(selp, 2).expect("selp resolves");
        let selector = u16::from_le_bytes([bytes[0], bytes[1]]);

        let at = FarPtr { offset: 0, selector };
        let expected_base = f.machine.resolve(at, 1).expect("resolves").as_ptr() as usize as u32;

        let descp = f.words(&[0xdead, 0xbeef, 0xdead, 0xbeef, 0xdead]);
        let ret = f
            .invoke(dosgetsegdesc, &[selector, descp.offset, descp.selector])
            .expect("dosgetsegdesc never refuses for a real selector");
        assert_eq!(ret, Ret::U16(0));

        let desc = f.machine.resolve(descp, 10).expect("descp resolves");
        let base = u32::from_le_bytes(desc[0..4].try_into().expect("4 bytes"));
        let size = u32::from_le_bytes(desc[4..8].try_into().expect("4 bytes"));
        let attrib = u16::from_le_bytes(desc[8..10].try_into().expect("2 bytes"));

        assert_eq!(base, expected_base, "base must be the segment's true linear address");
        assert_eq!(size, 100, "size must be exactly what dosallocseg was asked for");
        assert_eq!(attrib, DATA16, "every segment dosallocseg hands out is non-executable");
    }

    #[test]
    fn dosgetsegdesc_answers_code16_for_the_scratch_code_selector() {
        let mut f = Fixture::new();
        let code_sel = f.machine.code_selector();
        let descp = f.words(&[0, 0, 0, 0, 0]);

        f.invoke(dosgetsegdesc, &[code_sel, descp.offset, descp.selector])
            .expect("the scratch code segment is a real selector");

        let desc = f.machine.resolve(descp, 10).expect("resolves");
        let attrib = u16::from_le_bytes(desc[8..10].try_into().expect("2 bytes"));
        assert_eq!(attrib, CODE16, "the one selector this host knows is executable");
    }

    #[test]
    fn dosgetsegdesc_answers_error_invalid_selector_and_zeroes_the_descriptor() {
        let mut f = Fixture::new();
        let selp = f.words(&[0]);
        f.invoke(dosallocseg, &[16u16, selp.offset, selp.selector, 0u16])
            .expect("alloc");
        let bytes = f.machine.resolve(selp, 2).expect("selp resolves");
        let selector = u16::from_le_bytes([bytes[0], bytes[1]]);
        f.invoke(dosfreeseg, &[selector]).expect("free, so the selector is now invalid");

        let descp = f.words(&[0xdead, 0xbeef, 0xdead, 0xbeef, 0xdead]);
        let ret = f
            .invoke(dosgetsegdesc, &[selector, descp.offset, descp.selector])
            .expect("dosgetsegdesc never refuses, even for a bad selector");
        assert_eq!(ret, Ret::U16(ERROR_INVALID_SELECTOR));
        assert_eq!(
            f.machine.resolve(descp, 10).expect("descp resolves"),
            &[0u8; 10][..],
            "zeroed, not the 0xdead/0xbeef it was seeded with"
        );
    }

    // -- dosgetmodname / dosloadmodule: the same registry, two angles ------

    #[test]
    fn dosgetmodname_round_trips_the_name_dosgetmodhandle_minted_a_handle_for() {
        let mut f = Fixture::new();
        let name = f.text("MAJORBBS");
        let mhandp = f.words(&[0]);
        f.invoke(
            dosgetmodhandle,
            &[name.offset, name.selector, mhandp.offset, mhandp.selector],
        )
        .expect("dosgetmodhandle never refuses");
        let bytes = f.machine.resolve(mhandp, 2).expect("mhandp resolves");
        let handle = u16::from_le_bytes([bytes[0], bytes[1]]);
        assert_ne!(handle, 0);

        let buffp = f.buffer(16);
        let ret = f
            .invoke(dosgetmodname, &[handle, 16u16, buffp.offset, buffp.selector])
            .expect("dosgetmodname never refuses for a real handle");
        assert_eq!(ret, Ret::U16(0));
        assert_eq!(f.read(buffp), "MAJORBBS");
    }

    #[test]
    fn dosgetmodname_truncates_to_fit_a_small_buffer_and_still_terminates() {
        let mut f = Fixture::new();
        let name = f.text("MAJORBBS");
        let mhandp = f.words(&[0]);
        f.invoke(
            dosgetmodhandle,
            &[name.offset, name.selector, mhandp.offset, mhandp.selector],
        )
        .expect("mint a handle");
        let bytes = f.machine.resolve(mhandp, 2).expect("resolves");
        let handle = u16::from_le_bytes([bytes[0], bytes[1]]);

        let buffp = f.buffer(4); // room for 3 characters plus the terminator
        f.invoke(dosgetmodname, &[handle, 4u16, buffp.offset, buffp.selector])
            .expect("never refuses");
        assert_eq!(f.read(buffp), "MAJ", "truncated to buffc - 1 characters, still NUL-terminated");
    }

    #[test]
    fn dosgetmodname_answers_error_mod_not_found_and_touches_nothing_for_an_unminted_handle() {
        let mut f = Fixture::new();
        let buffp = f.words(&[0x4141]);
        let ret = f
            .invoke(dosgetmodname, &[0u16, 2u16, buffp.offset, buffp.selector])
            .expect("dosgetmodname never refuses");
        assert_eq!(ret, Ret::U16(ERROR_MOD_NOT_FOUND));
        assert_eq!(
            f.machine.resolve(buffp, 2).expect("resolves"),
            &0x4141u16.to_le_bytes()[..],
            "a miss must not touch the buffer at all"
        );
    }

    #[test]
    fn dosloadmodule_finds_a_known_library_and_mints_the_same_handle_dosgetmodhandle_would() {
        let mut f = Fixture::new();
        let name = f.text("MAJORBBS");
        let mhandp = f.words(&[0]);
        f.invoke(
            dosgetmodhandle,
            &[name.offset, name.selector, mhandp.offset, mhandp.selector],
        )
        .expect("mint via DosGetModHandle");
        let expected = u16::from_le_bytes(
            f.machine.resolve(mhandp, 2).expect("resolves").try_into().expect("2 bytes"),
        );

        let failp = f.buffer(16);
        let name2 = f.text("MAJORBBS");
        let mhandp2 = f.words(&[0]);
        let ret = f
            .invoke(
                dosloadmodule,
                &[
                    failp.offset,
                    failp.selector,
                    16u16,
                    name2.offset,
                    name2.selector,
                    mhandp2.offset,
                    mhandp2.selector,
                ],
            )
            .expect("dosloadmodule never refuses for a known name");
        assert_eq!(ret, Ret::U16(0));
        let got = u16::from_le_bytes(
            f.machine.resolve(mhandp2, 2).expect("resolves").try_into().expect("2 bytes"),
        );
        assert_eq!(got, expected, "the same registry, so the same handle");
    }

    #[test]
    fn dosloadmodule_writes_the_failing_name_into_failp_for_an_unknown_library() {
        let mut f = Fixture::new();
        let failp = f.buffer(32);
        let name = f.text("NOSUCHLIBRARY");
        let mhandp = f.words(&[0xbeef]);
        let ret = f
            .invoke(
                dosloadmodule,
                &[failp.offset, failp.selector, 32u16, name.offset, name.selector, mhandp.offset, mhandp.selector],
            )
            .expect("dosloadmodule never refuses");
        assert_eq!(ret, Ret::U16(ERROR_MOD_NOT_FOUND));
        assert_eq!(
            f.read(failp),
            "NOSUCHLIBRARY",
            "the diagnostic name must be the one that actually failed"
        );
        assert_eq!(
            f.machine.resolve(mhandp, 2).expect("resolves"),
            &0u16.to_le_bytes()[..],
            "the documented zero sentinel"
        );
    }

    // -- dosallocrealseg / dosrealintr: argued refusals ---------------------

    #[test]
    fn dosallocrealseg_never_answers_ok_and_names_the_missing_bridge() {
        let mut f = Fixture::new();
        let parap = f.words(&[0]);
        let selp = f.words(&[0]);
        let args = [16u16, 0u16, parap.offset, parap.selector, selp.offset, selp.selector];

        let err = f
            .invoke(dosallocrealseg, &args)
            .expect_err("no real-mode address space exists to alias");
        let text = err.to_string();
        assert!(
            text.contains("crates/dos"),
            "the refusal should name what is actually missing, not just fail silently: {text}"
        );
    }

    #[test]
    fn dosrealintr_never_answers_ok_and_names_the_missing_bridge() {
        let mut f = Fixture::new();
        let regsp = f.words(&[0; 13]);
        // int_no, regsp(offset,selector), reserved(lo,hi), word_count
        let args = [0u16, regsp.offset, regsp.selector, 0u16, 0u16, 4u16];

        let err = f
            .invoke(dosrealintr, &args)
            .expect_err("no real-mode CPU exists to raise the interrupt against");
        let text = err.to_string();
        assert!(
            text.contains("crates/dos"),
            "the refusal should name what is actually missing, not just fail silently: {text}"
        );
    }
}
