//! The GSBL routines `WCCMMUD.DLL` actually imports.
//!
//! ```text
//! btutsw 21   btuxct 16   btuxnf 14   btuxmt  8   btuoes  3   btuclo  3
//! btulok  2   btucli  2   btuinj  2   btutrg  2   btuech  1   btumil  1
//! btuibw  1   btuica  1
//! ```
//!
//! Fourteen routines and seventy-seven call sites, and **not one of them in
//! segment 21**, where initialisation lives -- which is the mechanical reason
//! `_INIT__WCCMMUD` could run to completion without any of this existing.
//!
//! Every one is thin. The state is [`crate::gsbl`]; these read arguments,
//! bound-check the channel and delegate. The return codes are the guide's:
//! `-10` channel not defined, `-11` out of range, `0` all is well. **`-10` is
//! unreachable here** -- `Host::new` allocates every channel and there is no
//! `btudef` -- so out of range is the only refusal.
//!
//! `bturno`, the fifteenth import, is not here: it is a datum, placed in
//! `globals.rs`, and the module reads it directly at 1,096 fixups.
//!
//! Three more live here without being an import at all: `btuhpk`, `btupbc`
//! and `btucpc`, `WCCMMUD.DLL` never asks for -- `re/exports/imports.txt` has
//! no site for any of them (Task 1 of `docs/plans/2026-08-11-live-session-defects.md`
//! is the inventory). They exist because `MAJORBBS.C:3776`'s `rstrxf`
//! (`crate::shims::screen`) needs their behaviour, and every other GALGSBL
//! routine lives here rather than wherever its one caller happens to be.
//! `rstrxf` does not call through this table -- there is no module far call
//! to dispatch and no stack to read arguments off -- it calls each `apply_*`
//! function directly with values it already has.
//!
//! # Task 3: the character-interrupt family (`btuche`, `btuchi`, `btuclc`,
//! `btucls`, `btutru`, `chiout`)
//!
//! `WCCMMUD.DLL` imports none of these; RTSLORD imports all six and The Rose
//! imports `btuchi`. Ordinals from the vendor's own `re/wg33src/LIB/
//! GALGSBL.DEF` (`btuche@3`, `btuchi@4`, `btuclc@5`, `btucls@8`, `btutru@52`,
//! `chiout@64`), declarations from `archive/galacticomm/extract/wg1/
//! GALDSRC/SRC/BRKTHU.H` (the **wg1** tree; wg20 shares the filenames at
//! different line numbers) and semantics from `.scratch/gsbl_guide.txt`, a
//! full-text extraction of the *Worldgroup 1.0 GSBL Development Guide*
//! (`archive/tooling/reference-documents/`) -- no `GALGSBL.C` survives
//! anywhere in this archive (only compiled `.LIB`s and `.DLL`s; checked), so
//! the guide is the only oracle for these six the way it is not for
//! `btuxnf`/`btupbc`/`btucpc`, which had `re/wg33src` callers to cross-check
//! against instead.
//!
//! **This task's file scope started as `crates/mbbs/src/shims/gsbl.rs`
//! only** and was extended mid-task, by the coordinator, to include
//! `crates/mbbs/src/gsbl.rs` (where [`crate::gsbl::Channel`] lives) once it
//! became clear that `btutru` was refusing for a boundary drawn one file
//! too narrow, not a real capability gap. Both files are in scope below.
//!
//! **Five implement for real.** [`btucls`] clears
//! [`crate::gsbl::Channel::status`], the FIFO this host already uses for
//! every status it raises -- exactly the "status-input buffer" the guide
//! describes, simplified for a host with no modem to sense but not
//! reinvented. [`btuclc`] answers the channel-bound check and nothing else,
//! because `btucmd` (the command channel it would abort) is not implemented
//! anywhere in this crate -- and, unlike everything else refused or
//! recorded-inert below, this is not contingent on a gap this host might
//! close later: there is no modem to command on a socket-based host, ever,
//! so "a command was in progress" is a structural invariant, not today's
//! implementation status. [`chiout`] writes into
//! [`crate::gsbl::Channel::output`], the same place ordinary echoed input
//! already lands, because this host has no echo buffer distinct from the
//! data output buffer either. [`btutru`] stores its abort character in
//! [`crate::gsbl::Channel::trunch`], and [`btuche`] stores its notify flag
//! in [`crate::gsbl::Channel::chi_notify_on_idle`] -- both **recorded, not
//! acted on**, the same established shape `xon`/`xoff`/`pause_char`/
//! `clear_pause_char`/`pause_handler_installed` already use for a setting
//! whose consuming mechanism this host does not (yet, or ever) drive. See
//! each field's own doc comment for why storing them honestly, rather than
//! refusing or discarding, is the right call for these two specifically.
//!
//! **One refuses.** [`btuchi`] installs a module callback -- `char far
//! (*rouadr)(int chan, int c)` -- invoked on every character a channel
//! receives, replacing the input pipeline's translate-table stage. This
//! host has a real, working precedent for recording a callback pointer now
//! and invoking it later from somewhere with `A::Module` access
//! ([`crate::shims::task::initask`]/`Host::prctask`), but that precedent's
//! shape needs a place to attach to -- a periodic sweep, the way
//! `Host::cycle` sweeps `host.tasks` once a cycle -- and character arrival
//! has no such sweep today; it runs straight from the transport layer into
//! `Channel::take`. Building one is input-path work this task does not do.
//! See `btuchi`'s own doc comment for the precise wall and for why, even
//! setting that aside, this callback's all-or-nothing substitution of a
//! mandatory pipeline stage makes "record and silently do nothing" a worse
//! failure here than it is for `btuche`'s merely-additive flag.
//!
//! # Generic core, converted together with `shims::screen`
//!
//! All seventeen routines here (the fourteen real imports plus `btuhpk`/
//! `btupbc`/`btucpc`) are generic now, and so is [`crate::shims::screen::rstrxf`]
//! -- a genuine cycle, one commit: `rstrxf` calls `apply_xnf`/`apply_hpk`/
//! `apply_pbc`/`apply_cpc` directly (never through the dispatch table -- see
//! this module's own doc comment), and those four already took no `Machine`
//! at all (they mutate a [`Gsbl`] handed to them), so nothing about *them*
//! needed to move. What did: [`on_channel`] gained an `A: Abi` parameter so
//! its `host: &mut Host<A>` matches every converted routine that calls it,
//! and every routine that used to read `machine.read_cstr`/`resolve`/`write`
//! now reads through [`Call::mem`] instead.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;
use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::chan::Chan;
use crate::gsbl::Gsbl;

/// `-11`: "channel number is out of range". See the module docs for why `-10`
/// cannot happen.
pub(crate) const OUT_OF_RANGE: u16 = -11i16 as u16;

/// Run `body` against a channel, or answer `-11`.
///
/// Every one of the fourteen begins this way, so it is written once. The
/// alternative -- fourteen copies of the same bound check -- is fourteen places
/// for one of them to be missing.
///
/// `body` is handed the [`Chan`] this minted rather than being left to find the
/// channel again from the raw number. Every one of these used to do that, and
/// every one of them ended `.expect("in range")` -- fourteen assertions that the
/// check two lines above had happened, which is what having the check and the
/// use in different types buys you.
fn on_channel<A: Abi, T>(
    host: &mut Host<A>,
    chan: i16,
    body: impl FnOnce(&mut crate::gsbl::Gsbl, Chan) -> T,
) -> Option<T> {
    let chan = host.gsbl().terms().chan(chan)?;
    Some(body(host.gsbl_mut(), chan))
}

// # `call.int()` width audit
//
// `A::Int` is `u16` under `Wg16` and `u32` under `Wg32` -- four bytes, not
// two, the moment this file's routines answer a 32-bit module. See
// `docs/2026-08-14-gsbl-width-audit.md` for the full site-by-site audit this
// backs; the three helpers below are its two surviving buckets, made
// callable instead of restated at each of the nine value-narrowing sites the
// audit found (the eighteen `chan` narrowings to `i16` are the host's own
// [`Chan`] domain and are not part of this audit -- `on_channel`, above,
// already bound-checks every one of those against `nterms` regardless of
// what a bogus wide value would have reinterpreted to, which is why `Chan`
// itself does not need a checked reader here).
//
// The third bucket, "genuinely wide", has no helper: [`btuxct`] and
// [`btuica`] read their byte counts with a bare `Into::<u32>::into(call.int())
// as usize` at the point of use, because there is nothing to check against --
// see each function's own doc comment.

/// Read the next argument and require it to fit in a `u16`, refusing rather
/// than truncating.
///
/// For the sites in this file that store their argument into a `u16`
/// [`crate::gsbl::Channel`] field -- `btutsw`'s `width`, `btumil`'s
/// `maxinl`, `btutrg`'s `nbyt` and `btuxnf`'s `cnt` -- and whose real 32-bit
/// callers never come close to needing the other two bytes `Wg32`'s `int`
/// carries: `width` comes from `usaptr->scnwid` (`re/wg33src/SRC/apps/
/// galfil/GALFILUT.C:2755`), `maxinl` from small fixed buffer sizes like
/// `DFTIMX`/`ALSSIZ-1`/`UIDSIZ-1` (`galalias/GALALIAS.C`), and `nbyt` from
/// `OUTSIZ`-derived block sizes (`icsrc/galtnt/TELNET.C:386`). Nothing in
/// the guide or the SDK source ever asks for a screen width, an input-line
/// cap or a binary-mode trigger past 65535, and the `Channel` fields these
/// feed did not grow when `Wg32` did -- `since_trigger` in particular is
/// `u16` too, so a `trigger` this could not represent would silently stop
/// ever firing rather than merely reading back wrong. Refusing what does
/// not fit costs a legitimate caller nothing.
///
/// `None` on overflow. Every call site here folds that into the same `-11`
/// [`OUT_OF_RANGE`] a bad channel number already answers -- the guide draws
/// no distinction between "channel not valid" and "argument not valid", so
/// this host does not invent one.
fn u16_arg<A: Abi>(v: A::Int) -> Option<u16> {
    u16::try_from(Into::<u32>::into(v)).ok()
}

/// Read the next argument and require it to fit in a `u8`, refusing rather
/// than truncating.
///
/// `btupbc`'s `pausch`, `btucpc`'s `cpchar` and `btuxnf`'s `xon` are all
/// declared `INT` in `BRKTHU.H`, but every one feeds a `u8`
/// [`crate::gsbl::Channel`] field (`pause_char`, `clear_pause_char`, `xon`)
/// and every real 32-bit call site passes a literal single-character value:
/// `pausch`/`cpchar` are `CHAR` in the guide's own prose (Control-T and
/// Control-S, the guide's own examples), and `xon` is `0` at every call site
/// `re/wg33src` has (`galirc/IRCFNC.C:610`, `galftpd/FTPD.C:358`, and every
/// other `btuxnf` caller) -- a real flow-control byte is never sent because
/// flow control is meaningless once GSBL is behind a socket rather than a
/// modem, which is also why `Channel::xon`/`xoff` are recorded but never
/// acted on. `int` in the prototype is calling-convention noise, the same
/// reason C's own `putchar(int c)` takes `int` for a byte; the domain is a
/// byte either way.
///
/// `None` on overflow, folded into `-11` [`OUT_OF_RANGE`] the same way
/// [`u16_arg`]'s is.
fn u8_arg<A: Abi>(v: A::Int) -> Option<u8> {
    u8::try_from(Into::<u32>::into(v)).ok()
}

/// Read the next argument and require it to fit in an `i16`, refusing rather
/// than reinterpreting.
///
/// `btuinj`'s `status` is the one signed site: [`crate::gsbl::Channel`]
/// queues it in a `VecDeque<i16>`, and the guide's whole status vocabulary
/// -- `CRSTG`, `INBLK`, `OUTMT`, `OVRFLW`, `POLSTS`, `CYCLE` -- is a small,
/// closed, host-defined set (`Gsbl`'s own associated constants; the widest,
/// `POLSTS`, is `192`). This is deliberately **not** the reinterpreting
/// `i16_arg` `crate::shims::btrieve` uses for `keynum`/`mode`/`loktyp`:
/// those are Btrieve wire fields the module itself defines and a caller is
/// free to hand back whatever bit pattern it likes, so truncating and
/// reinterpreting is the correct generic reading. A status code is
/// different -- it is *this host's* vocabulary being injected back into the
/// module, and a value too wide to be any real status wrapping into one by
/// coincidence (a `btuinj` computed from a 32-bit expression landing on `4`,
/// `INBLK`, by pure accident of which sixteen bits survived) is a wrong
/// status silently delivered rather than a byte position with no meaning of
/// its own. Refuse it instead.
///
/// "Fits" means round-trips, not merely "is non-negative": `BRKTHU.H`'s own
/// status vocabulary is entirely 0..=253 today, but this checks the general
/// property rather than that narrower fact, the same way [`u16_arg`] and
/// [`u8_arg`] do.
///
/// The two ABIs do not agree on how a genuine `i16` arrives in `A::Int`, so
/// the round-trip check below only makes sense on one of them.
/// `Into::<u32>::into` **zero-extends**: it has no notion of the source
/// type's signedness, only its width. Under `Wg32` (`A::Int = u32`) that is
/// irrelevant -- a real `-1` was already sign-extended to `0xFFFF_FFFF` by
/// the module's own 32-bit `int` before this ever saw it, so `wide` already
/// carries the sign and re-widening the narrowed candidate is a real check
/// against real extra bits. Under `Wg16` (`A::Int = u16`) there is no such
/// extension: every 16 bits of `A::Int` already *are* the whole `i16`, sign
/// included, and `wide`'s top 16 bits are always zero regardless of what
/// the low 16 bits mean. Running the same round-trip there compares a
/// sign-extended candidate (`i32::from(narrow) as u32`, which is
/// `0xFFFF_FFFF` for a negative `narrow`) against a zero-extended `wide`
/// (`0x0000_FFFF`) and always disagrees for the entire negative half --
/// this file's own first shipped version of this function had exactly that
/// bug, rejecting a genuine `Wg16` status of `-1`. `A::INT_WIDTH <= 2`
/// therefore skips the check rather than performing a broken one: every
/// bit pattern `A::Int` can hold is already exactly an `i16`'s worth of
/// bits, so a plain reinterpret is not merely adequate but the only
/// question that has an answer at that width. `Wg32`, `A::INT_WIDTH == 4`,
/// keeps the round-trip: there the check is answering a real question
/// (did the extra 16 bits carry information a genuine `i16` could not have
/// produced) and accepts every value a genuine `i16` -- positive or
/// negative -- would sign-extend into.
fn i16_arg<A: Abi>(v: A::Int) -> Option<i16> {
    let wide: u32 = v.into();
    if A::INT_WIDTH <= 2 {
        // Every bit pattern `A::Int` can hold already IS an `i16`'s worth
        // of bits -- see this function's own doc comment for why the
        // round-trip check below would be wrong here, not merely
        // redundant.
        return Some(wide as i16);
    }
    let narrow = wide as i16;
    if (i32::from(narrow) as u32) == wide { Some(narrow) } else { None }
}

/// Read the next argument as a sign-and-magnitude byte, refusing rather than
/// truncating either half.
///
/// [`btuxnf`]'s `xoff` is the one site this shape describes. The guide
/// (page 193) overloads its sign as the page-mode flag and its magnitude as
/// the flow-control character -- `Channel::xoff` is a `u8` -- so a checked
/// reader here has to protect two different things a plain `i16_arg` alone
/// would not: that the value round-trips through `A::Int`'s width at all
/// (same check `i16_arg` makes), and that what is left after the sign is
/// removed still fits the byte it is ultimately stored in. Every real
/// 32-bit call site (`re/wg33src/SRC/.../MAJORBBS.C:4490` among them) passes
/// `0`, `19` or `-19`, so this is the tenth member of this audit's
/// "genuinely narrow" bucket, not a new bucket -- see
/// `docs/2026-08-14-gsbl-width-audit.md` for why it was filed separately
/// from the other nine when it was found, and this reader for why it no
/// longer needs to be.
fn signed_byte_arg<A: Abi>(v: A::Int) -> Option<i16> {
    let xoff = i16_arg::<A>(v)?;
    u8::try_from(xoff.unsigned_abs()).ok()?;
    Some(xoff)
}

/// Read the next argument at its full width, refusing nothing.
///
/// The "genuinely wide" bucket's one reader: [`btuxct`]'s `nbyt` and
/// [`btuica`]'s `max` are never stored in a `Channel` field narrower than
/// `usize`, so unlike [`u16_arg`]/[`u8_arg`]/[`i16_arg`] there is nothing to
/// check the value against -- carrying it is strictly better than refusing
/// it, and refusing it would turn a legitimate large binary transfer into a
/// spurious `-11`. `u32 -> usize` is lossless on every platform this host
/// targets (`usize` is 64 bits there); the widen is the whole of what makes
/// this different from the `as u16` it replaces.
fn usize_arg<A: Abi>(v: A::Int) -> usize {
    Into::<u32>::into(v) as usize
}

/// `int btutsw(int chan, int width)` -- output word-wrap width. Zero disables.
///
/// `width` is read with [`u16_arg`] -- genuinely 16-bit in this host's own
/// model, not merely narrow by convention: see that function's doc comment.
pub fn btutsw<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(width) = u16_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).width = width;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btumil(int chan, int maxinl)` -- maximum input line length. Zero
/// disables the limit.
///
/// `maxinl` is read with [`u16_arg`] -- see that function's doc comment for
/// why this is genuinely 16-bit rather than merely narrow by convention.
pub fn btumil<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(maxinl) = u16_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).maxinl = maxinl;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuech(int chan, int onoff)` -- echo input back to the terminal.
pub fn btuech<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let onoff = Into::<u32>::into(call.int());
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).echo = onoff != 0;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btulok(int chan, int onoff)` -- input lockout: arriving bytes are
/// discarded while locked.
pub fn btulok<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let onoff = Into::<u32>::into(call.int());
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).locked = onoff != 0;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuoes(int chan, int onoff)` -- raise status 5 when the output buffer
/// empties.
pub fn btuoes<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let onoff = Into::<u32>::into(call.int());
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).oes = onoff != 0;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btutrg(int chan, int nbyt)` -- byte-count input trigger. Zero is ASCII
/// mode; non-zero switches to binary mode and sets the block size.
///
/// `nbyt` is read with [`u16_arg`], not carried wide: unlike [`btuxct`]'s
/// and [`btuica`]'s byte counts, this one is stored in
/// [`crate::gsbl::Channel::trigger`], a `u16`, and compared against
/// `since_trigger`, also `u16` -- both this host's own design, made before
/// this audit and out of this file's scope to widen. A `trigger` too big to
/// fit either would not merely read back wrong, it would never fire at all.
/// See [`u16_arg`]'s own doc comment for why real callers never ask for one
/// past 65535 in the first place.
pub fn btutrg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(nbyt) = u16_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).trigger = nbyt;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuxnf(int chan, int xon, int xoff, ...)` -- the XON and XOFF
/// characters, and (R5, guide `btuxnf` page 193) page mode. A **negative**
/// `xoff` selects page mode and adds two more arguments: `cnt`, the number of
/// lines to show before pausing, and `stg`, the pause message -- which is why
/// the module cleans 3 words at six call sites (plain flow control) and 6 at
/// eight others (page mode). Those two are only read when `xoff` says to
/// expect them, never a blind read of the variadic tail.
///
/// Page mode itself is **not implemented** -- see `Channel::page_lines`.
/// `cnt` and the pause message are recorded so they are not lost, and
/// pagination is a driver problem (Batch C of this plan), not a GSBL one.
///
/// `xon` is read with [`u8_arg`] -- genuinely narrow, a single
/// flow-control byte; see that function's doc comment, which also covers why
/// real callers only ever pass `0`. `cnt` is read with [`u16_arg`] for the
/// same reason as [`btutrg`]'s `nbyt`: [`crate::gsbl::Channel::page_lines`]
/// is a `u16`.
///
/// `xoff` is read with [`signed_byte_arg`] -- the tenth "genuinely narrow"
/// site this audit's width pass found (`docs/2026-08-14-gsbl-width-audit.md`
/// has the full history: found after the plan's own table was already
/// written, fixed in a later pass rather than the same one that found it).
/// Its sign survives the read -- it is what selects page mode below -- and
/// its magnitude is checked against the byte [`crate::gsbl::Channel::xoff`]
/// actually is, the same guarantee [`u8_arg`] gives `xon`.
///
/// **A second, independent bug lived here past the width check**:
/// `apply_xnf` used to store `xoff as u8` -- a bit-truncating reinterpret,
/// not a width bug (`i16` and `u8` disagree about `-19`'s *bits*, not about
/// which module produced them, so this part was already ABI-invariant) but
/// a *domain* bug. The guide's own page-193 example calls the negative form
/// "xoff = -19, CTRL+S pauses, page mode is selected" -- the same CTRL+S
/// (`19`) the positive form uses, not `-19`'s two's-complement byte `0xED`.
/// `xoff`'s sign is a mode flag glued onto the character argument, not part
/// of the character. Fixed alongside the width check rather than filed as a
/// second finding, since both live in the same three lines and the correct
/// fix touches both: see [`apply_xnf`].
pub fn btuxnf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(xon) = u8_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let Some(xoff) = signed_byte_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    // The two page-mode arguments are read only when xoff says to expect
    // them -- see this function's own doc comment. The cursor reads them in
    // frame order regardless of which branch runs, same as `arg_u16(3)`/
    // `arg_far(4)` did: the reads that happen, happen sequentially.
    let page = if xoff < 0 {
        let Some(cnt) = u16_arg::<A>(call.int()) else {
            return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
        };
        let stg = call.ptr();
        let text = stg
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        Some((cnt, text))
    } else {
        None
    };
    Ok(match on_channel(host, chan, |g, chan| apply_xnf(g, chan, xon, xoff, page)) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// The mutation [`btuxnf`] performs, apart from reading the module's stack --
/// so that [`crate::shims::screen::rstrxf`] (`MAJORBBS.C:3778`) can drive the
/// same channel-state update with values it already has in hand, rather than
/// a second copy of these four lines that could drift from the first.
///
/// `xoff`'s sign selects page mode in [`btuxnf`] (the caller already
/// resolved that into `page`); by the time it reaches here the sign has one
/// job left, which is deciding whether to negate before storing. `-19` and
/// `19` are the guide's own page-193 example of the *same* flow-control
/// character, so `c.xoff` stores the magnitude, `xoff.unsigned_abs()`, not
/// `xoff`'s two's-complement bits. Trusts its caller for range the way
/// `c.xon = xon` already does: [`btuxnf`] checked it with
/// [`signed_byte_arg`] before calling this, and `rstrxf`'s own call passes
/// the literal `-19` -- magnitude `19`, trivially in range. The
/// `debug_assert` says so instead of leaving it to be discovered by whoever
/// adds the next caller.
pub(crate) fn apply_xnf(
    g: &mut Gsbl,
    chan: Chan,
    xon: u8,
    xoff: i16,
    page: Option<(u16, Vec<u8>)>,
) {
    let c = g.channel_mut(chan);
    c.xon = xon;
    debug_assert!(
        xoff.unsigned_abs() <= u16::from(u8::MAX),
        "apply_xnf's caller must validate xoff's magnitude fits a byte \
         before calling -- see this function's own doc comment"
    );
    c.xoff = xoff.unsigned_abs() as u8;
    if let Some((cnt, message)) = page {
        c.page_lines = cnt;
        c.page_message = Some(message);
    }
}

/// `int btuhpk(int chan, int far (*hpkrou)(int chan, char c))` -- install the
/// routine called for each keystroke received while a channel is in
/// screen-pause mode (guide `btuhpk`, page 99).
///
/// **Not registered as a `WCCMMUD.DLL` import** -- see the module doc comment
/// on `crate::shims::gsbl` and the inventory in `crate::shims::screen` --
/// this exists so [`crate::shims::screen::rstrxf`] (the one caller this host
/// has) has a real GSBL routine to call, the same way every other GALGSBL
/// entry in the registration table does, and so it is independently testable
/// through the same `Fixture::invoke` every other one of these fourteen is.
///
/// The second argument -- the far pointer to the handler -- is deliberately
/// never read: see [`crate::gsbl::Channel::pause_handler_installed`] for why
/// a `bool` is the whole of what this host records.
pub fn btuhpk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, apply_hpk) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// The mutation [`btuhpk`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_hpk(g: &mut Gsbl, chan: Chan) {
    g.channel_mut(chan).pause_handler_installed = true;
}

/// `int btupbc(int chan, char pausch)` -- set the screen-pause character
/// (guide `btupbc`, page 133): transmitting it puts the channel into
/// screen-pause mode. Zero disables it. The Major BBS uses Control-T (20).
///
/// Not a `WCCMMUD.DLL` import today -- see [`btuhpk`]'s doc comment, which
/// applies here unchanged.
///
/// `pausch` is read with [`u8_arg`]: genuinely narrow, per the plan this
/// audit implements -- a single character, `CHAR` in the guide's own
/// prototype even though `BRKTHU.H` widens it to `INT`. See that function's
/// doc comment.
pub fn btupbc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(pausch) = u8_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| apply_pbc(g, chan, pausch)) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// The mutation [`btupbc`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_pbc(g: &mut Gsbl, chan: Chan, pausch: u8) {
    g.channel_mut(chan).pause_char = pausch;
}

/// `int btucpc(int chan, char cpchar)` -- set the clear-pause-counter
/// character (guide `btucpc`, page 81): discovered in the output stream, it
/// resets the pending-lines counter to zero without being transmitted. The
/// Major BBS uses Control-S (19) to suppress a pause at strategic points.
///
/// Not a `WCCMMUD.DLL` import today -- see [`btuhpk`]'s doc comment, which
/// applies here unchanged.
///
/// `cpchar` is read with [`u8_arg`], for the same reason as [`btupbc`]'s
/// `pausch`.
pub fn btucpc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(cpchar) = u8_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| apply_cpc(g, chan, cpchar)) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// The mutation [`btucpc`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_cpc(g: &mut Gsbl, chan: Chan, cpchar: u8) {
    g.channel_mut(chan).clear_pause_char = cpchar;
}

/// `int btuclo(int chan)` -- throw away output that has not gone out yet.
pub fn btuclo<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        let c = g.channel_mut(chan);
        c.output.clear();
        c.column = 0;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btucli(int chan)` -- throw away input that has not been taken yet.
///
/// **Leaves the status FIFO alone.** The guide's CAUTIONS for `btucli`: calling
/// it "can cause inconsistencies between the status buffer contents and the
/// input buffer contents" -- a CR-terminated string's status can remain queued
/// with no string behind it. That inconsistency is documented behaviour, not a
/// bug to fix; a "helpful" implementation that also drained `status` would
/// diverge from every real board.
pub fn btucli<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        let c = g.channel_mut(chan);
        c.input.clear();
        c.line.clear();
        c.ready.clear();
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuinj(int chan, int status)` -- inject a status code into the FIFO.
///
/// `status` is read with [`i16_arg`], the checked reader -- not the
/// reinterpreting one `crate::shims::btrieve` uses for its own signed
/// fields. See that function's doc comment for why.
pub fn btuinj<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(status) = i16_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| {
        g.inject(chan, status);
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btusts(int chan)` -- the next status code from the channel's status
/// buffer (guide `btusts`, page 154).
///
/// The buffer is a FIFO and this is its only consumer verb; `0` means nothing to report (guide page 155), which is why an empty queue
/// answers `0` rather than [`OUT_OF_RANGE`]. The named codes are
/// `BRKTHU.H:30-52` (`RING`, `CMDOK`, `CRSTG`, `INBLK`, `OUTMT`, ...); this
/// host raises the subset [`crate::gsbl::Gsbl`] declares.
///
/// **This host's own poll loop is also a caller.** `Host::poll`
/// (`crate::Host::poll`, `lib.rs:3401`) pops the same FIFO to decide which
/// module entry point to dispatch to, so a module that calls `btusts`
/// directly takes statuses the host would otherwise have routed. That is the
/// original's behaviour, not a defect introduced here: `MAJORBBS.C`'s main
/// loop is itself a `btusts` caller, and a module polling underneath it
/// competes there in exactly the same way. Do not "fix" this by giving the
/// module a private queue -- there is one status buffer per channel in the
/// guide, and inventing a second would make `chiinj`/`btuinj` ambiguous
/// about which one they inject into.
pub fn btusts<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |g, chan| g.next_status(chan).unwrap_or(0)) {
        Some(status) => abi::Ret::Int(A::Int::from(status as u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int bturst(int chan)` -- reset a channel to its initial default
/// conditions (guide `bturst`, page 138).
///
/// [`crate::gsbl::Gsbl::reset`] is the whole operation and predates this
/// shim; the guide's hardware and software alike reduces to software
/// alone on a socket, where there is no hardware half to reset.
///
/// **Returns `0`, not `1`.** The guide's four success codes name hardware
/// categories -- Xecom, Hayes/UART, X.25, LAN -- and the caller acts on which
/// one it gets. `MAJORBBS.C:4177`'s `case 1` follows up with `btubbr`,
/// `btuhwh` and `btuusp`, none of which this host serves, so answering 1
/// would invite three calls it must refuse. `case 0` falls through to the
/// common tail and asks for nothing further. See this task's ruling in the
/// plan for the full switch.
pub fn bturst<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |g, chan| g.reset(chan)) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `void chiinj(int chan,int s)` -- inject a status code (guide `btuchi`
/// ADVANCED USAGE, pages 47-49).
///
/// [`btuinj`] with no return value. The guide restricts `chiinj` to being
/// called from a `btuchi` character interceptor or a `bturti` real-time
/// handler (page 49); this host installs neither, so today the restriction
/// cannot be violated and nothing is gained by enforcing it. [`chiout`] --
/// registered under the same restriction since Track A -- set that
/// precedent, and the reason holds here: the restriction is the vendor's
/// advice about interrupt-level reentrancy on a 1994 PC, not a property of
/// the operation.
pub fn chiinj<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(status) = i16_arg::<A>(call.int()) else {
        host.note(format!("chiinj: channel {chan}: status argument does not fit an int16"));
        return Ok(abi::Ret::Void);
    };
    if on_channel(host, chan, |g, chan| g.inject(chan, status)).is_none() {
        host.note(format!("chiinj: channel {chan} is out of range; status dropped"));
    }
    Ok(abi::Ret::Void)
}

/// `int btuibw(int chan)` -- input bytes waiting.
///
/// Everything not yet handed to the module: raw binary-mode bytes, the line
/// still being typed, and every completed line nobody has taken yet (R3: more
/// than one can queue up). The guide's use case is peeking at keystrokes without consuming them, which is only answerable if a half-typed line
/// counts.
///
/// Finding 11 (not fixed): this undercounts a queued line by one relative to
/// real GSBL, which keeps the CR in its buffer; this host stores lines
/// without their terminator. Only matters if the module compares the count
/// against a length it computed itself -- it does not.
pub fn btuibw<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let c = host.gsbl().channel(chan);
    let waiting: usize =
        c.input.len() + c.line.len() + c.ready.iter().map(Vec::len).sum::<usize>();
    Ok(abi::Ret::Int(A::Int::from(waiting as u16)))
}

/// `int btuxmt(int chan, char *datstg)` -- transmit an ASCIIZ string.
///
/// This is MajorMUD's whole output path. It has no `outprf`: it formats with
/// `prf` into `prfbuf` and calls `btuxmt(chan, prfbuf)` itself, through
/// `_TELL_USER` at 677 sites.
pub fn btuxmt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let at = call.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit(chan, &text);
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int btuxmn(int chan, char *datstg)` -- transmit an ASCIIZ string the
/// module's own [`btuclo`] cannot cancel.
///
/// # Prototype and arity
///
/// `re/wg33src/INC/BRKTHU.H:202`: `INT btuxmn(INT chan,CHAR *datstg);` --
/// the same two parameters as [`btuxmt`], and confirmed independently at a
/// real call site rather than trusted from the header alone. `LUNATIX.DLL`
/// imports `_btuxmn` from `GALGSBL.dll` (`objdump -p`, IAT slot at RVA
/// `0x3638c`) and calls it seven times through the thunk at VA `0x41d9be`;
/// every site is the same shape, e.g. VA `0x402fa8`:
///
/// ```text
/// 8b 15 48 63 43 00    mov  edx,ds:0x436348
/// ff 32                push dword ptr [edx]   ; datstg, pushed first (cdecl: right-to-left)
/// 8b 0d 74 63 43 00    mov  ecx,ds:0x436374
/// ff 31                push dword ptr [ecx]   ; chan, pushed last -- the near parameter
/// e8 01 aa 01 00        call 0x41d9be
/// 83 c4 08              add  esp,0x8          ; two 4-byte args, caller cleans -- cdecl
/// ```
///
/// Two arguments, caller-cleaned, matching the header and matching every
/// other `GALGSBL` entry in this file (all `Cleans::Caller`).
///
/// # What the guide says, and what this host actually does
///
/// GSBL guide page 187: `btuxmn` is the same as `btuxmt`, except
/// the block it writes is one `btuclo()` cannot discard -- real GSBL marks
/// it with a trailing `\x01` rather than `btuxmt`'s `\x00`, and `btuclo`
/// only throws away blocks of the latter kind. The guide's example use is a
/// message the user cannot skip or abort.
///
/// **Finding, not a guess: this host does not reproduce the non-clearable
/// half.** [`crate::gsbl::Channel::output`] is one flat `Vec<u8>` with no
/// block boundaries -- [`btuclo`] clears it unconditionally, with no way to
/// ask "except what `btuxmn` wrote". Giving `btuxmn` that protection for
/// real needs a field on `Channel`, which lives in `crate::gsbl`
/// (`src/gsbl.rs`), outside this file's ownership for this task. Until that
/// lands, `btuxmn` transmits exactly like `btuxmt` and a `btuclo` right
/// after it *will* discard the "unskippable" message --
/// `btuxmn_is_not_actually_protected_from_btuclo_on_this_host` asserts the
/// current behaviour explicitly, so this is a stated gap rather than a
/// silent one.
///
/// The primary behaviour -- transmitting the string, word-wrapped exactly as
/// `btuxmt` -- is not in doubt, which is why this is implemented rather than
/// left pinned: the module calls it seven times and the guide is explicit
/// about everything but the one property this host cannot yet keep.
pub fn btuxmn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let at = call.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit(chan, &text);
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int btuxct(int chan, int nbyt, const char *datstg)` -- transmit `nbyt`
/// bytes.
///
/// Binary: the length is given rather than scanned for, so an embedded NUL is
/// data. None of the ASCII output features apply -- the guide is explicit that
/// word wrap and XON/XOFF "are not in effect when you use btuxct()".
///
/// **Genuinely wide.** `nbyt` is never stored in a [`crate::gsbl::Channel`]
/// field -- it only sizes the one `resolve` call below, which already takes
/// a `usize` -- so there is nothing here for a narrower type to buy, and a
/// 32-bit module transmitting more than 65535 bytes in one call is not an
/// edge case a binary transmit routine gets to refuse. Read with
/// [`usize_arg`] rather than through `u16`: this is the exact shape of the
/// `cw3220mt` `fgets(buf, 40000, f)` bug -- a length argument narrowed on
/// the way to a `resolve`/read call -- this audit exists to catch, except
/// here the number was never going to be negative, only silently smaller
/// than the module asked for.
pub fn btuxct<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let nbyt = usize_arg::<A>(call.int());
    let at = call.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let data = at
        .resolve(call.mem(), nbyt)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit_raw(chan, &data);
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int btuica(int chan, char *rdbptr, int max)` -- take up to `max` bytes of
/// count-triggered input, and return how many were taken.
///
/// R12: resolve the destination *before* draining the channel. Draining
/// first and writing second means a bad pointer's `?` propagates only after
/// the bytes are already gone from `input` -- a write that never happened,
/// having destroyed the data it was supposed to deliver. `machine.resolve`
/// with the exact length `machine.write` will use validates the same bounds
/// without mutating anything, so if it succeeds, the write after the drain
/// cannot fail.
///
/// **Genuinely wide**, the same as [`btuxct`]'s `nbyt`: `max` is never
/// stored in a `Channel` field, only `min`-ed against `c.input.len()`
/// (already `usize`), so read it through the full width. The return value
/// -- how many bytes were actually taken -- carries the same width for the
/// same reason: narrowing `take` back to `u16` after widening `max` would
/// only move this call's own truncation from the argument to the result,
/// which is the exact failure mode the design that scoped this audit warns
/// against for a narrow `Channel` field, applied here to a narrow return
/// instead. [`Abi::int_from_u32`] is what makes that possible without
/// assuming `take` fits `u16`: `A::Int: From<u16>` alone cannot express a
/// `take` past 65535.
pub fn btuica<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let at = call.ptr();
    let max = usize_arg::<A>(call.int());
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let c = host.gsbl().channel(chan);
    let take = max.min(c.input.len());

    at.resolve(call.mem(), take)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let c = host.gsbl_mut().channel_mut(chan);
    let bytes: Vec<u8> = c.input.drain(..take).collect();
    at.write(call.mem(), &bytes)
        .expect("resolve above already validated this exact pointer and length");
    Ok(abi::Ret::Int(A::int_from_u32(take as u32)))
}

/// `int btuclc(int chan)` -- abort any command in progress and clear the
/// command output buffer (guide `btuclc`, page 50): cancels any command in progress (`btucmd()`, page 54) and empties the channel's command buffer.
///
/// This host has no command channel at all. `btucmd` -- Xecom/Hayes/UART
/// modem-command control, guide page 54 -- is not implemented anywhere in
/// this crate (checked: no `btucmd` shim, no command-buffer field on
/// [`crate::gsbl::Channel`]), and nothing else writes to a "command buffer"
/// distinct from [`btuclo`]'s ordinary data output buffer. So "a command
/// was in progress" is never true on this host -- there is no code path
/// that could have started one -- and "clears the command buffer" is
/// satisfied because the buffer it would clear does not exist. This
/// follows from `btucmd`'s absence, checked directly, not from a guess
/// standing in for unconfirmed vendor behaviour.
pub fn btuclc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |_, _| ()) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btucls(int chan)` -- clear the status input buffer (guide `btucls`,
/// page 53): the status-input buffer that modem-condition sensing depends on, provided for completeness alone -- the guide warns against calling it casually, since it
/// can discard something like a queued "lost carrier".
///
/// This host has no modem to sense, but [`crate::gsbl::Channel::status`] --
/// the FIFO [`btuinj`] pushes onto and the (unimplemented, not imported by
/// any surveyed build) `btusts` would drain -- is exactly the buffer the
/// guide describes, simplified rather than reinvented: every status this
/// host ever raises (`CRSTG`, `INBLK`, `OUTMT`, `Gsbl::CYCLE`, ...) already
/// goes through this one queue. Clearing it here is the genuine operation,
/// not a stand-in for one this host cannot perform -- unlike [`btuclc`],
/// which has nothing real to touch.
pub fn btucls<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).status.clear();
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuche(int chan, int onoff)` -- enable calling the [`btuchi`]
/// interceptor an extra time, with pseudo-key-code `-1`, whenever the
/// channel's echo buffer goes idle (guide `btuche`, page 42): it switches a callback on or off: whenever the channel's echo buffer drains, the `btuchi()` routine is called with the channel number and a pseudo key code of -1.
///
/// **Not the same routine as the already-implemented [`btuech`]**, despite
/// the near-identical name and identical two-`int` signature -- `btuech`
/// (guide page 84, `Channel::echo`) is the ordinary input-echo toggle;
/// `btuche` is this narrower thing, documented by the guide as existing
/// "mainly to support certain advanced real-time protocols" and a routine
/// its own CAUTIONS say not to use until `btuchi` is fully understood.
///
/// # Revised: records rather than refuses
///
/// An earlier version of this routine refused, reasoning that its only
/// effect is notifying an *already-installed* [`btuchi`] interceptor, and
/// `btuchi` can never install a live one on this host. That premise is
/// still true -- see `btuchi`'s own doc comment -- but the conclusion was
/// wrong: [`crate::gsbl::Channel::pause_handler_installed`] already
/// establishes the precedent for exactly this shape ("record the caller's
/// intent for a mechanism this host does not yet drive"), and `btuche`'s
/// flag is additive in the same way -- unlike `btuchi`'s callback, which
/// *replaces* a mandatory pipeline stage for every future character (see
/// `btuchi`'s own doc comment for why that difference matters), `btuche`'s
/// only effect is whether one *extra*, otherwise-nonexistent notification
/// fires. Nothing else about this channel's behaviour depends on it either
/// way, so recording it and answering `0` is not a fabrication -- it is
/// the same honest bookkeeping `pause_handler_installed` already performs,
/// stored in [`crate::gsbl::Channel::chi_notify_on_idle`]. **What would
/// reveal this is wrong**, the same test `pause_handler_installed`'s doc
/// comment names for its own field: the day a future host closes the
/// `btuchi` gap, an interceptor that never gets its `c == -1` notification
/// despite `btuche(chan, 1)` having succeeded would be the bug this
/// recording exists to prevent.
pub fn btuche<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let onoff = Into::<u32>::into(call.int());
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).chi_notify_on_idle = onoff != 0;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `int btuchi(int chan, char far (*rouadr)(int chan, int c))` -- install an
/// input character interceptor (guide `btuchi`, page 44): every byte
/// received from the channel, in ASCII input mode, is handed to `rouadr`
/// instead of the ordinary translate table, and `rouadr`'s return value
/// becomes the character that continues down the rest of the input
/// pipeline (backspace handling, line assembly, echo, ...). A `NULL`
/// `rouadr` de-installs it.
///
/// # The wall, stated precisely -- not "no shim can ever invoke a callback"
///
/// A shim genuinely cannot call *synchronously* into a module: `Call` holds
/// only `cpu`, so a routine dispatched through the shim table has no
/// `A::Module` to run against, ever. But this host already routes around
/// that for a different callback, and the precise version of the wall has
/// to say why the same route does not reach here.
///
/// [`crate::shims::task::initask`] does not refuse: it appends the far
/// pointer it is handed to `host.tasks` and returns success, and
/// [`Host::prctask`] (`lib.rs`) later calls `self.run(machine, module,
/// task, ...)` for every one of them -- it can, because `Host::cycle`,
/// which calls `prctask`, is invoked by the driver thread
/// (`crates/mbbs-server/src/host.rs`) with both `machine` and `module`
/// already in scope; the shim only ever had to remember the pointer, not
/// invoke it. That is a real, working precedent for "record now, call back
/// later from somewhere that has `A::Module`" -- not a wall this host
/// cannot route around in general.
///
/// What `btuchi` is missing is not that precedent's *shape*, it is a place
/// for that shape to attach to: `prctask` exists because `Host::cycle`
/// already sweeps `host.tasks` once every cycle, on its own schedule. A
/// character interceptor does not fire once a cycle -- it fires **on
/// arrival**, from `Channel::take` (`crates/mbbs/src/gsbl.rs`), which is
/// driven directly by the transport layer's `push_input`, not by
/// `Host::cycle` and not by anything holding `A::Module`. There is no
/// per-character equivalent of `tasks`/`prctask` today. Building one would
/// mean giving the input-cooking path the same treatment `initask` gets --
/// record the pointer somewhere `Host::cycle` (or a new per-character sweep
/// with the same access) can reach, and invoke it from there instead of
/// from `Channel::take` directly. That is real work on the input path,
/// which this task does not do -- it is out of scope here, the same way it
/// was named out of scope when this refusal was written, and the shape
/// above is recorded so the next task that does take it on does not have
/// to rediscover `initask`/`prctask` as the model.
///
/// # Why this still refuses at install, now that recording is possible
///
/// `crate::gsbl::Channel` is in scope for this task (see `btutru`'s own
/// revision), so storing *something* at install time is no longer
/// physically blocked the way it was in this routine's first version. Two
/// reasons this still refuses rather than recording `rouadr` and deferring
/// the refusal to the first character, the way [`btuche`] now defers to a
/// flag nothing reads:
///
/// 1. **`Channel` is not generic over `A`.** `host.tasks: Vec<A::Ptr>`
///    works because `Host<A>` is generic and can hold a typed pointer per
///    ABI; `Channel` holds concrete `u8`/`u16`/`bool` fields shared by both
///    ABIs, precisely so it does not need to be. Storing a genuinely
///    invokable `A::Ptr` here would need `Channel` (or `Gsbl`) to grow an
///    ABI parameter -- a structural change to every existing field's
///    owner, not a task-sized addition next to `chi_notify_on_idle`.
/// 2. **The consequence of a wrong deferral is worse here than `btuche`'s.**
///    `btuche`'s flag gates one *additional* notification nothing else
///    depends on; recording it and never firing it changes nothing else
///    about the channel. `btuchi`'s callback *replaces* the translate-table
///    stage of every character's processing from then on (the guide is
///    explicit: "Our character handler routine replaces the character
///    translation function... However, the effects of all functions
///    associated with ASCII input mode are still in effect" -- guide page
///    46). A module that installed one and got `0` back would believe
///    every subsequent keystroke is running through its own logic; this
///    host would silently keep running the default translate table
///    instead, with no error at the moment that stops mattering and no
///    error ever, for as long as the channel lives. That is an active,
///    continuous divergence from what the caller was told succeeded, not
///    an inert flag -- refusing at the one moment this host can still be
///    honest about it is the smaller failure.
///
/// A channel out of range still refuses with the ordinary `-11`, ahead of
/// the capability question, matching every other routine in this file.
pub fn btuchi<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let rouadr = call.ptr();
    if host.gsbl().terms().chan(chan).is_none() {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    }
    Err(ShimError::Failed(format!(
        "btuchi({chan}, {rouadr}): this host has no per-character equivalent \
         of shims::task::initask's tasks/Host::prctask arrangement -- \
         Channel::take fires on every byte the transport layer delivers, \
         not once a cycle from Host::cycle, so there is nowhere with \
         A::Module access to invoke this from, and building one is input-\
         path work outside this task. Even setting invocation aside, the \
         callback replaces the translate-table stage of every future \
         character (guide page 46) rather than gating an optional feature, \
         so recording success now and silently keeping the default \
         pipeline would be an active, continuing divergence from what this \
         call told the caller succeeded -- worse than refusing here"
    )))
}

/// `int btutru(int chan, char trunch)` -- set the output-abort character
/// (guide `btutru`, page 171): while ASCII output is in progress, receiving
/// this byte from the channel truncates the *current* output block -- the
/// one the most recent [`btuxmt`]/[`btuxct`] queued -- leaving the rest of
/// the output buffer alone. Zero disables it, and it is disabled by
/// default; the guide's own worked example uses Control-O (Worldgroup) or
/// Control-X (other systems).
///
/// # Revised: this task's file scope grew to include `crate::gsbl::Channel`
///
/// The first version of this routine refused: `Channel` had no field to
/// hold `trunch`, and this task's files were `crates/mbbs/src/shims/gsbl.rs`
/// only, which excluded `crates/mbbs/src/gsbl.rs` where `Channel` lives.
/// That was a boundary drawn one file too narrow, not a real capability
/// gap -- the coordinator confirmed no other agent owns that file and
/// extended this task's scope to include it. [`crate::gsbl::Channel::trunch`]
/// now exists, and this stores into it, following exactly the shape
/// `xon`/`xoff`/`pause_char`/`clear_pause_char` already use: **the
/// abort-on-receipt mechanism itself is still not implemented** (see
/// `Channel::trunch`'s own doc comment for why -- `Channel::output` has no
/// block boundaries for a matching byte to truncate), so `trunch` is
/// recorded, not yet acted on. That is a real, previously-established
/// shape in this file, not the fabricated "0 and discard it" this routine
/// refused rather than do the first time.
///
/// `trunch` is read with [`u8_arg`] -- `CHAR` in the guide's synopsis, the
/// same genuinely-narrow shape as `btupbc`'s `pausch`/`btucpc`'s `cpchar` --
/// and a value that does not fit answers the ordinary `-11`, same as a
/// channel out of range.
pub fn btutru<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(trunch) = u8_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).trunch = trunch;
    }) {
        Some(()) => abi::Ret::Int(A::Int::from(0u16)),
        None => abi::Ret::Int(A::Int::from(OUT_OF_RANGE)),
    })
}

/// `void chiout(int chan, char c)` -- character output via the echo buffer
/// (guide, documented under `btuchi`, page 47): character output through the echo buffer.
///
/// The guide restricts `chiout`/`chious`/`chiinp`/`chiinj` to being called
/// only from inside a `btuchi` interceptor or a `bturti` real-time
/// interrupt handler -- neither of which this host can ever run (see
/// [`btuchi`]'s own doc comment) -- but `chiout` is a real, independently
/// linkable `GALGSBL` export (ordinal 64), and RTSLORD imports it directly
/// rather than only reaching it from inside an interceptor this host could
/// never invoke anyway. The guide's restriction is a caution for the
/// *module author* writing the interceptor ("must be called only by the
/// routines that are used as input character interceptors"), not a
/// contract this host's own callers observe through a return code -- there
/// is no return code; `chiout` is `void`. So this implements the
/// mechanical half -- route the byte to the channel's echo path -- without
/// trying to police who called it.
///
/// This host has no echo buffer distinct from
/// [`crate::gsbl::Channel::output`] -- ordinary echoed input already lands
/// there (`Channel::take`'s echo stage) -- so `chiout` writes to the same
/// place. `void`, so a bad channel or an over-wide character has no return
/// code to carry a refusal: note it and otherwise do nothing, rather than
/// stopping the machine over a byte nobody but this host's own log will
/// ever see was dropped.
pub fn chiout<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(c) = u8_arg::<A>(call.int()) else {
        host.note(format!(
            "chiout: channel {chan}: character argument does not fit a byte"
        ));
        return Ok(abi::Ret::Void);
    };
    if on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).output.push_back(c);
    })
    .is_none()
    {
        host.note(format!("chiout: channel {chan} is out of range; character dropped"));
    }
    Ok(abi::Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Wg16, Wg32};
    use crate::testing::Fixture;

    // # Why these run against `Wg32::Int` directly, not a `Call<Wg32>`
    //
    // `docs/plans/2026-08-14-stage3-channel-entry-implementation.md`'s Task 6
    // asks for a test that "build[s] a Wg32 fixture, invoke[s] btuica with
    // max = 70000". No such fixture exists: `crate::testing::Fixture` is
    // hard-coded to `Wg16` (its `machine: mbbs_machine::m16::Machine` field,
    // `invoke`'s `Shim<Wg16>` parameter), and `testing.rs` is not this task's
    // file to change.
    //
    // Building a real `Wg32Cpu` in this file would not merely be out of
    // scope, it would reintroduce a bug this codebase already paid for and
    // documented: `abi/wg32.rs`'s own module comment records that
    // `mbbs_machine::m32::Machine::new` unconditionally registers this ABI's
    // fault claim with the process-wide arbiter in
    // `crates/mbbs-machine/src/fault.rs`, and an earlier version of that file
    // built a `Wg32Cpu` in its own `#[cfg(test)] mod tests` -- which runs in
    // the same `cargo test -p mbbs --lib` process as every `Wg16` test here --
    // and took three unrelated `Wg16` fault-recovery tests down with it
    // (`abi/wg32.rs`'s comment names them). That file now deliberately has no
    // test module, and the tests that need a real `Wg32Cpu` live in
    // `crates/mbbs/tests/wg32_abi.rs` instead -- a separate `cargo test`
    // binary, a separate OS process. That file is this wave's other agent's,
    // not this task's.
    //
    // What *is* this task's, and is enough to prove the fix: every one of
    // the checked readers this audit adds -- [`u16_arg`], [`u8_arg`],
    // [`i16_arg`], [`usize_arg`] -- is a free function generic over `A: Abi`
    // that takes `A::Int` as a plain value, not a `Call`. `Wg32::Int` is
    // `u32` (`abi/wg32.rs:129`) and `Wg32` itself is a zero-sized marker with
    // no `Machine` behind it (`abi/wg32.rs:118`), so naming `Wg32` as the
    // type parameter below builds nothing and arms nothing -- it only picks
    // which `Into<u32>` this call goes through. A value like `70_000u32` is
    // not a fabrication standing in for what a real `Wg32` module could
    // produce; it is bit-for-bit what `call.int()` would have handed back
    // had a genuine `Call<Wg32>` read it, because `int_from_bytes` for
    // `Wg32` is exactly `u32::from_le_bytes`. What is not exercised here is
    // argument-frame decoding (already covered elsewhere) and the
    // channel-bound check `on_channel` performs after these readers return
    // -- everything downstream of "was this value accepted or refused".

    /// The nine sites this audit classified "genuinely narrow" or
    /// "genuinely 16-bit in the host's own model" all refuse a value a real
    /// `Wg32` module's `int` can carry but the site's own `Channel` field
    /// cannot -- the same shape as the `cw3220mt` `fgets(buf, 40000, f)` bug
    /// this audit's own plan cites, moved from "wraps negative" (that bug's
    /// `u16` cast) to "wraps into some other in-range value" (these `u16`/
    /// `u8`/`i16` casts), which is the more dangerous of the two precisely
    /// because nothing about the wrapped result looks wrong on its own.
    ///
    /// One table entry per site named in this audit's table
    /// (`docs/2026-08-14-gsbl-width-audit.md`), each independently asserted
    /// and independently able to fail -- the same shape
    /// `every_routine_refuses_a_channel_out_of_range` above already uses for
    /// "every one refuses the same way".
    #[test]
    fn checked_narrow_readers_refuse_a_32_bit_value_their_channel_field_cannot_hold() {
        for (site, accepted) in [
            ("btutsw's width (u16, Channel::width)", u16_arg::<Wg32>(70_000).is_some()),
            ("btumil's maxinl (u16, Channel::maxinl)", u16_arg::<Wg32>(70_000).is_some()),
            ("btutrg's nbyt (u16, Channel::trigger)", u16_arg::<Wg32>(70_000).is_some()),
            ("btuxnf's xon (u8, Channel::xon)", u8_arg::<Wg32>(300).is_some()),
            ("btuxnf's xoff (sign+u8, Channel::xoff)", signed_byte_arg::<Wg32>(300).is_some()),
            ("btuxnf's cnt (u16, Channel::page_lines)", u16_arg::<Wg32>(70_000).is_some()),
            ("btupbc's pausch (u8, Channel::pause_char)", u8_arg::<Wg32>(300).is_some()),
            ("btucpc's cpchar (u8, Channel::clear_pause_char)", u8_arg::<Wg32>(300).is_some()),
            ("btuinj's status (i16, Channel::status)", i16_arg::<Wg32>(70_000).is_some()),
        ] {
            assert!(!accepted, "{site} accepted a value its own field cannot hold");
        }
    }

    /// The same nine sites still accept every value a `Wg16` module could
    /// ever have produced -- the fix is a refusal added at the top of the
    /// representable range, not a new restriction inside it. `0xFFFF` is the
    /// widest `Wg16::Int` there is; `255` and `0x7FFF` are the widest a
    /// `u8`/`i16` site could receive from it once `Wg16`'s own `u16` is the
    /// source.
    ///
    /// `i16_arg` gets its own `A = Wg16` half here, not only the `A = Wg32`
    /// half above: `Wg16::Int` is `u16`, and `Into::<u32>::into` for a `u16`
    /// **zero-extends** -- there is no sign to preserve on the way in, unlike
    /// `Wg32::Int = u32`, which arrives already sign-extended by the CPU that
    /// produced it. A genuine `i16` status of `-1` is the bit pattern
    /// `0xFFFF` under `Wg16`; that is a value `i16_arg::<Wg16>` must accept,
    /// and the widest-positive-only case above cannot catch a bug in how the
    /// negative half is handled because it never exercises the negative
    /// half. This is the actual claim this test's name makes -- "everything
    /// `Wg16` could produce" includes the values with the high bit set.
    #[test]
    fn checked_narrow_readers_still_accept_everything_wg16_could_produce() {
        assert_eq!(u16_arg::<Wg32>(0xFFFF), Some(0xFFFF));
        assert_eq!(u8_arg::<Wg32>(0xFF), Some(0xFF));
        assert_eq!(i16_arg::<Wg32>(0x7FFF), Some(0x7FFF));
        assert_eq!(signed_byte_arg::<Wg32>(255), Some(255));
        assert_eq!(signed_byte_arg::<Wg32>(0xFFFF_FF01), Some(-255), "-255, the widest magnitude a byte-and-sign holds");

        assert_eq!(i16_arg::<Wg16>(0xFFFF), Some(-1), "Wg16's zero-extended -1");
        assert_eq!(i16_arg::<Wg16>(0x8000), Some(i16::MIN), "Wg16's zero-extended i16::MIN");
        assert_eq!(signed_byte_arg::<Wg16>(0xFF01), Some(-255), "Wg16's zero-extended -255");
    }

    /// [`i16_arg`]'s round-trip check accepts a genuinely negative value via
    /// sign extension, not only the non-negative half of `i16`'s range.
    ///
    /// This is the bug this file's own first draft of `i16_arg` had: a naive
    /// `i16::try_from(wide as i64)` rejects `0xFFFF_FFFF` (a `Wg32` module's
    /// `int` holding `-1`) because it looks like the very large unsigned
    /// number `4_294_967_295`, not the small negative one it actually
    /// represents. No real `btuinj` status is negative today (`BRKTHU.H`'s
    /// vocabulary is `0..=253`), but the checked reader's contract is "does
    /// this fit in an `i16`", not "is this today's status set", and getting
    /// that contract wrong the first time this file wrote it is exactly the
    /// kind of mistake this whole audit exists to catch mutation-tested
    /// rather than assumed correct from the diff alone.
    #[test]
    fn i16_arg_accepts_a_negative_value_by_sign_extension_not_only_small_positives() {
        assert_eq!(i16_arg::<Wg32>(0xFFFF_FFFF), Some(-1));
        assert_eq!(i16_arg::<Wg32>(0xFFFF_8000), Some(i16::MIN));
        assert_eq!(i16_arg::<Wg32>(0x0000_8000), None, "0x8000 fits no i16, signed or not");
    }

    /// `btuxct`'s `nbyt` and `btuica`'s `max` -- this audit's two "genuinely
    /// wide" sites -- carry a byte count past 65535 intact rather than
    /// wrapping it into a smaller one.
    ///
    /// `70_000 as u16` is `4_464`: a module asking to transmit or receive
    /// 70,000 bytes would, under the old `as u16` cast, silently be given a
    /// 4,464-byte operation instead -- not a crash, not an error, a
    /// plausible-looking wrong answer. That is the `cw3220mt`
    /// `fgets(buf, 40000, f)` bug's shape exactly, minus the sign flip
    /// (`nbyt`/`max` are never compared as signed, so there is no negative
    /// length here, only a silently smaller positive one).
    #[test]
    fn usize_arg_does_not_truncate_a_32_bit_byte_count() {
        assert_eq!(usize_arg::<Wg32>(70_000), 70_000, "not 4_464, u16's wraparound of 70_000");
    }

    /// Every one of the fourteen refuses the same way, so this is asserted once
    /// per routine rather than reasoned about once.
    #[test]
    fn every_routine_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        for (name, ret) in [
            ("btutsw", f.invoke(btutsw, &[past, 80])),
            ("btumil", f.invoke(btumil, &[past, 40])),
            ("btuech", f.invoke(btuech, &[past, 1])),
            ("btulok", f.invoke(btulok, &[past, 1])),
            ("btuoes", f.invoke(btuoes, &[past, 1])),
            ("btutrg", f.invoke(btutrg, &[past, 4])),
            ("btuinj", f.invoke(btuinj, &[past, 3])),
            ("btuclo", f.invoke(btuclo, &[past])),
            ("btucli", f.invoke(btucli, &[past])),
            ("btuibw", f.invoke(btuibw, &[past])),
            ("btuhpk", f.invoke(btuhpk, &[past, 0, 0])),
            ("btupbc", f.invoke(btupbc, &[past, 20])),
            ("btucpc", f.invoke(btucpc, &[past, 19])),
            ("btuclc", f.invoke(btuclc, &[past])),
            ("btucls", f.invoke(btucls, &[past])),
            // The three that refuse once the channel is valid still answer
            // the ordinary -11 for one that is not -- the capability
            // question is unrelated to the bound check, and every routine
            // in this file makes the bound check first. See each one's own
            // doc comment.
            ("btuche", f.invoke(btuche, &[past, 1])),
            ("btuchi", f.invoke(btuchi, &[past, 0, 0])),
            ("btutru", f.invoke(btutru, &[past, 15])),
        ] {
            assert_eq!(
                ret.expect(name),
                Ret::U16(OUT_OF_RANGE),
                "{name} on a channel past nterms"
            );
        }
    }

    #[test]
    fn btuxmt_transmits_and_btutsw_is_what_wraps_it() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btutsw, &[0, 10]).expect("width set");
        let text = f.text("the quick brown fox");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"the quick\r\nbrown fox".to_vec()
        );
    }

    #[test]
    fn btuxmt_writes_to_the_channel_it_was_given_and_not_the_current_one() {
        // MajorMUD's entire cross-user output path. `_TELL_USER(chan)`
        // (`re/exports/WCCMMUD_named.c:65778`) is handed a channel number,
        // reads *that* player's filter bits out of `user[chan]`, and
        // transmits. It never calls `curusr`, so the channel `btuxmt` is given
        // is routinely not the channel the module is running as -- and every
        // other test in this file, and the two-channel acceptance test in
        // `tests/wccmmud.rs`, share a shape that hides the difference.
        //
        // Three channels, not two; the module runs as channel 2 and writes to
        // channel 1. Under any two-channel arrangement a shim that transmitted
        // to `usrnum`, and a shim that always transmitted to channel zero, are
        // each indistinguishable from a correct one for some assignment of the
        // two roles. Here every one of the three rings answers separately.
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let terms = f.host.gsbl().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");
        let two = terms.chan(2).expect("channel 2");

        // The module is running as channel 2: `usrnum`, `usrptr`, `usaptr` and
        // `vdaptr` all name it, exactly as `Host::poll` leaves them before a
        // dispatch.
        f.host
            .point_curusr(&mut f.machine, two)
            .expect("channel 2 is current");

        let text = f.text("Kaimon just entered the Realm.");
        f.invoke(btuxmt, &[1, text.offset, text.selector])
            .expect("transmitted");

        assert_eq!(
            [
                f.host.gsbl_mut().drain_output(zero),
                f.host.gsbl_mut().drain_output(one),
                f.host.gsbl_mut().drain_output(two),
            ],
            [
                Vec::new(),
                b"Kaimon just entered the Realm.".to_vec(),
                Vec::new()
            ],
            "the argument names the ring -- not the current channel, and not zero"
        );
    }

    #[test]
    fn btuxmn_transmits_like_btuxmt() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btutsw, &[0, 10]).expect("width set");
        let text = f.text("the quick brown fox");
        f.invoke(btuxmn, &[0, text.offset, text.selector])
            .expect("transmitted");
        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"the quick\r\nbrown fox".to_vec()
        );
    }

    /// A stated finding, not a silent one. Real GSBL's `btuxmn` writes a
    /// block `btuclo()` cannot clear (guide page 187: it terminates the
    /// block with `\x01` rather than `btuxmt`'s `\x00`, and `btuclo` only
    /// discards blocks of the latter kind). This host's
    /// [`crate::gsbl::Channel::output`] is one flat byte buffer with no
    /// block boundaries at all -- `btuclo` clears it unconditionally -- so
    /// there is currently no way for `btuxmn` to keep a message alive
    /// through a `btuclo` the way real GSBL would. See `btuxmn`'s own doc
    /// comment for why that is not fixed here.
    #[test]
    fn btuxmn_is_not_actually_protected_from_btuclo_on_this_host() {
        let mut f = Fixture::new();
        let console = f.console();
        let text = f.text("you cannot skip this");
        f.invoke(btuxmn, &[0, text.offset, text.selector])
            .expect("transmitted");
        f.invoke(btuclo, &[0]).expect("cleared");
        assert!(
            f.host.gsbl_mut().drain_output(console).is_empty(),
            "real GSBL would refuse to clear this -- this host does; see \
             btuxmn's doc comment"
        );
    }

    /// Moved from the dead `echo::btuxmn` twin
    /// (`docs/2026-08-15-dead-twin-shims.md`): neither this routine nor its
    /// sibling [`btuxmt_transmits_and_btutsw_is_what_wraps_it`] was in
    /// `every_routine_refuses_a_channel_out_of_range`'s sweep (both need a
    /// real `ASCIIZ` pointer, not a bare `int`), so this is the one place
    /// that bound check is pinned for `btuxmn` specifically.
    #[test]
    fn btuxmn_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        let text = f.text("paged");
        let ret = f
            .invoke(btuxmn, &[past, text.offset, text.selector])
            .expect("refused, not an error");
        assert_eq!(ret, Ret::U16(OUT_OF_RANGE));
    }

    #[test]
    fn btuxct_sends_the_byte_count_it_was_given_and_no_terminator() {
        // Binary: the length is an argument, not a NUL scan, so an embedded
        // zero is data.
        let mut f = Fixture::new();
        let console = f.console();
        let data = f.bytes(&[b'a', 0, b'b'], false);
        f.invoke(btuxct, &[0, 3, data.offset, data.selector])
            .expect("transmitted");
        assert_eq!(f.host.gsbl_mut().drain_output(console), vec![b'a', 0, b'b']);
    }

    #[test]
    fn btuibw_counts_what_is_waiting_and_btucli_throws_it_away() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcd");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(4));
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(0));
    }

    /// Raw mode's bytes are ordinary input as far as these three are
    /// concerned, which is the whole reason `Channel::raw` collects into
    /// `input` rather than a buffer of its own.
    ///
    /// Here rather than in `crate::gsbl`'s tests, and the difference is not
    /// cosmetic. The version this replaces lived there and asserted `btuica`
    /// and `btucli` by calling `input.drain(..)` and `input.clear()` itself --
    /// which measures `VecDeque`, not the shims, and would have survived any
    /// mutation to either of them. The routines are reachable from here.
    ///
    /// The bytes are chosen so the answer would change if raw mode were not
    /// in force: `\x1b` and `\n` are both dropped by the input translate
    /// table, so a channel out of raw mode counts three of these five.
    ///
    /// The `btuibw` after the partial `btuica` is the second half of
    /// `gsbl::tests::leaving_raw_mode_restores_line_assembly_and_keeps_what_was_not_drained`:
    /// bytes raw mode collected and nobody drained keep being counted, which
    /// is the price of `fsdcof` not clearing input and is asserted rather than
    /// left to be discovered.
    #[test]
    fn raw_bytes_are_what_btuica_takes_btuibw_counts_and_btucli_throws_away() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).raw = true;
        f.host.gsbl_mut().push_input(console, b"a\x1b[A\n");

        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(5),
            "all five keystrokes are waiting, ESC and LF included"
        );

        let buf = f.buffer(16);
        let ret = f
            .invoke(btuica, &[0, buf.offset, buf.selector, 3])
            .expect("copied");
        assert_eq!(ret, Ret::U16(3));
        assert_eq!(
            f.machine.resolve(buf, 3).expect("in bounds"),
            b"a\x1b[",
            "in arrival order, uncooked"
        );
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(2),
            "and what the FSD did not take is still waiting to be asked for"
        );

        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(0),
            "btucli reaches raw bytes -- it is how fsdcon drops type-ahead"
        );
    }

    #[test]
    fn btuclo_throws_away_output_that_has_not_gone_out() {
        let mut f = Fixture::new();
        let console = f.console();
        let text = f.text("wasted");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        f.invoke(btuclo, &[0]).expect("cleared");
        assert!(f.host.gsbl_mut().drain_output(console).is_empty());
    }

    #[test]
    fn btuinj_puts_a_status_where_the_host_will_find_it() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btuinj, &[0, 3]).expect("injected");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(3));
    }

    #[test]
    fn btuica_copies_what_is_waiting_up_to_the_maximum_it_was_given() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcdef");
        let buf = f.buffer(16);
        let ret = f
            .invoke(btuica, &[0, buf.offset, buf.selector, 4])
            .expect("copied");
        assert_eq!(ret, Ret::U16(4), "the count copied, not the count waiting");
        assert_eq!(
            f.machine.resolve(buf, 4).expect("in bounds"),
            b"abcd",
            "and only four bytes landed"
        );
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(2),
            "what was copied is consumed"
        );
    }

    #[test]
    fn btuica_does_not_drain_input_when_the_destination_pointer_is_bad() {
        // R12: draining before validating the write destination meant a bad
        // pointer's error arrived after the bytes it was supposed to deliver
        // were already gone. Selector 0xdead names no segment of this
        // module's, so resolve (and the write it would otherwise attempt)
        // must fail -- and the bytes must still be waiting to be asked for
        // again.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcd");
        let ret = f.invoke(btuica, &[0, 0, 0xdead, 4]);
        assert!(ret.is_err(), "a destination that resolves to nothing must fail");
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(4),
            "nothing was drained -- the bytes are still there to ask for again"
        );
    }

    #[test]
    fn btuxnf_with_a_negative_xoff_records_the_page_parameters_without_paginating() {
        // R5, guide btuxnf page 193: a negative xoff selects page mode and
        // adds cnt/stg -- measured from the DLL's own six-word call sites:
        // btuxnf(usrnum, 0, 0xffed, 0x16, <far ptr to "Hit any key...">).
        // Pagination is deliberately not implemented; this only pins that
        // the parameters are not lost.
        let mut f = Fixture::new();
        let console = f.console();
        let msg = f.text("Hit any key to continue...");
        f.invoke(btuxnf, &[0, 0, 0xffed, 22, msg.offset, msg.selector])
            .expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(
            c.xoff, 19,
            "the guide's own page-193 example: xoff=-19 still means CTRL+S \
             (19), the same byte the positive form uses -- not 0xed, the \
             bit pattern -19 happens to have"
        );
        assert_eq!(c.page_lines, 22);
        assert_eq!(
            c.page_message.as_deref(),
            Some(b"Hit any key to continue...".as_slice())
        );
    }

    /// The guide's positive form of the same character: `btuxnf(chan,0,19)`
    /// is the documented default (page 194) and must store the identical
    /// byte the negative form (page-mode) does -- the sign is a mode flag,
    /// not part of the character.
    #[test]
    fn btuxnf_with_a_positive_xoff_stores_the_same_byte_as_its_negation() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btuxnf, &[0, 0, 19]).expect("ok");
        assert_eq!(f.host.gsbl().channel(console).xoff, 19);
    }

    /// A 32-bit module's `xoff` whose magnitude does not fit the byte
    /// [`crate::gsbl::Channel::xoff`] actually is. Genuinely narrow, same
    /// bucket as `xon` (`checked_narrow_readers_refuse_a_32_bit_value_
    /// their_channel_field_cannot_hold`) -- refused with `-11`, not
    /// truncated into some other in-range byte.
    #[test]
    fn btuxnf_refuses_an_xoff_whose_magnitude_does_not_fit_a_byte() {
        let mut f = Fixture::new();
        let console = f.console();
        let before = f.host.gsbl().channel(console).xoff;
        let ret = f
            .invoke(btuxnf, &[0, 0, 300])
            .expect("the routine itself does not error -- it returns -11");
        assert_eq!(ret, Ret::U16(OUT_OF_RANGE));
        assert_eq!(
            f.host.gsbl().channel(console).xoff,
            before,
            "refused, not silently truncated to 300 as u8 == 44"
        );
    }

    #[test]
    fn btuxnf_with_a_positive_xoff_records_no_page_parameters() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btuxnf, &[0, 0, 19]).expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(c.page_lines, 0);
        assert_eq!(c.page_message, None);
    }

    #[test]
    fn btuhpk_records_that_a_handler_was_installed() {
        let mut f = Fixture::new();
        let console = f.console();
        assert!(
            !f.host.gsbl().channel(console).pause_handler_installed,
            "nothing installed one yet"
        );
        f.invoke(btuhpk, &[0, 0x1234, 0x5678]).expect("ok");
        assert!(f.host.gsbl().channel(console).pause_handler_installed);
    }

    #[test]
    fn btupbc_and_btucpc_record_their_characters() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btupbc, &[0, 20]).expect("ok");
        f.invoke(btucpc, &[0, 19]).expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(c.pause_char, 20, "Control-T, the guide's own example");
        assert_eq!(c.clear_pause_char, 19, "Control-S, the guide's own example");
    }

    #[test]
    fn the_settings_reach_the_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btutsw, &[0, 80]).expect("ok");
        f.invoke(btumil, &[0, 40]).expect("ok");
        f.invoke(btuech, &[0, 0]).expect("ok");
        f.invoke(btulok, &[0, 1]).expect("ok");
        f.invoke(btuoes, &[0, 1]).expect("ok");
        f.invoke(btutrg, &[0, 8]).expect("ok");
        f.invoke(btuxnf, &[0, 17, 19]).expect("ok");

        let c = f.host.gsbl().channel(console);
        assert_eq!(c.width, 80);
        assert_eq!(c.maxinl, 40);
        assert!(!c.echo, "btuech(chan, 0) turns echo off");
        assert!(c.locked);
        assert!(c.oes);
        assert_eq!(c.trigger, 8);
        assert_eq!((c.xon, c.xoff), (17, 19));
    }

    #[test]
    fn btucli_leaves_a_status_queued_with_no_string_behind_it() {
        // The guide's own CAUTIONS. Clearing the status too would be tidier
        // and would not be GSBL.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().push_input(console, b"look\r");
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(crate::gsbl::Gsbl::CRSTG));
        assert_eq!(f.host.gsbl_mut().take_line(console), None);
    }

    // # Task 3: the six GALGSBL character-interrupt routines
    //
    // `btuclc`/`btucls`/`btuche`/`btuchi`/`btutru` on a channel out of range
    // are already covered by `every_routine_refuses_a_channel_out_of_range`,
    // above -- what follows is each routine's *own* behaviour on a valid
    // channel, which that shared table cannot exercise.

    #[test]
    fn btucls_clears_the_status_fifo_but_btuclc_touches_nothing() {
        // The discriminating test: btuclc and btucls have the identical
        // shape everywhere except here -- both take only a channel, both
        // answer 0 on a valid one, both answer -11 on a bad one. A mutation
        // that swapped their bodies, or that made either one a pure no-op,
        // would pass every other test in this file. Only checking the
        // status FIFO itself tells them apart.
        let mut f = Fixture::new();
        let console = f.console();

        f.invoke(btuinj, &[0, 3]).expect("injected");
        f.invoke(btuclc, &[0]).expect("btuclc has nothing to clear");
        // `next_status` *pops*: reading it here to check btuclc's effect and
        // again below to check btucls's would drain the one entry on the
        // first read, leaving the second assertion checking an
        // already-empty buffer regardless of what either routine did. That
        // was this test's own first draft, and it passed against a btucls
        // that never cleared anything -- a mutation that should have failed
        // and did not, caught by hand rather than by cargo-mutants. Reading
        // the field directly here, and reserving the one `next_status` call
        // for the real proof below, is what makes the two halves actually
        // independent.
        assert_eq!(
            f.host.gsbl().channel(console).status.front().copied(),
            Some(3),
            "btuclc must not touch the status FIFO -- it has no command \
             buffer of its own to clear, see its own doc comment"
        );

        f.invoke(btucls, &[0]).expect("cleared");
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "btucls empties the status buffer btuinj fills"
        );
    }

    #[test]
    fn btuclc_answers_ok_on_a_valid_channel() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(btuclc, &[0]).expect("ok"), Ret::U16(0));
    }

    /// `btuchi` alone has a valid-channel refusal path left in this family;
    /// it still makes the ordinary bound check first -- a channel out of
    /// range is not this host's missing capability, and every other
    /// routine in this file answers `-11` for it rather than stopping the
    /// machine. Covered once here rather than folded into
    /// `every_routine_refuses_a_channel_out_of_range`, which asserts
    /// `Ok(Ret::U16(..))` for the whole table; a routine that *also* has a
    /// valid-channel refusal path needs its own two-sided test to prove the
    /// ordering, not just the one side that table already checks.
    #[test]
    fn a_bad_channel_answers_out_of_range_even_though_btuchi_otherwise_refuses() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        assert_eq!(
            f.invoke(btuchi, &[past, 0, 0]).expect("must not stop the machine"),
            Ret::U16(OUT_OF_RANGE)
        );
    }

    /// Mirrors `btuhpk_records_that_a_handler_was_installed`: `btuche`
    /// records caller intent for a mechanism this host does not drive,
    /// exactly the shape `pause_handler_installed` already established.
    /// Both `onoff` values are exercised on *different* channels so a
    /// mutation that ignored `chan` (always writing channel 0) or ignored
    /// `onoff` (always recording the same value) would leave one of the
    /// two assertions false.
    #[test]
    fn btuche_records_the_notify_flag_per_channel() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let terms = f.host.gsbl().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");

        assert!(!f.host.gsbl().channel(zero).chi_notify_on_idle, "off by default");
        f.invoke(btuche, &[0, 1]).expect("ok");
        f.invoke(btuche, &[1, 0]).expect("ok");

        assert!(f.host.gsbl().channel(zero).chi_notify_on_idle, "channel 0 turned on");
        assert!(!f.host.gsbl().channel(one).chi_notify_on_idle, "channel 1 turned off");
    }

    #[test]
    fn btuchi_refuses_on_a_valid_channel_and_names_the_input_path_gap() {
        let mut f = Fixture::new();
        // rouadr as a far pointer: offset 0x0010, segment 0x1234 -- the same
        // shape btuhpk's own test uses for its (deliberately unread) handler
        // pointer.
        let e = f
            .invoke(btuchi, &[0, 0x0010, 0x1234])
            .expect_err("no per-character equivalent of tasks/Host::prctask exists");
        let msg = e.to_string();
        assert!(msg.contains("btuchi"), "{msg}");
        assert!(msg.contains("1234:0010"), "must name the far pointer it was handed: {msg}");
        assert!(msg.contains("initask"), "{msg}");
    }

    /// Mirrors `btupbc_and_btucpc_record_their_characters`: `trunch` is
    /// recorded exactly like the sibling settings it now shares a field
    /// shape with, per-channel rather than globally.
    #[test]
    fn btutru_records_the_abort_character_per_channel() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let terms = f.host.gsbl().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");

        f.invoke(btutru, &[0, 15]).expect("Control-O, Worldgroup's own default"); // 0x0F
        f.invoke(btutru, &[1, 24]).expect("Control-X, the other systems' default"); // 0x18

        assert_eq!(f.host.gsbl().channel(zero).trunch, 15);
        assert_eq!(f.host.gsbl().channel(one).trunch, 24);
    }

    /// `trunch` not fitting a byte is the same ordinary `-11` every other
    /// `u8_arg` site in this file answers.
    #[test]
    fn btutru_answers_the_ordinary_code_for_a_trunch_that_does_not_fit_a_byte() {
        let mut f = Fixture::new();
        let console = f.console();
        let before = f.host.gsbl().channel(console).trunch;
        let ret = f
            .invoke(btutru, &[0, 300])
            .expect("the routine itself does not error for a bad width");
        assert_eq!(ret, Ret::U16(OUT_OF_RANGE));
        assert_eq!(
            f.host.gsbl().channel(console).trunch,
            before,
            "refused, not silently truncated to 300 as u8 == 44"
        );
    }

    #[test]
    fn chiout_writes_the_character_to_the_channels_output() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(chiout, &[0, b'~' as u16]).expect("void");
        assert_eq!(f.host.gsbl_mut().drain_output(console), vec![b'~']);
    }

    #[test]
    fn chiout_writes_to_the_channel_it_was_given_not_channel_zero() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let terms = f.host.gsbl().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");

        f.invoke(chiout, &[1, b'Q' as u16]).expect("void");

        assert_eq!(
            [f.host.gsbl_mut().drain_output(zero), f.host.gsbl_mut().drain_output(one)],
            [Vec::new(), vec![b'Q']],
            "the argument names the channel -- not channel zero"
        );
    }

    #[test]
    fn chiout_on_a_channel_out_of_range_drops_the_character_without_stopping_the_machine() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        f.invoke(chiout, &[past, b'x' as u16])
            .expect("void routines note and continue -- see chiout's own doc comment");
    }

    // # Task 2: btusts, chiinj and bturst -- shims over methods that already
    // existed
    //
    // All three delegate to `Gsbl` methods `Host::poll` and `btuinj`/`btucli`
    // already exercised; what is new here is only that a module can reach
    // them.

    #[test]
    fn btusts_pops_the_status_fifo_in_order_then_answers_quiet() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().inject(console, Gsbl::CRSTG);
        f.host.gsbl_mut().inject(console, Gsbl::OUTMT);

        assert_eq!(f.invoke(btusts, &[0]).expect("btusts"), Ret::U16(Gsbl::CRSTG as u16));
        assert_eq!(f.invoke(btusts, &[0]).expect("btusts"), Ret::U16(Gsbl::OUTMT as u16));
        // Guide page 155: 0 is nothing to report -- an empty
        // FIFO is not an error and must not answer OUT_OF_RANGE.
        assert_eq!(f.invoke(btusts, &[0]).expect("btusts"), Ret::U16(0));
    }

    #[test]
    fn btusts_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(btusts, &[9999]).expect("btusts"), Ret::U16(OUT_OF_RANGE));
    }

    #[test]
    fn bturst_returns_a_channel_to_its_defaults() {
        let mut f = Fixture::new();
        let console = f.console();
        // Dirty every kind of state a reset must clear.
        f.host.gsbl_mut().channel_mut(console).width = 40;
        f.host.gsbl_mut().channel_mut(console).echo = false;
        // Seeded directly into `input`, not through `push_input`: this
        // channel is in cooked ASCII mode (the default), where an
        // unterminated byte string is assembled into `Channel::line`, not
        // `Channel::input` -- see `Channel::take`'s default-arm. Going
        // through `push_input` here would leave `input` empty before *and*
        // after `bturst`, making the assertion below pass whether or not
        // the reset ran at all.
        f.host.gsbl_mut().channel_mut(console).input.extend(b"half-typed".iter().copied());
        f.host.gsbl_mut().inject(console, Gsbl::CRSTG);

        assert_eq!(
            f.invoke(bturst, &[0]).expect("bturst"),
            Ret::U16(0),
            "see the ruling: 0, not 1"
        );

        let c = f.host.gsbl().channel(console);
        assert_eq!(c.width, 0);
        assert!(c.echo, "echo defaults on");
        assert!(c.input.is_empty(), "a half-typed line must not survive into the next session");
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "and neither must a queued status"
        );
    }

    #[test]
    fn bturst_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(bturst, &[9999]).expect("bturst"), Ret::U16(OUT_OF_RANGE));
    }

    #[test]
    fn chiinj_queues_a_status_the_host_then_dispatches() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(chiinj, &[0, Gsbl::CRSTG as u16]).expect("void");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(Gsbl::CRSTG));
    }
}
