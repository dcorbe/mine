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
/// [`u8_arg`] do. Sign-extending the low 16 bits back out and comparing
/// against the original widened value accepts every value a genuine `i16`
/// -- positive or negative -- would zero/sign-extend into under either ABI,
/// and refuses anything where bits above position 15 carried information
/// that extension did not put there.
fn i16_arg<A: Abi>(v: A::Int) -> Option<i16> {
    let wide: u32 = v.into();
    let narrow = wide as i16;
    if (i32::from(narrow) as u32) == wide { Some(narrow) } else { None }
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

/// `void echonu(int usrnum)` -- `MAJORBBS.C:3847`, "turn echo on utility".
///
///
/// **The counterpart to the `btuech(chan,0)` a module makes when it begins a
/// timed action, and reaching it is what ends one.** MajorMUD silences echo in
/// its `_ADD_DELAY` and restores it here once the delay expires. Nothing could
/// reach this routine until `Host::cycle` began calling the `syscyc` vector --
/// which is why no survey ever named it, and why it surfaced as a module stop
/// the first time a move ran to completion.
///
/// Two simplifications, both made from what this host *is* rather than by
/// guessing at the original:
///
/// - `echtyp[grpnum[usrnum]]` is the echo type of the user's **group**. This
///   host has neither: `echtyp` and `grpnum` are not placed globals, because
///   no module it loads addresses them. Every channel it serves is an ordinary
///   user, whose group echo type is "on", so this restores echo instead of
///   indexing a table that would have exactly one entry.
/// - The `extptr->wid` branch is `echsec`'s teardown -- `echsec` sets a
///   secret echo character and a line width, and this clears both. `echsec` is
///   not implemented here, so nothing can make `wid` non-zero and the branch is
///   unreachable. Recorded rather than quietly dropped: a host that grows
///   `echsec` must grow this with it.
///

pub fn echonu<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    if on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).echo = true;
    })
    .is_none()
    {
        // `void`, so there is no status to answer with -- the original would
        // have indexed `grpnum` out of bounds here. A note is the only way to
        // say it happened.
        host.note(format!("echonu: channel {chan} is out of range; echo not restored"));
    }
    Ok(abi::Ret::Void)
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
/// **`xoff` is not covered by this audit's checked readers**, and that is a
/// finding, not an oversight folded in silently: it narrows to `i16` here
/// and again to `u8` in [`apply_xnf`], on the same `call.int()` -- `A::Int`
/// -- shape as the nine sites this audit's own plan enumerated, but it is
/// not one of them (`docs/plans/2026-08-14-stage3-channel-entry-
/// implementation.md`'s Task 6 table lists `xon` at this line's neighbour
/// and `cnt` two lines below, never `xoff`). Every real 32-bit call site
/// (`re/wg33src/SRC/.../MAJORBBS.C:4490` among them) passes `0`, `19` or
/// `-19` -- well inside a byte, sign included -- so this is not believed to
/// be live, but "not believed to be live" is exactly the reasoning this
/// audit exists to distrust. Left as `as i16`/`as u8` because fixing it was
/// not this task's scope to expand on its own initiative; recorded here and
/// in `docs/2026-08-14-gsbl-width-audit.md` so a later reader does not
/// mistake the silence for having been checked.
pub fn btuxnf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let Some(xon) = u8_arg::<A>(call.int()) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    // Not covered by this audit -- see this function's own doc comment.
    let xoff = Into::<u32>::into(call.int()) as i16;
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
pub(crate) fn apply_xnf(
    g: &mut Gsbl,
    chan: Chan,
    xon: u8,
    xoff: i16,
    page: Option<(u16, Vec<u8>)>,
) {
    let c = g.channel_mut(chan);
    c.xon = xon;
    c.xoff = xoff as u8;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg32;
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

    /// The eight sites this audit classified "genuinely narrow" or
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
            ("btuxnf's cnt (u16, Channel::page_lines)", u16_arg::<Wg32>(70_000).is_some()),
            ("btupbc's pausch (u8, Channel::pause_char)", u8_arg::<Wg32>(300).is_some()),
            ("btucpc's cpchar (u8, Channel::clear_pause_char)", u8_arg::<Wg32>(300).is_some()),
            ("btuinj's status (i16, Channel::status)", i16_arg::<Wg32>(70_000).is_some()),
        ] {
            assert!(!accepted, "{site} accepted a value its own field cannot hold");
        }
    }

    /// The same eight sites still accept every value a `Wg16` module could
    /// ever have produced -- the fix is a refusal added at the top of the
    /// representable range, not a new restriction inside it. `0xFFFF` is the
    /// widest `Wg16::Int` there is; `255` and `0x7FFF` are the widest a
    /// `u8`/`i16` site could receive from it once `Wg16`'s own `u16` is the
    /// source.
    #[test]
    fn checked_narrow_readers_still_accept_everything_wg16_could_produce() {
        assert_eq!(u16_arg::<Wg32>(0xFFFF), Some(0xFFFF));
        assert_eq!(u8_arg::<Wg32>(0xFF), Some(0xFF));
        assert_eq!(i16_arg::<Wg32>(0x7FFF), Some(0x7FFF));
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
        assert_eq!(c.xoff, 0xed, "the low byte still lands, negative or not");
        assert_eq!(c.page_lines, 22);
        assert_eq!(
            c.page_message.as_deref(),
            Some(b"Hit any key to continue...".as_slice())
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
}
