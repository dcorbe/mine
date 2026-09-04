//! The FSD's host-side state: what `FSDBBS.C` keeps per channel and per
//! board, and no module can see.
//!
//! [`super`] is the port of `FSD.C`, the form compiler: a pure function of
//! two byte strings. This module is the other half of the original's split.
//! `FSDBBS.C` is the glue between that compiler and a live board -- which
//! channel is in which form, where each channel's control block lives, the
//! keystroke decoder mid-escape-sequence -- and the original hangs all of it
//! off `struct fsdbbs` (`fsdusr`), one per channel, allocated by
//! `inifsdscb()` (`FSDBBS.C:64`). [`Fsd`] is that array, plus the two
//! board-wide caches `FSDBBS.C` keeps as globals.
//!
//! Every field used to sit directly on `Host<A>`. They moved here together
//! because they are one subsystem's state and nothing else's: the shims in
//! `crate::shims::fsd` are the only code that reads or writes them, and
//! `Host` only sizes them at construction and registers the FSD's `state`
//! slot in `finish_init`.

use std::collections::HashMap;

use super::{Form, ain};
use crate::abi::Abi;
use crate::chan::Terms;

/// The FSD's host-side state. See the module doc.
///
/// `A` carries no default, for the reason [`DateBuffers`](crate::DateBuffers)
/// carries none. Not `#[derive(..)]`: the derive macros would bound `A:
/// Trait`, which `Wg16` does not implement and does not need to.
pub struct Fsd<A: Abi> {
    /// Every form `fsdroom` has sized, keyed by the `(message number, amode)`
    /// it was compiled from. See [`Fsd::forms`].
    ///
    /// **Channel-keyed as of the commit that added this doc comment.** Used
    /// to be a flat `Vec<Form>` -- see [`Fsd::scb`]'s
    /// history for why that was a debt -- but the compiled form itself is not
    /// per-channel state at all: two channels filling out the *same* form
    /// (the same message number and amode) share one compilation, the way the
    /// real host's `fsdroom` would have parsed the same template twice and
    /// gotten the same answer both times. What is per-channel is which form a
    /// given channel is using, which [`Fsd::tmp`] records.
    pub(crate) forms: HashMap<(u16, i16), Form>,

    /// Where each channel's `struct fsdscb` lives, once its `fsdroom` has
    /// needed one. Indexed by [`Chan::index`](crate::Chan::index).
    ///
    /// `inifsdscb()`, `FSDBBS.C:64`, allocates `nterms` of them, and the real
    /// `setfsd(chan)` exists precisely to select among them -- which this
    /// mirrors: one segment per channel rather than one segment shared by
    /// all of them. `None` until that channel's first `fsdroom`, because the
    /// module *tests* the `fsdscb` global for null -- `seg 3:0x430f` -- and
    /// takes another path when it is.
    ///
    /// # The debt this repays
    ///
    /// This used to be a single `Option<FarPtr>`, on the reasoning that the
    /// FSD was out of scope for the multi-channel work and nothing could
    /// reach the hazard. That reasoning held until [`Fsd::state`]
    /// existed to dispatch a channel into an FSD session at all -- from that
    /// point on, two channels entering data at once would have shared one
    /// control block and interleaved their answers into a single `newans`.
    /// Keyed by channel now, so that cannot happen by construction.
    pub(crate) scb: Vec<Option<A::Ptr>>,

    /// Each channel's `fsdusr->{curmbk,tmpmsg,amode}` -- which message block
    /// `fsdroom` last read a template out of, which template, and in which
    /// mode. `FSDBBS.C:134`, and Rust-side rather than in module memory
    /// because `fsdusr` is ordinal 264 and `WCCMMUD.DLL` never imports it.
    /// Indexed by [`Chan::index`](crate::Chan::index), for the same reason [`Fsd::scb`] is.
    pub(crate) tmp: Vec<Option<(A::Ptr, u16, i16)>>,

    /// The FSD's own `state` slot, registered in [`Host::finish_init`](crate::Host::finish_init) the
    /// way `inifsd()` registers FSDBBS as a module. `None` before
    /// `finish_init` has run.
    pub(crate) state_slot: Option<usize>,

    /// Per-channel state an entry session needs that no module can see, so
    /// it lives only here rather than round-tripping through `Machine` the
    /// way [`Scb`](super::Scb) does.
    ///
    /// `FSDBBS.C`'s own home for these is `struct fsdbbs` (`fsdusr`):
    /// `whndun` there is a far pointer into the module the host must call
    /// back, and the save/quit flag is `fsdusr->flags & FBSAVE`, read by
    /// `goback()` after the session's own buffer may already be gone. Both
    /// are genuinely invisible to the module -- unlike `Scb`'s bytes, which
    /// the module dereferences directly -- so they are Rust-side. Indexed by
    /// [`Chan::index`](crate::Chan::index), for the reason [`Fsd::scb`] is: one session per
    /// channel, not one shared by all of them.
    pub(crate) sessions: Vec<Option<Session<A>>>,

    /// Per-channel ANSI keystroke-decoder state, one byte apiece.
    ///
    /// The original hangs this off `struct fsdbbs` as `fsdusr->ainscb` and
    /// reaches it through a global pointer that `fsdchi` swaps in and back
    /// out around each call (`FSDBBS.C:344-355`). It is invisible to the
    /// module either way -- a half-finished `ESC [` is not something a form
    /// can ask about -- so it lives here rather than in [`Scb`](super::Scb).
    ///
    /// Sized for every channel and never `Option`: a decoder with no session
    /// in progress is just one sitting in `WT4ESC`, which is exactly what
    /// [`Ainscb::default`](super::ain::Ainscb::default) is. `fsdego` calls
    /// `ainbeg` on it for **both** modes (`FSDBBS.C:217-218`), which is the
    /// whole reason line mode is decoded too.
    pub(crate) ain: Vec<ain::Ainscb>,

    /// `getasc(tmpmsg)`'s output, materialised in module memory, keyed by the
    /// `(message block, message number)` it came from.
    ///
    /// `fsdrft` hands the module a `char *`, and the module passes it straight
    /// back in as `fsdbkg(fsdrft())` (`FSDBBS.C:87`). That pointer has to
    /// address the *same* string the form's field offsets were measured
    /// against -- the ASCII-expanded one (`FSDBBS.C:137`) -- so it cannot
    /// simply be the message text where it already sits. The genuine host has
    /// the same problem and solves it the same way: `getasc` writes into a
    /// buffer of the host's and returns a pointer to that.
    ///
    /// Cached rather than rebuilt because message text does not change once
    /// read, and because a fresh segment per `fsdrft` call would leak one per
    /// redisplay.
    pub(crate) ascii: HashMap<(A::Ptr, u16), A::Ptr>,

    /// Scratch memory for the candidate answer `fsdprc`'s `FSDBUF` arm
    /// hands `fldvfy`: the module reads `char *answer` out of it, and
    /// `VFYOK`'s own contract (`FSD.H` Note 2) lets it rewrite the bytes
    /// there in place. `None` until the first field-verify call needs it.
    ///
    /// **Not per-channel, unlike [`Fsd::scb`].** The original's own
    /// `fsdbuf` (`FSDBBS.C:45`) is a single global buffer too, not one per
    /// channel -- `alcmem(fsdbln)` runs once, in `inifsd()`. That is safe
    /// there for the same reason it is safe here: only one channel's
    /// `fsdprc` ever runs at a time (this host is single-threaded by
    /// force), and the buffer's whole lifetime is the span of one
    /// `fldvfy` call, never carried across one. Sized `ANSLEN+1` rather
    /// than the original's `fsdbln` (`ANSILN*ANSIWD*2`, a much larger
    /// buffer also used by the ANSI screen paths this crate does not
    /// build) -- the one purpose this port ever writes it for is a single
    /// candidate answer, never longer than `ANSLEN`.
    pub(crate) scratch: Option<A::Ptr>,
}

impl<A: Abi> Fsd<A> {
    /// Sized for every channel the board has, with nothing allocated yet:
    /// `inifsdscb()` allocates `nterms` control blocks up front, but this
    /// host allocates each channel's on its first `fsdroom` instead.
    pub(crate) fn new(terms: Terms) -> Self {
        let count = usize::from(terms.count());
        Self {
            forms: HashMap::new(),
            scb: vec![None; count],
            tmp: vec![None; count],
            state_slot: None,
            sessions: vec![None; count],
            ain: vec![ain::Ainscb::default(); count],
            ascii: HashMap::new(),
            scratch: None,
        }
    }

    /// Every form the module asked `fsdroom` to size, keyed by the
    /// `(message number, amode)` it was compiled from.
    ///
    /// A cache, not a session: what a caller can usefully ask this host is
    /// "what forms exist" and not "what is channel 0 in the middle of" --
    /// see [`Fsd::tmp`] and [`Fsd::scb`] for the per-channel half of
    /// that question.
    pub fn forms(&self) -> &HashMap<(u16, i16), Form> {
        &self.forms
    }

    /// The FSD's own `state` slot, the way `register_module`'s caller keeps
    /// the number it returned.
    ///
    /// # Panics
    ///
    /// If called before [`Host::finish_init`](crate::Host::finish_init) has
    /// registered it -- nothing in this crate can reach a channel's `state`
    /// that early, so this is a programming error rather than a condition
    /// callers should handle.
    pub(crate) fn state(&self) -> usize {
        self.state_slot
            .expect("finish_init registers the FSD before anything can reach it")
    }
}

/// The two things about an FSD session no module can see. See
/// [`Fsd::sessions`].
///
/// `A` carries no default, for the same reason [`DateBuffers`](crate::DateBuffers) carries
/// none. Not
/// `#[derive(Debug, Clone, Default)]`: same trap, same fix -- see
/// `DateBuffers`'s own doc comment. `Default` in particular would bound `A:
/// Default`, which `Wg16` does not implement and does not need to: every
/// field here defaults on its own (`bool` and `Option<A::Ptr>` both do,
/// regardless of what `A::Ptr` is).
pub(crate) struct Session<A: Abi> {
    /// Whether `fsdego` started this session with `fsdent` rather than
    /// `fsdlin` -- the original's `fsdusr->flags & FBFULL` (`FSDBBS.C:207`,
    /// `:211`). `goback` reads it to decide whether to park the cursor below
    /// the form on the way out (`FSDBBS.C:227`).
    ///
    /// Written by `fsdego`, and read by `goback` (Task 12) to decide whether
    /// to emit the `FBFULL` cursor park. Recorded at `fsdego` time rather
    /// than reconstructed later from `amode`, because it is the original's
    /// own `fsdusr->flags` bookkeeping, set at the moment the fork is taken;
    /// reconstructing it later would be a second source of truth for one
    /// fact.
    pub(crate) full_screen: bool,

    /// The `whndun(save)` callback `fsdego` was handed, or `None` if the
    /// module passed `NULL` -- `goback()`'s own `else` branch
    /// (`FSDBBS.C:236`) is what a `None` here means to it.
    pub whndun: Option<A::Ptr>,

    /// Whether the session is exiting to save (`FSDSAV`) or to quit
    /// (`FSDQIT`). `fsdusr->flags & FBSAVE`, read by `goback()` after
    /// `xitfsd` decided.
    pub save: bool,
}

impl<A: Abi> Clone for Session<A> {
    fn clone(&self) -> Self {
        Self {
            full_screen: self.full_screen,
            whndun: self.whndun,
            save: self.save,
        }
    }
}

impl<A: Abi> std::fmt::Debug for Session<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("full_screen", &self.full_screen)
            .field("whndun", &self.whndun)
            .field("save", &self.save)
            .finish()
    }
}

impl<A: Abi> Default for Session<A> {
    fn default() -> Self {
        Self {
            full_screen: false,
            whndun: None,
            save: false,
        }
    }
}
