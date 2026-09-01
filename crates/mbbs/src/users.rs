//! The per-channel tables MajorBBS kept, and the layout the module indexes them by.
//!
//! MajorBBS's "current user" is three parallel arrays and one index between
//! them: `user[]` (`MAJORBBS.C:735`), `extusr[]` (`:736`) and the account block
//! `uablok` (`ACCOUNT.C:109`). Every one is `nterms` slots long, and `curusr`
//! is what holds the index still. The sizes below are what makes indexing them
//! arithmetic rather than a guess.
//!
//! # `sizeof(struct user)` is 41, and that is measured rather than derived
//!
//! `WCCMMUD.DLL` imports `_USER` (ordinal 625) at 58 sites and indexes the
//! array itself, so the stride is in the module's own code:
//!
//! ```text
//! *(int *)((int)_user_625 + _usrnum_628 * 0x29 + 6) = DAT_1118_0e0a;  /* ->state  */
//! *(int *)((int)_user_625 + _usrnum_628 * 0x29 + 8) = 0x38;           /* ->substt */
//! if ((*(byte *)((int)_user_625 + _usrnum_628 * 0x29 + 0x15) & 0x40) == 0) { ... }
//! ```
//!
//! `0x29` is 41, which is exactly what `MAJORBBS.H:74`'s seventeen fields add
//! up to under **byte alignment** -- Borland's default, and `CL.CFG` in the
//! recovered SDK passes no `-a`. A host that padded the trailing `char lcstat`
//! to a word would stride by 42 and put every channel but the first at the
//! wrong address.
//!
//! The offsets in [`UserLayout`] are pinned the same way: the module reaches
//! `+6`, `+8`, `+0x14`, `+0x15`, `+0x16` and `+0x1a`, off `usrptr` as well as
//! off `user[usrnum]`. Those three consecutive bytes at `+0x14`..`+0x16` are
//! one 4-byte `unsigned long flags`, and no other reading of the header
//! produces them.
//!
//! **41 is `WCCMMUD.DLL`'s own stride, not the only one.** It is `Wg16`'s
//! stride because `WCCMMUD.DLL` is a `GCV2` build; a non-`GCV2` build such as
//! `Wg32`'s has a differently-ordered `struct user` at a different stride
//! (88, measured against a real `WGSERVER.EXE`). See [`UserLayout::of`] and
//! [`crate::abi::Abi::GCV2`] for why the two are not one struct at two
//! widths.
//!
//! # The other two are arithmetic, and one of them is written down
//!
//! Nothing in `WCCMMUD.DLL` strides by `struct extusr` -- the module imports
//! neither `extusr` nor `extptr` -- so [`extusr_stride`] is the header's
//! eleven fields added up and nothing more, for the one ABI that has the
//! table at all. See [`extusr_stride`]'s own doc comment for why a non-GCV2
//! build (`Wg32`) has none.
//!
//! [`AccountLayout::stride`] would be the same, except that Galacticomm
//! recorded the total themselves. `USRACC.H:22` is `#define USRACCSPARE
//! (338-301)`: the declared fields come to 301 bytes and the spare array
//! pads the record to 338, so that it can grow without moving. That makes
//! 338 the size on disk as well as in memory (for `Wg16`; see
//! [`AccountLayout::of`] for why `Wg32` pads to 304 instead), and it is
//! what `ACCOUNT.C:108` opens `bbsusr.dat` with.

use std::io;

use mbbs_machine::ptr::ModulePtr;

use crate::ShimError;
use crate::abi::Abi;
use crate::chan::{Chan, Terms};

/// `sizeof(struct extusr)` for an ABI that has one, `None` for an ABI that
/// does not. `MAJORBBS.H:139`.
///
/// `struct extusr` is a GCV2 invention. Where a non-GCV2 build declares
/// `tckrst`, `tckonl`, `lingo`, `entstt`, `tspxt`, `col`, `wid`, `ech` and
/// `byecnt` inline in `struct user`, GCV2 moves them into a second per-channel
/// table and shortens `struct user` from 88 bytes to 41. So this is not a
/// table whose size varies -- it is a table that exists for one ABI and not the
/// other, and every caller has to say what it does when there is none.
///
/// Returning `None` rather than `Some(0)` is the whole point. A zero stride
/// would make `extoff(unum)` hand back the table head for every channel, which
/// reads as a working lookup right up until two channels disagree about their
/// own data.
pub fn extusr_stride<A: Abi>() -> Option<u16> {
    A::GCV2.then_some(22)
}

/// One field of a per-channel struct: where its first byte sits, and how many
/// bytes it occupies at this ABI's widths.
///
/// An offset alone is not enough to read a field. `struct user`'s `state` is a
/// C `int` -- two bytes under `Wg16`, four under `Wg32` -- so a reader that
/// knows only where it starts reads half of it and gets a plausible number.
/// That is the failure this type exists to make impossible: every call site
/// takes both halves from the same place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// Byte offset from the start of the slot.
    pub at: u16,
    /// How many bytes the field occupies.
    pub width: u8,
}

impl Field {
    pub(crate) const fn new(at: u16, width: u8) -> Self {
        Self { at, width }
    }
}

/// `struct user`'s stride and field offsets, at `A`'s own widths and field set.
///
/// The shape [`FndblkLayout`](crate::shims::stream) established for `ffblk`,
/// for the same reason: two ABIs whose records are not one record. This one is
/// worse than `ffblk` was, because the difference is not only width. See
/// [`Abi::GCV2`](crate::abi::Abi::GCV2).
///
/// # Which fields are here
///
/// Only the ones something reads. The rest of `MAJORBBS.H:98` is real, and is
/// what the arithmetic between these is made of, but a constant nothing indexes
/// by is a constant nothing checks.
///
/// # Why no field is optional
///
/// The design doc asked for fields that can be *absent*, so that asking for one
/// an ABI does not have fails loudly instead of returning a plausible zero.
/// That requirement is right and it is met -- one level up, at
/// [`Users::extra`]. Summing both branches of `MAJORBBS.H:98` shows non-GCV2 is
/// a strict superset of GCV2's field set: every field placed here exists in
/// both ABIs, at different offsets and sometimes different widths. What GCV2
/// does is move nine of them (`tckrst`, `tckonl`, `lingo`, `entstt`, `tspxt`,
/// `col`, `wid`, `ech`, `byecnt`) out into a separate `struct extusr`, which a
/// non-GCV2 build has no table for at all. So the thing that can be absent is
/// that whole table, not any field here, and an `Option` on each field would
/// have a `None` arm no caller could ever reach.
#[derive(Clone, Copy)]
pub struct UserLayout {
    /// `sizeof(struct user)` -- what `usroff` strides by.
    pub stride: u16,
    /// `INT usrcls` -- the class of channel this is (offline, or type of
    /// online). The module never reads it; the host does, to decide what a
    /// channel is before any module gets a look.
    pub usrcls: Field,
    /// `INT state` -- the module number in effect on this channel.
    pub state: Field,
    /// `INT substt` -- the module's own substate. `LUNATIX.DLL` dereferences
    /// `usrptr` at this offset at 134 sites, more than at any other, which is
    /// what a module's own state machine should look like.
    pub substt: Field,
    /// `ULONG flags` -- runtime flags, tested a byte at a time by the module
    /// and read-modify-written a bit at a time by [`Host::connect_state`].
    pub flags: Field,
    /// `SHORT crdrat` -- credit-consumption rate. A `SHORT` in both branches,
    /// which is why its width does not follow `INT_WIDTH`.
    pub crdrat: Field,
    /// `VOID (*polrou)()` -- the channel's current polling routine, or NULL.
    /// The module reads this one directly; see
    /// `docs/plans/2026-08-08-polling-design.md`.
    pub polrou: Field,
    /// `CHAR lcstat` -- LAN channel state, and the last declared byte in both
    /// branches.
    pub lcstat: Field,
}

impl UserLayout {
    /// `struct user` as `A`'s host declares it.
    pub fn of<A: Abi>() -> Self {
        if A::GCV2 {
            // `MAJORBBS.H:98`, `#ifdef GCV2`, at `Wg16`'s widths. `usrcls`
            // first; `flags` and `baud` demoted to the middle; `lingo`,
            // `entstt`, `tspxt`, `col`, `wid`, `ech` and `byecnt` living in
            // `struct extusr` instead. Sums to 41.
            Self {
                stride: 41,
                usrcls: Field::new(0x00, 2),
                state: Field::new(0x06, 2),
                substt: Field::new(0x08, 2),
                flags: Field::new(0x14, 4),
                crdrat: Field::new(0x1a, 2),
                polrou: Field::new(0x24, 4),
                lcstat: Field::new(40, 1),
            }
        } else {
            // `MAJORBBS.H:98`, `#ifndef GCV2`, at `Wg32`'s widths. `flags`
            // first, then two tick stamps and a `LONG baud` before `usrcls`
            // -- which is why every offset here is larger than a naive
            // "same struct, wider fields" reading predicts. Sums to 85,
            // padded to the 88 the oracle's allocation site pushes.
            Self {
                stride: 88,
                usrcls: Field::new(0x10, 4),
                state: Field::new(0x18, 4),
                substt: Field::new(0x1c, 4),
                flags: Field::new(0x00, 4),
                crdrat: Field::new(0x4c, 2),
                polrou: Field::new(0x48, 4),
                lcstat: Field::new(0x54, 1),
            }
        }
    }

    /// Every field this layout places, named, for checks that must cover all
    /// of them rather than the ones a test author remembered.
    pub fn fields(&self) -> [(&'static str, Field); 7] {
        [
            ("usrcls", self.usrcls),
            ("state", self.state),
            ("substt", self.substt),
            ("flags", self.flags),
            ("crdrat", self.crdrat),
            ("polrou", self.polrou),
            ("lcstat", self.lcstat),
        ]
    }
}

/// `struct usracc`'s stride and the field offsets this host writes, at `A`'s
/// own field set. `re/wg33src/INC/UStructs.h:20`.
///
/// # Only the stride is ABI-dependent
///
/// Unlike [`UserLayout`], the two branches of this struct share a declaration:
/// `GCV2` adds a trailing `CHAR spare[338-301]` and changes nothing in front of
/// it. Every field named here lives in the leading run of `CHAR` arrays and
/// single bytes, so all five offsets are identical for both ABIs and only
/// `sizeof` moves.
///
/// That is worth stating rather than assuming, because it is the reason
/// [`Host::connect_state`](crate::Host::connect_state) needed no change when
/// `Wg32` arrived while [`Users::account`] did: writing the *right* bytes of
/// the *wrong* record is exactly what a shared field offset and an unshared
/// stride produce, and it only becomes visible above channel zero.
#[derive(Clone, Copy, Debug)]
pub struct AccountLayout {
    /// `sizeof(struct usracc)` -- what `uacoff` strides by.
    pub stride: u16,
    /// `CHAR userid[UIDSIZ]` -- 30 bytes including the trailing NUL. What
    /// `obtbtvl` keys the character lookup on.
    pub userid: u16,
    /// `CHAR ansifl` -- ANSI flags. Bit `ANSON` is 1.
    pub ansifl: u16,
    /// `CHAR scnwid` -- screen width in columns. MajorMUD wants at least 80.
    pub scnwid: u16,
    /// `CHAR scnbrk` -- screen length for page breaks, i.e. how many lines
    /// `rstrxf` (`MAJORBBS.C:3776`) tells `btuxnf` to show before pausing
    /// (`cnt = scnbrk-CTNUOS`).
    ///
    /// **Never written by [`Host::connect_state`](crate::Host::connect_state)**
    /// -- it sets `userid`, `ansifl`, `scnwid` and `scnfse` and stops there,
    /// because this host has no account-level page-break setting to source
    /// one from. A channel therefore always reads this as whatever its
    /// account memory happened to hold, ordinarily zero. `shims::screen::rstrxf`'s
    /// own doc comment says what that does to its computed `cnt`.
    pub scnbrk: u16,
    /// `CHAR scnfse` -- screen length for full-screen entry. MajorMUD wants at
    /// least 23.
    pub scnfse: u16,
}

impl AccountLayout {
    /// `struct usracc` as `A`'s host declares it.
    pub fn of<A: Abi>() -> Self {
        Self {
            // 301 declared either way. GCV2 pads with `spare[338-301]` to a
            // round 338; non-GCV2 has no spare and pads only to the struct's
            // own 4-byte alignment, giving the 304 the oracle pushes.
            stride: if A::GCV2 { 338 } else { 304 },
            userid: 0x00,
            ansifl: 0xd0,
            scnwid: 0xd1,
            scnbrk: 0xd2,
            scnfse: 0xd3,
        }
    }
}

/// What a connecting user is.
///
/// On a real board `bbsusr.dat` decided these and `loadup()` read them. This
/// host has no accounts and is not going to grow them here -- the goal is
/// running a module headless, and the module cannot tell where the bytes came
/// from. It reads `usaptr` and has no way to ask.
pub struct Connection {
    /// `usracc.userid`. Keys the character lookup. Truncated to `UIDSIZ`
    /// (30) bytes if longer -- `psword` starts immediately after `userid`
    /// in the record, and a name that ran into it would corrupt the next
    /// field rather than merely being cut short.
    pub userid: String,
    /// `usracc.ansifl` bit `ANSON`.
    pub ansi: bool,
    /// `usracc.scnwid`. MajorMUD wants at least 80.
    pub width: u8,
    /// `usracc.scnfse`. MajorMUD wants at least 23.
    pub height: u8,
    /// What this user is allowed to do.
    ///
    /// Empty unless a caller says otherwise, and deliberately so: the login
    /// method decides access, and a default that granted anything would make
    /// every test's access an accident of this struct rather than a statement
    /// at the call site. See [`Connection::with_keys`].
    pub keys: crate::KeySet,
}

impl Connection {
    /// An ANSI terminal of the size MajorMUD's full-screen path requires.
    pub fn ansi(userid: &str) -> Self {
        Self {
            userid: userid.to_string(),
            ansi: true,
            width: 80,
            height: 24,
            keys: crate::KeySet::default(),
        }
    }

    /// A non-ANSI terminal, otherwise the same size as [`Connection::ansi`].
    ///
    /// `_EDIT_CHARACTER_STATS`'s fork (`WCCMMUD_decompiled.c:1799-1805`) is an
    /// `||` of three conditions -- `(ansifl & ANSON) == 0`, `scnfse < 23`,
    /// `scnwid < 80` -- any one of which sends it down `fsdroom(7, spec, 0)`
    /// (line mode) instead of `fsdroom(6, spec, 1)` (full-screen). Clearing
    /// `ansi` alone is the minimal difference from [`Connection::ansi`] that
    /// still takes that branch: it also matches what a real line-mode
    /// connection *is* -- a terminal too dumb for ANSI, not an ANSI terminal
    /// too small for it -- so `width`/`height` stay full-screen size rather
    /// than being shrunk to manufacture the same outcome.
    pub fn line_mode(userid: &str) -> Self {
        Self {
            ansi: false,
            ..Self::ansi(userid)
        }
    }

    /// The keys this user holds.
    ///
    /// This is the seam the whole design turns on. A real board resolved keys
    /// at logon, out of `bbsk.dat`, before any module could ask -- so keys
    /// belong to whatever authenticated the user, and this host has no opinion
    /// about where they came from. A DOS door, a PAM stack, a local keys file
    /// and a `bbsk.dat` reader are all just things that build a
    /// [`Connection`].
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.keys = crate::KeySet::new(keys);
        self
    }

    /// Give this user the master flag. **Read [`crate::KeySet::master`] first**
    /// -- it grants every lock, including the ones that ban you.
    pub fn master(mut self, yes: bool) -> Self {
        self.keys = std::mem::take(&mut self.keys).master(yes);
        self
    }
}

/// The per-channel tables, and where each one starts.
///
/// One allocation each, `nterms` slots long, exactly as `MAJORBBS.C:735-736`
/// and `ACCOUNT.C:109` made them. Held here rather than as three globals
/// because two of the three heads -- `extusr` and `uablok` -- are not globals
/// the module can address: `WCCMMUD.DLL` imports neither, and reaches the
/// account block only through `uacoff`.
///
/// # Generic type, split method surface
///
/// The four table-head fields and `vda`'s address are typed `A::Ptr` rather
/// than `FarPtr`, so this is genuinely `Users<A>`. [`Users::nth`] and the
/// accessors built on it ([`slot`](Users::slot), [`extra`](Users::extra),
/// [`account`](Users::account), [`vda`](Users::vda), plus [`head`](Users::head),
/// [`channels`](Users::channels), [`terms`](Users::terms), the keyring
/// accessors, and the private `state_at`/`substt_at`/`polrou_at`) touch no
/// `Machine` at all -- they are pure pointer arithmetic and bookkeeping over
/// fields this struct already owns -- so they live in `impl<A: Abi> Users<A>`
/// and are real for any ABI.
///
/// `alcvda`, `polrou`/`set_polrou` and `state`/`set_state`/`substt`/
/// `set_substt` do read or write module memory, so going generic changes
/// their signature (`&mut A::Mem`/`&A::Mem` and `&mut Heap<A>` in place of
/// `&mut Machine`/`&mut Heap`) -- a real break for shim call sites built
/// against the old ones. So each keeps its name and `Wg16` signature
/// (delegating into the generic core through [`Machine::mem`]/
/// [`Machine::mem_mut`], the same shape `Globals`/`TextVars`/`Streams`/
/// `Messages` use), and the generic core gets a new name per method --
/// `alcvda_mem`, `polrou_mem`/`set_polrou_mem`, `state_mem`/`set_state_mem`,
/// `substt_mem`/`set_substt_mem` -- the same `_mem` convention.
///
/// `new` stays `impl Users<Wg16>`-only outright: it is not in this task's
/// scope (see the top-level task list), and unlike the six methods above it
/// has no generic-core/`Wg16`-facade split to make -- there is exactly one
/// caller, `Host::load`, which is itself `Wg16`-only 16-bit loading
/// machinery.
///
/// `A` carries no default; every caller spells its ABI. It was `= Wg16` until
/// Task 3 of `docs/plans/2026-08-12-abi-border-implementation.md`.
pub struct Users<A: Abi> {
    /// How many channels there are: `nterms`, and the only thing that mints a
    /// [`Chan`] for these tables. The same value
    /// [`Gsbl`](crate::gsbl::Gsbl) was built from -- see [`crate::chan`].
    terms: Terms,
    /// `struct user` as this ABI declares it. Held rather than recomputed
    /// because `slot` is on the hot path of every poll.
    user: UserLayout,
    /// `struct usracc` as this ABI declares it. Held for the same reason
    /// [`Users::user`] is: [`Users::account`] is on the same hot path.
    usracc: AccountLayout,
    /// `struct user *user` -- the head of the array the module indexes itself.
    users: A::Ptr,
    /// `struct extusr *extusr` -- `None` for a non-GCV2 ABI, which has no such
    /// table. See [`extusr_stride`].
    extra: Option<A::Ptr>,
    /// `uablok`, `ACCOUNT.C:30` -- the account records, one per channel.
    accounts: A::Ptr,
    /// `int *channel` -- and this one points [`SENTINELS`] words *into* its own
    /// allocation, exactly as `MAJORBBS.C:741-743` left it.
    channels: A::Ptr,
    /// `vdahdl`, `MAJORBBS.C:1373` -- one volatile data area per channel, and
    /// how big each is. `None` until `alcvda`, which cannot run until every
    /// module's `dclvda` has been counted.
    vda: Option<(A::Ptr, u16)>,
    /// `usrptr->keys` -- what each channel is allowed to do.
    ///
    /// The fourth per-channel table, and the only one that does not live in
    /// module memory. `LOCKNKEY.C` kept a bitset here, indexed by `lockbit`'s
    /// interned lock array; `WCCMMUD.DLL` imports neither that field nor any
    /// routine that reads it, so there is nothing to be faithful *to* at the
    /// byte level and this is a [`crate::KeySet`] instead. See `keys.rs`.
    ///
    /// `None` is `keys == NULL`: a channel nobody has logged onto.
    /// `Some(empty)` is a channel that logged on holding nothing. The two are
    /// different answers, not the same one -- `low_haskey` (`LOCKNKEY.C:194`)
    /// tests the null before it tests the lock, so a never-logged-on channel
    /// refuses even an empty lock. `loadkeys()` allocated unconditionally, so
    /// the `None`-to-`Some` transition is exactly logon.
    keys: Vec<Option<crate::KeySet>>,
}

/// Words `MAJORBBS.C:740` puts *before* `channel[0]`, so that `channel[-1]`,
/// `[-2]` and `[-3]` are reads rather than accidents.
const SENTINELS: u16 = 3;

/// `CHAR col`'s offset inside `struct extusr`, for a GCV2 ABI (`Wg16`).
///
/// Not part of [`UserLayout`], for the same reason [`EXTUSR_WID`] is not --
/// see that constant's own doc comment. `lingo` (`SHORT`, 2 bytes) puts
/// `col` at offset 2, one byte wide, immediately before `wid`.
const EXTUSR_COL: Field = Field::new(0x02, 1);

/// `CHAR wid`'s offset inside `struct extusr`, for a GCV2 ABI (`Wg16`).
///
/// Not part of [`UserLayout`] -- a GCV2 build does not declare `wid` in
/// `struct user` at all; it is one of the nine fields `MAJORBBS.H:139`'s
/// `struct extusr` holds instead (see [`extusr_stride`]'s own doc comment).
/// Byte-packed like `struct user`, and summed the same way
/// [`extusr_stride`] itself was: `lingo` (`SHORT`, 2 bytes) then `col`
/// (`CHAR`, 1 byte) puts `wid` at offset 3, one byte wide -- and the six
/// fields after it (`ech`, `baud`, `tspxt`, `tckrst`, `tckonl`, `byecnt`,
/// `entstt`) still sum to the 22 `extusr_stride` already has independent
/// confirmation for (`an_extusr_slot_is_twenty_two_bytes`), which is why
/// this offset is trusted rather than re-measured from nothing.
const EXTUSR_WID: Field = Field::new(0x03, 1);

/// `CHAR ech`'s offset inside `struct extusr`, for a GCV2 ABI (`Wg16`).
///
/// Not part of [`UserLayout`], for the same reason [`EXTUSR_WID`] is not --
/// see that constant's own doc comment. Immediately after `wid`, one byte
/// wide, at offset 4 -- the sentinel byte `wid_mem_round_trips_through_extusr_
/// without_disturbing_its_neighbours` already pokes at this exact offset,
/// before this constant existed to name it.
const EXTUSR_ECH: Field = Field::new(0x04, 1);

/// `CHAR col`'s offset inside `struct user`, for a non-GCV2 ABI (`Wg32`).
///
/// `MAJORBBS.H:98`'s `#ifndef GCV2` branch keeps `col` inline, immediately
/// before `wid`. See [`WG32_USER_WID`]'s own doc comment for how this whole
/// neighbourhood (`col`/`wid`/`ech`/`byecnt` landing exactly on `lcstat`'s
/// already-measured 0x54) was derived.
const WG32_USER_COL: Field = Field::new(0x50, 1);

/// `CHAR wid`'s offset inside `struct user`, for a non-GCV2 ABI (`Wg32`).
///
/// `MAJORBBS.H:98`'s `#ifndef GCV2` branch keeps `wid` inline, immediately
/// after `col`. Computed the same way every other `Wg32` offset in
/// [`UserLayout::of`] was -- summing the declared fields in order at
/// 32-bit widths -- and checked against two fields that arithmetic already
/// measured independently: `col`/`wid` land at 0x50/0x51, and the two
/// fields after them (`ech` at 0x52, `byecnt` at 0x53) land exactly on
/// `lcstat`'s own already-measured 0x54
/// (`user_layout_matches_both_abis_declared_field_sets`'s `Wg32` half).
const WG32_USER_WID: Field = Field::new(0x51, 1);

/// `CHAR ech`'s offset inside `struct user`, for a non-GCV2 ABI (`Wg32`).
///
/// `MAJORBBS.H:98`'s `#ifndef GCV2` branch keeps `ech` inline, immediately
/// after `wid`. See [`WG32_USER_WID`]'s own doc comment for the derivation.
const WG32_USER_ECH: Field = Field::new(0x52, 1);

impl<A: Abi> Users<A> {
    /// How many channels there are -- and the only thing that names one.
    pub fn terms(&self) -> Terms {
        self.terms
    }

    /// The head of `user[]`, which is what the `user` global holds.
    pub fn head(&self) -> A::Ptr {
        self.users
    }

    /// The head of `channel[]`, which is three words *into* its allocation.
    pub fn channels(&self) -> A::Ptr {
        self.channels
    }

    /// `struct user` as this ABI declares it.
    pub fn user_layout(&self) -> &UserLayout {
        &self.user
    }

    /// `struct usracc` as this ABI declares it.
    pub fn account_layout(&self) -> &AccountLayout {
        &self.usracc
    }

    /// `sizeof(struct usracc)` -- what [`Users::account`] strides by.
    pub fn account_stride(&self) -> u16 {
        self.usracc.stride
    }

    /// `&user[unum]`.
    pub fn slot(&self, unum: Chan) -> A::Ptr {
        self.nth(self.users, self.user.stride, unum)
    }

    /// `&extusr[unum]`, or `None` if this ABI has no `extusr` table.
    ///
    /// See [`extusr_stride`] for why the `None` is a real answer and not a
    /// failure to look.
    pub fn extra(&self, unum: Chan) -> Option<A::Ptr> {
        let base = self.extra?;
        let stride = extusr_stride::<A>()?;
        Some(self.nth(base, stride, unum))
    }

    /// `uacoff(unum)` -- the channel's account record.
    pub fn account(&self, unum: Chan) -> A::Ptr {
        self.nth(self.accounts, self.usracc.stride, unum)
    }

    /// `vdaoff(unum)` -- the channel's volatile data area, or `None` if
    /// [`Users::alcvda`] has not run.
    ///
    /// `MAJORBBS.C:1380`. Null before `alcvda` is the answer the real host's
    /// `vdaoff` gave too, because `vdahdl` was still null: every module's
    /// `dclvda` has to be counted before the size is known.
    ///
    /// That is now the *only* thing a `None` here means. It used to mean either
    /// that or "no such channel", and a caller could not tell which.
    pub fn vda(&self, unum: Chan) -> Option<A::Ptr> {
        let (base, size) = self.vda?;
        Some(self.nth(base, size, unum))
    }

    /// What channel `unum` is allowed to do, or `None` if it never logged on.
    ///
    /// As with [`Users::vda`], the `None` now carries one meaning instead of
    /// two.
    pub fn keys(&self, unum: Chan) -> Option<&crate::KeySet> {
        self.keys[unum.index()].as_ref()
    }

    /// Give channel `unum` a keyring. What `loadkeys()` did at logon.
    pub fn set_keys(&mut self, unum: Chan, keys: crate::KeySet) {
        self.keys[unum.index()] = Some(keys);
    }

    /// Drop this channel's keyring entirely.
    ///
    /// `freekey()`, as `dftrst` calls it (`MAJORBBS.C:3492-3494`, guarded by
    /// `if (usrptr->keys != NULL)`). **Not the same as an empty
    /// [`KeySet`](crate::KeySet)**: the original tests the pointer for null, so
    /// "no keyring" and "a keyring holding nothing" are different states -- see
    /// the field's own documentation -- and this produces the first.
    pub fn clear_keys(&mut self, unum: Chan) {
        self.keys[unum.index()] = None;
    }

    /// The `unum`th slot of a table of `each`-byte entries.
    ///
    /// `MAJORBBS.C:4293`'s `if (0 <= uno && uno < nterms)` used to live here,
    /// restated once per table. It lives in [`Terms::chan`] now, and a [`Chan`]
    /// is what is left of having asked it.
    ///
    /// The add -- base plus `each * unum` -- goes through
    /// [`Abi::ptr_checked_add`], not [`Abi::ptr_offset`]: a table
    /// [`Users::table`] placed through `Heap::reserve_large` is larger than
    /// one segment, so the product no longer fits `ptr_offset`'s `u16`. The
    /// check is what turns an out-of-range `unum` into the named panic below
    /// rather than a wrapped offset.
    ///
    /// # Panics
    ///
    /// If the slot is past what this ABI's pointer can name. Unreachable for
    /// a `Chan` of this `Users`' own [`Terms`]: [`Users::table`] allocated
    /// `each * terms` bytes at `base` and that allocation succeeded, so every
    /// offset below it is addressable. A panic here means `unum` came from a
    /// larger `Terms` than the one that sized these tables.
    fn nth(&self, base: A::Ptr, each: u16, unum: Chan) -> A::Ptr {
        let by = usize::from(each) * unum.index();
        A::ptr_checked_add(base, by).unwrap_or_else(|| {
            panic!("channel {unum} is past the end of a table of {each}-byte slots")
        })
    }

    /// `&user[unum].state`.
    fn state_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), self.user.state.at)
    }

    /// `&user[unum].substt`.
    fn substt_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), self.user.substt.at)
    }

    /// `&user[unum].polrou`.
    fn polrou_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), self.user.polrou.at)
    }

    /// Read a [`Field`] whole, at its own width, and narrow it to a `u16`.
    ///
    /// The narrowing is checked. Silently truncating is the `cw3220mt` bug
    /// this repository already paid for once -- seventeen routines aliased
    /// onto a 32-bit module while six of them read a C `int` through
    /// `as u16`, which turned `fgets(buf, 40000, f)` into a negative length.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment, or the value does not fit a `u16`.
    fn field_u16(
        &self,
        mem: &A::Mem,
        unum: Chan,
        at: A::Ptr,
        field: Field,
        name: &'static str,
    ) -> Result<u16, ShimError> {
        let bytes = at
            .resolve(mem, usize::from(field.width))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let mut wide = [0u8; 4];
        wide[..bytes.len()].copy_from_slice(bytes);
        let value = u32::from_le_bytes(wide);
        u16::try_from(value).map_err(|_| {
            ShimError::Failed(format!(
                "user[{unum}].{name} is {value}, which does not fit the u16 this \
                 host carries state numbers in"
            ))
        })
    }

    /// Write a [`Field`] whole, at its own width.
    ///
    /// Zero-extends. A `u16` written into a four-byte `INT` must clear the
    /// high half rather than leave whatever the last occupant put there --
    /// `rstchn` clears a channel precisely so the next user does not inherit
    /// it, and a half-width write would defeat that quietly.
    fn write_field_u16(
        &self,
        mem: &mut A::Mem,
        at: A::Ptr,
        field: Field,
        value: u16,
    ) -> Result<(), ShimError> {
        let wide = u32::from(value).to_le_bytes();
        at.write(mem, &wide[..usize::from(field.width)])
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(())
    }

    /// `user[unum].polrou` -- the channel's polling routine, or `None` for
    /// NULL, against memory directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::polrou`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    /// Null is checked on the raw bytes rather than through an ABI-specific
    /// `NULL` constant, the same way [`TextVars::get_mem`](crate::textvar::TextVars::get_mem)
    /// does.
    ///
    /// # Errors
    ///
    /// If the read runs off the segment.
    pub fn polrou_mem(&self, mem: &A::Mem, unum: Chan) -> Result<Option<A::Ptr>, ShimError> {
        let bytes = self
            .polrou_at(unum)
            .resolve(mem, A::PTR_WIDTH)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let is_null = bytes.iter().all(|b| *b == 0);
        let rou = A::ptr_from_bytes(bytes);
        Ok((!is_null).then_some(rou))
    }

    /// Install or clear channel `unum`'s polling routine, against memory
    /// directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::set_polrou`]'s `Wg16` facade delegates
    /// into -- see the struct's own doc comment for why the two need
    /// different names.
    ///
    /// # Errors
    ///
    /// If the write runs off the segment.
    pub fn set_polrou_mem(
        &mut self,
        mem: &mut A::Mem,
        unum: Chan,
        rou: Option<A::Ptr>,
    ) -> Result<(), ShimError> {
        let bytes = match rou {
            Some(ptr) => A::ptr_to_bytes(ptr),
            None => vec![0u8; A::PTR_WIDTH],
        };
        self.polrou_at(unum)
            .write(mem, &bytes)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(())
    }

    /// `user[unum].state` -- which registered module this channel is in,
    /// against memory directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::state`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment, or the value does not fit a `u16`.
    ///
    /// Read at [`UserLayout::state`]'s own width, not at a literal 2. `state`
    /// is a C `INT`: two bytes under `Wg16` and four under `Wg32`, and a
    /// two-byte read of a four-byte field returns a plausible number rather
    /// than an error.
    ///
    /// The return stays `u16` because every state number this host deals in
    /// fits one -- module numbers are small and `MAJORBBS.C` compares them to
    /// `nmodul` -- and widening it would push an `A::Int` through every
    /// caller for no information gained. A `Wg32` value that does not fit is
    /// a real error and says so rather than truncating.
    pub fn state_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        self.field_u16(mem, unum, self.state_at(unum), self.user.state, "state")
    }

    /// Put channel `unum` in state `state`, against memory directly rather
    /// than a whole `Machine`.
    ///
    /// The generic core [`Users::set_state`]'s `Wg16` facade delegates
    /// into -- see the struct's own doc comment for why the two need
    /// different names.
    ///
    /// # Errors
    ///
    /// If the write runs off the segment.
    pub fn set_state_mem(&mut self, mem: &mut A::Mem, unum: Chan, state: u16) -> Result<(), ShimError> {
        let at = self.state_at(unum);
        self.write_field_u16(mem, at, self.user.state, state)
    }

    /// `user[unum].usrcls` -- what kind of channel this is, against memory
    /// directly rather than a whole `Machine`. Same width caveat as
    /// [`Users::state_mem`].
    ///
    /// # Errors
    ///
    /// If the read runs off a segment, or the value does not fit a `u16`.
    pub fn usrcls_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        let at = A::ptr_offset(self.slot(unum), self.user.usrcls.at);
        self.field_u16(mem, unum, at, self.user.usrcls, "usrcls")
    }

    /// `user[unum].flags` -- the whole `ULONG`, against memory directly
    /// rather than a whole `Machine`.
    ///
    /// **Not routed through [`Users::field_u16`].** `flags` is a bitfield,
    /// not a magnitude -- `WCCMMUD.DLL` tests individual bits of it
    /// (`lib.rs`'s own `MASTER` write is the host's side of that) -- and
    /// `field_u16` refuses any value that does not fit sixteen bits. A
    /// caller that only wants one high bit (`INVISB` is `shims::user`'s,
    /// `MASTER` is `lib.rs`'s) should not have a *different* high bit, set by
    /// something else entirely, turn its read into an error. This reads the
    /// field whole, at its own width, and leaves the masking to the caller.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment.
    pub fn flags_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u32, ShimError> {
        let at = A::ptr_offset(self.slot(unum), self.user.flags.at);
        let bytes = at
            .resolve(mem, usize::from(self.user.flags.width))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let mut wide = [0u8; 4];
        wide[..bytes.len()].copy_from_slice(bytes);
        Ok(u32::from_le_bytes(wide))
    }

    /// `usrptr->flags |= bits`, at the field's own width.
    ///
    /// The read-modify-write [`Users::flags_mem`] leaves to its callers, done
    /// once here so `entmdl`'s `usrptr->flags|=X2MAIN` (`MENUING.C:664`) is a
    /// call and not a third open-coded copy of the same three lines.
    ///
    /// # Errors
    ///
    /// If the read or the write runs off the segment.
    pub fn or_flags_mem(&mut self, mem: &mut A::Mem, unum: Chan, bits: u32) -> Result<(), ShimError> {
        let flags = self.flags_mem(mem, unum)? | bits;
        let at = A::ptr_offset(self.slot(unum), self.user.flags.at);
        at.write(mem, &flags.to_le_bytes()[..usize::from(self.user.flags.width)])
            .map_err(|e| ShimError::Failed(e.to_string()))
    }

    /// `user[unum].substt` -- the registered module's own substate, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::substt`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    /// Same width caveat as [`Users::state_mem`].
    ///
    /// # Errors
    ///
    /// If the read runs off a segment, or the value does not fit a `u16`.
    pub fn substt_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        self.field_u16(mem, unum, self.substt_at(unum), self.user.substt, "substt")
    }

    /// Put channel `unum` in substate `substt`, against memory directly
    /// rather than a whole `Machine`.
    ///
    /// The generic core [`Users::set_substt`]'s `Wg16` facade delegates
    /// into -- see the struct's own doc comment for why the two need
    /// different names.
    ///
    /// # Errors
    ///
    /// If the write runs off the segment.
    pub fn set_substt_mem(
        &mut self,
        mem: &mut A::Mem,
        unum: Chan,
        substt: u16,
    ) -> Result<(), ShimError> {
        let at = self.substt_at(unum);
        self.write_field_u16(mem, at, self.user.substt, substt)
    }

    /// Where a `struct extusr`-relocated field lives for this ABI, and how
    /// wide it is -- the shape `wid`/`col`/`ech` all share.
    ///
    /// Not one offset off one base: GCV2 (`Wg16`) moved all three out of
    /// `struct user` entirely, into `struct extusr` ([`Users::extra`]);
    /// non-GCV2 (`Wg32`) never moved them, and each is read inline off
    /// [`Users::slot`] instead. `gcv2`/`wg32` are the pair of constants for
    /// whichever one field this call is resolving -- [`EXTUSR_WID`]/
    /// [`WG32_USER_WID`] and their `col`/`ech` siblings -- and `name` is only
    /// for the error message, so a GCV2 host with no `extusr` table says
    /// which field it failed to find rather than just "some field".
    fn extusr_field(&self, unum: Chan, name: &str, gcv2: Field, wg32: Field) -> Result<(A::Ptr, Field), ShimError> {
        if A::GCV2 {
            let base = self.extra(unum).ok_or_else(|| {
                ShimError::Failed(format!(
                    "user[{unum}].{name}: this ABI is GCV2 but built no extusr table"
                ))
            })?;
            Ok((A::ptr_offset(base, gcv2.at), gcv2))
        } else {
            Ok((A::ptr_offset(self.slot(unum), wg32.at), wg32))
        }
    }

    /// Where `usrptr->wid` lives for this ABI. See [`Users::extusr_field`].
    fn wid_field(&self, unum: Chan) -> Result<(A::Ptr, Field), ShimError> {
        self.extusr_field(unum, "wid", EXTUSR_WID, WG32_USER_WID)
    }

    /// Where `usrptr->col` lives for this ABI. See [`Users::extusr_field`].
    fn col_field(&self, unum: Chan) -> Result<(A::Ptr, Field), ShimError> {
        self.extusr_field(unum, "col", EXTUSR_COL, WG32_USER_COL)
    }

    /// Where `usrptr->ech` lives for this ABI. See [`Users::extusr_field`].
    fn ech_field(&self, unum: Chan) -> Result<(A::Ptr, Field), ShimError> {
        self.extusr_field(unum, "ech", EXTUSR_ECH, WG32_USER_ECH)
    }

    /// `usrptr->wid` -- the secret-character-echo line width, against
    /// memory directly rather than a whole `Machine`. See [`Users::wid_field`]
    /// for where this actually reads from.
    ///
    /// # Errors
    ///
    /// If the read runs off the segment, or (GCV2 only, and unreachable for
    /// any `Users` this crate constructs -- [`Users::new`] always builds the
    /// `extusr` table alongside `struct user` for a GCV2 ABI) if this ABI
    /// has no `extusr` table.
    pub fn wid_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u8, ShimError> {
        let (at, field) = self.wid_field(unum)?;
        let bytes = at
            .resolve(mem, usize::from(field.width))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(bytes[0])
    }

    /// Write `usrptr->wid`, against memory directly rather than a whole
    /// `Machine`. See [`Users::wid_mem`].
    ///
    /// # Errors
    ///
    /// Same as [`Users::wid_mem`].
    pub fn set_wid_mem(&mut self, mem: &mut A::Mem, unum: Chan, value: u8) -> Result<(), ShimError> {
        let (at, _field) = self.wid_field(unum)?;
        at.write(mem, &[value]).map_err(|e| ShimError::Failed(e.to_string()))
    }

    /// `usrptr->col` -- the secret-echo column cursor `echsec` resets to
    /// zero, against memory directly rather than a whole `Machine`. See
    /// [`Users::wid_mem`] for the ABI-split this shares.
    ///
    /// Nothing on this host reads it back: `secchi`, the only real reader
    /// (`MAJORBBS.C:4577`), has no shim here -- see `shims::user::echsec`'s
    /// own doc comment for what that costs. The accessor exists anyway so a
    /// write lands at the true vendor byte rather than nowhere, and so a
    /// test can prove it does.
    ///
    /// # Errors
    ///
    /// Same as [`Users::wid_mem`].
    pub fn col_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u8, ShimError> {
        let (at, field) = self.col_field(unum)?;
        let bytes = at
            .resolve(mem, usize::from(field.width))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(bytes[0])
    }

    /// Write `usrptr->col`. See [`Users::col_mem`].
    ///
    /// # Errors
    ///
    /// Same as [`Users::wid_mem`].
    pub fn set_col_mem(&mut self, mem: &mut A::Mem, unum: Chan, value: u8) -> Result<(), ShimError> {
        let (at, _field) = self.col_field(unum)?;
        at.write(mem, &[value]).map_err(|e| ShimError::Failed(e.to_string()))
    }

    /// `usrptr->ech` -- the character `secchi` would echo back in place of
    /// whatever was typed, against memory directly rather than a whole
    /// `Machine`. See [`Users::col_mem`] for why this is write-observable
    /// only through a test, not through any consumer this host runs.
    ///
    /// # Errors
    ///
    /// Same as [`Users::wid_mem`].
    pub fn ech_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u8, ShimError> {
        let (at, field) = self.ech_field(unum)?;
        let bytes = at
            .resolve(mem, usize::from(field.width))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(bytes[0])
    }

    /// Write `usrptr->ech`. See [`Users::ech_mem`].
    ///
    /// # Errors
    ///
    /// Same as [`Users::wid_mem`].
    pub fn set_ech_mem(&mut self, mem: &mut A::Mem, unum: Chan, value: u8) -> Result<(), ShimError> {
        let (at, _field) = self.ech_field(unum)?;
        at.write(mem, &[value]).map_err(|e| ShimError::Failed(e.to_string()))
    }

    /// Allocate `size` bytes of volatile data area per channel, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// `MAJORBBS.C:1373`, `vdahdl=alcblok(nterms,vdasiz)` -- one table, laid
    /// out by [`Users::table`].
    ///
    /// The generic core [`Users::alcvda`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If the heap has no room, or the table is larger than this ABI's pointer
    /// can span -- see [`Users::table`].
    pub fn alcvda_mem(
        &mut self,
        mem: &mut A::Mem,
        heap: &mut crate::Heap<A>,
        size: u16,
    ) -> io::Result<()> {
        let at = Self::table(mem, heap, size, self.terms.count())?;
        self.vda = Some((at, size));
        Ok(())
    }
}

impl<A: Abi> Users<A> {
    /// One per-channel table: `count` slots of `each` bytes, zeroed.
    ///
    /// The vendor made these with `alcblok(nterms, size)` (`MAJORBBS.C:1021`,
    /// `:1373`; `ACCOUNT.C:110`), whose flat branch is one `alczer` of the
    /// whole product with no ceiling. This is that: the byte count is sized
    /// at full width and branches on the *value*, exactly as `shims::memory`'s
    /// `alcmem`/`alczer` do -- fits `u16`, and it packs into a shared region
    /// through [`Heap::reserve`](crate::Heap::reserve); does not, and it takes
    /// a region of its own through
    /// [`Heap::reserve_large`](crate::Heap::reserve_large). 128 channels of
    /// MajorMUD-NT's 1961-byte VDA is 251,008 bytes, and until this branch
    /// existed `mbbs-server --terms 128` stopped at "128 channels of 1961
    /// bytes".
    ///
    /// Under `Wg16` the large branch refuses: no far pointer addresses across
    /// a segment, and the vendor's own 16-bit `alcblok` split such a table
    /// into globs (`shims::memory::alcblok`) that this host's tables do not
    /// build. That is a clean refusal naming the table, not a gap this
    /// function papers over.
    ///
    /// # Errors
    ///
    /// If the heap has no room, or the table does not fit this ABI's pointer.
    fn table(
        mem: &mut A::Mem,
        heap: &mut crate::Heap<A>,
        each: u16,
        count: u16,
    ) -> io::Result<A::Ptr> {
        let bytes = usize::from(each) * usize::from(count);
        let at = match u16::try_from(bytes) {
            Ok(small) => heap.reserve(mem, small),
            Err(_) => heap.reserve_large(mem, bytes),
        }
        .map_err(|e| io::Error::other(format!("{count} channels of {each} bytes: {e}")))?;
        at.write(mem, &vec![0u8; bytes])
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(at)
    }

    /// Allocate `terms` channels' worth of everything, zeroed.
    ///
    /// `alczer` and not `alcmem`, at `MAJORBBS.C:735-736`, and `ACCOUNT.C:112`
    /// follows its `alcblok` with a `setmem(...,0)` over every slot. A channel
    /// whose `state` came up as whatever the heap last held would be in some
    /// module the module never entered.
    ///
    /// Takes `&mut A::Mem` rather than the `&mut Machine` it was written
    /// with. Construction was left 16-bit on the reasoning `Globals`' doc
    /// comment still gives -- "construction and 32-bit widths are a later
    /// task's concern" -- but nothing here was ever 16-bit in substance: the
    /// three allocations are [`Heap::reserve`], the fills are
    /// [`ModulePtr::write`], and the sentinel arithmetic is
    /// [`Abi::ptr_offset`]. All three had generic forms already, and the only
    /// thing pinning this to `Wg16` was that it had not been asked.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    pub fn new(mem: &mut A::Mem, heap: &mut crate::Heap<A>, terms: Terms) -> io::Result<Self> {
        let user = UserLayout::of::<A>();
        let usracc = AccountLayout::of::<A>();
        let count = terms.count();
        let users = Self::table(mem, heap, user.stride, count)?;
        // Allocated only for an ABI that has the struct. A non-GCV2 host never
        // made this table, and reserving heap for it here would be inventing
        // storage the module has no name for.
        let extra = match extusr_stride::<A>() {
            Some(each) => Some(Self::table(mem, heap, each, count)?),
            None => None,
        };
        let accounts = Self::table(mem, heap, usracc.stride, count)?;

        // `MAJORBBS.C:740-743`, which is three statements doing one thing:
        //
        //     setmem(channel=(int *)alcmem((nterms+3)*2),(nterms+3)*2,-1);
        //     *channel++=-3;     /* note: channel[-3] == -3 */
        //     *channel++=-2;     /*       channel[-2] == -2 */
        //     *channel++=-1;     /*       channel[-1] == -1 */
        //
        // Three words of slack in front, filled with their own negative index,
        // and then the pointer walks past them -- so `channel[-1]` is a read
        // that yields -1 rather than whatever precedes the block. That matters
        // because `usrnum` is -1 whenever nobody is on a channel, and
        // `channel[usrnum]` is what a module puts in a log line.
        let words = count
            .checked_add(SENTINELS)
            .and_then(|words| words.checked_mul(2))
            .ok_or_else(|| io::Error::other(format!("{count} channels of channel[]")))?;
        let base = heap
            .reserve(mem, words)
            .map_err(|e| io::Error::other(e.to_string()))?;
        base.write(mem, &vec![0xffu8; usize::from(words)])
            .map_err(|e| io::Error::other(e.to_string()))?;
        for (index, value) in [-3i16, -2, -1].into_iter().enumerate() {
            let at = A::ptr_offset(base, index as u16 * 2);
            at.write(mem, &value.to_le_bytes())
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        let channels = A::ptr_offset(base, SENTINELS * 2);

        // `MAJORBBS.C:878` -- `channel[usrnum]=0` with `usrnum` still zero,
        // the local console. Reached only when no hardware channel groups are
        // configured, which is this host: no serial board.
        //
        // Only channel zero is written. Every other entry keeps the `-1` the
        // whole block was filled with, which is the same value the three
        // sentinels in front of it carry -- so at more than one channel a read
        // of `channel[1]` is indistinguishable from a read of `channel[-1]`.
        // Harmless for MajorMUD, which does not import `channel` (ordinal 97)
        // at all, and left as it is rather than invented: the real host filled
        // these in from configured channel groups, and this host has none to
        // read. Whoever gives this host real hardware or a real transport owes
        // the rest of the array.
        channels
            .write(mem, &0i16.to_le_bytes())
            .map_err(|e| io::Error::other(e.to_string()))?;

        Ok(Self {
            terms,
            user,
            usracc,
            users,
            extra,
            accounts,
            channels,
            vda: None,
            keys: vec![None; usize::from(count)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Wg16, Wg32};

    #[test]
    fn a_user_slot_is_the_forty_one_bytes_the_module_strides_by() {
        // Not arithmetic from the header alone. `WCCMMUD.DLL` imports `_USER`
        // and indexes the array itself, and every one of those sites strides by
        // `0x29`:
        //
        //     *(int *)((int)_user_625 + _usrnum_628 * 0x29 + 6) = ...
        //
        // 0x29 is 41, which is what `MAJORBBS.H:74` adds up to under Borland's
        // default byte alignment -- `CL.CFG` in the recovered SDK passes no
        // `-a`. A host that padded the trailing `char lcstat` to a word would
        // put every channel but the first at the wrong address.
        assert_eq!(UserLayout::of::<Wg16>().stride, 0x29);
    }

    #[test]
    fn the_user_fields_are_where_the_module_reaches_for_them() {
        // Every one of these offsets appears in `WCCMMUD.DLL`, off `usrptr` and
        // off `user[usrnum]` both. `FLAGS` is the load-bearing one: the module
        // tests `+0x14 & 2`, `+0x15 & 0x40` and `+0x16 & 0x80`, which are three
        // bytes of a single 4-byte field and rule out every other layout.
        let user = UserLayout::of::<Wg16>();
        assert_eq!(user.state.at, 6);
        assert_eq!(user.substt.at, 8);
        assert_eq!(user.flags.at, 0x14);
        assert_eq!(user.crdrat.at, 0x1a);
        assert_eq!(user.lcstat.at, 40);
    }

    #[test]
    fn every_user_field_fits_inside_a_slot() {
        // The check that makes the two tests above one fact rather than two
        // lists: the last field is one byte, and it ends exactly at the stride.
        let user = UserLayout::of::<Wg16>();
        assert_eq!(user.lcstat.at + 1, user.stride, "lcstat is the last byte of a slot");
        assert!(user.flags.at + 4 <= user.stride, "flags is a long and must fit");
    }

    #[test]
    fn an_extusr_slot_is_twenty_two_bytes() {
        // `MAJORBBS.H:94`, byte-aligned like `struct user`. Nothing in
        // `WCCMMUD.DLL` strides by it -- the module imports neither `extusr`
        // nor `extptr` -- so unlike `USER` this one is arithmetic from the
        // header. It is here because `curusr`'s array is real whether or not
        // this module looks at it. `Wg16` is the GCV2 build this crate has
        // always run, and is the only ABI with a table to measure; see
        // `extusr_exists_for_gcv2_only` for the `Wg32` half.
        assert_eq!(extusr_stride::<Wg16>(), Some(22));
    }

    #[test]
    fn every_channel_gets_a_slot_in_all_three_tables() {
        let f = crate::testing::Fixture::new();
        let users = f.host.users();
        assert_eq!(users.terms().count(), 1, "one channel, as `nterms` says");
        for unum in users.terms().all() {
            // Every one of these is infallible now, so what is left to assert
            // is that the slots are distinct and inside the tables -- which
            // `nth`'s own panic covers. The loop stands as the statement that
            // every channel `terms` names has a slot in all three.
            assert_ne!(
                users.slot(unum),
                users.extra(unum).expect("Wg16 is GCV2, extusr exists"),
                "user[{unum}] vs extusr[{unum}]"
            );
            assert_ne!(users.slot(unum), users.account(unum), "user[{unum}] vs uacoff({unum})");
        }
    }

    #[test]
    fn the_slots_are_a_stride_apart() {
        // The only way a second channel is reachable at all. Checked over a
        // table sized past `nterms` so that the arithmetic is tested even
        // though this host has one channel -- a stride bug would otherwise be
        // invisible until the day `nterms` moved.
        let mut machine = mbbs_machine::m16::Machine::new().expect("machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let terms = Terms::new(4);
        // Annotated because `Users::new` is generic now: this test reads
        // `.offset` off the returned pointers, which only a `FarPtr` has, so
        // the fixture has to say which ABI it means rather than leave `A` to
        // inference that no longer has anything to work from.
        let users: Users<Wg16> =
            Users::new(machine.mem_mut(), &mut heap, terms).expect("four channels");
        let ch = |n| terms.chan(n).expect("one of the four");
        let at = |n| users.slot(ch(n)).offset;
        let stride = UserLayout::of::<Wg16>().stride;
        assert_eq!(at(1) - at(0), stride);
        assert_eq!(at(3) - at(2), stride);
        assert_eq!(
            users.account(ch(1)).offset - users.account(ch(0)).offset,
            AccountLayout::of::<Wg16>().stride
        );
    }

    #[test]
    fn a_per_channel_table_may_exceed_one_segment_under_wg32() {
        // 128 channels of MajorMUD-NT's 1961-byte VDA is 251,008 bytes. The
        // vendor's flat `alcblok` (`ALCBLOK.C`, non-`GCDOS`) took that in one
        // `alczer` with no ceiling; this host answered `mbbs-server --terms
        // 128` with "128 channels of 1961 bytes" because every table's byte
        // count was a `u16`.
        let mut mem = mbbs_machine::m32::Memory::new(4 * 1024 * 1024).expect("arena");
        let mut heap = crate::Heap::new(crate::Config::default());
        let terms = Terms::new(128);
        let mut users: Users<Wg32> =
            Users::new(&mut mem, &mut heap, terms).expect("128 channels");
        users
            .alcvda_mem(&mut mem, &mut heap, 1961)
            .expect("128 areas of 1961 bytes");
        let ch = |n| terms.chan(n).expect("one of the 128");
        let first = users.vda(ch(0)).expect("allocated");
        let last = users.vda(ch(127)).expect("allocated");
        assert_eq!(last.0 - first.0, 127 * 1961);
        // The last slot is memory, not an address past the block.
        last.write(&mut mem, &[0xa5; 1961]).expect("writable");
        assert_eq!(
            users.account(ch(127)).0 - users.account(ch(0)).0,
            127 * u32::from(AccountLayout::of::<Wg32>().stride)
        );
    }

    #[test]
    fn a_per_channel_table_past_one_segment_is_refused_under_wg16() {
        // No far pointer addresses across a segment, and the vendor's own
        // 16-bit `alcblok` split such a table into globs this host does not
        // build -- so the answer is a refusal naming the table, not a panic
        // and not a wrapped offset.
        let mut machine = mbbs_machine::m16::Machine::new().expect("machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let terms = Terms::new(128);
        let mut users: Users<Wg16> =
            Users::new(machine.mem_mut(), &mut heap, terms).expect("128 channels");
        let err = users
            .alcvda_mem(machine.mem_mut(), &mut heap, 1961)
            .expect_err("251,008 bytes in one 16-bit segment");
        assert!(err.to_string().contains("128 channels of 1961 bytes"), "{err}");
    }

    #[test]
    fn a_channel_that_does_not_exist_cannot_be_named() {
        // `curusr`'s guard is `0 <= uno && uno < nterms`, so out of range has
        // to be answerable as *absent* rather than as some address. A table
        // that returned a pointer here would hand the module the bytes after
        // the last channel and call them channel 1.
        //
        // The guard is `Terms::chan` now, asked once, instead of one copy per
        // table -- so this asserts that nothing past the end can be named at
        // all, rather than that four separate lookups each said `None`.
        let f = crate::testing::Fixture::new();
        let terms = f.host.users().terms();
        assert!(terms.chan(-1).is_none(), "there is no channel -1");
        assert!(
            terms.chan(terms.count() as i16).is_none(),
            "one past the end"
        );
    }

    #[test]
    fn the_tables_start_zeroed() {
        // `alczer`, not `alcmem`, at MAJORBBS.C:735 -- and `ACCOUNT.C:112`
        // follows `alcblok` with a `setmem(...,0)` over every slot. A channel
        // whose `state` came up as whatever the heap last held would be in some
        // module the module never entered.
        let f = crate::testing::Fixture::new();
        let console = f.console();
        let at = f.host.users().slot(console);
        let stride = UserLayout::of::<Wg16>().stride;
        let bytes = f.machine.resolve(at, usize::from(stride)).expect("readable");
        assert!(bytes.iter().all(|b| *b == 0), "a fresh channel is all zero");
    }

    #[test]
    fn the_user_global_points_at_channel_zero() {
        // `MAJORBBS.H:345` declares `struct user *user`, and the module indexes
        // off it rather than being handed a slot: `_user_625 + usrnum * 0x29`.
        // Null here is not "no users" -- it is a segment-zero dereference at
        // the module's first `user[0].state`.
        let f = crate::testing::Fixture::new();
        let console = f.console();
        let head = f.host.globals().pointer(&f.machine, "user").expect("user");
        assert_ne!(head, mbbs_machine::m16::FarPtr::NULL, "the module dereferences this");
        assert_eq!(head, f.host.users().slot(console));
        assert_eq!(head, f.host.users().head());
    }

    #[test]
    fn the_channel_table_has_three_sentinels_before_it() {
        // `MAJORBBS.C:740-743` allocates `nterms+3` words, fills them with -1,
        // writes -3, -2, -1 into the first three and advances the pointer past
        // them. The comments in that source say what for: `channel[-1] == -1`
        // is a legal read. It has to be, because `usrnum` is -1 for as long as
        // no user is on a channel, and `channel[usrnum]` is what a module puts
        // in a log line. Without these three words that read is off the front
        // of the block and returns whatever the heap holds.
        let f = crate::testing::Fixture::new();
        let at = f.host.globals().pointer(&f.machine, "channel").expect("channel");
        assert_ne!(at, mbbs_machine::m16::FarPtr::NULL);
        let word = |delta: i16| -> i16 {
            let from = mbbs_machine::m16::FarPtr {
                offset: at.offset.wrapping_add((delta * 2) as u16),
                selector: at.selector,
            };
            let bytes = f.machine.resolve(from, 2).expect("readable");
            i16::from_le_bytes([bytes[0], bytes[1]])
        };
        assert_eq!(word(-3), -3);
        assert_eq!(word(-2), -2);
        assert_eq!(word(-1), -1);
    }

    #[test]
    fn the_local_console_is_channel_zero() {
        // `MAJORBBS.C:878` -- `channel[usrnum]=0`, reached with `usrnum` still
        // zero because no hardware channel groups are configured. This host has
        // exactly that shape: one channel, no serial hardware.
        let f = crate::testing::Fixture::new();
        let at = f.host.globals().pointer(&f.machine, "channel").expect("channel");
        let bytes = f.machine.resolve(at, 2).expect("readable");
        assert_eq!(i16::from_le_bytes([bytes[0], bytes[1]]), 0);
    }

    #[test]
    fn the_volatile_data_area_is_not_allocated_until_after_init() {
        // `MAJORBBS.C:896` calls `alcvda()` *after* `inimod()`, because
        // `dclvda` is still accumulating `vdasiz` while modules initialise.
        // Null through init is not an omission -- it is the order the real host
        // ran in, and a host that allocated in `Host::new` would size the area
        // off a `vdasiz` of zero.
        let f = crate::testing::Fixture::new();
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs_machine::m16::FarPtr::NULL
        );
    }

    #[test]
    fn alcvda_gives_every_channel_an_area_and_the_host_a_spare() {
        // `vdahdl=alcblok(nterms,vdasiz)` and `vdatmp=alcmem(vdasiz)`. `vdatmp`
        // is a separate block, not a slot -- `fsdapr(vdaptr, vdasiz, vdatmp)`
        // hands the FSD both at once and they must not be the same bytes.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.invoke(crate::shims::system::dclvda, &[512]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");

        let g = f.host.globals();
        let area = g.pointer(&f.machine, "vdaptr").expect("vdaptr");
        let temp = g.pointer(&f.machine, "vdatmp").expect("vdatmp");
        assert_ne!(area, mbbs_machine::m16::FarPtr::NULL);
        assert_ne!(temp, mbbs_machine::m16::FarPtr::NULL);
        assert_ne!(area, temp, "the area and the scratch copy are two blocks");
        assert_eq!(area, f.host.users().vda(console).expect("allocated"));
    }

    /// The step that was missing, and the guard that makes forgetting it loud.
    ///
    /// `Host::alcvda` was correct and complete for weeks, and nothing in the
    /// crate ever called it -- every caller was a test. The cost was not an
    /// error: `vdatmp` stayed null, and MajorMUD's `_EDIT_CHARACTER_STATS`
    /// tests that pointer before it draws anything and returns silently when it
    /// is null. Character creation took the player's answer, computed the whole
    /// character, and stopped without a word. **A missing step that produces a
    /// silent wall is worse than one that produces a crash**, so this refuses.
    #[test]
    fn a_host_that_never_finished_initialising_refuses_to_connect() {
        // Deliberately NOT a `Fixture`: a fixture has finished starting up,
        // which is the whole point of this test's opposite.
        let mut machine = mbbs_machine::m16::Machine::new().expect("16-bit machine");
        let mut host = crate::Host::<crate::abi::Wg16>::new(
            &mut machine,
            crate::testing::data(),
            Terms::new(crate::globals::NTERMS),
        )
        .expect("host");
        let console = host.users().terms().chan(0).expect("channel zero");
        let who = Connection::ansi("someone");

        let e = host
            .connect_state(&mut machine, console, &who)
            .expect_err("a host that skipped finish_init");
        assert!(e.to_string().contains("finish_init"), "{e}");

        host.finish_init(&mut machine).expect("finished");
        host.connect_state(&mut machine, console, &who)
            .expect("and now it connects");
    }

    /// Finishing initialisation is what allocates the volatile data areas.
    ///
    /// `MAJORBBS.C:896` runs `alcvda()` immediately after `inimod()`, because
    /// `dclvda` is still accumulating `vdasiz` while modules initialise.
    #[test]
    fn finishing_initialisation_allocates_what_dclvda_asked_for() {
        let mut f = crate::testing::Fixture::new();
        f.invoke(crate::shims::system::dclvda, &[512]).expect("declared");
        f.host.finish_init(&mut f.machine).expect("finished");

        let g = f.host.globals();
        assert_ne!(
            g.pointer(&f.machine, "vdatmp").expect("vdatmp"),
            mbbs_machine::m16::FarPtr::NULL,
            "vdatmp is the pointer MajorMUD gates character creation on"
        );
        assert_ne!(
            g.pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs_machine::m16::FarPtr::NULL
        );
    }

    #[test]
    fn alcvda_does_nothing_when_no_module_declared_a_size() {
        // The `if (vdasiz != 0)` guard. Allocating zero bytes is an error this
        // heap refuses outright, so the guard is load-bearing and not decorative.
        let mut f = crate::testing::Fixture::new();
        f.host.alcvda(&mut f.machine).expect("nothing to do");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs_machine::m16::FarPtr::NULL
        );
    }

    #[test]
    fn a_connection_lands_on_the_bytes_the_module_gates_its_output_on() {
        // WCCMMUD_named.c:11201 --
        //   if ((usaptr[0xd0] & 1) == 0 || usaptr[0xd3] < 0x17 || usaptr[0xd1] < 0x50)
        // Fail any of the three and MajorMUD prints the degraded rendering.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("channel 0");
        let at = f.host.users().account(console);
        let account = AccountLayout::of::<Wg16>();
        let rec = f.machine.resolve(at, account.stride as usize).expect("in bounds");

        // `0xd0`/`0xd1`/`0xd3`, not `account.ansifl`/`.scnwid`/`.scnfse`,
        // deliberately: `connect_state` (`lib.rs`) writes through this same
        // `AccountLayout`, so reading back through it too would only prove
        // the two agree with each other, not that either is where
        // `WCCMMUD_named.c:11201` (quoted above) actually looks. These are
        // the same literals `account_layout_moves_the_stride_and_not_the_fields`
        // pins independently.
        assert_eq!(&rec[..9], b"rangerdan", "userid keys the character lookup");
        assert_eq!(rec[0xd0] & 1, 1, "ANSON");
        assert!(rec[0xd1] >= 0x50, "80 columns");
        assert!(rec[0xd3] >= 0x17, "23 rows");
    }

    #[test]
    fn a_connection_names_the_channel_the_module_will_run_on() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("channel 0");
        let at = f.host.users().slot(console);
        let user = UserLayout::of::<Wg16>();
        let rec = f.machine.resolve(at, user.stride as usize).expect("in bounds");
        assert_eq!(rec[user.state.at as usize], 0, "state is set by connect()");
        assert_eq!(rec[user.substt.at as usize], 0);
    }

    #[test]
    fn a_userid_longer_than_uidsiz_is_truncated_rather_than_overrunning_psword() {
        // `UIDSIZ` (`UStructs.h:10`) is 30 *including the trailing zero* --
        // the comment says so -- so only 29 characters fit and byte 29 must
        // be the NUL. `psword` starts immediately after `userid` in the
        // record, at 30; a connection whose name is longer than that must
        // lose the tail of the name, not spill into the password field that
        // follows it.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let long = "a".repeat(40);
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi(&long))
            .expect("channel 0");
        let at = f.host.users().account(console);
        let account = AccountLayout::of::<Wg16>();
        let rec = f.machine.resolve(at, account.stride as usize).expect("in bounds");

        assert_eq!(&rec[..29], vec![b'a'; 29].as_slice(), "29 characters, not 30");
        assert_eq!(rec[29], 0, "byte 29 is the trailing zero UIDSIZ counts in");
        assert!(
            rec[30..40].iter().all(|&b| b == 0),
            "nothing past userid was written -- psword starts at 30 and stays zero: {:?}",
            &rec[30..40]
        );
    }

    #[test]
    fn a_shorter_second_userid_does_not_leave_the_first_ones_tail_behind() {
        // R13: connect_state only ever `take` bytes, so a channel reused by a
        // shorter name kept whatever the longer, earlier name left behind --
        // "rangerdan" then "dan" read back as "dangerdan". `userid` is what
        // `obtbtvl` keys the character lookup on (`WCCMMUD_named.c:9847`), so
        // that splice hands the second user someone else's identity.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("channel 0, first connect");
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("dan"))
            .expect("channel 0, second connect");

        let at = f.host.users().account(console);
        let account = AccountLayout::of::<Wg16>();
        let rec = f.machine.resolve(at, account.stride as usize).expect("in bounds");

        assert_eq!(&rec[..3], b"dan", "the second userid");
        assert!(
            rec[3..30].iter().all(|&b| b == 0),
            "no tail of \"rangerdan\" survives past the new name: {:?}",
            &rec[3..30]
        );
    }

    /// `connect_state` no longer has a refusal of its own to make -- the caller
    /// cannot name a channel past the end to hand it. This asserts the refusal
    /// where it lives now.
    #[test]
    fn a_channel_past_the_end_cannot_be_connected_because_it_cannot_be_named() {
        let f = crate::testing::Fixture::new();
        let terms = f.host.users().terms();
        assert!(terms.chan(terms.count() as i16).is_none());
    }

    #[test]
    fn a_channel_nobody_connected_to_has_no_keyring_at_all() {
        // `usrptr->keys == NULL` -- `loadkeys()` has not run. Distinct from a
        // channel that logged on holding nothing, and `low_haskey` answers the
        // two differently; see `shims::user::haskey`.
        let f = crate::testing::Fixture::new();
        let console = f.console();
        assert!(f.host.users().keys(console).is_none());
    }

    #[test]
    fn connecting_gives_the_channel_the_keys_it_arrived_with() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let who = Connection::ansi("rangerdan").with_keys(["USER"]);
        f.host.connect_state(&mut f.machine, console, &who).expect("channel 0");

        let keys = f.host.users().keys(console).expect("the channel logged on");
        assert!(keys.evaluate("USER"));
        assert!(!keys.evaluate("WCCSYSOP"));
    }

    #[test]
    fn connecting_with_no_keys_is_a_keyring_holding_nothing_not_the_absence_of_one() {
        // `loadkeys()` (LOCKNKEY.C:97) allocates unconditionally, even for a user
        // whose `bbsk.dat` record is blank -- so `keys` goes non-NULL at logon
        // whatever the user holds. The distinction is observable: an empty lock
        // is true for a channel holding nothing and false for one that never
        // logged on.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("channel 0");

        let keys = f.host.users().keys(console).expect("logged on, holding nothing");
        assert!(keys.evaluate(""), "an empty lock is true once logged on");
        assert!(!keys.evaluate("USER"));
    }

    #[test]
    fn a_reconnecting_channel_does_not_keep_the_previous_users_keys() {
        // R13's shape, for the keyring: `connect_state` runs again on a channel
        // that already held a user, and the second user must not inherit the
        // first one's access.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("sysop").with_keys(["USER", "WCCSYSOP"]),
            )
            .expect("first connect");
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("guest").with_keys(["USER"]),
            )
            .expect("second connect");

        let keys = f.host.users().keys(console).expect("logged on");
        assert!(keys.evaluate("USER"));
        assert!(!keys.evaluate("WCCSYSOP"), "the sysop's key did not survive");
    }

    #[test]
    fn the_master_flag_lands_on_the_bit_majorbbs_h_names() {
        // MASTER is 0x40 in the low byte of `user.flags`, offset 0x14
        // (MAJORBBS.H:206). WCCMMUD tests that byte only with masks 2, 4 and
        // 0x10, so this bit is host-private -- written for fidelity, and because
        // a host that kept the flag only in Rust would have `user.flags` lying.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let who = Connection::ansi("root").with_keys(["USER"]).master(true);
        f.host.connect_state(&mut f.machine, console, &who).expect("channel 0");

        let at = f.host.users().slot(console);
        let user = UserLayout::of::<Wg16>();
        let rec = f.machine.resolve(at, user.stride as usize).expect("in bounds");
        assert_eq!(rec[user.flags.at as usize] & 0x40, 0x40);
    }

    #[test]
    fn connecting_without_the_master_flag_clears_it_and_leaves_its_neighbours() {
        // Read-modify-write on bit 0x40 alone. The other bits of `flags` are the
        // module's -- WCCMMUD sets and tests 2, 4, 0x10 in this same byte -- and
        // a whole-field store would clear them out from under it. The clear
        // direction matters too: a channel reused by a non-master must not keep
        // the last user's master flag.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("root").master(true),
            )
            .expect("first connect");

        // Whatever the module had set in the rest of the byte.
        let at = f.host.users().slot(console);
        let flags = mbbs_machine::m16::FarPtr {
            offset: at.offset + UserLayout::of::<Wg16>().flags.at,
            selector: at.selector,
        };
        let was = f.machine.resolve(flags, 1).expect("in bounds")[0];
        f.machine.write(flags, &[was | 0x16]).expect("in bounds");

        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("guest"))
            .expect("second connect");

        let now = f.machine.resolve(flags, 1).expect("in bounds")[0];
        assert_eq!(now & 0x40, 0, "the master flag is cleared");
        assert_eq!(now & 0x16, 0x16, "the module's own bits survive");
    }

    #[test]
    fn polrou_round_trips_through_the_bytes_the_module_reads() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let rou = mbbs_machine::m16::FarPtr {
            offset: 0x2184,
            selector: 0x1010,
        };

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            None,
            "a fresh slot is NULL, because alczer zeroed it"
        );

        f.host
            .users
            .set_polrou_mem(f.machine.mem_mut(), console, Some(rou))
            .expect("channel 0");
        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            Some(rou)
        );

        // What `WCCMMUD_named.c:12241` actually reads: the two words at
        // `user[unum] + 0x24` and `+ 0x26`.
        //
        // `0x24` is written out rather than taken from `UserLayout::polrou`,
        // and that is the whole point of this assertion. An address derived
        // from the field under test moves when the field moves, so the write
        // and the check stay in agreement no matter how wrong both are -- it
        // can only prove the accessor agrees with itself. The literal is the
        // independent statement of `MAJORBBS.H:90`'s offset that makes a
        // wrong `polrou` observable.
        let slot = f.host.users().slot(console);
        let at = mbbs_machine::m16::FarPtr {
            offset: slot.offset + 0x24,
            selector: slot.selector,
        };
        assert_eq!(
            f.machine.resolve(at, 4).expect("in the slot"),
            &[0x84, 0x21, 0x10, 0x10],
            "offset then selector, little-endian"
        );

        f.host
            .users
            .set_polrou_mem(f.machine.mem_mut(), console, None)
            .expect("channel 0");
        assert_eq!(
            f.machine.resolve(at, 4).expect("in the slot"),
            &[0, 0, 0, 0],
            "NULL is four zero bytes, which is what the module tests for"
        );
    }

    /// Likewise: `polrou` used to answer `Err` for a channel that did not
    /// exist, and now cannot be asked about one. Its `Err` is a segment fault
    /// and nothing else.
    #[test]
    fn polrou_cannot_be_asked_about_a_channel_that_does_not_exist() {
        let f = crate::testing::Fixture::new();
        let terms = f.host.users().terms();
        assert!(terms.chan(1).is_none(), "nterms is 1");
        assert!(terms.chan(-1).is_none());
    }

    #[test]
    fn set_state_writes_where_the_module_reads_state() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();

        assert_eq!(f.host.users().state_mem(f.machine.mem(), console).expect("read"), 0);

        f.host
            .users
            .set_state_mem(f.machine.mem_mut(), console, 7)
            .expect("write");
        assert_eq!(f.host.users().state_mem(f.machine.mem(), console).expect("read"), 7);

        // The literal `+6`, not `UserLayout::state`, for the same reason
        // `polrou_round_trips_through_the_bytes_the_module_reads` uses a
        // literal `0x24`: an address derived from the constant under test
        // could only prove the accessor agrees with itself.
        let slot = f.host.users().slot(console);
        let at = mbbs_machine::m16::FarPtr {
            offset: slot.offset + 6,
            selector: slot.selector,
        };
        assert_eq!(f.machine.resolve(at, 2).expect("in the slot"), &[7, 0]);
    }

    /// Both ABIs' `struct user`, asserted explicitly so a mutation to either is
    /// visible.
    ///
    /// # Where these numbers come from
    ///
    /// Not from this host. `Wg32`'s stride is the literal in the allocation
    /// site of the real Worldgroup host's own user table, read off
    /// `archive/_acquire/pools/full/cfca0b96eae9602a_WGSERVER.EXE` at
    /// VA `0x4210c8`:
    ///
    /// ```text
    /// 6a 58                 push 0x58            ; sizeof(struct user) = 88
    /// 66 a1 c0 48 45 00     mov  ax,ds:0x4548c0  ; nterms
    /// 50                    push eax
    /// e8 4e 6a 01 00        call 0x437b24        ; alloc(count, elemsize)
    /// ```
    ///
    /// `usroff` itself carries no multiply -- it tail-calls a shared accessor
    /// that reads the element size back out of the block header the allocator
    /// wrote -- so the allocation site is the only place the number is a
    /// compile-time immediate. The same `push 0x58` appears byte-for-byte in
    /// the sibling build `bfe3ab588c1273a4_WGSERVER.EXE` at VA `0x41f0fc`.
    ///
    /// The field offsets are the `#ifndef GCV2` branch of
    /// `re/wg33src/INC/MAJORBBS.H:98` summed at 32-bit widths, which lands on
    /// 85 declared and 88 padded -- selecting that branch exactly, where the
    /// GCV2 branch computes to 64. Eleven of them were independently read off
    /// instructions in the oracle; see the design doc's table.
    #[test]
    fn user_layout_matches_both_abis_declared_field_sets() {
        use crate::abi::Wg32;

        let wg16 = UserLayout::of::<Wg16>();
        assert_eq!(wg16.stride, 41, "Wg16: GCV2 at 16-bit widths, and the odd \
                                     trailing `lcstat` byte is why it is not 42");
        assert_eq!(wg16.usrcls, Field { at: 0x00, width: 2 }, "Wg16 usrcls");
        assert_eq!(wg16.state, Field { at: 0x06, width: 2 }, "Wg16 state");
        assert_eq!(wg16.substt, Field { at: 0x08, width: 2 }, "Wg16 substt");
        assert_eq!(wg16.flags, Field { at: 0x14, width: 4 }, "Wg16 flags -- a ULONG \
                                                              even at 16-bit INT");
        assert_eq!(wg16.crdrat, Field { at: 0x1a, width: 2 }, "Wg16 crdrat");
        assert_eq!(wg16.polrou, Field { at: 0x24, width: 4 }, "Wg16 polrou -- a far \
                                                               pointer, 4 bytes");
        assert_eq!(wg16.lcstat, Field { at: 40, width: 1 }, "Wg16 lcstat");

        let wg32 = UserLayout::of::<Wg32>();
        assert_eq!(wg32.stride, 88, "Wg32: the `push 0x58` in the oracle");
        assert_eq!(wg32.flags, Field { at: 0x00, width: 4 }, "Wg32 flags -- non-GCV2 \
                                                              puts it first, not at 0x14");
        assert_eq!(wg32.usrcls, Field { at: 0x10, width: 4 }, "Wg32 usrcls");
        assert_eq!(wg32.state, Field { at: 0x18, width: 4 }, "Wg32 state");
        assert_eq!(wg32.substt, Field { at: 0x1c, width: 4 }, "Wg32 substt -- the \
                                                               offset LunatiX \
                                                               dereferences at 134 sites");
        assert_eq!(wg32.polrou, Field { at: 0x48, width: 4 }, "Wg32 polrou");
        assert_eq!(wg32.crdrat, Field { at: 0x4c, width: 2 }, "Wg32 crdrat -- still a \
                                                               SHORT, after polrou not \
                                                               before it");
        assert_eq!(wg32.lcstat, Field { at: 0x54, width: 1 }, "Wg32 lcstat -- last, \
                                                               and 0x55 declared rounds \
                                                               to the 0x58 stride");

        // The two ABIs are not one struct at two widths. If a refactor ever
        // makes these agree, it has collapsed a real distinction.
        assert_ne!(wg16.usrcls.at, wg32.usrcls.at, "GCV2 puts usrcls first; \
                                                    non-GCV2 puts flags first");
        assert_ne!(wg16.flags.at, wg32.flags.at, "and the same in reverse");
    }

    /// Every placed field lies inside its own slot.
    ///
    /// A field whose last byte runs past `stride` would read the next
    /// channel's record -- silently, because a wrong `int` read still returns
    /// a number. Cheap to state, and it is the one property no offset table
    /// can satisfy by accident.
    #[test]
    fn every_placed_field_fits_inside_the_stride() {
        use crate::abi::Wg32;

        for (name, layout) in [
            ("Wg16", UserLayout::of::<Wg16>()),
            ("Wg32", UserLayout::of::<Wg32>()),
        ] {
            for (field_name, field) in layout.fields() {
                let end = usize::from(field.at) + usize::from(field.width);
                assert!(
                    end <= usize::from(layout.stride),
                    "{name}: {field_name} ends at {end}, past the {}-byte stride",
                    layout.stride
                );
            }
        }
    }

    #[test]
    fn set_substt_writes_where_the_module_reads_substt() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();

        assert_eq!(
            f.host.users().substt_mem(f.machine.mem(), console).expect("read"),
            0
        );

        f.host
            .users
            .set_substt_mem(f.machine.mem_mut(), console, 1)
            .expect("write");
        assert_eq!(
            f.host.users().substt_mem(f.machine.mem(), console).expect("read"),
            1
        );

        // The literal `+8`, for the reason `set_state_writes_where_the_
        // module_reads_state`'s own literal is.
        let slot = f.host.users().slot(console);
        let at = mbbs_machine::m16::FarPtr {
            offset: slot.offset + 8,
            selector: slot.selector,
        };
        assert_eq!(f.machine.resolve(at, 2).expect("in the slot"), &[1, 0]);
    }

    /// `or_flags_mem` sets its bits and leaves every other bit alone.
    ///
    /// Both halves of a `LONG` are exercised on purpose. `X2MAIN` alone is
    /// `0x400`, so a writer that narrowed the field to a word would still
    /// answer correctly for the one caller this exists for; `MONALL`
    /// (`MAJORBBS.H`, `0x00010000L`) is in the high word and a narrowed write
    /// loses it.
    #[test]
    fn or_flags_mem_sets_bits_without_disturbing_the_rest() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();

        let slot = f.host.users().slot(console);
        let flags = mbbs_machine::m16::FarPtr {
            offset: slot.offset + UserLayout::of::<Wg16>().flags.at,
            selector: slot.selector,
        };
        f.machine
            .write(flags, &0x0002_0002u32.to_le_bytes())
            .expect("in bounds");

        f.host
            .users
            .or_flags_mem(f.machine.mem_mut(), console, 0x0001_0400)
            .expect("write");

        assert_eq!(
            f.host.users().flags_mem(f.machine.mem(), console).expect("read"),
            0x0003_0402,
            "both bits are set and both that were there survive"
        );
        assert_eq!(
            f.machine.resolve(flags, 4).expect("in bounds"),
            &0x0003_0402u32.to_le_bytes(),
            "and it landed in the module's own four bytes"
        );
    }

    /// `struct usracc` at both ABIs.
    ///
    /// # The stride moves and the fields do not
    ///
    /// `re/wg33src/INC/UStructs.h:20` declares one struct with a trailing
    /// `spare[USRACCSPARE]` gated on `GCV2`, where
    /// `#define USRACCSPARE (338-301)`. So the *declaration* is shared and only
    /// the tail differs: every field this host writes sits in the leading
    /// `CHAR` region -- `userid[30]`, `psword[10]`, five `NADSIZ` name/address
    /// lines, `usrpho[16]`, then eight single bytes -- none of which has a
    /// width that varies and none of which needs alignment padding. Summing
    /// them puts `ansifl` at 208, `scnwid` 209, `scnbrk` 210, `scnfse` 211 in
    /// *both* branches, which is why only the stride is ABI-dependent here.
    ///
    /// The non-GCV2 declaration sums to 301 and the struct's alignment is 4
    /// (it carries five `LONG`s), so `sizeof` is 304. Measured rather than
    /// trusted: `push 0x130` at the account table's allocation site in
    /// `cfca0b96eae9602a_WGSERVER.EXE` (VA `0x40128e` -- `0x40129b` is the
    /// `call` thirteen bytes later, which earlier drafts of this comment and
    /// the plan both cited by mistake), counted by the same
    /// `nterms` global `ds:0x4548c0` the user table's site uses, and present at
    /// VA `0x401281` in *both* sibling builds.
    #[test]
    fn account_layout_moves_the_stride_and_not_the_fields() {
        use crate::abi::Wg32;

        let wg16 = AccountLayout::of::<Wg16>();
        let wg32 = AccountLayout::of::<Wg32>();

        assert_eq!(wg16.stride, 338, "Wg16: GCV2, 301 declared plus 37 spare");
        assert_eq!(wg32.stride, 304, "Wg32: the `push 0x130` in the oracle -- \
                                      301 declared, padded to the struct's \
                                      4-byte alignment");
        assert_ne!(wg16.stride, wg32.stride, "the account table is not one \
                                              stride for both ABIs, and othusp \
                                              is what notices");

        for (name, layout) in [("Wg16", &wg16), ("Wg32", &wg32)] {
            assert_eq!(layout.userid, 0x00, "{name} userid");
            assert_eq!(layout.ansifl, 0xd0, "{name} ansifl");
            assert_eq!(layout.scnwid, 0xd1, "{name} scnwid");
            assert_eq!(layout.scnbrk, 0xd2, "{name} scnbrk");
            assert_eq!(layout.scnfse, 0xd3, "{name} scnfse");
        }
    }

    /// `struct extusr` exists in GCV2 builds and nowhere else.
    ///
    /// This is the absence the design doc asked [`UserLayout`] to model, in the
    /// place it actually occurs. GCV2 moves nine fields -- `tckrst`, `tckonl`,
    /// `lingo`, `entstt`, `tspxt`, `col`, `wid`, `ech`, `byecnt` -- out of
    /// `struct user` and into a second per-channel table
    /// (`MAJORBBS.H:139`). A non-GCV2 build keeps them inline and has no such
    /// table, which the oracle confirms from the other side: of the twelve
    /// calls to `WGSERVER.EXE`'s table allocator, the two counted by `nterms`
    /// stride by 88 and 304, and nothing strides by anything `extusr`-shaped.
    ///
    /// So asking a `Wg32` host for a channel's `extusr` is not a lookup that
    /// returns zeros -- it is a question with no answer, and it says so.
    #[test]
    fn extusr_exists_for_gcv2_only() {
        use crate::abi::Wg32;

        assert_eq!(
            extusr_stride::<Wg16>(),
            Some(22),
            "Wg16 is GCV2, so struct extusr is real and is 22 bytes"
        );
        assert_eq!(
            extusr_stride::<Wg32>(),
            None,
            "Wg32 is non-GCV2: those nine fields are inline in struct user, \
             and there is no second table to index"
        );
    }

    /// `echonu` (`MAJORBBS.C:4548`) reads `usrptr->wid` directly, and `wid`
    /// is not at the same address for both ABIs -- GCV2 moved it into
    /// `struct extusr`. This is the offsets alone, before any shim exists to
    /// call them: [`EXTUSR_WID`] must sit inside the 22-byte `extusr` slot,
    /// and [`WG32_USER_WID`] must sit inside `struct user`'s own 88-byte
    /// `Wg32` stride, distinct from where `Wg16` would have put it.
    #[test]
    fn wid_is_at_a_different_address_for_each_abi() {
        use crate::abi::Wg32;

        assert_eq!(EXTUSR_WID, Field::new(0x03, 1), "lingo (2) + col (1) puts wid at 3");
        assert!(
            u16::from(EXTUSR_WID.at) + u16::from(EXTUSR_WID.width)
                <= extusr_stride::<Wg16>().expect("Wg16 has extusr"),
            "wid must fit inside the 22-byte extusr slot"
        );

        assert_eq!(WG32_USER_WID, Field::new(0x51, 1));
        let wg32 = UserLayout::of::<Wg32>();
        assert!(
            u16::from(WG32_USER_WID.at) + u16::from(WG32_USER_WID.width) <= wg32.stride,
            "wid must fit inside struct user's own 88-byte Wg32 stride"
        );
        // Not the same offset repurposed for the other ABI's `struct user` --
        // Wg16's `struct user` has no `wid` at all, so a shared offset here
        // would be a coincidence, not a design.
        assert_ne!(
            u16::from(EXTUSR_WID.at),
            u16::from(WG32_USER_WID.at),
            "one is extusr-relative, the other is user-slot-relative -- \
             agreeing would be an accident"
        );
    }

    /// `Users::wid_mem`/`set_wid_mem` round-trip through `extusr`, not
    /// through `struct user` -- and leave `extusr`'s neighbouring fields
    /// alone. This is the test that would have caught writing `wid` at the
    /// wrong offset, the exact class of bug this session has already hit
    /// four times (`user`, `usracc`, `module`, `FILE`).
    #[test]
    fn wid_mem_round_trips_through_extusr_without_disturbing_its_neighbours() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();

        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            0,
            "a fresh channel's extusr is zeroed"
        );

        // Sentinel bytes either side of `wid` (`col` at 0x02, `ech` at
        // 0x04), written directly rather than through an accessor this
        // crate does not have yet -- so a `wid` write that lands one byte
        // short or long is caught here, not just a `wid` write that lands
        // in the completely wrong table.
        let extra = f.host.users().extra(console).expect("Wg16 has extusr");
        let col_at = mbbs_machine::m16::FarPtr { offset: extra.offset + 0x02, selector: extra.selector };
        let ech_at = mbbs_machine::m16::FarPtr { offset: extra.offset + 0x04, selector: extra.selector };
        f.machine.write(col_at, &[0xAA]).expect("sentinel written");
        f.machine.write(ech_at, &[0xBB]).expect("sentinel written");

        f.host
            .users_mut()
            .set_wid_mem(f.machine.mem_mut(), console, 40)
            .expect("write");
        assert_eq!(f.host.users().wid_mem(f.machine.mem(), console).expect("read"), 40);

        assert_eq!(f.machine.resolve(col_at, 1).expect("readable")[0], 0xAA, "col untouched");
        assert_eq!(f.machine.resolve(ech_at, 1).expect("readable")[0], 0xBB, "ech untouched");

        // And not in `struct user` either -- a fresh slot is all zero
        // (`the_tables_start_zeroed`), so a `wid` write that landed there
        // instead would show up as a nonzero byte somewhere in it.
        let slot = f.host.users().slot(console);
        let stride = UserLayout::of::<Wg16>().stride;
        let bytes = f.machine.resolve(slot, usize::from(stride)).expect("readable");
        assert!(bytes.iter().all(|b| *b == 0), "struct user is untouched by a wid write");
    }

    /// `Users::col_mem`/`set_col_mem` and `ech_mem`/`set_ech_mem` round-trip
    /// through `extusr`, the same way [`wid_mem_round_trips_through_extusr_
    /// without_disturbing_its_neighbours`] already proved for `wid` -- and
    /// `wid` itself, sitting directly between them at 0x03, is the sentinel
    /// this time: a `col` or `ech` write that landed one byte short or long
    /// would show up here as `wid` corruption instead.
    #[test]
    fn col_and_ech_mem_round_trip_through_extusr_without_disturbing_wid() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();

        assert_eq!(f.host.users().col_mem(f.machine.mem(), console).expect("read"), 0);
        assert_eq!(f.host.users().ech_mem(f.machine.mem(), console).expect("read"), 0);

        f.host
            .users_mut()
            .set_wid_mem(f.machine.mem_mut(), console, 0xCC)
            .expect("sentinel write");

        f.host
            .users_mut()
            .set_col_mem(f.machine.mem_mut(), console, 7)
            .expect("write");
        f.host
            .users_mut()
            .set_ech_mem(f.machine.mem_mut(), console, b'*')
            .expect("write");

        assert_eq!(f.host.users().col_mem(f.machine.mem(), console).expect("read"), 7);
        assert_eq!(f.host.users().ech_mem(f.machine.mem(), console).expect("read"), b'*');
        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            0xCC,
            "col/ech writes must not have touched wid, sitting between them"
        );
    }
}
