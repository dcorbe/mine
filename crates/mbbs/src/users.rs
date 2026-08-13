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
//! The offsets in [`user`] are pinned the same way: the module reaches `+6`,
//! `+8`, `+0x14`, `+0x15`, `+0x16` and `+0x1a`, off `usrptr` as well as off
//! `user[usrnum]`. Those three consecutive bytes at `+0x14`..`+0x16` are one
//! 4-byte `unsigned long flags`, and no other reading of the header produces
//! them.
//!
//! # The other two are arithmetic, and one of them is written down
//!
//! Nothing in `WCCMMUD.DLL` strides by `struct extusr` -- the module imports
//! neither `extusr` nor `extptr` -- so [`EXTUSR`] is the header's eleven fields
//! added up and nothing more.
//!
//! [`USRACC`] would be the same, except that Galacticomm recorded the total
//! themselves. `USRACC.H:22` is `#define USRACCSPARE (338-301)`: the declared
//! fields come to 301 bytes and the spare array pads the record to 338, so that
//! it can grow without moving. That makes 338 the size on disk as well as in
//! memory, and it is what `ACCOUNT.C:108` opens `bbsusr.dat` with.

use std::io;

use mbbs_machine::ptr::ModulePtr;

use crate::ShimError;
use crate::abi::Abi;
use crate::chan::{Chan, Terms};

/// `sizeof(struct user)`, `MAJORBBS.H:74`. See the module header: this is the
/// `0x29` the module strides by, not arithmetic from the declaration.
pub const USER: u16 = 41;

/// `sizeof(struct extusr)`, `MAJORBBS.H:94`.
pub const EXTUSR: u16 = 22;

/// `sizeof(struct usracc)`, `USRACC.H:24`, and the 338 that `:22` writes down.
pub const USRACC: u16 = 338;

/// Field offsets within `struct user`.
///
/// Only the five the module reaches for. The rest of `MAJORBBS.H:74` is real
/// and is what the arithmetic between these is made of, but a constant nothing
/// indexes by is a constant nothing checks.
pub mod user {
    /// `int usrcls` -- the class of channel this is (console, remote, etc).
    /// `MAJORBBS.H:74`'s GCV2 layout puts it first. The module itself never
    /// reads it -- the host does, to decide what a channel is before any
    /// module gets a look -- so there is no call site to cite, only the
    /// header's own field order.
    pub const USRCLS: u16 = 0;
    /// `int state` -- the module number in effect on this channel. Assigned the
    /// module's own state number at 14 sites.
    pub const STATE: u16 = 6;
    /// `int substt` -- the module's own substate. Assigned `0x38`, `0x82`,
    /// `0x0b`, `0x11`..`0x15` and `0x84`..`0x88`.
    pub const SUBSTT: u16 = 8;
    /// `unsigned long flags` -- runtime flags. Tested a byte at a time:
    /// `+0x14 & 2/4/0x10`, `+0x15 & 0x40`, `+0x16 & 0x80`.
    pub const FLAGS: u16 = 0x14;
    /// `int crdrat` -- credit-consumption rate. Assigned at `+0x1a`.
    pub const CRDRAT: u16 = 0x1a;
    /// `void (*polrou)()` -- the channel's current polling routine, or NULL.
    /// `MAJORBBS.H:90`, four bytes.
    ///
    /// **The module reads this one.** `WCCMMUD_named.c:12241` indexes
    /// `user[usrnum]` by hand and tests `+0x24` and `+0x26` for zero before
    /// calling `begin_polling`, so unlike the keyring at offset 2 this field
    /// cannot live Rust-side. See
    /// `docs/plans/2026-08-08-polling-design.md`.
    pub const POLROU: u16 = 0x24;
    /// `char lcstat` -- LAN channel state, and the odd byte that makes the
    /// stride 41 and not 42.
    pub const LCSTAT: u16 = 40;
}

/// Field offsets within `struct usracc` (`UStructs.h:20`, v10 SDK).
///
/// The five this crate reads. **`UIDSIZ` is 30 here, not the 10 of the
/// v6 header** -- every offset below moves if that is got wrong, and nothing
/// would report it except the module quietly taking a different branch.
///
/// Independently derived, not copied: adding up `UStructs.h:21-34` under the
/// same byte alignment `struct user` uses (`userid[30]`, `psword[10]`,
/// `usrnam[30]`, `usrad1..4[30]` each, `usrpho[16]`, then the two one-byte
/// flags `systyp` and `usrprf`) lands `ansifl` at 208 (`0xd0`), `scnwid` at
/// 209 (`0xd1`), `scnbrk` at 210 (`0xd2`) and `scnfse` at 211 (`0xd3`).
/// Continuing the same sum through `birthd` totals exactly 301 declared
/// bytes, which is what `USRACC.H:22`'s `#define USRACCSPARE (338-301)` says
/// it should be -- so the total and the four offsets confirm each other.
pub mod usracc {
    /// `sizeof(struct usracc)`. `USRACC.H:22`'s `(338-301)` writes the total
    /// down, which is why this is 338 and not a sum.
    pub const SIZE: usize = 338;
    /// `char userid[30]` -- and what `obtbtvl` keys the character lookup on.
    pub const USERID: usize = 0x00;
    /// `char ansifl` -- bit 0 is `ANSON`.
    pub const ANSIFL: usize = 0xd0;
    /// `char scnwid` -- screen width in columns.
    pub const SCNWID: usize = 0xd1;
    /// `char scnbrk` -- screen length for page breaks, i.e. how many lines
    /// `rstrxf` (`MAJORBBS.C:3776`) tells `btuxnf` to show before pausing
    /// (`cnt = scnbrk-CTNUOS`). Between `ansifl` and `scnwid`'s neighbour
    /// `scnfse` in `UStructs.h`'s field order, hence 0xd0+2.
    ///
    /// **Never written by [`Host::connect_state`](crate::Host::connect_state)**
    /// -- it sets `userid`, `ansifl`, `scnwid` and `scnfse` and stops there,
    /// because this host has no account-level page-break setting to source
    /// one from. A channel therefore always reads this as whatever its
    /// account memory happened to hold, ordinarily zero. `rstrxf`'s own doc
    /// comment says what that does to its computed `cnt`.
    pub const SCNBRK: usize = 0xd2;
    /// `char scnfse` -- screen length for full-screen stuff.
    pub const SCNFSE: usize = 0xd3;
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
    /// `struct user *user` -- the head of the array the module indexes itself.
    users: A::Ptr,
    /// `struct extusr *extusr`.
    extra: A::Ptr,
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

    /// `&user[unum]`.
    pub fn slot(&self, unum: Chan) -> A::Ptr {
        self.nth(self.users, USER, unum)
    }

    /// `&extusr[unum]`.
    pub fn extra(&self, unum: Chan) -> A::Ptr {
        self.nth(self.extra, EXTUSR, unum)
    }

    /// `uacoff(unum)` -- the channel's account record.
    pub fn account(&self, unum: Chan) -> A::Ptr {
        self.nth(self.accounts, USRACC, unum)
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
    /// The final add -- base plus `each * unum` -- goes through
    /// [`Abi::ptr_offset`] rather than a hand-built `FarPtr`, which is what
    /// makes this method, and every accessor built on it, real for any `A`
    /// rather than only `Wg16`. The `checked_mul` above it stays: it is what
    /// turns an out-of-range `unum` into the named panic below rather than a
    /// wrapped offset, and [`Abi::ptr_offset`] carries no such check of its
    /// own. A second overflow check on the add itself (`base`'s own offset
    /// plus that product) was dropped rather than pushed through the trait:
    /// [`Users::new`] already proved `each * terms.count()` bytes fit in one
    /// region before handing out `base`, so for any `unum` this `Chan` can
    /// name, the add cannot leave that region either.
    ///
    /// # Panics
    ///
    /// If the slot does not fit in the segment. Unreachable for a `Chan` of
    /// this `Users`' own [`Terms`]: [`Users::new`] allocated `each * terms`
    /// bytes at `base` and that allocation succeeded, so every offset below it
    /// is addressable. A panic here means `unum` came from a larger `Terms`
    /// than the one that sized these tables.
    fn nth(&self, base: A::Ptr, each: u16, unum: Chan) -> A::Ptr {
        let offset = u16::try_from(unum.index())
            .ok()
            .and_then(|unum| each.checked_mul(unum))
            .unwrap_or_else(|| {
                panic!("channel {unum} is past the end of a table of {each}-byte slots")
            });
        A::ptr_offset(base, offset)
    }

    /// `&user[unum].state`.
    fn state_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), user::STATE)
    }

    /// `&user[unum].substt`.
    fn substt_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), user::SUBSTT)
    }

    /// `&user[unum].polrou`.
    fn polrou_at(&self, unum: Chan) -> A::Ptr {
        A::ptr_offset(self.slot(unum), user::POLROU)
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
    /// If the read runs off the segment.
    pub fn state_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        let bytes = self
            .state_at(unum)
            .resolve(mem, 2)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
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
        self.state_at(unum)
            .write(mem, &state.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(())
    }

    /// `user[unum].substt` -- the registered module's own substate, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::substt`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If the read runs off the segment.
    pub fn substt_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        let bytes = self
            .substt_at(unum)
            .resolve(mem, 2)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
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
        self.substt_at(unum)
            .write(mem, &substt.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(())
    }

    /// Allocate `size` bytes of volatile data area per channel, against
    /// memory directly rather than a whole `Machine`.
    ///
    /// The generic core [`Users::alcvda`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    pub fn alcvda_mem(
        &mut self,
        mem: &mut A::Mem,
        heap: &mut crate::Heap<A>,
        size: u16,
    ) -> io::Result<()> {
        let count = self.terms.count();
        let bytes = size
            .checked_mul(count)
            .ok_or_else(|| io::Error::other(format!("{count} channels of {size} bytes")))?;
        let at = heap
            .reserve(mem, bytes)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.vda = Some((at, size));
        Ok(())
    }
}

impl<A: Abi> Users<A> {
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
        let count = terms.count();
        let mut block = |each: u16| -> io::Result<A::Ptr> {
            let bytes = each
                .checked_mul(count)
                .ok_or_else(|| io::Error::other(format!("{count} channels of {each} bytes")))?;
            let at = heap
                .reserve(mem, bytes)
                .map_err(|e| io::Error::other(e.to_string()))?;
            at.write(mem, &vec![0u8; usize::from(bytes)])
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(at)
        };
        let users = block(USER)?;
        let extra = block(EXTUSR)?;
        let accounts = block(USRACC)?;

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
    use crate::abi::Wg16;

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
        assert_eq!(USER, 0x29);
    }

    #[test]
    fn the_user_fields_are_where_the_module_reaches_for_them() {
        // Every one of these offsets appears in `WCCMMUD.DLL`, off `usrptr` and
        // off `user[usrnum]` both. `FLAGS` is the load-bearing one: the module
        // tests `+0x14 & 2`, `+0x15 & 0x40` and `+0x16 & 0x80`, which are three
        // bytes of a single 4-byte field and rule out every other layout.
        assert_eq!(user::STATE, 6);
        assert_eq!(user::SUBSTT, 8);
        assert_eq!(user::FLAGS, 0x14);
        assert_eq!(user::CRDRAT, 0x1a);
        assert_eq!(user::LCSTAT, 40);
    }

    #[test]
    fn every_user_field_fits_inside_a_slot() {
        // The check that makes the two tests above one fact rather than two
        // lists: the last field is one byte, and it ends exactly at the stride.
        assert_eq!(user::LCSTAT + 1, USER, "lcstat is the last byte of a slot");
        assert!(user::FLAGS + 4 <= USER, "flags is a long and must fit");
    }

    #[test]
    fn an_account_record_is_the_three_hundred_and_thirty_eight_bytes_usracc_h_says() {
        // `USRACC.H:24` declares the fields and `:22` writes the total down:
        // `#define USRACCSPARE (338-301)`. The spare array exists so the record
        // can grow without moving, so 338 is the size on disk *and* in memory,
        // and it is also what `ACCOUNT.C:108` opens `bbsusr.dat` with.
        assert_eq!(USRACC, 338);
    }

    #[test]
    fn an_extusr_slot_is_twenty_two_bytes() {
        // `MAJORBBS.H:94`, byte-aligned like `struct user`. Nothing in
        // `WCCMMUD.DLL` strides by it -- the module imports neither `extusr`
        // nor `extptr` -- so unlike `USER` this one is arithmetic from the
        // header. It is here because `curusr`'s array is real whether or not
        // this module looks at it.
        assert_eq!(EXTUSR, 22);
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
            assert_ne!(users.slot(unum), users.extra(unum), "user[{unum}] vs extusr[{unum}]");
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
        assert_eq!(at(1) - at(0), USER);
        assert_eq!(at(3) - at(2), USER);
        assert_eq!(
            users.account(ch(1)).offset - users.account(ch(0)).offset,
            USRACC
        );
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
        let bytes = f.machine.resolve(at, usize::from(USER)).expect("readable");
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
        let rec = f.machine.resolve(at, usracc::SIZE).expect("in bounds");

        assert_eq!(&rec[..9], b"rangerdan", "userid keys the character lookup");
        assert_eq!(rec[usracc::ANSIFL] & 1, 1, "ANSON");
        assert!(rec[usracc::SCNWID] >= 0x50, "80 columns");
        assert!(rec[usracc::SCNFSE] >= 0x17, "23 rows");
    }

    #[test]
    fn a_connection_names_the_channel_the_module_will_run_on() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("channel 0");
        let at = f.host.users().slot(console);
        let rec = f.machine.resolve(at, USER as usize).expect("in bounds");
        assert_eq!(rec[user::STATE as usize], 0, "state is set by connect()");
        assert_eq!(rec[user::SUBSTT as usize], 0);
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
        let rec = f.machine.resolve(at, usracc::SIZE).expect("in bounds");

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
        let rec = f.machine.resolve(at, usracc::SIZE).expect("in bounds");

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
        let rec = f.machine.resolve(at, USER as usize).expect("in bounds");
        assert_eq!(rec[user::FLAGS as usize] & 0x40, 0x40);
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
            offset: at.offset + user::FLAGS,
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
        // `0x24` is written out rather than taken from `user::POLROU`, and that
        // is the whole point of this assertion. An address derived from the
        // constant under test moves when the constant moves, so the write and
        // the check stay in agreement no matter how wrong both are -- it can
        // only prove the accessor agrees with itself. The literal is the
        // independent statement of `MAJORBBS.H:90`'s offset that makes a wrong
        // `POLROU` observable.
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

        // The literal `+6`, not `user::STATE`, for the same reason
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
}
