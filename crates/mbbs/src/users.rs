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

use mbbs16::{FarPtr, Machine};

use crate::ShimError;

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
/// Only the four the module reads. **`UIDSIZ` is 30 here, not the 10 of the
/// v6 header** -- every offset below moves if that is got wrong, and nothing
/// would report it except the module quietly taking a different branch.
///
/// Independently derived, not copied: adding up `UStructs.h:21-34` under the
/// same byte alignment `struct user` uses (`userid[30]`, `psword[10]`,
/// `usrnam[30]`, `usrad1..4[30]` each, `usrpho[16]`, then the two one-byte
/// flags `systyp` and `usrprf`) lands `ansifl` at 208 (`0xd0`), `scnwid` at
/// 209 (`0xd1`) and -- skipping the one-byte `scnbrk` nothing here reads --
/// `scnfse` at 211 (`0xd3`). Continuing the same sum through `birthd` totals
/// exactly 301 declared bytes, which is what `USRACC.H:22`'s
/// `#define USRACCSPARE (338-301)` says it should be -- so the total and the
/// three offsets confirm each other.
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
pub struct Users {
    /// How many channels there are: `nterms`.
    terms: u16,
    /// `struct user *user` -- the head of the array the module indexes itself.
    users: FarPtr,
    /// `struct extusr *extusr`.
    extra: FarPtr,
    /// `uablok`, `ACCOUNT.C:30` -- the account records, one per channel.
    accounts: FarPtr,
    /// `int *channel` -- and this one points [`SENTINELS`] words *into* its own
    /// allocation, exactly as `MAJORBBS.C:741-743` left it.
    channels: FarPtr,
    /// `vdahdl`, `MAJORBBS.C:1373` -- one volatile data area per channel, and
    /// how big each is. `None` until `alcvda`, which cannot run until every
    /// module's `dclvda` has been counted.
    vda: Option<(FarPtr, u16)>,
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

impl Users {
    /// Allocate `terms` channels' worth of everything, zeroed.
    ///
    /// `alczer` and not `alcmem`, at `MAJORBBS.C:735-736`, and `ACCOUNT.C:112`
    /// follows its `alcblok` with a `setmem(...,0)` over every slot. A channel
    /// whose `state` came up as whatever the heap last held would be in some
    /// module the module never entered.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    pub fn new(machine: &mut Machine, heap: &mut crate::Heap, terms: u16) -> io::Result<Self> {
        let mut block = |each: u16| -> io::Result<FarPtr> {
            let bytes = each
                .checked_mul(terms)
                .ok_or_else(|| io::Error::other(format!("{terms} channels of {each} bytes")))?;
            let at = heap.alloc(machine, bytes).map_err(io::Error::other)?;
            machine
                .write(at, &vec![0u8; usize::from(bytes)])
                .map_err(io::Error::other)?;
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
        let words = terms
            .checked_add(SENTINELS)
            .and_then(|words| words.checked_mul(2))
            .ok_or_else(|| io::Error::other(format!("{terms} channels of channel[]")))?;
        let base = heap.alloc(machine, words).map_err(io::Error::other)?;
        machine
            .write(base, &vec![0xffu8; usize::from(words)])
            .map_err(io::Error::other)?;
        for (index, value) in [-3i16, -2, -1].into_iter().enumerate() {
            let at = FarPtr {
                offset: base.offset + index as u16 * 2,
                selector: base.selector,
            };
            machine
                .write(at, &value.to_le_bytes())
                .map_err(io::Error::other)?;
        }
        let channels = FarPtr {
            offset: base.offset + SENTINELS * 2,
            selector: base.selector,
        };

        // `MAJORBBS.C:878` -- `channel[usrnum]=0` with `usrnum` still zero,
        // the local console. Reached only when no hardware channel groups are
        // configured, which is this host: one channel, no serial board.
        machine
            .write(channels, &0i16.to_le_bytes())
            .map_err(io::Error::other)?;

        Ok(Self {
            terms,
            users,
            extra,
            accounts,
            channels,
            vda: None,
            keys: vec![None; usize::from(terms)],
        })
    }

    /// Allocate `size` bytes of volatile data area per channel.
    ///
    /// `vdahdl=alcblok(nterms,vdasiz)`, `MAJORBBS.C:1373`. **Not zeroed**, and
    /// that is deliberate: `alcblok` has no recovered source, but both of its
    /// other callers initialise every slot themselves right afterwards --
    /// `ACCOUNT.C:111-113` with a `setmem(...,0)` loop and `GALFILU.C:296` with
    /// `nlibaxs=-1` -- which they would not do if the block came back clean.
    /// `MAJORBBS.C:1373` does neither, so a module reading its volatile data
    /// area before writing it read whatever was there, and it reads the same
    /// here.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    pub fn alcvda(
        &mut self,
        machine: &mut Machine,
        heap: &mut crate::Heap,
        size: u16,
    ) -> io::Result<()> {
        let bytes = size
            .checked_mul(self.terms)
            .ok_or_else(|| io::Error::other(format!("{} channels of {size} bytes", self.terms)))?;
        let at = heap.alloc(machine, bytes).map_err(io::Error::other)?;
        self.vda = Some((at, size));
        Ok(())
    }

    /// How many channels there are.
    pub fn terms(&self) -> u16 {
        self.terms
    }

    /// The head of `user[]`, which is what the `user` global holds.
    pub fn head(&self) -> FarPtr {
        self.users
    }

    /// The head of `channel[]`, which is three words *into* its allocation.
    pub fn channels(&self) -> FarPtr {
        self.channels
    }

    /// `&user[unum]`, or `None` for a channel that does not exist.
    pub fn slot(&self, unum: i16) -> Option<FarPtr> {
        self.nth(self.users, USER, unum)
    }

    /// `&extusr[unum]`, or `None` for a channel that does not exist.
    pub fn extra(&self, unum: i16) -> Option<FarPtr> {
        self.nth(self.extra, EXTUSR, unum)
    }

    /// `uacoff(unum)` -- the channel's account record, or `None` for a channel
    /// that does not exist.
    pub fn account(&self, unum: i16) -> Option<FarPtr> {
        self.nth(self.accounts, USRACC, unum)
    }

    /// `vdaoff(unum)` -- the channel's volatile data area, or `None` if there
    /// is no such channel or [`Users::alcvda`] has not run.
    ///
    /// `MAJORBBS.C:1380`. Null before `alcvda` is the answer the real host's
    /// `vdaoff` gave too, because `vdahdl` was still null: every module's
    /// `dclvda` has to be counted before the size is known.
    pub fn vda(&self, unum: i16) -> Option<FarPtr> {
        let (base, size) = self.vda?;
        self.nth(base, size, unum)
    }

    /// What channel `unum` is allowed to do, or `None` if it never logged on
    /// -- or if there is no such channel.
    pub fn keys(&self, unum: i16) -> Option<&crate::KeySet> {
        self.index(unum).and_then(|at| self.keys[at].as_ref())
    }

    /// Give channel `unum` a keyring. What `loadkeys()` did at logon.
    ///
    /// A channel that does not exist is a silent no-op, matching
    /// [`Users::nth`]'s bound and `curusr`'s.
    pub fn set_keys(&mut self, unum: i16, keys: crate::KeySet) {
        if let Some(at) = self.index(unum) {
            self.keys[at] = Some(keys);
        }
    }

    /// `user[unum].polrou` -- the channel's polling routine, or `None` for
    /// NULL.
    ///
    /// Read out of emulated memory every time rather than cached: the whole
    /// point of the check `dopoll` makes after calling a polling routine is
    /// that the routine may have called `stop_polling` on itself while it ran,
    /// and a remembered copy would not have noticed.
    ///
    /// # Errors
    ///
    /// If `unum` names no channel, or the read runs off the segment.
    pub fn polrou(&self, machine: &Machine, unum: i16) -> Result<Option<FarPtr>, ShimError> {
        let bytes = machine.resolve(self.polrou_at(unum)?, 4)?;
        let rou = FarPtr::from_bytes(bytes.try_into().expect("4 bytes"));
        Ok((rou != FarPtr::NULL).then_some(rou))
    }

    /// Install or clear channel `unum`'s polling routine.
    ///
    /// # Errors
    ///
    /// If `unum` names no channel, or the write runs off the segment.
    pub fn set_polrou(
        &mut self,
        machine: &mut Machine,
        unum: i16,
        rou: Option<FarPtr>,
    ) -> Result<(), ShimError> {
        let at = self.polrou_at(unum)?;
        machine.write(at, &rou.unwrap_or(FarPtr::NULL).to_bytes())?;
        Ok(())
    }

    /// `&user[unum].polrou`.
    ///
    /// A channel that does not exist is an error here and a silent no-op in
    /// [`Users::set_keys`], and the difference is deliberate: `set_keys` is
    /// reached from `curusr`, whose documented behaviour for a bad channel is
    /// to do nothing (`MAJORBBS.C:4293`), while every caller of this one is a
    /// routine the module handed a channel number to.
    fn polrou_at(&self, unum: i16) -> Result<FarPtr, ShimError> {
        let slot = self
            .slot(unum)
            .ok_or_else(|| ShimError::Failed(format!("polrou({unum}): there is no such channel")))?;
        Ok(FarPtr {
            offset: slot.offset + user::POLROU,
            selector: slot.selector,
        })
    }

    /// `unum` as an index, or `None` if there is no such channel.
    ///
    /// The same bound [`Users::nth`] applies -- `MAJORBBS.C:4293`'s
    /// `if (0 <= uno && uno < nterms)` -- stated once so the four tables
    /// cannot come to disagree about which channels exist.
    fn index(&self, unum: i16) -> Option<usize> {
        (unum >= 0 && unum < i16::try_from(self.terms).ok()?).then_some(unum as usize)
    }

    /// The `unum`th slot of a table of `each`-byte entries, or `None` if there
    /// is no such channel.
    fn nth(&self, base: FarPtr, each: u16, unum: i16) -> Option<FarPtr> {
        let unum = u16::try_from(self.index(unum)?).ok()?;
        Some(FarPtr {
            offset: base.offset.checked_add(each.checked_mul(unum)?)?,
            selector: base.selector,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(users.terms(), 1, "one channel, as `nterms` says");
        for unum in 0..users.terms() as i16 {
            assert!(users.slot(unum).is_some(), "user[{unum}]");
            assert!(users.extra(unum).is_some(), "extusr[{unum}]");
            assert!(users.account(unum).is_some(), "uacoff({unum})");
        }
    }

    #[test]
    fn the_slots_are_a_stride_apart() {
        // The only way a second channel is reachable at all. Checked over a
        // table sized past `nterms` so that the arithmetic is tested even
        // though this host has one channel -- a stride bug would otherwise be
        // invisible until the day `nterms` moved.
        let mut machine = mbbs16::Machine::new().expect("machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let users = Users::new(&mut machine, &mut heap, 4).expect("four channels");
        let at = |n| users.slot(n).expect("placed").offset;
        assert_eq!(at(1) - at(0), USER);
        assert_eq!(at(3) - at(2), USER);
        assert_eq!(
            users.account(1).expect("placed").offset - users.account(0).expect("placed").offset,
            USRACC
        );
    }

    #[test]
    fn a_channel_that_does_not_exist_has_no_slot() {
        // `curusr`'s guard is `0 <= uno && uno < nterms`, so out of range has
        // to be answerable as *absent* rather than as some address. A table
        // that returned a pointer here would hand the module the bytes after
        // the last channel and call them channel 1.
        let f = crate::testing::Fixture::new();
        let users = f.host.users();
        assert!(users.slot(-1).is_none(), "there is no channel -1");
        assert!(users.slot(users.terms() as i16).is_none(), "one past the end");
        assert!(users.account(-1).is_none());
        assert!(users.extra(-1).is_none());
    }

    #[test]
    fn the_tables_start_zeroed() {
        // `alczer`, not `alcmem`, at MAJORBBS.C:735 -- and `ACCOUNT.C:112`
        // follows `alcblok` with a `setmem(...,0)` over every slot. A channel
        // whose `state` came up as whatever the heap last held would be in some
        // module the module never entered.
        let f = crate::testing::Fixture::new();
        let at = f.host.users().slot(0).expect("channel 0");
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
        let head = f.host.globals().pointer(&f.machine, "user").expect("user");
        assert_ne!(head, mbbs16::FarPtr::NULL, "the module dereferences this");
        assert_eq!(head, f.host.users().slot(0).expect("channel 0"));
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
        assert_ne!(at, mbbs16::FarPtr::NULL);
        let word = |delta: i16| -> i16 {
            let from = mbbs16::FarPtr {
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
            mbbs16::FarPtr::NULL
        );
    }

    #[test]
    fn alcvda_gives_every_channel_an_area_and_the_host_a_spare() {
        // `vdahdl=alcblok(nterms,vdasiz)` and `vdatmp=alcmem(vdasiz)`. `vdatmp`
        // is a separate block, not a slot -- `fsdapr(vdaptr, vdasiz, vdatmp)`
        // hands the FSD both at once and they must not be the same bytes.
        let mut f = crate::testing::Fixture::new();
        f.invoke(crate::shims::system::dclvda, &[512]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");

        let g = f.host.globals();
        let area = g.pointer(&f.machine, "vdaptr").expect("vdaptr");
        let temp = g.pointer(&f.machine, "vdatmp").expect("vdatmp");
        assert_ne!(area, mbbs16::FarPtr::NULL);
        assert_ne!(temp, mbbs16::FarPtr::NULL);
        assert_ne!(area, temp, "the area and the scratch copy are two blocks");
        assert_eq!(area, f.host.users().vda(0).expect("channel 0"));
    }

    #[test]
    fn alcvda_does_nothing_when_no_module_declared_a_size() {
        // The `if (vdasiz != 0)` guard. Allocating zero bytes is an error this
        // heap refuses outright, so the guard is load-bearing and not decorative.
        let mut f = crate::testing::Fixture::new();
        f.host.alcvda(&mut f.machine).expect("nothing to do");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs16::FarPtr::NULL
        );
    }

    #[test]
    fn a_connection_lands_on_the_bytes_the_module_gates_its_output_on() {
        // WCCMMUD_named.c:11201 --
        //   if ((usaptr[0xd0] & 1) == 0 || usaptr[0xd3] < 0x17 || usaptr[0xd1] < 0x50)
        // Fail any of the three and MajorMUD prints the degraded rendering.
        let mut f = crate::testing::Fixture::new();
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("rangerdan"))
            .expect("channel 0");
        let at = f.host.users().account(0).expect("channel 0");
        let rec = f.machine.resolve(at, usracc::SIZE).expect("in bounds");

        assert_eq!(&rec[..9], b"rangerdan", "userid keys the character lookup");
        assert_eq!(rec[usracc::ANSIFL] & 1, 1, "ANSON");
        assert!(rec[usracc::SCNWID] >= 0x50, "80 columns");
        assert!(rec[usracc::SCNFSE] >= 0x17, "23 rows");
    }

    #[test]
    fn a_connection_names_the_channel_the_module_will_run_on() {
        let mut f = crate::testing::Fixture::new();
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("rangerdan"))
            .expect("channel 0");
        let at = f.host.users().slot(0).expect("channel 0");
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
        let long = "a".repeat(40);
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi(&long))
            .expect("channel 0");
        let at = f.host.users().account(0).expect("channel 0");
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
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("rangerdan"))
            .expect("channel 0, first connect");
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("dan"))
            .expect("channel 0, second connect");

        let at = f.host.users().account(0).expect("channel 0");
        let rec = f.machine.resolve(at, usracc::SIZE).expect("in bounds");

        assert_eq!(&rec[..3], b"dan", "the second userid");
        assert!(
            rec[3..30].iter().all(|&b| b == 0),
            "no tail of \"rangerdan\" survives past the new name: {:?}",
            &rec[3..30]
        );
    }

    #[test]
    fn connect_state_refuses_a_channel_that_does_not_exist() {
        let mut f = crate::testing::Fixture::new();
        let past = f.host.users().terms() as i16;
        assert!(f.host.connect_state(&mut f.machine, past, &Connection::ansi("rangerdan")).is_err());
    }

    #[test]
    fn a_channel_nobody_connected_to_has_no_keyring_at_all() {
        // `usrptr->keys == NULL` -- `loadkeys()` has not run. Distinct from a
        // channel that logged on holding nothing, and `low_haskey` answers the
        // two differently; see `shims::user::haskey`.
        let f = crate::testing::Fixture::new();
        assert!(f.host.users().keys(0).is_none());
    }

    #[test]
    fn connecting_gives_the_channel_the_keys_it_arrived_with() {
        let mut f = crate::testing::Fixture::new();
        let who = Connection::ansi("rangerdan").with_keys(["USER"]);
        f.host.connect_state(&mut f.machine, 0, &who).expect("channel 0");

        let keys = f.host.users().keys(0).expect("the channel logged on");
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
        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("rangerdan"))
            .expect("channel 0");

        let keys = f.host.users().keys(0).expect("logged on, holding nothing");
        assert!(keys.evaluate(""), "an empty lock is true once logged on");
        assert!(!keys.evaluate("USER"));
    }

    #[test]
    fn a_reconnecting_channel_does_not_keep_the_previous_users_keys() {
        // R13's shape, for the keyring: `connect_state` runs again on a channel
        // that already held a user, and the second user must not inherit the
        // first one's access.
        let mut f = crate::testing::Fixture::new();
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &Connection::ansi("sysop").with_keys(["USER", "WCCSYSOP"]),
            )
            .expect("first connect");
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &Connection::ansi("guest").with_keys(["USER"]),
            )
            .expect("second connect");

        let keys = f.host.users().keys(0).expect("logged on");
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
        let who = Connection::ansi("root").with_keys(["USER"]).master(true);
        f.host.connect_state(&mut f.machine, 0, &who).expect("channel 0");

        let at = f.host.users().slot(0).expect("channel 0");
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
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &Connection::ansi("root").master(true),
            )
            .expect("first connect");

        // Whatever the module had set in the rest of the byte.
        let at = f.host.users().slot(0).expect("channel 0");
        let flags = mbbs16::FarPtr {
            offset: at.offset + user::FLAGS,
            selector: at.selector,
        };
        let was = f.machine.resolve(flags, 1).expect("in bounds")[0];
        f.machine.write(flags, &[was | 0x16]).expect("in bounds");

        f.host
            .connect_state(&mut f.machine, 0, &Connection::ansi("guest"))
            .expect("second connect");

        let now = f.machine.resolve(flags, 1).expect("in bounds")[0];
        assert_eq!(now & 0x40, 0, "the master flag is cleared");
        assert_eq!(now & 0x16, 0x16, "the module's own bits survive");
    }

    #[test]
    fn polrou_round_trips_through_the_bytes_the_module_reads() {
        let mut f = crate::testing::Fixture::new();
        let rou = mbbs16::FarPtr {
            offset: 0x2184,
            selector: 0x1010,
        };

        assert_eq!(
            f.host.users().polrou(&f.machine, 0).expect("channel 0"),
            None,
            "a fresh slot is NULL, because alczer zeroed it"
        );

        f.host
            .users
            .set_polrou(&mut f.machine, 0, Some(rou))
            .expect("channel 0");
        assert_eq!(
            f.host.users().polrou(&f.machine, 0).expect("channel 0"),
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
        let slot = f.host.users().slot(0).expect("channel 0");
        let at = mbbs16::FarPtr {
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
            .set_polrou(&mut f.machine, 0, None)
            .expect("channel 0");
        assert_eq!(
            f.machine.resolve(at, 4).expect("in the slot"),
            &[0, 0, 0, 0],
            "NULL is four zero bytes, which is what the module tests for"
        );
    }

    #[test]
    fn polrou_refuses_a_channel_that_does_not_exist() {
        let f = crate::testing::Fixture::new();
        assert!(f.host.users().polrou(&f.machine, 1).is_err(), "nterms is 1");
        assert!(f.host.users().polrou(&f.machine, -1).is_err());
    }
}
