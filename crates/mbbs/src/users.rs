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
    /// `char lcstat` -- LAN channel state, and the odd byte that makes the
    /// stride 41 and not 42.
    pub const LCSTAT: u16 = 40;
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
}

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
        Ok(Self {
            terms,
            users,
            extra,
            accounts,
        })
    }

    /// How many channels there are.
    pub fn terms(&self) -> u16 {
        self.terms
    }

    /// The head of `user[]`, which is what the `user` global holds.
    pub fn head(&self) -> FarPtr {
        self.users
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

    /// The `unum`th slot of a table of `each`-byte entries, or `None` if there
    /// is no such channel.
    ///
    /// The bound is `curusr`'s own -- `MAJORBBS.C:4293`'s
    /// `if (0 <= uno && uno < nterms)` -- and it is stated here once so that
    /// the three tables cannot come to disagree about which channels exist.
    fn nth(&self, base: FarPtr, each: u16, unum: i16) -> Option<FarPtr> {
        if unum < 0 || unum >= i16::try_from(self.terms).ok()? {
            return None;
        }
        Some(FarPtr {
            offset: base.offset.checked_add(each.checked_mul(unum as u16)?)?,
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
}
