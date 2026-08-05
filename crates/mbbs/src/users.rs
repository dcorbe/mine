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
}
