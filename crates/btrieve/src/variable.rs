//! Variable-length records: the fragment chain behind a fixed record.
//!
//! A Btrieve file whose records vary in length still keeps a fixed-length slot
//! per record in its data pages. What varies lives elsewhere, in *fragments*
//! on other pages, and the slot carries four bytes of pointer to the first of
//! them. The file control record says how to tell: bit 0 of the user flags at
//! `0x106`, corroborated by `0xff` at `0x38`, and the physical record length
//! exceeding the logical one by the four bytes that pointer needs.
//!
//! `WCCTEXT` is the one file of the eighteen MajorMUD ships that is like this,
//! and the whole of MajorMUD's character-creation, room and item prose is in
//! it. A reader that stopped at the 22-byte fixed part handed the module
//! `c cls\r\t\r` and then zeros.
//!
//! # A variable page
//!
//! ```text
//!   0x00  +-------------------------------+
//!         | page number, high word first  |
//!   0x04  | usage counter                 |
//!   0x06  | next page with free space     |  <- write-side free list; ffffffff = none
//!   0x0a  | fragment count                |
//!   0x0c  | fragment 0's bytes            |  <- always 0x0c, and the engine checks it
//!         | fragment 1's bytes            |
//!         |             ...               |
//!         |         (free space)          |
//!         | entry[n] ... entry[1] entry[0]|  <- the array, at the END, growing DOWN
//!   page  +-------------------------------+
//! ```
//!
//! Entry `i` is the two bytes at `page - 2*(i+1)`. It holds where fragment `i`
//! *starts*; where it *ends* is the next valid entry's offset, which is why
//! there is always one more entry than there are fragments. `ff ff` marks an
//! entry whose fragment has been freed, and both the scan for the end and the
//! check on fragment 0 step over it.
//!
//! The high bit of an entry's second byte says the fragment begins with four
//! more bytes of pointer, to a fragment on another page -- the chain. Nothing
//! in `WCCTEXT` sets it; see [`Chain::follow`].
//!
//! # Read off the engine, not guessed
//!
//! The genuine Pervasive Btrieve 6.15 microkernel is decompiled in
//! `re/btrieve_ghidra/exports/W32MKDE_decompiled.c` (regenerate per
//! `docs/plans/2026-08-08-btrieve-real-oracle.md`), and `FUN_00420850` at
//! `:18973` **is** this routine: it is what the engine runs to answer a read
//! on a variable-length file. Every rule below is cited to a line of it.
//! MBBSEmu's `MBBSEmu/Btrieve/BtrieveFile.cs:511-608` (MIT) agrees with it on
//! everything it covers, and is the shape this was first written from.

use std::collections::HashSet;

use super::Version;

/// Where a variable page says which page it is: four bytes, high word first,
/// like every other page pointer in the format. **Version 5 only** -- see
/// [`LOGICAL`] for what the same two bytes mean in a version 6 file.
const PAGE_NUMBER: usize = 0x00;

/// Where a v6 variable page's own logical id lives: a `u16`, plain little-
/// endian, at the same offset every other v6 page in the file uses for its
/// own logical id (`super::v6::Map`'s own `LOGICAL` constant). A v6 page has
/// no equivalent of [`PAGE_NUMBER`] -- its first two bytes are a type tag
/// (`0x5600`, `'V'` in the low byte), not the high half of a four-byte page
/// number, which is exactly why comparing all four bytes against a physical
/// page number (the v5 rule) can never hold for v6 (Task 6 ground truth,
/// `.scratch-v6-exec/NOTES.md`).
const LOGICAL: usize = 0x02;

/// The byte of a v6 page's two-byte type tag that carries the letter.
///
/// The tag reads `0x5600` as a little-endian `u16`, so the `'V'` is at byte 1
/// and byte 0 is zero. Named rather than written as `1` at the one place that
/// reads it, because `records::walk_v6` checks the same byte for `0x44` and
/// the two should be recognisably the same check.
const TAG: usize = 0x01;

/// Where a variable page names the next variable page with room in it.
///
/// The **write side's** free list. A [`super::pages::long`], with three
/// meanings rather than two -- see [`FreeChain`], and
/// `docs/2026-08-17-variable-write-oracle.md` for the ladder that measured
/// them. `W32MKDE_decompiled.c:19267` (`FUN_00420da0`) is the allocator that
/// maintains it, and `0xa0` of the live file control record is where the
/// chain starts.
const FREE_CHAIN: usize = 0x06;

/// Read the free-space chain's head out of a file control record.
///
/// The offset and its "nothing" value live in [`super::pages::fcr`] beside
/// the record free list they must not be confused with.
pub(crate) fn head_of(fcr: &[u8]) -> Option<u32> {
    use super::pages::fcr;
    match super::pages::long(&fcr[fcr::VARIABLE_HEAD..fcr::VARIABLE_HEAD + 4]) {
        fcr::NO_VARIABLE_HEAD | 0 => None,
        page => Some(page),
    }
}

/// What [`v5_head_of`] reads when no variable page is offered: the sentinel
/// a virgin variable-length file carries at
/// [`super::format::fcr::at::VARIABLE_HIGHEST`], and what
/// [`set_v5_head`] writes back when the chain empties.
const NO_V5_HEAD: u16 = 0xffff;

/// Read the free-space chain's head out of a **version 5** file control
/// record.
///
/// A different field from [`head_of`]'s: v5 keeps its head at
/// [`super::format::fcr::at::VARIABLE_HIGHEST`] (`0x3a`, a plain
/// little-endian `u16`) rather than at `pages::fcr::VARIABLE_HEAD`
/// (`0xa0`, a [`super::pages::long`]), which stays zero on every v5 file
/// this crate has written or read. See [`V5Pages`]'s doc comment for the two
/// genuine recordings that measured it and for why `0x3a` is the head rather
/// than only the highest page reached.
pub(crate) fn v5_head_of(fcr: &[u8]) -> Option<u32> {
    use super::format::fcr::at::VARIABLE_HIGHEST;
    match u16::from_le_bytes([fcr[VARIABLE_HIGHEST], fcr[VARIABLE_HIGHEST + 1]]) {
        NO_V5_HEAD | 0 => None,
        page => Some(u32::from(page)),
    }
}

/// Write the free-space chain's head into a **version 5** file control
/// record, and mark the file as no longer virgin.
///
/// Both bytes together, because the genuine engine changed both: the seed's
/// `ff ff ff ff` at `0x38..0x3c` reads `ff 00 05 00` after the insert
/// scenario, which is [`super::format::fcr::at::VARIABLE_SUBFLAG`] going
/// from `0xff` (virgin) to `0x00` in the same breath as the head being set.
/// `create.rs`'s own `VARIABLE_SUBFLAG` doc comment measured the same flip
/// across the corpus; this is the write side of it.
pub(crate) fn set_v5_head(fcr: &mut [u8], head: Option<u32>) -> Result<(), String> {
    use super::format::fcr::at::{VARIABLE_HIGHEST, VARIABLE_SUBFLAG};
    let value = match head {
        None => NO_V5_HEAD,
        Some(page) => u16::try_from(page).map_err(|_| {
            format!("variable page {page} is past the 65,535 a v5 control record can name")
        })?,
    };
    fcr[VARIABLE_SUBFLAG] = 0x00;
    fcr[VARIABLE_HIGHEST..VARIABLE_HIGHEST + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Where a page says how many fragments it holds.
const FRAGMENT_COUNT: usize = 0x0a;

/// Where fragment 0 always starts, and the whole of the page header.
///
/// The engine checks this: `W32MKDE_decompiled.c:19035` walks the entry array
/// from entry 0, steps over freed slots, and refuses the file with status 54
/// -- "variable page error" -- if the first live entry is not exactly `0x0c`.
const FIRST_FRAGMENT: u32 = 0x0c;

/// The most fragments a page can hold. `W32MKDE_decompiled.c:19489`.
const MAX_FRAGMENTS: u16 = 256;

/// The entry that marks a slot whose fragment is gone.
const UNUSED: u32 = 0xffff;

/// The pointer that ends a chain, as the four bytes sit in the record.
///
/// The engine compares the raw double word against `0xffffffff`
/// (`W32MKDE_decompiled.c:19004`); split by [`Pointer::decode`] that is page
/// `0xffffff` and fragment `0xff`.
const END_PAGE: u32 = 0x00ff_ffff;

/// The fragment index that ends a chain, with [`END_PAGE`].
const END_FRAGMENT: u8 = 0xff;

/// A page number that means "no such page" in the free chain.
const NO_PAGE: u32 = 0xffff_ffff;

/// Bytes of pointer at the head of a continued fragment.
const POINTER: usize = 4;

/// Somewhere whole pages can be read from, by page number.
///
/// A chain jumps to arbitrary pages, so the walk that finds records in
/// physical order cannot serve it; this is the seam that lets the walk read
/// from a file and the tests read from a `Vec` of hand-built pages.
///
/// The borrow ends at the next call, which is what forces every caller to copy
/// a fragment out before following the pointer inside it.
pub(crate) trait Pages {
    /// The whole of page `number`, exactly one page long.
    fn page(&mut self, number: u32) -> Result<&[u8], String>;
}

/// [`Pages`], plus the write half [`rewrite_fragment_in_place`] needs.
///
/// Kept separate from [`Pages`] rather than folded into it: every reader --
/// [`Chain::follow`], [`records::walk`](super::records) -- only ever needs to
/// read a page, and giving a read path write access it never exercises is
/// exactly the kind of unused capability that turns into a bug the day
/// someone reaches for it by accident.
pub(crate) trait PagesMut: Pages {
    /// Replace the whole of page `number` with `page`, which must be exactly
    /// one page long.
    fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String>;
}

/// The pointer at the end of a fixed record: which page, and which fragment on
/// it, the record's body starts at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pointer {
    page: u32,
    fragment: u8,
}

impl Pointer {
    /// Decode the four bytes that follow a variable-length file's logical
    /// record: a 24-bit page number, scrambled, and a fragment index.
    ///
    /// # Which byte holds the fragment index
    ///
    /// `[high][low][mid][fragment]`. **The corpus cannot show this**: byte 0
    /// and byte 3 are `0x00` in all 3,467 of `WCCTEXT.DAT`'s pointers, so a
    /// competing reading -- `[fragment][page, 16-bit little-endian][unused]`
    /// -- produces the same page and the same fragment for every record this
    /// host has ever seen. They diverge only on a page number above `0xffff`
    /// or a non-zero fragment index, neither of which occurs here.
    ///
    /// **The decompiled engine settles it.** `W32MKDE_decompiled.c:19951`
    /// (`FUN_00421c20`) is the microkernel's own unpack, and its first
    /// statement is `*param_2 = param_1._3_1_` -- the fragment index out of
    /// byte 3, exactly as here. `FUN_00421c50` at `:19968` is the matching
    /// pack.
    ///
    /// The engine then rearranges the remaining bytes into an *internal*
    /// packed form with the page-type byte spliced into byte 1, which is why
    /// engine code masks with `0xffff00ff` and why its in-memory nothing is
    /// `0xffff00ff` rather than `0xffffffff`. That form never reaches the
    /// disk and is not reproduced.
    pub(crate) fn decode(bytes: [u8; POINTER]) -> Self {
        Self {
            page: u32::from(bytes[0]) << 16 | u32::from(bytes[1]) | u32::from(bytes[2]) << 8,
            fragment: bytes[3],
        }
    }

    /// The inverse of [`Self::decode`]: `[high][low][mid][fragment]`.
    ///
    /// The engine's own pack is `FUN_00421c50` at
    /// `W32MKDE_decompiled.c:19968`. **Only the on-disk form is produced.**
    /// The engine also keeps an in-memory variant with a page-type byte
    /// spliced into byte 1, which is why its code masks with `0xffff00ff`;
    /// nothing here reproduces that, and a record trailer holding it would
    /// name a page no file has.
    ///
    /// Confirmed against genuine 6.15: a fragment continued onto logical page
    /// 3 carries `00 03 00 00`, which is what this produces for
    /// `Pointer { page: 3, fragment: 0 }`.
    pub(crate) fn encode(self) -> [u8; POINTER] {
        [
            (self.page >> 16) as u8,
            self.page as u8,
            (self.page >> 8) as u8,
            self.fragment,
        ]
    }

    /// Whether this pointer ends a chain rather than naming a fragment.
    fn is_end(self) -> bool {
        self.page == END_PAGE && self.fragment == END_FRAGMENT
    }
}

/// A variable page's header: everything before fragment 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    /// The page's own number -- physical for v5, logical for v6. Checked
    /// against the number that was asked for, which is what makes
    /// [`Pointer::decode`]'s scrambled page number a reading rather than an
    /// assumption: a wrong decode lands on a page that disagrees about which
    /// page it is.
    number: u32,

    /// How many fragments the page holds.
    fragments: u16,

    /// Whether this page is on the file's free-space chain, and what follows
    /// it there. See [`FreeChain`].
    free_chain: FreeChain,
}

/// Where a variable page stands in its file's free-space chain.
///
/// **Three states, not two**, which is what
/// `docs/2026-08-17-variable-write-oracle.md` measured and what this crate
/// read wrongly before it did. The field at [`FREE_CHAIN`] is a
/// [`super::pages::long`] like every other page number in the format, and:
///
/// | on disk | `pages::long` | meaning |
/// |---|---|---|
/// | `00 00 05 00` | 5 | [`Self::Next`] -- on the chain, logical 5 follows |
/// | `ff 00 ff ff` | [`END_PAGE`] | [`Self::Last`] -- on the chain, and last |
/// | `ff ff ff ff` | [`NO_PAGE`] | [`Self::Off`] -- not on the chain at all |
///
/// Collapsing the last two -- which is what testing only against [`NO_PAGE`]
/// did -- decodes an ordinary on-chain page as `Some(0x00ff_ffff)`, a page
/// number no file has. That was invisible while nothing followed the field
/// and would have been a corruption the moment [`Space`] did.
///
/// The head of the chain is **not** here: it is at `0xa0` of the live half of
/// the file control record, measured in the same document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FreeChain {
    /// The page is full, or otherwise not offered for new fragments.
    Off,

    /// The page has room and is the last member of the chain.
    Last,

    /// The page has room, and the next page with room is this one.
    Next(u32),
}

impl Header {
    /// Read a page's header, and refuse a page that cannot hold one.
    ///
    /// `asked` is what `number` must equal: a physical page for v5, since
    /// that is what [`PAGE_NUMBER`] holds there, and a **logical** id for v6,
    /// since v6 has no equivalent field -- its own page number is read off
    /// [`LOGICAL`] instead (Task 6 ground truth). Reading the v5 way on a v6
    /// page compares four bytes `[tag_lo][tag_hi][logical_lo][logical_hi]`
    /// against a physical page number and can never hold; that is the
    /// reading this refuses by construction rather than by a runtime check.
    ///
    /// # Zero fragments
    ///
    /// A **version 5** page may report zero, and this reads it. Measured in
    /// `crates/btrieve-oracle/fixtures/v5_variable_release_empty.fixture`:
    /// genuine Btrieve deletes the only record on the file and leaves its
    /// variable page 5 in the file, at `0x1400`, reading `00 00 05 00` /
    /// stamp `01 00` / free chain `ff 00 ff ff` / fragment count `00 00`,
    /// with entry 0 at `0x17fe` still naming `0x0c`. See
    /// [`free_fragment`]'s own doc comment for the whole page.
    ///
    /// A **version 6** page may not. Nothing has recorded what that engine
    /// leaves behind, and [`free_fragment_v6`] refuses to make one, so the
    /// shape stays refused rather than guessed at from its v5 sibling.
    fn read(page: &[u8], asked: u32, version: Version) -> Result<Self, String> {
        if page.len() < FIRST_FRAGMENT as usize {
            return Err(format!(
                "a {}-byte page, too short for a {FIRST_FRAGMENT}-byte header",
                page.len()
            ));
        }
        let number = match version {
            Version::V5 => super::pages::long(&page[PAGE_NUMBER..PAGE_NUMBER + 4]),
            Version::V6 => {
                // The tag as well as the id. `v6::Map` is one table over every
                // kind of page, so a logical id resolves to *a* page, not
                // necessarily a fragment page -- and a data page's slot-filled
                // tail can in principle be read as an entry array. `fragment`
                // would almost certainly refuse it downstream on the "first
                // live entry sits at 0x0c" check, but "almost certainly errors
                // out later" is not this crate's standard: `walk_v6` checks the
                // same tag before reading a page as records, and so does this.
                if page[TAG] != b'V' {
                    return Err(format!(
                        "page {asked} carries the type tag {:#04x}, not {:#04x} \
                         ('V'), so it is not a fragment page",
                        page[TAG],
                        b'V'
                    ));
                }
                u32::from(u16::from_le_bytes([page[LOGICAL], page[LOGICAL + 1]]))
            }
        };
        if number != asked {
            return Err(format!("page {asked} says it is page {number}"));
        }
        let fragments = u16::from_le_bytes([page[FRAGMENT_COUNT], page[FRAGMENT_COUNT + 1]]);
        if fragments > MAX_FRAGMENTS {
            return Err(format!(
                "{fragments} fragments, and a page holds at most {MAX_FRAGMENTS}"
            ));
        }
        if fragments == 0 && version == Version::V6 {
            return Err(format!(
                "page {asked} reports 0 fragments, and nothing has recorded what a \
                 version 6 page looks like once its last fragment is freed -- see \
                 this function's own doc comment"
            ));
        }
        Ok(Self {
            number,
            fragments,
            free_chain: match super::pages::long(&page[FREE_CHAIN..FREE_CHAIN + 4]) {
                NO_PAGE => FreeChain::Off,
                END_PAGE => FreeChain::Last,
                next => FreeChain::Next(next),
            },
        })
    }
}

/// One entry of a page's fragment array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// Where in the page the fragment starts, or [`UNUSED`].
    offset: u32,

    /// Whether the fragment starts with four bytes of pointer to the next one.
    ///
    /// **A v5 rule, and only ever consulted for v5.** `W32MKDE_decompiled.c:19045`
    /// gates it on the file version: below `0x600` this bit decides, and at
    /// or above it every fragment carries the pointer whatever the bit says.
    /// The plan this was implemented from claims 0 of 853 live v6 entries
    /// have it set but says that count was not re-derived; it has been now,
    /// independently and more narrowly -- every real (non-boundary-overrun)
    /// entry of every claimed `'V'` page across the four committed v6
    /// variable-length fixtures, 165 entries, 0 with the bit set. [`fragment`]
    /// overrides this field for v6 rather than trusting a bit the format
    /// does not use; see [`Chain::follow`] for what decides continuation
    /// there instead.
    continued: bool,
}

impl Entry {
    /// Read a two-byte entry.
    fn decode(bytes: &[u8]) -> Self {
        if bytes[0] == 0xff && bytes[1] == 0xff {
            return Self {
                offset: UNUSED,
                continued: false,
            };
        }
        Self {
            offset: u32::from(bytes[0]) | u32::from(bytes[1] & 0x7f) << 8,
            continued: bytes[1] & 0x80 != 0,
        }
    }
}

/// A fragment: where it is in its page, how long, and whether it continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fragment {
    at: usize,
    length: usize,

    /// Whether the record's chain goes on past this fragment. [`fragment`]
    /// sets this from [`Entry::continued`] for v5 and unconditionally `true`
    /// for v6 -- see [`Entry::continued`]'s doc comment for why the entry
    /// bit is not the answer there, and [`Chain::follow`] for how a v6
    /// fragment's own leading bytes settle it instead.
    continued: bool,
}

/// Where entry `which` of a `len`-byte page's array sits.
fn entry_at(len: u32, which: u32) -> Result<usize, String> {
    len.checked_sub(2 * (which + 1))
        .map(|at| at as usize)
        .ok_or_else(|| format!("entry {which} is before the start of a {len}-byte page"))
}

/// Find fragment `which` in `page`.
///
/// Three things are checked, and all three are the engine's own
/// (`W32MKDE_decompiled.c:19029-19060`):
///
/// - the first live entry of the array names offset `0x0c`, which is where
///   fragment 0 has to start because the header ends there. Status 54 in the
///   engine, and true of all 3,467 of `WCCTEXT`'s variable pages;
/// - the length is *derived*, not stored: it runs to wherever the next
///   fragment starts, skipping freed slots, which is why the array has one
///   more entry than the page has fragments;
/// - the fragment is inside the page.
///
/// The last is stricter here than in the engine, which only refuses a fragment
/// as long as the whole page: this refuses one that reaches into the array
/// behind it, as MBBSEmu does. Nothing in the corpus distinguishes them --
/// every `WCCTEXT` fragment is `0x0c..0x7dc` of a 2,048-byte page whose array
/// starts at `0x7fc`.
///
/// Everything above is version-independent -- measured directly against the
/// v6 corpus (Task 6 ground truth): the entry array sits at the same place,
/// grows the same direction, and fragment 0 starts at the same `0x0c` either
/// version. Only the returned [`Fragment::continued`] differs from
/// [`Entry::continued`], and that override is what this version parameter is
/// for -- see [`Entry::continued`]'s own doc comment.
fn fragment(page: &[u8], which: u8, header: Header, version: Version) -> Result<Fragment, String> {
    let len = page.len() as u32;
    let count = header.fragments;

    // Fragment 0 starts where the header ends. Checked before anything is
    // read out of the page, because a page that fails it is not a variable
    // page and every offset below would be measured against nothing.
    let mut first = None;
    for i in 0..=u32::from(count) {
        let entry = Entry::decode(&page[entry_at(len, i)?..][..2]);
        if entry.offset != UNUSED {
            first = Some(entry.offset);
            break;
        }
    }
    match first {
        Some(FIRST_FRAGMENT) => {}
        Some(other) => {
            return Err(format!(
                "the first live fragment starts at {other} and not at {FIRST_FRAGMENT} -- \
                 status 54, a variable page error"
            ));
        }
        None => return Err(format!("all {count} fragment entries are freed slots")),
    }

    let which = u32::from(which);
    if which >= u32::from(count) {
        return Err(format!("fragment {which} of a page holding {count}"));
    }
    let entry = Entry::decode(&page[entry_at(len, which)?..][..2]);
    if entry.offset == UNUSED {
        return Err(format!("fragment {which} of a page holding {count} is a freed slot"));
    }

    // The neighbour that ends this fragment. `count` inclusive: the array has
    // one more entry than the page has fragments, and it is that last entry
    // that marks the end of the last fragment.
    let mut end = None;
    for i in which + 1..=u32::from(count) {
        let next = Entry::decode(&page[entry_at(len, i)?..][..2]);
        if next.offset == UNUSED {
            continue;
        }
        end = Some(next.offset);
        break;
    }
    let Some(end) = end else {
        return Err(format!(
            "fragment {which} of a page holding {count} has no entry after it to end it"
        ));
    };
    let Some(length) = end.checked_sub(entry.offset) else {
        return Err(format!(
            "fragment {which} starts at {} and the entry after it is at {end}",
            entry.offset
        ));
    };

    // The array itself is the ceiling: `count + 1` entries of two bytes at the
    // end of the page, and a fragment reaching into them would be reading its
    // own bookkeeping.
    let ceiling = len.saturating_sub(2 * (u32::from(count) + 1));
    if entry.offset < FIRST_FRAGMENT || entry.offset + length > ceiling {
        return Err(format!(
            "fragment {which} spans {}..{} of a {len}-byte page whose fragments must lie \
             within {FIRST_FRAGMENT}..{ceiling}",
            entry.offset,
            entry.offset + length
        ));
    }

    Ok(Fragment {
        at: entry.offset as usize,
        length: length as usize,
        continued: match version {
            Version::V5 => entry.continued,
            // Every v6 fragment carries a 4-byte prefix, continued or not
            // (Task 6 ground truth) -- so this is unconditionally true, and
            // `Chain::follow` is what tells a real next-pointer apart from
            // the all-ones one that ends the chain, by decoding the prefix
            // and checking `Pointer::is_end` exactly as it already does for
            // an ordinary continuation.
            Version::V6 => true,
        },
    })
}

/// A walk along one record's fragments.
pub(crate) struct Chain;

impl Chain {
    /// Append the body of a record to `into`, following its chain from `first`.
    ///
    /// `into` is the record's fixed part on the way in and the whole record on
    /// the way out, so a caller never has to concatenate.
    ///
    /// # Two layouts, one loop
    ///
    /// `W32MKDE_decompiled.c:19045`:
    ///
    /// For v5, whether a fragment carries a leading pointer is the entry's
    /// own `0x8000` bit ([`Entry::continued`]), and a fragment that does not
    /// carry one is the end of the chain, full stop -- `fragment` reports
    /// this straight from the entry, unchanged from before Task 6.
    ///
    /// **In a v6 file every fragment carries the pointer, whatever the entry
    /// bit says** (Task 6 ground truth) -- so `fragment` reports `continued`
    /// as unconditionally `true` for v6, and this loop always decodes the
    /// leading four bytes and asks [`Pointer::is_end`] whether they are the
    /// chain's own `0xffffffff` terminator rather than a real next pointer.
    /// That terminator decodes to the same `page == END_PAGE, fragment ==
    /// END_FRAGMENT` pair the v5 sentinel already checks at the top of this
    /// loop, so v6 needs no second stopping condition: the existing
    /// `at.is_end()` check is what stops it, on the very next iteration,
    /// without reading another page.
    ///
    /// # Errors
    ///
    /// If a page cannot be read, a page disagrees about which page (v5) or
    /// logical id (v6) it is, a fragment is not inside its page, a continued
    /// fragment is too short to hold the pointer it promises, or the chain
    /// revisits a fragment it has already been to. The last is in neither the
    /// engine nor MBBSEmu, both of which would follow such a chain until they
    /// ran out of memory; a file whose chain re-enters itself is corrupt
    /// rather than merely long, and the same check guards the free list in
    /// [`records`](super::records).
    pub(crate) fn follow(
        pages: &mut impl Pages,
        version: Version,
        first: Pointer,
        into: &mut Vec<u8>,
    ) -> Result<(), String> {
        let mut at = first;
        let mut seen = HashSet::new();

        loop {
            if at.is_end() {
                return Ok(());
            }
            if !seen.insert((at.page, at.fragment)) {
                return Err(format!(
                    "the fragment chain returns to fragment {} of page {}",
                    at.fragment, at.page
                ));
            }

            let page = pages.page(at.page)?;
            let header = Header::read(page, at.page, version)?;
            let found = fragment(page, at.fragment, header, version)
                .map_err(|why| format!("page {}: {why}", at.page))?;
            let bytes = &page[found.at..found.at + found.length];

            if !found.continued {
                into.extend_from_slice(bytes);
                return Ok(());
            }

            // Continued: the first four bytes are where to go next, and are
            // not part of the record. Copied out before `into` grows, because
            // the next `pages.page` invalidates this borrow.
            if bytes.len() < POINTER {
                return Err(format!(
                    "page {}: fragment {} says it continues and is {} bytes, too short for a \
                     {POINTER}-byte pointer",
                    at.page,
                    at.fragment,
                    bytes.len()
                ));
            }
            let next = Pointer::decode([bytes[0], bytes[1], bytes[2], bytes[3]]);
            into.extend_from_slice(&bytes[POINTER..]);
            at = next;
        }
    }
}

/// Overwrite a single, whole, unfragmented, equal-length fragment in place.
///
/// This is the one shape a `dupdbtv` write to `WCCTEXT` ever asks for -- see
/// the module comment at the top of this file for the measurement -- and it
/// is validated by the page's own shape, not assumed from that measurement:
/// the page `pointer` names is re-read and checked before a byte of it is
/// touched, so a file that does not actually have that shape is refused
/// rather than corrupted.
///
/// # What is checked, in order
///
/// - **the file is Btrieve 5.** A v6 fragment page is addressed by logical
///   id through the `"PP"` allocation table rather than a physical byte
///   offset, and every v6 fragment carries its 4-byte pointer whether or
///   not the chain continues -- different enough, on both counts, that v6
///   has its own counterpart, [`rewrite_fragment_in_place_v6`], rather than
///   a version branch inside this one. This function still refuses a v6
///   file outright, and stays v5-only.
/// - **the page `pointer` names says it is that page** ([`Header::read`]).
/// - **the page holds exactly one fragment.** A page mid-split, or any page
///   with more on it than the one fragment this pointer names, is refused
///   rather than guessed at -- a second fragment's entry sits in the same
///   array this never touches, but nothing here has reason to assume it is
///   safe to leave alone on a page shaped differently from every one
///   `WCCTEXT` has.
/// - **that fragment starts at [`FIRST_FRAGMENT`]** -- the engine's own
///   status 54 check, reused from [`fragment`].
/// - **that fragment is not continued.** Rewriting one link of a chain that
///   spans pages needs the allocator and the entry array this does not
///   have; refused rather than attempted.
/// - **that fragment's existing length equals `new_body.len()`.** Anything
///   shorter or longer needs the free chain, the entry array, or a second
///   page, all of which are the work a later track does.
///
/// # What is written
///
/// Only `new_body`, into exactly the byte range the fragment already
/// occupied. The header, the free chain, the fragment count and the whole
/// entry array are read and never written --
/// [`tests::a_matching_shape_is_rewritten_in_place_and_touches_only_the_payload`]
/// asserts this on the actual bytes, not on the code that is supposed to
/// produce them.
///
/// # Errors
///
/// If any of the checks above fails, or the page cannot be read or written
/// back.
pub(crate) fn rewrite_fragment_in_place<P: PagesMut>(
    pages: &mut P,
    version: Version,
    pointer: Pointer,
    new_body: &[u8],
) -> Result<(), String> {
    if version != Version::V5 {
        return Err(format!(
            "{version:?} addresses a fragment page by logical id through the \"PP\" \
             allocation table, not a physical byte offset, and every one of its \
             fragments carries a leading pointer whether or not the chain continues \
             (W32MKDE_decompiled.c:19045) -- see `rewrite_fragment_in_place_v6` for \
             the {version:?} counterpart"
        ));
    }

    let page = pages.page(pointer.page)?.to_vec();
    let header = Header::read(&page, pointer.page, version)?;

    if header.fragments != 1 {
        return Err(format!(
            "page {}: holds {} fragments, and an in-place rewrite only handles a page \
             that holds exactly one",
            pointer.page, header.fragments
        ));
    }

    let found = fragment(&page, pointer.fragment, header, version)
        .map_err(|why| format!("page {}: {why}", pointer.page))?;

    if found.continued {
        return Err(format!(
            "page {}: fragment {} continues onto another page, and an in-place rewrite \
             only handles a fragment that is the whole record",
            pointer.page, pointer.fragment
        ));
    }

    if found.length != new_body.len() {
        return Err(format!(
            "page {}: fragment {} is {} bytes and the new body is {} -- an in-place \
             rewrite only handles a replacement of the same length",
            pointer.page,
            pointer.fragment,
            found.length,
            new_body.len()
        ));
    }

    let mut rewritten = page;
    rewritten[found.at..found.at + found.length].copy_from_slice(new_body);
    pages.write_page(pointer.page, &rewritten)
}

/// Overwrite a single, whole, unchained, equal-length v6 fragment in place --
/// the v6 counterpart of [`rewrite_fragment_in_place`].
///
/// `pointer.page` is a **logical** id, resolved through `pages`
/// ([`V6Pages`], backed by the `"PP"` allocation table), not a physical
/// page number -- the same distinction [`Header::read`]'s own v6 branch
/// makes.
///
/// # Why "not continued" cannot be [`Fragment::continued`] here
///
/// Every v6 fragment carries its 4-byte leading pointer whether or not the
/// chain actually goes on ([`Entry::continued`]'s own doc comment, harvest 5
/// SS3.4) -- so [`fragment`] always reports `continued: true` for a v6 page,
/// and that field cannot tell a whole record from one link of a longer
/// chain. What can is the pointer's own *value*: [`Chain::follow`] decodes
/// it and asks [`Pointer::is_end`], and this does the identical check on
/// the same bytes before touching anything, rather than inventing a second
/// way to ask the same question.
///
/// # Why this rewrite does not require the page to hold only one fragment
///
/// [`rewrite_fragment_in_place`] (v5) refuses any page with more than one
/// fragment on it, conservatively, because the one real file it was proven
/// against (`WCCTEXT.DAT`) never packed more than one. This v6 counterpart
/// does not need that restriction and does not take it: measured directly
/// against real MajorMUD-NT data (`wccnt7pw`'s copy of `wcctext2.vir`, whose
/// short 12-byte-`reclen` records pack many fragments per 4096-byte page --
/// pages with 9 and 13 live fragments observed), a v6 fragment page routinely
/// holds several. [`fragment`] already derives *this* fragment's own
/// `at`/`length` from the entry array regardless of how many neighbours
/// share the page (that is the whole purpose of the array), and only the
/// bytes `at..at+length` are ever touched here -- a sibling fragment's own
/// span is never read or written, so leaving it alone needs no assumption
/// beyond what [`fragment`] itself already guarantees.
///
/// # What is checked, in order
///
/// - **the page `pointer` names says it is that logical page**
///   ([`Header::read`]).
/// - **that fragment starts at [`FIRST_FRAGMENT`], if it is fragment 0** --
///   the engine's own status 54 check, reused from [`fragment`].
/// - **that fragment's own leading pointer is the chain's end-of-chain
///   sentinel** ([`Pointer::is_end`]). A real next pointer means this
///   record's body spans more than one page; rewriting that needs the
///   allocator and the entry-array edits a resize or a chain splice would
///   take, none of which is measured against genuine Btrieve 6.15 for v6 --
///   refused rather than guessed, the same standard the v5 function already
///   holds itself to for exactly this shape.
/// - **that fragment's existing body length (its span minus the leading
///   pointer) equals `new_body.len()`.** Anything shorter or longer needs
///   the free chain, the entry array, or a second page -- unmeasured, and
///   out of scope for the same reason as the point above.
///
/// # What is written
///
/// Only `new_body`, into exactly the bytes past the fragment's own leading
/// pointer -- which is read, checked, and left untouched, not rewritten:
/// the fragment does not move, so its own pointer does not change.
///
/// # Errors
///
/// If any of the checks above fails, or the page cannot be read or written
/// back.
pub(crate) fn rewrite_fragment_in_place_v6<P: PagesMut>(
    pages: &mut P,
    pointer: Pointer,
    new_body: &[u8],
) -> Result<(), String> {
    let page = pages.page(pointer.page)?.to_vec();
    let header = Header::read(&page, pointer.page, Version::V6)?;

    let found = fragment(&page, pointer.fragment, header, Version::V6)
        .map_err(|why| format!("logical page {}: {why}", pointer.page))?;

    if found.length < POINTER {
        return Err(format!(
            "logical page {}: fragment {} is {} bytes, too short for the \
             {POINTER}-byte leading pointer every v6 fragment carries",
            pointer.page, pointer.fragment, found.length
        ));
    }
    let leading: [u8; POINTER] = page[found.at..found.at + POINTER]
        .try_into()
        .expect("checked against POINTER above");
    let next = Pointer::decode(leading);
    if !next.is_end() {
        return Err(format!(
            "logical page {}: fragment {}'s own pointer names page {}, fragment {} -- \
             this record's body continues onto another page, and rewriting a chain \
             that spans more than one page is not implemented",
            pointer.page, pointer.fragment, next.page, next.fragment
        ));
    }

    let body_len = found.length - POINTER;
    if body_len != new_body.len() {
        return Err(format!(
            "logical page {}: fragment {} carries a {body_len}-byte body and the new \
             body is {} -- an in-place rewrite only handles a replacement of the same \
             length",
            pointer.page,
            pointer.fragment,
            new_body.len()
        ));
    }

    let mut rewritten = page;
    let body_at = found.at + POINTER;
    rewritten[body_at..body_at + body_len].copy_from_slice(new_body);
    pages.write_page(pointer.page, &rewritten)
}

/// Free a single, unchained v6 fragment: the delete-side counterpart of
/// [`rewrite_fragment_in_place_v6`].
///
/// # What genuine Btrieve does, which this follows
///
/// **This is the one v6 variable-length mutation this crate has an actual
/// oracle recording of** -- unlike [`rewrite_fragment_in_place_v6`], which
/// has none (see its own module's Task 6 report). `varfree.c`'s delete
/// ladder against a genuine, `B_CREATE`d (therefore v6) file
/// (`docs/2026-08-17-variable-write-oracle.md`, "Delete frees the entry and
/// compacts the page") measured deleting the first of three fragments on a
/// page:
///
/// ```text
/// before  frags 3  entries [0x0c,   0xd8, 0x1a4, 0x1f8]   free 0
/// after   frags 3  entries [0xffff, 0x0c, 0xd8,  0x12c]   free 204
/// ```
///
/// The freed entry becomes `0xffff` in place; every fragment after it
/// shifts down by the freed length to close the gap, and every entry after
/// it (including the boundary) is rebased by the same amount. Fragment
/// count is unchanged -- the freed slot is interior. That is the **interior**
/// branch below, applied verbatim.
///
/// The same document also measured freeing the *last* live fragment on a
/// page: "the count drops -- logical 5 went from 3 fragments to 2 ... while
/// keeping its `0xffff` at entry 0." No exact before/after bytes are given
/// for that step, so the **trailing** branch below is a derivation, not a
/// transcription: entry `which`'s own storage address (`entry_at(len,
/// which)`) is *identical* to what becomes the new boundary's address once
/// `fragments` decrements by one (`entry_at` depends only on `which`, not on
/// the page's fragment count) -- and entry `which` already holds exactly the
/// value the new boundary needs, the freed fragment's own start offset. So
/// decrementing the count is the *entire* write; no entry bytes change. This
/// reproduces the documented before/after of the interior case exactly when
/// checked the same way, and is the simplest change consistent with the
/// array's own documented invariant (`variable.rs`'s module doc: "the array
/// has one more entry than the page has fragments").
///
/// # What is refused, and why
///
/// - **A chained fragment** (this record's body continues onto another
///   page). Freeing a whole chain needs to walk and free every hop, in an
///   order and with a page-reclaim rule this host has not measured -- same
///   standard [`rewrite_fragment_in_place_v6`] already holds itself to.
/// - **Freeing the only fragment on a page** (`header.fragments == 1`).
///   The trailing derivation above decrements the count to zero, and
///   [`Header::read`] refuses a **version 6** page reporting zero fragments
///   -- so writing this would leave a page this crate's own reader cannot
///   open again. Whether genuine Btrieve reclaims the whole page, leaves a
///   zero-fragment marker this host's reader does not understand, or
///   something else, is not in the oracle ladder above (every page it
///   measured kept at least one fragment) -- refused rather than guessed.
///   The v5 side of this **is** measured now
///   (`v5_variable_release_empty.fixture`: the page stays where it is,
///   holding nothing -- see [`free_fragment`]), and there it is allowed;
///   nothing has recorded a v6 file doing the same, so this stays refused
///   rather than borrowing its sibling's answer.
/// - **An entry between `which` and the boundary that is already `0xffff`.**
///   The interior branch rebases every one of those entries by subtracting
///   the freed length; doing that to an already-`0xffff` entry corrupts the
///   freed-slot sentinel rather than shifting a real offset. This is the
///   *only* shape a second delete on the same page can make unsafe -- see
///   the next section for why a second delete that does not hit this is
///   fine, not merely untested.
///
/// # A second delete on the same page: what is and is not safe
///
/// No corpus file exercises this (every v6 file here is first-generation,
/// zero real deletions, harvest 5 SS6.3) and neither does the oracle ladder,
/// which never deletes twice from the same page before the fragments in
/// between are already gone -- so this is reasoned from the array's own
/// invariant, the same way the trailing derivation above is, not measured.
///
/// **A page that already took an *interior* free is unsafe for a later
/// delete whose rebase range reaches the resulting `0xffff`** -- refused
/// above, and that check is history-independent: it inspects the entries a
/// delete is about to rebase, not how many prior deletes produced them, so
/// it catches this whether it is the second delete on the page or the
/// fifth.
///
/// **A page that already took a *trailing* free is safe for another
/// delete, and this is not merely unrefused -- it is provably so.** The
/// trailing branch leaves no `0xffff` anywhere: it only decrements the
/// count, so the resulting page is byte-for-byte the shape a page that had
/// always held that many fragments would be (see the trailing derivation
/// above: entry `which`'s address becomes the new boundary's address
/// verbatim). Nothing downstream -- `fragment()`, this function's own
/// checks, a later `Chain::follow` -- can tell the two apart, because there
/// is no bit anywhere that distinguishes "always had N fragments" from
/// "had more, now has N." A later delete against such a page runs the
/// identical code a first delete against a virgin N-fragment page would,
/// and cannot behave differently. Exercised directly by
/// [`tests::a_second_delete_after_a_trailing_free_is_not_a_special_case`],
/// which frees, then frees again, and checks the resulting bytes rather
/// than only that the call succeeded.
///
/// # What is written
///
/// Interior: the content between the freed fragment and the old boundary
/// shifts down over it (`copy_within`), every entry from `which + 1` through
/// the boundary is rebased down by the freed length, and entry `which`
/// itself becomes `0xffff`. Trailing: only the fragment count, by one.
/// Either way, if the page was off the write-side free-space chain and now
/// has room, its own [`FREE_CHAIN`] field joins it at `head` -- see "What
/// this host also leaks" on `Block::delete_v6`, which this
/// replaces. The header (past `FREE_CHAIN`), the free chain (when this does
/// not rejoin it) and every fragment before `which` are read and never
/// written.
///
/// # Errors
///
/// If any of the checks above fails, or the page cannot be read or written
/// back.
///
/// # Returns
///
/// The write-side free-space chain's head after this call, for the caller
/// to write back to `pages::fcr::VARIABLE_HEAD` -- `head` unchanged unless
/// this page just joined the chain, the same threading `Space::head` does
/// for the insert side.
pub(crate) fn free_fragment_v6<P: PagesMut>(
    pages: &mut P,
    pointer: Pointer,
    head: Option<u32>,
) -> Result<Option<u32>, String> {
    let page = pages.page(pointer.page)?.to_vec();
    let header = Header::read(&page, pointer.page, Version::V6)?;

    let found = fragment(&page, pointer.fragment, header, Version::V6)
        .map_err(|why| format!("logical page {}: {why}", pointer.page))?;

    if found.length < POINTER {
        return Err(format!(
            "logical page {}: fragment {} is {} bytes, too short for the \
             {POINTER}-byte leading pointer every v6 fragment carries",
            pointer.page, pointer.fragment, found.length
        ));
    }
    let leading: [u8; POINTER] = page[found.at..found.at + POINTER]
        .try_into()
        .expect("checked against POINTER above");
    let next = Pointer::decode(leading);
    if !next.is_end() {
        return Err(format!(
            "logical page {}: fragment {}'s own pointer names page {}, fragment {} -- \
             this record's body continues onto another page, and freeing a chain \
             that spans more than one page is not implemented",
            pointer.page, pointer.fragment, next.page, next.fragment
        ));
    }

    let which = u32::from(pointer.fragment);
    let fragments = u32::from(header.fragments);
    let mut rewritten = page;

    if which + 1 == fragments {
        if fragments == 1 {
            return Err(format!(
                "logical page {}: fragment {} is the only one on its page, and \
                 freeing it would leave the page reporting 0 fragments -- a shape \
                 `Header::read` refuses for version 6 and no version 6 recording \
                 reaches (every delete `docs/2026-08-17-variable-write-oracle.md` \
                 measured left at least one fragment behind; the v5 answer is \
                 measured, see `free_fragment`, and is not borrowed here)",
                pointer.page, pointer.fragment
            ));
        }
        set_fragment_count(&mut rewritten, header.fragments - 1);
    } else {
        for i in (which + 1)..=fragments {
            if entry(&rewritten, i)? == UNUSED {
                return Err(format!(
                    "logical page {}: entry {i} is already a freed slot -- compacting \
                     past a pre-existing hole is not measured",
                    pointer.page
                ));
            }
        }
        let old_boundary = entry(&rewritten, fragments)? as usize;
        rewritten.copy_within(found.at + found.length..old_boundary, found.at);
        for i in (which + 1)..=fragments {
            let old = entry(&rewritten, i)?;
            set_entry(&mut rewritten, i, old - found.length as u32)?;
        }
        set_entry(&mut rewritten, which, UNUSED)?;
    }

    // Rejoin the write-side free-space chain if this page just gained real
    // room and was not already reachable from it. The oracle's own ladder
    // ("The chain is LIFO"): every delete that freed space on a page put
    // that page at the *head* -- `head 4` -> `delete key 1: head 5` -> etc.
    // A page already on the chain somewhere (`Next`/`Last`) is left exactly
    // where it is: moving it to the head from the middle needs an unlink
    // this host has not measured, the same restriction `Space::reoffer`
    // already holds itself to for the symmetric insert-side case.
    let after = Header::read(&rewritten, pointer.page, Version::V6)?;
    let new_head = if after.free_chain == FreeChain::Off && is_roomy(&rewritten, after)? {
        set_chain(
            &mut rewritten,
            match head {
                Some(next) => FreeChain::Next(next),
                None => FreeChain::Last,
            },
        );
        Some(pointer.page)
    } else {
        head
    };

    pages.write_page(pointer.page, &rewritten)?;
    Ok(new_head)
}

/// Free a single, unchained **version 5** fragment: the delete-side
/// counterpart of [`rewrite_fragment_in_place`], and the v5 sibling of
/// [`free_fragment_v6`].
///
/// # What genuine Btrieve does, which this follows
///
/// Two sources, and they agree.
///
/// **The recording.** `crates/btrieve-oracle/fixtures/v5_variable_delete.
/// fixture` is genuine Pervasive Btrieve 6.15 driven over the wire against a
/// version 5, variable-length file this crate's own [`super::create`] wrote
/// (31-byte fixed part, 1,024-byte pages): insert `Sysop` (body
/// `"EMO NORMAL SYSOP\0"`, 17 bytes), insert `Test` (body `"EMO\0"`, 4
/// bytes), get `Sysop`, **delete it**, get `Sysop` again (status 4, gone),
/// insert `Testy` (body `"EMO NORMAL MODERATE MASS_MAIL\0"`, 30 bytes),
/// close. The transcript carries the file as it stood after the *last* call,
/// so the intermediate state is inferred from those final bytes plus the
/// insert rules [`V5Pages`] measured -- said so explicitly below, fact by
/// fact.
///
/// Its variable page 5 (file offset `0x1400`) ends up:
///
/// ```text
/// 0x1400  00 00 05 00   PAGE_NUMBER = 5
/// 0x1404  03 00         modification stamp = 3
/// 0x1406  ff 00 ff ff   FREE_CHAIN = FreeChain::Last, unchanged by the delete
/// 0x140a  02 00         FRAGMENT_COUNT = 2
/// 0x140c  "EMO NORMAL MODERATE MASS_MAIL\0"   fragment 0, 30 bytes, to 0x142a
/// 0x142a  "EMO\0"                             fragment 1,  4 bytes, to 0x142e
/// 0x17fa  2e 00 2a 00 0c 00                   entry 2, entry 1, entry 0
/// ```
///
/// and the two surviving records' own pointers read `00 05 00 00` at
/// `0x1025` (`Testy` -> page 5, fragment **0**) and `00 05 00 01` at
/// `0x1048` (`Test` -> page 5, fragment **1**).
///
/// So, **measured** from those bytes:
///
/// - the page's fragment count did **not** drop: 2 before the delete, 2
///   after the re-insert;
/// - the surviving record kept fragment index **1**, and the re-inserted one
///   took index **0** -- the freed slot was **reused**, not appended past
///   the end;
/// - the free chain at `0x1406` and the control record's own head at
///   [`super::format::fcr::at::VARIABLE_HIGHEST`] (`0x3a`, still `05 00`)
///   were untouched: the page was already on the chain and stayed where it
///   was;
/// - the modification stamp reads **3** for a page written four times
///   (claim+first fragment, second fragment, the delete, the re-insert).
///   That settles the reading [`V5Pages`] had to choose from insert-only
///   evidence: the stamp is a **counter bumped on every write**, not
///   `fragments - 1` (which would read 1 here). The delete is one write of
///   the page, and the rule needs no delete-side special case.
///
/// **Inferred** -- the state between the delete and the re-insert, which no
/// recorded byte shows directly:
///
/// - entry 0 became the freed-slot sentinel `0xffff` ([`UNUSED`]). It is the
///   only way index 0 can be vacant while index 1 stays occupied, which the
///   two records' own pointers above require.
/// - the page was **compacted**: the surviving fragment moved down over the
///   freed one, to `0x0c`, and its entry was rebased from `0x1d` to `0x0c`.
///   Two independent arguments, and no third reading survives either. First,
///   this crate's own status 54 rule ([`fragment`], the engine's
///   `W32MKDE_decompiled.c:19035`): the **first live entry** of a variable
///   page must name [`FIRST_FRAGMENT`], and after the delete entry 0 is a
///   freed slot, so entry 1 has to be `0x0c` or the engine would refuse its
///   own file. Second, the engine's allocator (`FUN_00420da0` at
///   `W32MKDE_decompiled.c:19267`) starts a fragment that reuses a freed
///   slot at *the offset the next live entry currently holds*
///   (`*puVar16 = uVar2 & 0x7fff`, `uVar2` being that entry) -- and the
///   re-insert put `Testy` at `0x0c`, so the next live entry read `0x0c`
///   just before it, not the `0x1d` an uncompacted page would have left.
///
/// **The engine's own routine**, which is where the rest of the rules below
/// come from: `FUN_004217a0` at `W32MKDE_decompiled.c:19737` is the
/// microkernel's fragment free, and it is one routine for both file
/// versions. In order, it:
///
/// 1. shifts everything between the freed fragment's end and the free-space
///    boundary down over the freed fragment (`uVar7 = uVar9 - uVar10`, then
///    the copy loop), and **zeroes** the `length` bytes that leaves at the
///    top of the used area (the second loop, storing `0`);
/// 2. for an **interior** slot (`local_25 != count - 1`): writes `0xffff`
///    over the freed entry and subtracts the freed length from every entry
///    after it up to and including the boundary, **skipping** entries that
///    are already `0xffff` (`if (*puVar5 != 0xffff)`). The fragment count
///    does not move. This is the branch the recording above exercises;
/// 3. for a **trailing** slot: the freed entry becomes the new boundary
///    (`(uVar10 & 0x7fff) - local_24`, which is the value it already held),
///    the old boundary entry is zeroed, and the count drops by one -- then
///    the same collapse repeats while the entry *before* it is `0xffff`, so
///    a run of freed slots at the end of the array goes away with it;
/// 4. rejoins the write-side free-space chain at the head if the page was
///    off it and now has room ([`is_roomy`]), exactly as
///    [`free_fragment_v6`] and [`Space::reoffer`] already do.
///
/// # What is refused, and why
///
/// - **A chained fragment** ([`Fragment::continued`], the v5 entry's
///   `0x8000` bit). Freeing every hop of a chain is a walk this host has not
///   measured -- the same standard [`free_fragment_v6`] holds itself to.
///
/// # Emptying the page, which is now measured too
///
/// This used to be the second refusal here: freeing a page's only fragment
/// takes the count to zero, and what genuine Btrieve did with the emptied
/// page had not been recorded. Two more recordings settle it, both driven
/// against the same seed file and both carrying six 1,024-byte pages
/// afterwards.
///
/// **`v5_variable_release_empty.fixture`** -- open, insert `Only` (body
/// `"EMO\0"`, 4 bytes), get it, **delete it**, get it again (status 4),
/// close. Statuses `0,0,0,0,4,0`. Its page 5 (file offset `0x1400`):
///
/// ```text
/// 0x1400  00 00 05 00   PAGE_NUMBER = 5, still page 5 of a six-page file
/// 0x1404  01 00         modification stamp = 1
/// 0x1406  ff 00 ff ff   FREE_CHAIN = FreeChain::Last, unchanged by the delete
/// 0x140a  00 00         FRAGMENT_COUNT = 0
/// 0x140c  ..0x17fc      every byte zero
/// 0x17fc  00 00         entry 1, the old boundary, zeroed
/// 0x17fe  0c 00         entry 0, the new boundary, back to FIRST_FRAGMENT
/// ```
///
/// and its control record:
///
/// ```text
/// 0x10  00 00 06 10   fcr::FREE = 0x1006, the record slot the delete freed
/// 0x1c  00 00 00 00   the file holds no records
/// 0x26  00 00 06 00   fcr::PAGES = 6, unchanged -- the page is still there
/// 0x39  00           no longer virgin
/// 0x3a  05 00        VARIABLE_HIGHEST = 5, unchanged -- still the chain head
/// ```
///
/// So, **measured**: genuine does not release, truncate, relink or blank the
/// emptied page. It leaves it exactly where it is, on the free-space chain
/// where it already was, holding no fragments, with the boundary entry back
/// at [`FIRST_FRAGMENT`] and the freed body zeroed -- which is byte for byte
/// what rule 3 above (the trailing collapse) already produces, with the
/// count reaching zero instead of stopping at one. Neither `fcr::PAGES` nor
/// `VARIABLE_HIGHEST` is touched. Whatever `FUN_00418dc0` does, it does not
/// do it to a v5 file's variable page.
///
/// **`v5_variable_release_reinsert.fixture`** -- the same up to the delete,
/// then insert `Next` (body `"EMO NORMAL\0"`, 11 bytes), get `next` through
/// the ACS, close. Statuses `0,0,0,0,0,0,0`. Its page 5:
///
/// ```text
/// 0x1400  00 00 05 00   PAGE_NUMBER = 5 -- the SAME page, nothing was claimed
/// 0x1404  02 00         modification stamp = 2, one more than the delete left
/// 0x1406  ff 00 ff ff   FREE_CHAIN = FreeChain::Last
/// 0x140a  01 00         FRAGMENT_COUNT = 1
/// 0x140c  "EMO NORMAL\0"                  fragment 0, 11 bytes, to 0x1417
/// 0x17fc  17 00 0c 00                     entry 1 (boundary), entry 0
/// ```
///
/// with the record's own pointer at `0x1025` reading `00 05 00 00` -- page
/// 5, fragment 0 -- `fcr::PAGES` still 6 and `VARIABLE_HIGHEST` still 5. So
/// the emptied page is **reused**: the next insert walks the chain, finds
/// page 5 with room, and appends fragment 0 to it exactly as it would to any
/// other part-full page. [`Space`] needs no new branch for it, only a
/// [`Header::read`] that will open a zero-fragment page.
///
/// The two stamps are also what pinned [`V5Pages`]'s stamp rule to the write
/// counter it is: 1 after two writes of the page, 2 after three.
///
/// # What is written
///
/// One page, once -- which is what the modification stamp above requires.
/// The header past [`FREE_CHAIN`], every fragment before the freed one, and
/// every entry the rules above do not name are read and never written.
///
/// # Errors
///
/// If any of the checks above fails, or the page cannot be read or written
/// back.
///
/// # Returns
///
/// The write-side free-space chain's head after this call, for the caller to
/// write back to [`super::format::fcr::at::VARIABLE_HIGHEST`] through
/// [`set_v5_head`] -- `head` unchanged unless this page just joined the
/// chain, the same threading [`Space::head`] does for the insert side.
pub(crate) fn free_fragment<P: PagesMut>(
    pages: &mut P,
    pointer: Pointer,
    head: Option<u32>,
) -> Result<Option<u32>, String> {
    let page = pages.page(pointer.page)?.to_vec();
    let header = Header::read(&page, pointer.page, Version::V5)?;

    let found = fragment(&page, pointer.fragment, header, Version::V5)
        .map_err(|why| format!("page {}: {why}", pointer.page))?;

    if found.continued {
        return Err(format!(
            "page {}: fragment {} continues onto another page, and freeing a chain \
             that spans more than one page is not implemented",
            pointer.page, pointer.fragment
        ));
    }

    let which = u32::from(pointer.fragment);
    let fragments = u32::from(header.fragments);

    // How many entries this free takes out of the array: one for the
    // fragment itself, plus the run of already-freed slots the engine's
    // trailing branch collapses along with it. Zero for an interior free,
    // whose array keeps every entry it has. It may take out every entry the
    // page has, which leaves the page holding nothing -- what genuine does
    // there is measured, see this function's own doc comment.
    let collapsed = if which + 1 == fragments {
        let mut collapsed = 1;
        while collapsed <= which && entry(&page, which - collapsed)? == UNUSED {
            collapsed += 1;
        }
        collapsed
    } else {
        0
    };
    let mut rewritten = page;
    let boundary = entry(&rewritten, fragments)? as usize;
    if boundary == UNUSED as usize {
        return Err(format!(
            "page {}'s entry {fragments} is free, so nothing says where its fragments end",
            pointer.page
        ));
    }

    // Close the gap, and zero what that leaves behind at the top of the used
    // area. A trailing free moves nothing and zeroes the fragment itself.
    rewritten.copy_within(found.at + found.length..boundary, found.at);
    rewritten[boundary - found.length..boundary].fill(0);

    let length = found.length as i32;
    if collapsed == 0 {
        for i in (which + 1)..=fragments {
            move_entry(&mut rewritten, i, -length)?;
        }
        set_entry(&mut rewritten, which, UNUSED)?;
    } else {
        // Highest index first, the order the engine's own loop takes them
        // in: each step zeroes the entry above the one it is dropping, so
        // going the other way would write the new boundary into an entry a
        // later step has to zero and leave it there.
        let new_boundary = (boundary - found.length) as u32;
        for i in ((which + 1 - collapsed)..=which).rev() {
            set_entry(&mut rewritten, i + 1, 0)?;
            set_entry(&mut rewritten, i, new_boundary)?;
        }
        set_fragment_count(
            &mut rewritten,
            header.fragments - collapsed as u16,
        );
    }

    // Rejoin the write-side free-space chain if this page just gained real
    // room and was not already reachable from it -- `free_fragment_v6`'s own
    // comment on the LIFO the oracle ladder measured applies unchanged, and
    // a page already on the chain (as the recording's page 5 is) keeps its
    // place and its successor.
    let after = Header::read(&rewritten, pointer.page, Version::V5)?;
    let new_head = if after.free_chain == FreeChain::Off && is_roomy(&rewritten, after)? {
        set_chain(
            &mut rewritten,
            match head {
                Some(next) => FreeChain::Next(next),
                None => FreeChain::Last,
            },
        );
        Some(pointer.page)
    } else {
        head
    };

    pages.write_page(pointer.page, &rewritten)?;
    Ok(new_head)
}

/// [`PagesMut`] over an actual file on disk, addressed by page number.
///
/// A file handle is opened fresh for each [`Pages::page`] or
/// [`PagesMut::write_page`] call rather than held open across both --
/// [`rewrite_fragment_in_place`] touches exactly one page per call, so there
/// is nothing to be gained by the kind of borrowed, held-open file
/// [`records::walk`](super::records)'s `Chained` uses to follow a chain
/// across many pages in one read.
pub(crate) struct FilePages<'a> {
    path: &'a std::path::Path,
    page_len: u16,
    pages: u32,
    buffer: Vec<u8>,
}

impl<'a> FilePages<'a> {
    /// `page_len` is the file's own page size and `pages` is how many pages
    /// it currently is -- both `Geometry`'s, passed rather than read again so
    /// this cannot disagree with the caller about either.
    pub(crate) fn new(path: &'a std::path::Path, page_len: u16, pages: u32) -> Self {
        Self {
            path,
            page_len,
            pages,
            buffer: vec![0u8; usize::from(page_len)],
        }
    }
}

impl Pages for FilePages<'_> {
    fn page(&mut self, number: u32) -> Result<&[u8], String> {
        use std::io::{Read, Seek, SeekFrom};

        // Page 0 is the file control record and never holds a fragment; see
        // `records::Chained::page`, which refuses the same thing for the same
        // reason.
        if number == 0 || number >= self.pages {
            return Err(format!(
                "page {number}, and the file is {} pages",
                self.pages
            ));
        }
        let mut file = crate::open_for_read(self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        let at = u64::from(number) * u64::from(self.page_len);
        file.seek(SeekFrom::Start(at))
            .and_then(|_| file.read_exact(&mut self.buffer))
            .map_err(|e| format!("page {number}: {e}"))?;
        Ok(&self.buffer)
    }
}

impl PagesMut for FilePages<'_> {
    fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String> {
        use std::io::{Seek, SeekFrom, Write};

        if page.len() != usize::from(self.page_len) {
            return Err(format!(
                "a {}-byte page for a {}-byte page slot",
                page.len(),
                self.page_len
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        let at = u64::from(number) * u64::from(self.page_len);
        file.seek(SeekFrom::Start(at))
            .and_then(|_| file.write_all(page))
            .and_then(|_| file.flush())
            .map_err(|e| format!("page {number}: {e}"))
    }
}

/// The two-byte type tag a variable page carries, as [`super::v6::Map::claim`]
/// wants it: `0x00` then the letter, so the page reads `0x5600` as a
/// little-endian `u16` and [`TAG`] finds `'V'` at byte 1.
pub(crate) const V_TAG: [u8; 2] = [0x00, b'V'];

/// [`PagesMut`], plus the ability to bring a *new* page into the file.
///
/// Separate from [`PagesMut`] because claiming is the one thing v5 and v6
/// disagree about in kind rather than in degree: v6 claims a **logical** id
/// through the `"PP"` allocation table, and v5 **appends** a physical page to
/// the end of the file ([`V5Pages`], measured). Folding that into [`PagesMut`]
/// would hand every reader a capability it never uses, which is the mistake
/// [`PagesMut`]'s own doc comment already declines to make.
pub(crate) trait PageSource: PagesMut {
    /// Bring `content` into the file as a new variable page, and answer with
    /// the number a [`Pointer`] must name to reach it -- **logical** for v6,
    /// physical for v5.
    fn claim(&mut self, content: &[u8]) -> Result<u32, String>;

    /// Bytes per page. Fragment placement needs it and [`Pages`] does not
    /// expose it.
    fn page_size(&self) -> u16;
}

/// A v6 file's pages, resolved and written through its `"PP"` allocation
/// table.
///
/// Backed by a [`super::v6::Store`] -- the same lazy, page-at-a-time cache
/// `Block::insert_v6` now works through, not a whole-file `Vec` read
/// upfront. A variable-length record's own placement touches only its own
/// pages plus the allocation table, and `Store` is what makes that bounded
/// rather than incidental.
///
/// **The map is re-read after every claim and every write**, because both
/// move pages: `relocate` writes a logical page to its *other* physical twin
/// and rewrites the allocation-table entry, so a `Map` taken before the call
/// resolves to the stale twin afterwards. Re-reading costs a pass over the
/// table per page written and is what makes the alternative -- caching a map
/// and hoping -- not worth reasoning about.
pub(crate) struct V6Pages<'a> {
    store: &'a mut super::v6::Store,
    page_size: u16,
    map: super::v6::Map,
}

impl<'a> V6Pages<'a> {
    /// Read the allocation table and take the store.
    pub(crate) fn new(store: &'a mut super::v6::Store, page_size: u16) -> Result<Self, String> {
        let map = super::v6::Map::read(store, page_size)?;
        Ok(Self {
            store,
            page_size,
            map,
        })
    }
}

impl Pages for V6Pages<'_> {
    fn page(&mut self, number: u32) -> Result<&[u8], String> {
        let physical = self.map.physical(number).ok_or_else(|| {
            format!(
                "logical page {number}, and the allocation table names no live physical \
                 page for it"
            )
        })?;
        self.store.page(physical as usize)
    }
}

impl PagesMut for V6Pages<'_> {
    fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String> {
        super::v6::Map::relocate(self.store, self.page_size, number, page, V_TAG)?;
        self.map = super::v6::Map::read(self.store, self.page_size)?;
        Ok(())
    }
}

impl PageSource for V6Pages<'_> {
    fn claim(&mut self, content: &[u8]) -> Result<u32, String> {
        let logical = super::v6::Map::claim(self.store, self.page_size, content, V_TAG)?;
        self.map = super::v6::Map::read(self.store, self.page_size)?;
        Ok(logical)
    }

    fn page_size(&self) -> u16 {
        self.page_size
    }
}

/// A version 5 file's pages, addressed physically, with a fresh one appended
/// to the end of the file.
///
/// # Measured, not inferred
///
/// Every rule below was read out of the two committed recordings of genuine
/// Pervasive Btrieve 6.15 writing into a **version 5** variable-length file
/// this crate's own [`create`](super::create) wrote:
/// `crates/btrieve-oracle/fixtures/v5_variable_insert.fixture` and
/// `v5_variable_grow.fixture` (see `fixtures/README.md` for each scenario).
/// The offsets below are offsets into those fixtures' own
/// `transcript.file` -- the genuine engine's resulting file, byte for byte.
/// Both files have 1,024-byte pages.
///
/// ## Where a fresh variable page comes from: the end of the file
///
/// The seed is four pages (`fcr::PAGES`, `0x26..0x2a`, reads `00 00 04 00`).
/// After the insert scenario's two records it reads `00 00 06 00` and the
/// file is six pages; after the grow scenario's sixty it reads `00 00 0d 00`
/// and the file is thirteen. Every page the engine brought in is a page it
/// **appended**: the first variable page of the insert scenario is physical
/// page 5, at file offset `0x1400`, which is one past the last page the file
/// had. Nothing was taken from a free list -- the v5 free-list head at
/// `0x10..0x14` (`super::pages::fcr::FREE`) is `ff ff ff ff` in the seed and
/// holds a **record slot position** afterwards, not a page: `00 00 4c 10` =
/// `0x104c` in the insert scenario (page 4, third 35-byte slot) and
/// `00 00 4c 30` = `0x304c` in the grow one. That field threads free record
/// slots on data pages and never names a variable page, so a v5 claim has
/// nowhere to take one from and appends.
///
/// ## The fresh page's own bytes
///
/// The insert scenario's page 5 opens
/// `00 00 05 00 | 01 00 | ff 00 ff ff | 02 00` at `0x1400`:
///
/// - `0x00..0x04` [`PAGE_NUMBER`]: `00 00 05 00`, [`super::pages::long`] of
///   5 -- its own **physical** page number. [`Header::read`] checks it, so
///   [`claim`](PageSource::claim) has to stamp it; [`blank_page`] cannot,
///   because it does not know which page it is about to become.
/// - `0x04..0x06`: `01 00`. The same modification stamp
///   [`super::pages::Header`] reads for a data page, and on all three
///   genuine variable pages it is one less than the fragment count: 1 with
///   2 fragments here, `2b 00` (43) with `2c 00` (44) fragments on the grow
///   scenario's page 5 at `0x1400`, `0f 00` (15) with `10 00` (16) on its
///   page 10 at `0x2800`. That equality is a coincidence of an insert-only
///   history, one write per fragment; the field is a **counter of writes
///   since the page was created**, starting at zero. Three later recordings
///   separate the two readings, and all three say counter:
///   `v5_variable_delete.fixture` reads 3 on a page written four times but
///   holding two fragments, `v5_variable_release_empty.fixture` reads 1 on a
///   page written twice and holding **none**, and
///   `v5_variable_release_reinsert.fixture` reads 2 on a page written three
///   times and holding one.
///
///   [`claim`](PageSource::claim) writing the blank page to disk is this
///   crate's own step, not the engine's -- genuine builds the page and its
///   first fragment in one write -- so that write does not count, and
///   [`V5Pages::claimed`] is what remembers it.
/// - `0x06..0x0a` [`FREE_CHAIN`]: `ff 00 ff ff`, [`FreeChain::Last`]. What
///   [`Space::reoffer`] already writes for a fresh page joining an empty
///   chain.
/// - `0x0a..0x0c` [`FRAGMENT_COUNT`], then fragment 0 at [`FIRST_FRAGMENT`]
///   and the entry array growing down from the end of the page -- the
///   layout this module's own doc comment describes, unchanged for v5.
///
/// ## The chain head is `VARIABLE_HIGHEST`, at `0x3a`
///
/// The seed reads `ff ff ff ff` at `0x38..0x3c`; the insert scenario's file
/// reads `ff 00 05 00` and the grow scenario's `ff 00 0a 00`. That is
/// [`super::format::fcr::at::VARIABLE_SUBFLAG`] (`0x39`) flipping to `0x00`
/// -- the file is no longer virgin -- and
/// [`super::format::fcr::at::VARIABLE_HIGHEST`] (`0x3a`, a plain
/// little-endian `u16`) becoming 5 and 10, the number of the last variable
/// page each scenario claimed. The corpus already reads this field as "the
/// v5 analogue of v6's `pages::fcr::VARIABLE_HEAD`"
/// (`format::fcr::v5_fixed`'s own `variable_highest` citation), and the grow
/// recording is what settles it: its page 5 fills up (44 fragments, `ff ff
/// ff ff` at `0x1406` -- [`FreeChain::Off`]) before its page 10 is claimed,
/// and page 10's own chain field at `0x2806` reads `ff 00 ff ff`
/// ([`FreeChain::Last`]), **nothing following it**. Had the head still been
/// 5 when page 10 was claimed, [`Space::reoffer`]'s measured
/// last-in-first-out threading would have written `Next(5)` there instead.
/// So the field really is the head, and it goes back to the `0xffff`
/// sentinel when a page fills up and no other page is offered.
///
/// Reading and writing that field is [`Block`](super::Block)'s job, not this
/// type's, exactly as the v6 head at `pages::fcr::VARIABLE_HEAD` is -- see
/// [`Space`]'s own doc comment on why the head is passed in and handed back
/// rather than read from the file here.
///
/// ## The pointer in the record's own slot
///
/// [`Pointer::decode`]'s encoding, unchanged: the insert scenario's first
/// record sits at `0x1006` (page 4, first slot), its 31-byte fixed part runs
/// to `0x1025`, and the four bytes at `0x1025..0x1029` read `00 05 00 00` --
/// page 5, fragment 0. The second record's, at `0x1048..0x104c`, read
/// `00 05 00 01` -- page 5, fragment 1. That is `[high][low][mid][fragment]`
/// exactly as [`Pointer::encode`] produces it and `records::walk` reads it
/// back at `reclen`, so the v5 write side needs nothing the v5 read side did
/// not already have.
pub(crate) struct V5Pages<'a> {
    file: FilePages<'a>,

    /// The page [`PageSource::claim`] last appended, until something writes
    /// over it.
    ///
    /// `claim` has to put its blank page on disk so [`Space::place`] can
    /// read it back ([`claim`](PageSource::claim)'s own doc comment says
    /// why), but genuine Btrieve writes a new variable page **once**, with
    /// its first fragment already on it. So that blank write is an artefact
    /// of this crate's own split, and the real write that follows it carries
    /// stamp 0 rather than 1. This field is what tells the two apart; see
    /// [`V5Pages::stamped`].
    claimed: Option<u32>,
}

impl<'a> V5Pages<'a> {
    /// `pages` is how many pages the file will be once the caller's own
    /// pending write has landed, **not** how many it is right now.
    ///
    /// The distinction matters because a v5 insert can need two new pages at
    /// once: `pages::Layout::next_slot` has already decided that the record
    /// goes on a new data page numbered `pages` when it answers
    /// `Slot::NewPage`, and that page is not written until after the body is
    /// placed. Counting it here is what stops [`PageSource::claim`] handing
    /// out the same number twice, and it is also the order the genuine
    /// engine used: `v5_variable_insert.fixture`'s data page is 4 and its
    /// variable page 5.
    pub(crate) fn new(path: &'a std::path::Path, page_len: u16, pages: u32) -> Self {
        Self {
            file: FilePages::new(path, page_len, pages),
            claimed: None,
        }
    }

    /// How many pages the file is once everything this source claimed has
    /// landed -- what the caller writes to `pages::fcr::PAGES`.
    pub(crate) fn pages(&self) -> u32 {
        self.file.pages
    }

    /// The modification stamp a page should carry once `page` is written
    /// over whatever is on disk at `number`.
    ///
    /// Zero for the first real write onto a page [`PageSource::claim`] just
    /// appended, one more than what is on disk for every write after that.
    /// See this type's doc comment for the five genuine pages this
    /// reproduces and for why the claim's own write does not count.
    ///
    /// **Not** "zero for a page holding no fragments", which is what this
    /// said while a blank claim was the only way to reach a fragment count
    /// of zero. `free_fragment` can leave a page empty now, and
    /// `v5_variable_release_reinsert.fixture` writes a fragment back onto
    /// exactly such a page: genuine stamps it 2, not 0.
    ///
    /// # Errors
    ///
    /// If the page cannot be read. Every page written through
    /// [`PagesMut::write_page`] is already inside the file --
    /// [`PageSource::claim`] counts a page and writes it before anything
    /// rewrites it -- so a failure here is a real one, and answering `0`
    /// instead would put a wrong byte in the field the oracle comparison
    /// pins.
    fn stamped(&mut self, number: u32, page: &mut [u8]) -> Result<(), String> {
        const STAMP: usize = 0x04;
        let stamp = if self.claimed == Some(number) {
            self.claimed = None;
            0
        } else {
            let on_disk = self.file.page(number)?;
            u16::from_le_bytes([on_disk[STAMP], on_disk[STAMP + 1]]).wrapping_add(1)
        };
        page[STAMP..STAMP + 2].copy_from_slice(&stamp.to_le_bytes());
        Ok(())
    }
}

impl Pages for V5Pages<'_> {
    fn page(&mut self, number: u32) -> Result<&[u8], String> {
        self.file.page(number)
    }
}

impl PagesMut for V5Pages<'_> {
    fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String> {
        let mut page = page.to_vec();
        self.stamped(number, &mut page)?;
        self.file.write_page(number, &page)
    }
}

impl PageSource for V5Pages<'_> {
    /// Append `content` as the file's next physical page, stamped with the
    /// number it just became.
    ///
    /// The page is written here rather than left in memory because
    /// [`Space::place`] reads it straight back -- and it has to, since
    /// [`Header::read`] refuses a page whose [`PAGE_NUMBER`] does not match
    /// the number asked for and [`blank_page`] cannot know that number.
    fn claim(&mut self, content: &[u8]) -> Result<u32, String> {
        let number = self.file.pages;
        let mut page = content.to_vec();
        if page.len() < FIRST_FRAGMENT as usize {
            return Err(format!(
                "a {}-byte page cannot be claimed as variable page {number}",
                page.len()
            ));
        }
        page[PAGE_NUMBER..PAGE_NUMBER + 4].copy_from_slice(&super::pages::to_long(number));
        // The file does not reach this page yet, so `write_page` has to be
        // allowed to seek past its end. Counting the page first is what
        // makes `FilePages::page` able to read it back afterwards.
        self.file.pages += 1;
        self.file.write_page(number, &page)?;
        // This write is not one of the engine's; see the field's own doc
        // comment and `stamped`.
        self.claimed = Some(number);
        Ok(number)
    }

    fn page_size(&self) -> u16 {
        self.file.page_len
    }
}

/// A variable page with no fragments on it yet.
///
/// Fragment count zero, [`FREE_CHAIN`] saying the page is not on the chain,
/// and entry 0 already naming [`FIRST_FRAGMENT`] -- the array always holds one
/// more entry than the page has fragments, so even an empty page has entry 0,
/// and it says where fragment 0 will begin.
///
/// [`Header::read`] refuses a v6 page with zero fragments, so a blank v6
/// page is not readable as a header until its first fragment lands. A blank
/// v5 page is readable -- it has to be, since genuine leaves an emptied v5
/// page in exactly this shape but on the free-space chain
/// ([`free_fragment`]) -- and it is [`FREE_CHAIN`] that tells the two apart:
/// a page here is off the chain, an emptied one is on it.
fn blank_page(page_size: u16, version: Version) -> Vec<u8> {
    let len = usize::from(page_size);
    let mut page = vec![0u8; len];
    if version == Version::V6 {
        page[..2].copy_from_slice(&V_TAG);
    }
    page[FREE_CHAIN..FREE_CHAIN + 4].copy_from_slice(&super::pages::to_long(NO_PAGE));
    page[len - 2..len].copy_from_slice(&(FIRST_FRAGMENT as u16).to_le_bytes());
    page
}

/// Write a page's free-chain field. See [`FreeChain`].
fn set_chain(page: &mut [u8], chain: FreeChain) {
    let value = match chain {
        FreeChain::Off => NO_PAGE,
        FreeChain::Last => END_PAGE,
        FreeChain::Next(next) => next,
    };
    page[FREE_CHAIN..FREE_CHAIN + 4].copy_from_slice(&super::pages::to_long(value));
}

/// Read entry `which` of a page as a plain offset, without going through
/// [`Header`].
///
/// A page being built has zero fragments right up until its first one
/// lands, and for v6 [`Header::read`] refuses it, so the allocator cannot
/// reach its entries the way a reader does.
fn entry(page: &[u8], which: u32) -> Result<u32, String> {
    let at = entry_at(page.len() as u32, which)?;
    Ok(Entry::decode(&page[at..at + 2]).offset)
}

/// Write entry `which` of a page.
fn set_entry(page: &mut [u8], which: u32, offset: u32) -> Result<(), String> {
    let at = entry_at(page.len() as u32, which)?;
    let bytes = (offset as u16).to_le_bytes();
    page[at..at + 2].copy_from_slice(&bytes);
    Ok(())
}

/// Move entry `which`'s offset by `delta` bytes, leaving a freed slot
/// exactly as it is and carrying [`Entry::continued`]'s `0x8000` bit
/// through.
///
/// Both sides of a v5 variable page's bookkeeping need this: freeing a
/// fragment slides every entry after it *down* by the freed length, and
/// reusing a freed slot slides every entry after it *up* by the new
/// fragment's length. The engine does both by adding to the raw entry word
/// (`W32MKDE_decompiled.c:19267` and `:19737`), so a continued fragment's
/// bit survives the arithmetic; going through [`set_entry`] instead would
/// write the offset back without it and quietly break a chain this crate
/// refuses to touch but does not have to corrupt.
///
/// # Errors
///
/// If the entry is outside the page, or the move would put the offset
/// outside the `0..0x8000` a fifteen-bit entry can name.
fn move_entry(page: &mut [u8], which: u32, delta: i32) -> Result<(), String> {
    const CONTINUED: u16 = 0x8000;
    let at = entry_at(page.len() as u32, which)?;
    let raw = u16::from_le_bytes([page[at], page[at + 1]]);
    if u32::from(raw) == UNUSED {
        return Ok(());
    }
    let offset = i64::from(raw & !CONTINUED) + i64::from(delta);
    let offset = u16::try_from(offset).ok().filter(|o| *o < CONTINUED).ok_or_else(|| {
        format!(
            "moving entry {which} by {delta} bytes puts it at {offset}, which no              fifteen-bit entry can name"
        )
    })?;
    page[at..at + 2].copy_from_slice(&(offset | (raw & CONTINUED)).to_le_bytes());
    Ok(())
}

/// The first entry a new fragment may be given, or `None` when the page
/// offers none and the fragment has to be appended past the last one.
///
/// The engine's own scan (`W32MKDE_decompiled.c:19267`, `FUN_00420da0`'s
/// `LAB_00421075`): walk the array from entry 0, and take the first entry
/// that is a freed slot ([`UNUSED`]) **and** is followed by one that is not.
/// A freed slot followed by another freed slot is passed over, which is why
/// this is the engine's condition rather than "the first `0xffff`".
///
/// # Errors
///
/// If an entry is outside the page.
fn reusable_slot(page: &[u8], fragments: u16) -> Result<Option<u32>, String> {
    for which in 0..u32::from(fragments) {
        if entry(page, which)? == UNUSED && entry(page, which + 1)? != UNUSED {
            return Ok(Some(which));
        }
    }
    Ok(None)
}

/// How many fragments a page says it holds, read without a [`Header`].
fn fragment_count(page: &[u8]) -> u16 {
    u16::from_le_bytes([page[FRAGMENT_COUNT], page[FRAGMENT_COUNT + 1]])
}

/// Write a page's fragment count.
fn set_fragment_count(page: &mut [u8], fragments: u16) {
    page[FRAGMENT_COUNT..FRAGMENT_COUNT + 2].copy_from_slice(&fragments.to_le_bytes());
}

/// The allocator: what puts a fragment on a page.
///
/// The read half of this file has always been able to *follow* a chain. This
/// is the first thing here that can build one, and it is the absence
/// [`rewrite_fragment_in_place`] named as the reason for each of its four
/// refusals.
///
/// # The free-space chain
///
/// A file offers its part-full variable pages through a chain: a head in the
/// live file control record at [`super::pages::fcr::VARIABLE_HEAD`], and each member naming the next
/// at [`FREE_CHAIN`]. `Space` walks it to find a page with room and takes a
/// page off it once it no longer has any.
///
/// The head is **passed in and handed back** rather than read from the file
/// here. `Space` writes pages; the file control record belongs to `Block`,
/// which already reads and rewrites it for the record free list at
/// `fcr::FREE_V6` and would otherwise have two places doing it.
///
/// Every rule here is measured in `docs/2026-08-17-variable-write-oracle.md`
/// against genuine Pervasive 6.15, not inferred from the decompile.
pub(crate) struct Space<'a, S: PageSource> {
    source: &'a mut S,
    version: Version,
    head: Option<u32>,
}

impl<'a, S: PageSource> Space<'a, S> {
    /// Take a page source and the file's current free-space head.
    pub(crate) fn new(source: &'a mut S, version: Version, head: Option<u32>) -> Self {
        Self {
            source,
            version,
            head,
        }
    }

    /// The free-space head after whatever this `Space` has done, for the
    /// caller to write back to [`super::pages::fcr::VARIABLE_HEAD`].
    pub(crate) fn head(&self) -> Option<u32> {
        self.head
    }

    /// Write `body` as a fragment and answer with a pointer to it.
    ///
    /// A v6 fragment always carries four leading bytes of pointer, continued
    /// or not (`W32MKDE_decompiled.c:19419`, and seen directly on disk: a
    /// 200-byte body occupies 204 bytes and leads with `ff ff ff ff`). A v5
    /// fragment carries them only when continued, and says so with the
    /// entry's `0x8000` bit.
    ///
    /// # Where on the page it goes
    ///
    /// Past the last fragment, unless the file is **version 5** and a delete
    /// left a slot free ([`reusable_slot`]) -- then **that** slot, with the
    /// fragments behind it sliding up to make room and their entries rebased
    /// to match. The fragment count does not move for a reuse: the array
    /// already has the entry. Both branches are the engine's own allocator
    /// (`W32MKDE_decompiled.c:19267`), and `v5_variable_delete.fixture`
    /// measured the reuse end to end -- see [`free_fragment`]'s doc comment
    /// for the recorded page.
    ///
    /// **A v6 file always appends, hole or no hole, and that is deliberate.**
    /// The engine's allocator is one routine for both versions and does not
    /// gate the reuse on the version, so this is not a claim that v6 behaves
    /// differently -- it is that nothing has *recorded* v6 behaving either
    /// way. `free_fragment_v6`'s interior branch leaves `0xffff` entries
    /// behind, so the reuse would be reachable the moment a v6 delete were
    /// followed by an insert, and the four committed v6 fixtures were
    /// recorded against a host that appended. Reuse for v6 awaits a
    /// recording of its own -- a v6 delete followed by an insert, the way
    /// `v5_variable_delete.fixture` is for v5 -- and until then a v6 file
    /// keeps exactly the placement its fixtures pin. The cost is a hole a v6
    /// file does not fill, which is space, not correctness.
    ///
    /// [`Self::room_for`] still asks a page for `needed + 2` bytes even when
    /// it will reuse a slot and grow the array by nothing; the engine asks
    /// for `needed` there (`param_3 <= piVar7`, the reuse branch, against
    /// `piVar8 = piVar7 - 2` for the append). The difference is two bytes
    /// and one direction: this can claim a fresh page where the engine
    /// would have squeezed the fragment onto the offered one. No recording
    /// reaches that boundary, so it is left conservative rather than
    /// tightened on a guess.
    ///
    /// # Errors
    ///
    /// If the body needs more room than one page can give -- splitting is not
    /// implemented yet and is refused rather than truncated -- or if a page
    /// cannot be read, claimed or written.
    pub(crate) fn place(&mut self, body: &[u8]) -> Result<Pointer, String> {
        let leads = self.version == Version::V6;
        let needed = body.len() + if leads { POINTER } else { 0 };
        let page_size = usize::from(self.source.page_size());

        // A fresh page's usable room: everything after the header, less the
        // two entries a single fragment needs (its own start, and the one
        // that says where it ends).
        let most = page_size - FIRST_FRAGMENT as usize - 4;
        if needed > most {
            return Err(format!(
                "a {}-byte body needs {needed} bytes with its pointer, and a fresh \
                 {page_size}-byte page holds {most} -- splitting a body across pages is \
                 not implemented, and truncating it to fit is the silent wrong answer \
                 this crate refuses",
                body.len()
            ));
        }

        let (number, fresh) = self.room_for(needed)?;
        // Read back even when the page was just claimed: `v6::Map::claim`
        // stamps the tag and the page's own logical id into the first four
        // bytes, and `Header::read` checks both. Rebuilding a blank here
        // instead would hand `reoffer` a page claiming to be logical 0.
        let mut page = self.source.page(number)?.to_vec();

        // Entry `i` names fragment `i`'s start, so the array has one more
        // entry than the page has fragments and the extra one is the
        // free-space boundary -- where an appended fragment goes.
        let fragments = fragment_count(&page);
        let boundary = entry(&page, u32::from(fragments))? as usize;
        if boundary == UNUSED as usize {
            return Err(format!(
                "page {number}'s entry {fragments} is free, so nothing says where its \
                 fragments end"
            ));
        }

        // A slot a delete freed is filled before the end of the page is: the
        // new fragment starts where the next live fragment starts today, and
        // everything from there to the boundary slides up to make room for
        // it. `reusable_slot` is the engine's own scan, and this is the
        // branch of its allocator that answers it
        // (`W32MKDE_decompiled.c:19267`, `FUN_00420da0`'s `else` at
        // `LAB_00421146`): the count does not move, because the array
        // already has the entry this fragment needs.
        //
        // `free_fragment`'s own doc comment has the recording that pins it:
        // `v5_variable_delete.fixture` deletes fragment 0 of two and the
        // insert that follows lands back on fragment 0, with the survivor
        // still fragment 1 and the page still holding two.
        // Version 5 only -- see this function's own doc comment for why a v6
        // file appends past a hole rather than filling it.
        let reused = if self.version == Version::V5 {
            reusable_slot(&page, fragments)?
        } else {
            None
        };
        let at = match reused {
            None => boundary,
            Some(which) => {
                let next = entry(&page, which + 1)? as usize;
                page.copy_within(next..boundary, next + needed);
                for i in (which + 1)..=u32::from(fragments) {
                    move_entry(&mut page, i, needed as i32)?;
                }
                set_entry(&mut page, which, next as u32)?;
                next
            }
        };

        if leads {
            let end = Pointer {
                page: END_PAGE,
                fragment: END_FRAGMENT,
            };
            page[at..at + POINTER].copy_from_slice(&end.encode());
            page[at + POINTER..at + needed].copy_from_slice(body);
        } else {
            page[at..at + needed].copy_from_slice(body);
        }

        if reused.is_none() {
            set_fragment_count(&mut page, fragments + 1);
            set_entry(&mut page, u32::from(fragments) + 1, (at + needed) as u32)?;
        }

        self.reoffer(number, &mut page, fresh)?;
        self.source.write_page(number, &page)?;

        Ok(Pointer {
            page: number,
            fragment: reused.unwrap_or(u32::from(fragments)) as u8,
        })
    }

    /// Find a page with `needed` bytes free, or claim one.
    ///
    /// Walks the free-space chain from the head. Answers the page's number
    /// and whether it is brand new -- a fresh page has no readable header
    /// yet, so the caller builds it rather than reading it.
    fn room_for(&mut self, needed: usize) -> Result<(u32, bool), String> {
        let mut at = self.head;
        let mut seen = HashSet::new();
        while let Some(number) = at {
            if !seen.insert(number) {
                return Err(format!(
                    "the free-space chain returns to page {number}"
                ));
            }
            let page = self.source.page(number)?;
            let header = Header::read(page, number, self.version)?;
            // The new fragment's own bytes, plus the entry that will say
            // where it ends.
            if free_bytes(page, header)? as usize >= needed + 2 {
                return Ok((number, false));
            }
            at = match header.free_chain {
                FreeChain::Next(next) => Some(next),
                FreeChain::Last | FreeChain::Off => None,
            };
        }

        let blank = blank_page(self.source.page_size(), self.version);
        let number = self.source.claim(&blank)?;
        Ok((number, true))
    }

    /// Put a page on the free-space chain, or take it off, according to
    /// whether it still has room.
    ///
    /// A page joins at the **head**, which is what the oracle ladder measured:
    /// each delete that freed space made that page the head, giving
    /// `3 -> 5 -> 4 -> end`.
    fn reoffer(&mut self, number: u32, page: &mut Vec<u8>, fresh: bool) -> Result<(), String> {
        let header = Header::read(page, number, self.version)?;
        let roomy = is_roomy(page, header)?;

        if roomy {
            if fresh {
                // A new page goes on the front; the old head follows it.
                set_chain(
                    page,
                    match self.head {
                        Some(next) => FreeChain::Next(next),
                        None => FreeChain::Last,
                    },
                );
                self.head = Some(number);
            }
            // An existing chain member that still has room keeps its place
            // and its successor.
            return Ok(());
        }

        // Out of room: unlink it. Only the head case is reachable today --
        // `room_for` returns the first page on the chain with space, and a
        // page deeper in the chain is only reached when the ones before it
        // are too full to take this fragment, which cannot then fill *this*
        // one. Refusing the other case is cheaper than writing an unlink
        // whose correctness nothing here can demonstrate.
        let successor = match header.free_chain {
            FreeChain::Next(next) => Some(next),
            FreeChain::Last | FreeChain::Off => None,
        };
        if fresh {
            // Never joined the chain; nothing to unlink.
            set_chain(page, FreeChain::Off);
            return Ok(());
        }
        if self.head != Some(number) {
            return Err(format!(
                "page {number} filled up but is not the head of the free-space chain, and \
                 unlinking from the middle of it has not been measured"
            ));
        }
        set_chain(page, FreeChain::Off);
        self.head = successor;
        Ok(())
    }
}

/// The divisor behind the engine's default roominess threshold.
///
/// `W32MKDE_decompiled.c:19937-19939`: when the file's own threshold is zero
/// the engine tests `pageSize / 0x14 <= free`. The file's own threshold lives
/// in the engine's *in-memory* block, so its on-disk home is unknown and every
/// file here gets this default -- see
/// `docs/2026-08-17-variable-write-oracle.md`.
#[allow(dead_code, reason = "consumed by `Space`; landed with its measurement first")]
const ROOM_DIVISOR: u32 = 20;

/// How many bytes of this page are neither header, fragment, nor entry array.
///
/// **Derived, never stored.** `W32MKDE_decompiled.c:19930-19934`
/// (`FUN_00421ba0`):
///
/// `param_1 + 10` is [`FRAGMENT_COUNT`], which is how that routine's offsets
/// are known to be a page's rather than the in-memory file block's -- the
/// distinction that governs everything else read off this decompile.
///
/// The entry array costs `2 * (fragments + 1)` because it always holds one
/// more entry than the page has fragments: entry `i` says where fragment `i`
/// starts, so the last one says where the free space begins.
///
/// Confirmed against the genuine engine: inserting a 200-byte body into a page
/// this reports 86 free bytes for produced an 84-byte fragment and left the
/// page at exactly zero.
#[allow(dead_code, reason = "consumed by `Space`; landed with its measurement first")]
fn free_bytes(page: &[u8], header: Header) -> Result<u32, String> {
    let len = page.len() as u32;
    let last = entry_at(len, u32::from(header.fragments))?;
    let ends = Entry::decode(&page[last..last + 2]).offset;
    if ends == UNUSED {
        return Err(format!(
            "the entry after this page's {} fragments is free, so nothing says where its \
             fragments end",
            header.fragments
        ));
    }
    let array = 2 * (u32::from(header.fragments) + 1);
    len.checked_sub(array)
        .and_then(|left| left.checked_sub(ends))
        .ok_or_else(|| {
            format!(
                "a {len}-byte page whose {} fragments end at {ends} and whose array needs \
                 {array} bytes has less than nothing left",
                header.fragments
            )
        })
}

/// Whether this page has enough room left to be worth offering for new
/// fragments. `W32MKDE_decompiled.c:19937-19944`.
#[allow(dead_code, reason = "consumed by `Space`; landed with its measurement first")]
fn is_roomy(page: &[u8], header: Header) -> Result<bool, String> {
    Ok(free_bytes(page, header)? >= page.len() as u32 / ROOM_DIVISOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pages held in memory, for tests that build a page by hand.
    struct Held(Vec<Vec<u8>>);

    impl Pages for Held {
        fn page(&mut self, number: u32) -> Result<&[u8], String> {
            self.0
                .get(number as usize)
                .map(Vec::as_slice)
                .ok_or_else(|| format!("no page {number}"))
        }
    }

    impl PagesMut for Held {
        fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String> {
            let slot = self
                .0
                .get_mut(number as usize)
                .ok_or_else(|| format!("no page {number}"))?;
            if slot.len() != page.len() {
                return Err(format!(
                    "a {}-byte page for a {number}-byte page slot",
                    page.len()
                ));
            }
            slot.copy_from_slice(page);
            Ok(())
        }
    }

    /// A page of `len` bytes holding `fragments`, laid out the way a real one
    /// is: its own number at the front, no free-space successor, bodies from
    /// `0x0c` upward, the entry array from the end downward, and one entry
    /// past the last fragment to mark where it ends.
    ///
    /// `continued` is the high bit of an entry's second byte.
    fn page(number: u32, len: usize, fragments: &[(&[u8], bool)]) -> Vec<u8> {
        let mut out = vec![0u8; len];
        out[PAGE_NUMBER..PAGE_NUMBER + 2].copy_from_slice(&((number >> 16) as u16).to_le_bytes());
        out[PAGE_NUMBER + 2..PAGE_NUMBER + 4].copy_from_slice(&(number as u16).to_le_bytes());
        out[FREE_CHAIN..FREE_CHAIN + 4].copy_from_slice(&[0xff; 4]);
        out[FRAGMENT_COUNT..FRAGMENT_COUNT + 2]
            .copy_from_slice(&(fragments.len() as u16).to_le_bytes());

        let mut at = FIRST_FRAGMENT as usize;
        for (i, (bytes, continued)) in fragments.iter().enumerate() {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            let entry = len - 2 * (i + 1);
            let mark = if *continued { 0x80 } else { 0 };
            out[entry] = (at & 0xff) as u8;
            out[entry + 1] = ((at >> 8) as u8) | mark;
            at += bytes.len();
        }
        // The one past the end, which is what gives the last fragment its
        // length.
        let entry = len - 2 * (fragments.len() + 1);
        out[entry] = (at & 0xff) as u8;
        out[entry + 1] = (at >> 8) as u8;
        out
    }

    /// A v6-shaped page: the same entry array and fragment layout [`page`]
    /// builds -- Task 6 measured that much is version-independent -- but a
    /// `'V'` type tag at `[0x00]` and the page's own **logical** id at
    /// [`LOGICAL`] rather than a four-byte physical page number, and no entry
    /// ever gets the `0x80` continuation bit, because Task 6 also measured
    /// that v6 never sets it (165 real entries checked, 0 set) and does not
    /// consult it either way.
    ///
    /// Continuation is instead in the fragment bytes themselves, exactly as
    /// on a real v6 page: every one of `fragments` must supply its own
    /// leading four-byte prefix -- a real pointer to continue on, or
    /// `[0xff; 4]` to end the chain there -- because [`fragment`] reports
    /// every v6 fragment as `continued` unconditionally and it is
    /// [`Chain::follow`] that reads this prefix to decide what happens next.
    fn page_v6(logical: u16, len: usize, fragments: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0u8; len];
        out[0..2].copy_from_slice(&0x5600u16.to_le_bytes()); // 'V' in the low byte
        out[LOGICAL..LOGICAL + 2].copy_from_slice(&logical.to_le_bytes());
        out[FREE_CHAIN..FREE_CHAIN + 4].copy_from_slice(&[0xff; 4]);
        out[FRAGMENT_COUNT..FRAGMENT_COUNT + 2]
            .copy_from_slice(&(fragments.len() as u16).to_le_bytes());

        let mut at = FIRST_FRAGMENT as usize;
        for (i, bytes) in fragments.iter().enumerate() {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            let entry = len - 2 * (i + 1);
            out[entry] = (at & 0xff) as u8;
            out[entry + 1] = (at >> 8) as u8;
            at += bytes.len();
        }
        let entry = len - 2 * (fragments.len() + 1);
        out[entry] = (at & 0xff) as u8;
        out[entry + 1] = (at >> 8) as u8;
        out
    }

    /// The four bytes at the front of a v6 fragment that says where the
    /// chain goes next -- a real pointer, in the same scrambled encoding
    /// [`pointer`] builds for a fixed record's own trailing four bytes.
    fn v6_next(page: u32, fragment: u8) -> [u8; 4] {
        [(page >> 16) as u8, (page & 0xff) as u8, ((page >> 8) & 0xff) as u8, fragment]
    }

    /// The four bytes at the front of a v6 fragment that says the chain ends
    /// there -- Task 6 ground truth: unlike v5, every fragment carries this
    /// prefix, terminal or not, and `[0xff; 4]` is what marks the terminal
    /// one (it decodes to the same `page == END_PAGE, fragment ==
    /// END_FRAGMENT` pair [`Pointer::is_end`] already checks).
    const V6_END: [u8; 4] = [0xff; 4];

    /// A page of nothing, for the slots a fixture does not use.
    fn blank(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    /// The four bytes a fixed record carries, for a fragment on a page.
    fn pointer(page: u32, fragment: u8) -> Pointer {
        Pointer::decode([
            (page >> 16) as u8,
            (page & 0xff) as u8,
            ((page >> 8) & 0xff) as u8,
            fragment,
        ])
    }

    fn follow(pages: &mut Held, first: Pointer) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        Chain::follow(pages, Version::V5, first, &mut out)?;
        Ok(out)
    }

    fn follow_v6(pages: &mut Held, first: Pointer) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        Chain::follow(pages, Version::V6, first, &mut out)?;
        Ok(out)
    }

    /// The shape every one of `WCCTEXT`'s 3,467 records has, built by hand
    /// rather than read: a 2,048-byte page holding one fragment, its entry
    /// `0c 00` and the entry past it `dc 07` -- 12 to 2,012, 2,000 bytes.
    ///
    /// Measured off `tmp/WCCTEXT.DAT`, where every variable page is
    /// byte-for-byte this shape, but the bytes here are this test's own.
    #[test]
    fn a_single_fragment_is_the_whole_body() {
        let body: Vec<u8> = (0..2000u32).map(|n| (n % 251) as u8).collect();
        let mut pages = Held(vec![blank(2048), blank(2048), page(2, 2048, &[(&body, false)])]);

        // The entries this fixture builds are the ones the real file holds.
        assert_eq!(&pages.0[2][2046..2048], &[0x0c, 0x00], "entry 0 is offset 12");
        assert_eq!(&pages.0[2][2044..2046], &[0xdc, 0x07], "and the end is 2,012");

        assert_eq!(follow(&mut pages, pointer(2, 0)).expect("follows"), body);
    }

    /// The page's own number, at its front, is what makes the scrambled page
    /// number in [`Pointer::decode`] checkable at all: a decode that landed on
    /// the wrong page would find a page that says it is a different one.
    #[test]
    fn a_page_that_disagrees_about_which_page_it_is_is_refused() {
        let mut pages = Held(vec![blank(512), page(9, 512, &[(b"body".as_slice(), false)])]);
        let e = follow(&mut pages, pointer(1, 0)).expect_err("page 1 says it is page 9");
        assert!(e.contains("says it is page 9"), "{e}");
    }

    /// **Synthetic.** No record in `tmp/WCCTEXT.DAT` sets the continuation
    /// bit -- all 3,467 chains are one fragment long -- so this path has no
    /// real input anywhere in the corpus and this hand-built pair of pages is
    /// the only thing that exercises it.
    #[test]
    fn a_continued_fragment_leads_to_the_next_page_and_its_pointer_is_not_data() {
        let mut head = vec![0x00u8, 0x03, 0x00, 0x01]; // page 3, fragment 1
        head.extend_from_slice(b"first half, ");

        let mut pages = Held(vec![
            blank(512),
            blank(512),
            page(2, 512, &[(&head, true)]),
            page(
                3,
                512,
                &[(b"not this one".as_slice(), false), (b"second half".as_slice(), false)],
            ),
        ]);

        assert_eq!(
            follow(&mut pages, pointer(2, 0)).expect("follows"),
            b"first half, second half",
            "the four pointer bytes are consumed, not appended"
        );
    }

    /// **Synthetic.** Same reason: nothing in the corpus has more than one
    /// fragment on a page, so a freed slot in the middle of an array cannot
    /// occur there either. A reader that did not skip it would give the
    /// fragment before it a length of `0xffff - offset`.
    #[test]
    fn a_freed_slot_is_stepped_over_when_the_length_is_derived() {
        let mut bytes =
            page(1, 512, &[(b"one".as_slice(), false), (b"two".as_slice(), false)]);
        // Free fragment 1 -- the entry, not the bytes.
        let entry = 512 - 2 * 2;
        bytes[entry] = 0xff;
        bytes[entry + 1] = 0xff;
        let mut pages = Held(vec![blank(512), bytes]);

        assert_eq!(
            follow(&mut pages, pointer(1, 0)).expect("follows"),
            b"onetwo",
            "fragment 0 runs to the next entry that is not freed"
        );
    }

    #[test]
    fn a_pointer_of_all_ones_ends_the_chain_without_reading_a_page() {
        let mut pages = Held(Vec::new());
        assert_eq!(
            follow(&mut pages, Pointer::decode([0xff, 0xff, 0xff, 0xff])).expect("ends"),
            b"",
            "no page is asked for, so an empty page source is enough"
        );
    }

    /// The engine's status 54. `W32MKDE_decompiled.c:19035` walks the array
    /// from entry 0 past any freed slots and refuses the page unless the first
    /// live entry is `0x0c` -- which it is on all 3,467 of `WCCTEXT`'s
    /// variable pages.
    #[test]
    fn a_page_whose_first_live_fragment_does_not_start_at_twelve_is_refused() {
        let mut bytes = page(1, 512, &[(b"body".as_slice(), false)]);
        bytes[512 - 2] = 0x0e; // fragment 0 at 14 rather than 12
        let mut pages = Held(vec![blank(512), bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("the header ends at 12");
        assert!(e.contains("status 54"), "{e}");
    }

    #[test]
    fn a_fragment_reaching_into_the_fragment_array_is_refused() {
        let mut bytes = page(1, 512, &[(b"body".as_slice(), false)]);
        // Move the end marker past the array: 0x01fe = 510, and the array of
        // two entries starts at 508.
        bytes[512 - 4] = 0xfe;
        bytes[512 - 3] = 0x01;
        let mut pages = Held(vec![blank(512), bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("that leaves the page");
        assert!(e.contains("must lie within"), "{e}");
    }

    #[test]
    fn a_page_whose_array_ends_before_a_neighbour_is_found_is_refused() {
        // One fragment claimed, and the entry that should end it freed -- so
        // the scan runs out.
        let mut bytes = page(1, 512, &[(b"body".as_slice(), false)]);
        bytes[512 - 4] = 0xff;
        bytes[512 - 3] = 0xff;
        let mut pages = Held(vec![blank(512), bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("nothing ends it");
        assert!(e.contains("no entry after it"), "{e}");
    }

    #[test]
    fn a_named_fragment_that_is_a_freed_slot_is_refused() {
        let mut bytes = page(
            1,
            512,
            &[
                (b"one".as_slice(), false),
                (b"two".as_slice(), false),
                (b"three".as_slice(), false),
            ],
        );
        let entry = 512 - 2 * 2; // fragment 1
        bytes[entry] = 0xff;
        bytes[entry + 1] = 0xff;
        let mut pages = Held(vec![blank(512), bytes]);

        let e = follow(&mut pages, pointer(1, 1)).expect_err("fragment 1 is gone");
        assert!(e.contains("freed slot"), "{e}");
    }

    #[test]
    fn a_fragment_past_the_pages_count_is_refused() {
        let mut pages = Held(vec![blank(512), page(1, 512, &[(b"only one".as_slice(), false)])]);
        let e = follow(&mut pages, pointer(1, 3)).expect_err("there is no fragment 3");
        assert!(e.contains("fragment 3 of a page holding 1"), "{e}");
    }

    #[test]
    fn a_page_claiming_more_fragments_than_a_page_can_hold_is_refused() {
        let mut bytes = page(1, 512, &[(b"body".as_slice(), false)]);
        bytes[FRAGMENT_COUNT..FRAGMENT_COUNT + 2].copy_from_slice(&300u16.to_le_bytes());
        let mut pages = Held(vec![blank(512), bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("256 is the most");
        assert!(e.contains("at most 256"), "{e}");
    }

    /// **Synthetic**, and not a case the engine or MBBSEmu handles: both would
    /// follow this until they ran out of memory. A chain is a linked list in a
    /// file a module can corrupt, so it gets the same cycle check the free list
    /// has.
    #[test]
    fn a_chain_that_returns_to_itself_is_refused_rather_than_followed_forever() {
        let head: Vec<u8> = [0x00, 0x01, 0x00, 0x00]
            .into_iter()
            .chain(b"round and round".iter().copied())
            .collect();
        let mut pages = Held(vec![blank(512), page(1, 512, &[(&head, true)])]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("it points at itself");
        assert!(e.contains("returns to fragment"), "{e}");
    }

    #[test]
    fn a_continued_fragment_too_short_to_hold_its_pointer_is_refused() {
        let mut pages = Held(vec![blank(512), page(1, 512, &[(b"ab".as_slice(), true)])]);
        let e = follow(&mut pages, pointer(1, 0)).expect_err("two bytes is not four");
        assert!(e.contains("too short for a 4-byte pointer"), "{e}");
    }

    /// Task 6: a v6 chain follows its own leading pointer across pages and
    /// stops on the all-ones terminator, without ever reading the entry's
    /// `0x8000` bit -- `page_v6` never sets it, so a test that passed only
    /// because the bit happened to agree with the prefix would still pass
    /// here, but [`a_v6_chain_ignores_the_entry_bit_even_when_it_disagrees`]
    /// rules that out directly.
    #[test]
    fn a_v6_chain_follows_its_own_leading_pointer_to_the_all_ones_terminator() {
        let mut first = v6_next(2, 0).to_vec();
        first.extend_from_slice(b"first ");
        let mut second = V6_END.to_vec();
        second.extend_from_slice(b"second");

        let mut pages = Held(vec![
            blank(64),
            page_v6(1, 64, &[&first]),
            page_v6(2, 64, &[&second]),
        ]);

        assert_eq!(
            follow_v6(&mut pages, pointer(1, 0)).expect("follows"),
            b"first second",
            "each fragment's own leading four bytes are consumed, not appended"
        );
    }

    /// The entry's `0x8000` bit is not consulted for v6 (Task 6 ground
    /// truth, 165 real entries measured, 0 set) -- proved here by setting it
    /// on a fragment whose own prefix says the chain ends, and confirming
    /// the chain still ends there rather than reading past the record into
    /// whatever the (nonexistent) next page would have been.
    #[test]
    fn a_v6_chain_ignores_the_entry_bit_even_when_it_disagrees() {
        let mut terminal = V6_END.to_vec();
        terminal.extend_from_slice(b"only this");
        let mut bytes = page_v6(1, 64, &[&terminal]);
        // Fragment 0's entry, second byte: set the bit a v5 reader would
        // take as "this fragment continues".
        let entry = 64 - 2;
        bytes[entry + 1] |= 0x80;

        let mut pages = Held(vec![blank(64), bytes]);
        assert_eq!(
            follow_v6(&mut pages, pointer(1, 0)).expect("follows"),
            b"only this",
            "the fragment's own 0xffffffff prefix ends the chain regardless of the entry bit"
        );
    }

    /// Task 6's counterexample fixture, in miniature: a page holding two
    /// fragments belonging to two different records (`NONMONO2.DAT`'s
    /// logical 14, reproduced directly -- see the plan's Evidence 2 and
    /// `tools/btrieve-oracle/fixtures/V6CORPUS.txt`). Fragment 0 is a
    /// standalone terminal fragment; fragment 1 is what a *different*
    /// record's chain reaches this page for. Following by the wrong index
    /// -- always fragment 0 -- would return fragment 0's text under
    /// fragment 1's name instead, which is exactly the mutation this guards
    /// against and exactly what `NONMONO2.DAT`'s own byte-for-byte test
    /// catches at the file level.
    #[test]
    fn a_v6_chain_selects_the_named_fragment_index_not_just_the_page() {
        let mut frag0 = V6_END.to_vec();
        frag0.extend_from_slice(b"not this one");
        let mut frag1 = V6_END.to_vec();
        frag1.extend_from_slice(b"this one");

        let mut pages = Held(vec![blank(64), page_v6(1, 64, &[&frag0, &frag1])]);

        assert_eq!(follow_v6(&mut pages, pointer(1, 1)).expect("follows"), b"this one");
        assert_eq!(follow_v6(&mut pages, pointer(1, 0)).expect("follows"), b"not this one");
    }

    /// [`Header::read`]'s v6 branch compares the logical id, not the v5
    /// four-byte page number -- a page built for logical 9 refuses when
    /// asked for logical 1, the same guard v5 has, on the field v6 actually
    /// uses.
    #[test]
    fn a_v6_page_that_disagrees_about_its_logical_id_is_refused() {
        let mut body = V6_END.to_vec();
        body.extend_from_slice(b"body");
        let mut pages = Held(vec![blank(64), page_v6(9, 64, &[&body])]);
        let e = follow_v6(&mut pages, pointer(1, 0)).expect_err("page 1 is logical 9");
        assert!(e.contains("says it is page 9"), "{e}");
    }

    /// A logical id resolves through one map shared by every kind of page, so
    /// a fragment pointer can name a page that is not a fragment page at all
    /// -- a data page, whose slot-filled tail would then be read as an entry
    /// array. Refused on the tag, the same byte `records::walk_v6` checks for
    /// `0x44` before reading a page as records, rather than left to fail
    /// further in on a structural check that would *probably* catch it.
    #[test]
    fn a_v6_page_that_is_not_a_fragment_page_is_refused_on_its_tag() {
        let mut body = V6_END.to_vec();
        body.extend_from_slice(b"body");
        let mut pages = Held(vec![blank(64), page_v6(1, 64, &[&body])]);

        // Everything else about the page is right -- it is logical 1, which is
        // what the pointer asks for -- and only the tag says data, not 'V'.
        pages.0[1][TAG] = 0x44;

        let e = follow_v6(&mut pages, pointer(1, 0)).expect_err("a data page is not a fragment");
        assert!(e.contains("not a fragment page"), "{e}");
        assert!(e.contains("0x44"), "{e}");
    }

    /// The scrambled order, spelled out on a number where all three bytes
    /// differ. `0x123456` is byte 0 = `0x12`, byte 1 = `0x56`, byte 2 = `0x34`
    /// -- high, low, mid -- and the fragment index is the fourth byte, per the
    /// engine's own `FUN_00421c20`.
    #[test]
    fn the_pointers_page_number_is_high_low_mid_and_its_fragment_is_last() {
        let decoded = Pointer::decode([0x12, 0x56, 0x34, 0x07]);
        assert_eq!(decoded.page, 0x0012_3456);
        assert_eq!(decoded.fragment, 7);
        assert!(!decoded.is_end());
        assert!(Pointer::decode([0xff, 0xff, 0xff, 0xff]).is_end());
    }

    /// The header field neither MBBSEmu nor this host's first pass accounted
    /// for. It is the write side's free list and a read never follows it, but
    /// it is four bytes that are not payload and not the fragment count.
    #[test]
    fn a_pages_header_is_its_number_its_free_successor_and_its_fragment_count() {
        let bytes = page(0x1234, 512, &[(b"body".as_slice(), false)]);
        let header = Header::read(&bytes, 0x1234, Version::V5).expect("a header");
        assert_eq!(header.number, 0x1234);
        assert_eq!(header.fragments, 1);
        assert_eq!(header.free_chain, FreeChain::Off, "a full page is not on the chain");
    }

    /// Pages in memory, stamped the way a real claim stamps them but without
    /// an allocation table underneath.
    ///
    /// [`Space`] is what these tests are about. `v6::Map` has its own tests
    /// and its own oracle validation, and routing through it here would make
    /// an allocator bug and a table bug look the same.
    struct Scratch {
        pages: Vec<Vec<u8>>,
        page_size: u16,
        version: Version,
    }

    impl Scratch {
        fn new(page_size: u16, version: Version) -> Self {
            Self {
                // Page 0 stands in for the file control record, so the first
                // claimable id is 1 and a page number is never confusable
                // with "no page".
                pages: vec![vec![0u8; usize::from(page_size)]],
                page_size,
                version,
            }
        }

        /// Stamp a page with the id it answers for, as `v6::Map::claim` does.
        fn stamp(&self, page: &mut [u8], number: u32) {
            match self.version {
                Version::V5 => {
                    page[PAGE_NUMBER..PAGE_NUMBER + 4]
                        .copy_from_slice(&super::super::pages::to_long(number));
                }
                Version::V6 => {
                    page[..2].copy_from_slice(&V_TAG);
                    page[LOGICAL..LOGICAL + 2]
                        .copy_from_slice(&(number as u16).to_le_bytes());
                }
            }
        }

        fn claimed(&self) -> usize {
            self.pages.len() - 1
        }
    }

    impl Pages for Scratch {
        fn page(&mut self, number: u32) -> Result<&[u8], String> {
            self.pages
                .get(number as usize)
                .map(Vec::as_slice)
                .ok_or_else(|| format!("no page {number}"))
        }
    }

    impl PagesMut for Scratch {
        fn write_page(&mut self, number: u32, page: &[u8]) -> Result<(), String> {
            let mut copy = page.to_vec();
            self.stamp(&mut copy, number);
            *self
                .pages
                .get_mut(number as usize)
                .ok_or_else(|| format!("no page {number}"))? = copy;
            Ok(())
        }
    }

    impl PageSource for Scratch {
        fn claim(&mut self, content: &[u8]) -> Result<u32, String> {
            let number = self.pages.len() as u32;
            let mut copy = content.to_vec();
            self.stamp(&mut copy, number);
            self.pages.push(copy);
            Ok(number)
        }

        fn page_size(&self) -> u16 {
            self.page_size
        }
    }

    /// `encode` is `decode`'s inverse. The scramble is not symmetric, so a
    /// backwards encode reads back as a different page -- and only an
    /// asymmetric page number can show it.
    #[test]
    fn a_pointer_survives_the_round_trip_through_its_scramble() {
        for (page, fragment) in [(0u32, 0u8), (1, 0), (3, 0), (0x1234, 3), (0xab_cdef, 0xfe)] {
            let there = Pointer { page, fragment };
            assert_eq!(Pointer::decode(there.encode()), there, "page {page:#x}");
        }
    }

    /// The bytes genuine 6.15 wrote for a fragment continued onto logical
    /// page 3, read straight out of the oracle ladder.
    #[test]
    fn a_continuation_to_page_three_encodes_the_way_the_engine_wrote_it() {
        let at = Pointer {
            page: 3,
            fragment: 0,
        };
        assert_eq!(at.encode(), [0x00, 0x03, 0x00, 0x00]);

        let end = Pointer {
            page: END_PAGE,
            fragment: END_FRAGMENT,
        };
        assert_eq!(end.encode(), [0xff; POINTER], "and the terminator it wrote");
        assert!(Pointer::decode(end.encode()).is_end());
    }

    /// The shape that stops MajorMUD's boot: a body short enough to need no
    /// split. In v6 the fragment still leads with four bytes of pointer, and
    /// with nothing after it those bytes are the terminator.
    #[test]
    fn placing_a_short_v6_body_writes_one_terminated_fragment() {
        let mut source = Scratch::new(512, Version::V6);
        let body = [0xa1u8; 7];

        let at = Space::new(&mut source, Version::V6, None)
            .place(&body)
            .expect("seven bytes fit anywhere");

        let mut got = Vec::new();
        Chain::follow(&mut source, Version::V6, at, &mut got).expect("the chain reads");
        assert_eq!(got, body, "what was placed is what comes back");

        let page = source.page(at.page).expect("the page reads");
        assert_eq!(fragment_count(page), 1);
        assert_eq!(
            &page[FIRST_FRAGMENT as usize..FIRST_FRAGMENT as usize + POINTER],
            &[0xff; POINTER],
            "a v6 fragment always leads with a pointer, and this chain ends here"
        );
    }

    /// A second body goes on the *same* page while that page has room. The
    /// free-space chain exists so that a file does not spend a page per
    /// record, and a `Space` that always claimed would pass the test above
    /// and fail this one.
    #[test]
    fn a_second_body_reuses_the_page_the_first_left_room_on() {
        let mut source = Scratch::new(512, Version::V6);
        let mut head = None;

        let mut at = Vec::new();
        for fill in [0xa1u8, 0xa2, 0xa3] {
            let mut space = Space::new(&mut source, Version::V6, head);
            at.push(space.place(&[fill; 20]).expect("twenty bytes fit"));
            head = space.head();
        }

        assert_eq!(source.claimed(), 1, "three small bodies, one page");
        assert!(
            at.iter().all(|p| p.page == at[0].page),
            "and all three fragments are on it: {at:?}"
        );
        assert_eq!(
            at.iter().map(|p| p.fragment).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "each takes the next fragment index"
        );

        for (p, fill) in at.iter().zip([0xa1u8, 0xa2, 0xa3]) {
            let mut got = Vec::new();
            Chain::follow(&mut source, Version::V6, *p, &mut got).expect("reads");
            assert_eq!(got, vec![fill; 20], "fragment {} survived its neighbours", p.fragment);
        }
    }

    /// A body that outgrows a page is refused, not truncated. Splitting is
    /// the next task; a silently short record is never an answer.
    #[test]
    fn a_body_too_large_for_one_page_is_refused_rather_than_cut_down() {
        let mut source = Scratch::new(512, Version::V6);
        let why = Space::new(&mut source, Version::V6, None)
            .place(&[0xcc; 600])
            .expect_err("600 bytes cannot fit a 512-byte page");
        assert!(why.contains("splitting"), "{why}");
        assert_eq!(source.claimed(), 0, "and nothing was claimed on the way out");
    }

    /// A page **already on the chain** that fills up is unlinked from it.
    ///
    /// Distinct from the fresh-page case below, and not a duplicate of it: a
    /// fresh page that never had room takes an early return and never touches
    /// the unlink. Deleting the unlink entirely left every other test in this
    /// file green, which is what this one exists to stop.
    #[test]
    fn a_chain_member_that_fills_up_is_unlinked_from_it() {
        let mut source = Scratch::new(512, Version::V6);

        // A 20-byte body leaves the page far more than the 512/20 = 25 bytes
        // the engine calls roomy, so it stays on the chain.
        let mut space = Space::new(&mut source, Version::V6, None);
        let small = space.place(&[0xe1; 20]).expect("20 fits");
        let head = space.head();
        assert_eq!(head, Some(small.page), "a roomy page is offered");

        // 450 more, on that same page, leaves 16 -- under the threshold.
        let mut space = Space::new(&mut source, Version::V6, head);
        let big = space.place(&[0xe2; 450]).expect("450 still fits");
        assert_eq!(big.page, small.page, "it went on the page that had room");
        assert_eq!(space.head(), None, "which is now off the chain, leaving none");

        let page = source.page(small.page).expect("reads");
        let header = Header::read(page, small.page, Version::V6).expect("a header");
        assert_eq!(header.free_chain, FreeChain::Off, "and the page says so itself");

        // Both records still read back whole.
        for (at, fill) in [(small, 0xe1u8), (big, 0xe2)] {
            let mut got = Vec::new();
            Chain::follow(&mut source, Version::V6, at, &mut got).expect("reads");
            assert_eq!(got.len(), if fill == 0xe1 { 20 } else { 450 });
            assert!(got.iter().all(|b| *b == fill), "fragment {} intact", at.fragment);
        }
    }

    /// A page that never had room does not go on the chain at all.
    #[test]
    fn a_page_that_fills_up_is_taken_off_the_free_space_chain() {
        let mut source = Scratch::new(512, Version::V6);

        // 512 less the 12-byte header and the two entries a lone fragment
        // needs is 496; a 470-byte body plus its four-byte pointer leaves 22,
        // under the 512/20 = 25 the engine calls roomy.
        let mut space = Space::new(&mut source, Version::V6, None);
        let first = space.place(&[0xd1; 470]).expect("470 fits");
        assert_eq!(
            space.head(),
            None,
            "the page it used has no room left, so nothing is offered"
        );

        let page = source.page(first.page).expect("reads");
        let header = Header::read(page, first.page, Version::V6).expect("a header");
        assert_eq!(
            header.free_chain,
            FreeChain::Off,
            "a full page says it is not on the chain"
        );
    }

    /// A variable page with the given entry offsets, laid out the way the
    /// format does: 12-byte header, entry array at the end growing down,
    /// entry `i` at `len - 2*(i+1)`. `entries` must hold one more offset than
    /// there are fragments.
    fn with_entries(len: usize, fragments: u16, chain: [u8; 4], entries: &[u16]) -> Vec<u8> {
        let mut page = vec![0u8; len];
        page[PAGE_NUMBER..PAGE_NUMBER + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        page[FREE_CHAIN..FREE_CHAIN + 4].copy_from_slice(&chain);
        page[FRAGMENT_COUNT..FRAGMENT_COUNT + 2].copy_from_slice(&fragments.to_le_bytes());
        for (which, offset) in entries.iter().enumerate() {
            let at = len - 2 * (which + 1);
            page[at..at + 2].copy_from_slice(&offset.to_le_bytes());
        }
        page
    }

    /// The three states of a page's own link, exactly as they sit on disk.
    ///
    /// `docs/2026-08-17-variable-write-oracle.md` measured all three in one
    /// ladder. Reading `ff 00 ff ff` as "no successor" -- which testing only
    /// against `NO_PAGE` did -- yielded `Some(0x00ffffff)`, a page number no
    /// file has.
    #[test]
    fn a_pages_link_says_off_the_chain_last_on_it_or_who_is_next() {
        let off = with_entries(512, 1, [0xff, 0xff, 0xff, 0xff], &[0x0c, 0x70]);
        let last = with_entries(512, 1, [0xff, 0x00, 0xff, 0xff], &[0x0c, 0x70]);
        let next = with_entries(512, 1, [0x00, 0x00, 0x05, 0x00], &[0x0c, 0x70]);

        let read = |p: &[u8]| Header::read(p, 1, Version::V5).expect("a header").free_chain;

        assert_eq!(read(&off), FreeChain::Off, "ffffffff: full, not offered");
        assert_eq!(read(&last), FreeChain::Last, "ff00ffff: on the chain, and last");
        assert_eq!(read(&next), FreeChain::Next(5), "the chain went 3 -> 5 -> 4 -> end");
    }

    /// Free space is derived from the fragment count and the last entry;
    /// there is no field holding it.
    ///
    /// The numbers are the genuine engine's own, from the oracle ladder: a
    /// 512-byte page holding two 204-byte fragments reports 86 free bytes,
    /// and the engine then wrote an 84-byte fragment into it and left the
    /// page at exactly zero.
    #[test]
    fn free_space_is_the_page_less_its_fragments_and_its_entry_array() {
        let two = with_entries(512, 2, [0xff, 0x00, 0xff, 0xff], &[0x0c, 0xd8, 0x1a4]);
        let header = Header::read(&two, 1, Version::V5).expect("a header");
        assert_eq!(free_bytes(&two, header), Ok(86), "512 - 2*(2+1) - 0x1a4");

        let full = with_entries(512, 3, [0xff, 0xff, 0xff, 0xff], &[0x0c, 0xd8, 0x1a4, 0x1f8]);
        let header = Header::read(&full, 1, Version::V5).expect("a header");
        assert_eq!(free_bytes(&full, header), Ok(0), "the engine filled it exactly");
    }

    /// The page the engine filled to zero came off the chain; the one with
    /// 246 bytes left stayed on it. The threshold between them is
    /// `pageSize / 20`.
    #[test]
    fn a_page_is_roomy_only_above_a_twentieth_of_its_size() {
        let full = with_entries(512, 3, [0xff, 0xff, 0xff, 0xff], &[0x0c, 0xd8, 0x1a4, 0x1f8]);
        let header = Header::read(&full, 1, Version::V5).expect("a header");
        assert_eq!(is_roomy(&full, header), Ok(false), "0 free is not roomy");

        // 512/20 = 25, so 25 free bytes is roomy and 24 is not. The engine
        // compares `pageSize / 0x14 <= free`, so the boundary is inclusive.
        let at = with_entries(512, 1, [0xff, 0x00, 0xff, 0xff], &[0x0c, 512 - 4 - 25]);
        let header = Header::read(&at, 1, Version::V5).expect("a header");
        assert_eq!(is_roomy(&at, header), Ok(true), "exactly at the threshold is roomy");

        let below = with_entries(512, 1, [0xff, 0x00, 0xff, 0xff], &[0x0c, 512 - 4 - 24]);
        let header = Header::read(&below, 1, Version::V5).expect("a header");
        assert_eq!(is_roomy(&below, header), Ok(false), "one byte below is not");
    }

    // `rewrite_fragment_in_place` -- the one shape a `dupdbtv` write to
    // `WCCTEXT` ever asks for. Deliberately unlike the fixtures above: a
    // 128-byte page rather than 2,048, a fragment far short of the page's
    // capacity rather than filling it, and (in the first test) more than one
    // page in the file with a second one this rewrite is never asked about --
    // the shape every `Chain::follow` test above shares and none of these
    // repeat.

    /// The one shape this handles, checked on the actual bytes rather than
    /// trusted from the code that is supposed to produce them: only the
    /// payload range changed, not the header, not the entry array, and not a
    /// page nobody asked about. The new payload differs from the old one in a
    /// single byte, not every byte -- a rewrite that happened to compare
    /// lengths and copy without truly overwriting would still pass a test
    /// whose payload changed in every position.
    #[test]
    fn a_matching_shape_is_rewritten_in_place_and_touches_only_the_payload() {
        let body: Vec<u8> = (0..30u8).collect();
        let mut new_body = body.clone();
        new_body[5] = new_body[5].wrapping_add(1);

        let mut pages = Held(vec![
            blank(128),
            blank(128),
            blank(128),
            page(3, 128, &[(&body, false)]),
            page(4, 128, &[(b"a neighbour this call was never asked about".as_slice(), false)]),
        ]);
        let before = pages.0[3].clone();
        let neighbour = pages.0[4].clone();

        rewrite_fragment_in_place(&mut pages, Version::V5, pointer(3, 0), &new_body)
            .expect("an equal-length, single-fragment, non-continued rewrite");

        let after = &pages.0[3];
        let at = FIRST_FRAGMENT as usize;
        assert_eq!(&after[at..at + new_body.len()], new_body.as_slice(), "the payload changed");
        for i in 0..after.len() {
            if (at..at + new_body.len()).contains(&i) {
                continue;
            }
            assert_eq!(after[i], before[i], "byte {i}, outside the payload, changed");
        }
        assert_eq!(pages.0[4], neighbour, "a page this call was never asked about is untouched");
    }

    /// Rewriting a fragment with the exact bytes it already held is not a
    /// special no-op case; it goes through the same write as any other
    /// equal-length body and still succeeds.
    #[test]
    fn rewriting_the_same_bytes_back_still_succeeds() {
        let body = b"identical, byte for byte, before and after".to_vec();
        let mut pages = Held(vec![blank(96), page(1, 96, &[(&body, false)])]);

        rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), &body)
            .expect("same length, same bytes, still a valid rewrite");

        let at = FIRST_FRAGMENT as usize;
        assert_eq!(&pages.0[1][at..at + body.len()], body.as_slice());
    }

    /// The length check the plan calls out by name: a body a different length
    /// from the fragment it would replace needs the free chain, the entry
    /// array, or a second page, none of which this function has -- so it
    /// refuses instead of silently resizing.
    #[test]
    fn a_body_of_a_different_length_is_refused_rather_than_resized() {
        let body = b"eleven long".to_vec();
        let mut pages = Held(vec![blank(96), page(1, 96, &[(&body, false)])]);
        let before = pages.0[1].clone();

        let shorter = b"short".to_vec();
        let e = rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), &shorter)
            .expect_err("11 bytes is not 5");
        assert!(e.contains("an in-place rewrite only handles a replacement of the same length"), "{e}");
        assert_eq!(pages.0[1], before, "a refused rewrite must not touch the page");
    }

    /// A page holding more than one fragment is refused whatever the pointed-
    /// at fragment's own length says, because a second fragment's entry sits
    /// in the same array this call never touches and nothing here has reason
    /// to assume that is safe on a page shaped differently from every one
    /// `WCCTEXT` has. The new body is deliberately the same length as the
    /// existing fragment 0, so the length check cannot be what refuses this.
    #[test]
    fn a_page_holding_more_than_one_fragment_is_refused() {
        let mut pages = Held(vec![
            blank(96),
            page(1, 96, &[(b"one".as_slice(), false), (b"two".as_slice(), false)]),
        ]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), b"one")
            .expect_err("two fragments on the page");
        assert!(e.contains("holds 2 fragments"), "{e}");
        assert_eq!(pages.0[1], before);
    }

    /// A continued fragment's payload is a pointer to the rest of the record
    /// on another page, not the whole record -- rewriting it as if it were
    /// the whole record would corrupt that pointer. Refused, with the new
    /// body the same length as the old one, so the length check cannot be
    /// what refuses this either.
    #[test]
    fn a_continued_fragment_is_refused_rather_than_rewritten_across_pages() {
        let mut head = vec![0x00u8, 0x02, 0x00, 0x00]; // page 2, fragment 0
        head.extend_from_slice(b"half");
        let mut pages = Held(vec![blank(64), page(1, 64, &[(&head, true)]), page(2, 64, &[(b"rest".as_slice(), false)])]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), &head)
            .expect_err("fragment 0 of page 1 continues onto page 2");
        assert!(e.contains("continues onto another page"), "{e}");
        assert_eq!(pages.0[1], before);
    }

    /// The engine's own status 54 check, reused here: the first live entry
    /// has to name offset `0x0c`, the same fact [`Chain::follow`] checks on
    /// the read side.
    #[test]
    fn a_rewrite_of_a_page_whose_first_live_fragment_does_not_start_at_twelve_is_refused() {
        let mut bytes = page(1, 96, &[(b"body".as_slice(), false)]);
        bytes[96 - 2] = 0x0e; // fragment 0 moved to offset 14
        let mut pages = Held(vec![blank(96), bytes]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), b"body")
            .expect_err("the header ends at 12");
        assert!(e.contains("status 54"), "{e}");
        assert_eq!(pages.0[1], before);
    }

    /// The page's own number is checked before anything else on it is
    /// trusted, the same guard [`Chain::follow`] has on the read side.
    #[test]
    fn a_rewrite_of_a_page_that_disagrees_about_which_page_it_is_is_refused() {
        let mut pages = Held(vec![blank(96), page(9, 96, &[(b"body".as_slice(), false)])]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), b"body")
            .expect_err("page 1 says it is page 9");
        assert!(e.contains("says it is page 9"), "{e}");
        assert_eq!(pages.0[1], before);
    }

    /// [`rewrite_fragment_in_place`] is the v5-only half of this mechanism
    /// and still refuses a v6 page -- deliberately, not because v6 writing
    /// is unimplemented: [`rewrite_fragment_in_place_v6`] above is that
    /// implementation, used by [`super::Block::update_v6`]. The two exist
    /// separately because a v6 page's `0x8000` bit means something else
    /// than it does in v5 (see the assertion below), so a shared function
    /// would have to branch on version internally rather than let a caller
    /// pick the right one; this test pins that [`rewrite_fragment_in_place`]
    /// itself never silently does the wrong thing with a v6 page, whatever
    /// its v6 counterpart does.
    #[test]
    fn a_btrieve_6_file_is_refused_rather_than_rewritten_by_the_version_5_rule() {
        let mut pages = Held(vec![blank(96), page(1, 96, &[(b"body".as_slice(), false)])]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V6, pointer(1, 0), b"body")
            .expect_err("the 0x8000 bit means something else in a v6 file");
        assert!(e.contains("V6") && e.contains("19045"), "{e}");
        assert_eq!(pages.0[1], before, "refused before the page was even asked for");
    }

    // `free_fragment_v6` -- the delete-side counterpart. Unlike
    // `rewrite_fragment_in_place_v6` above, this one has an actual oracle
    // recording (`docs/2026-08-17-variable-write-oracle.md`), so the first
    // test below reproduces its exact before/after entries rather than an
    // arbitrary shape.

    /// The oracle ladder's own numbers, reproduced exactly: freeing the
    /// first of three fragments on a page shifts the two behind it down to
    /// close the gap, rebases every entry from `which + 1` on, and leaves
    /// `0xffff` where the freed one was -- fragment count unchanged, because
    /// the freed slot is interior.
    #[test]
    fn freeing_an_interior_v6_fragment_matches_the_oracle_ladder() {
        let frag0 = [V6_END.as_slice(), &[0xa1u8; 200]].concat();
        let frag1 = [V6_END.as_slice(), &[0xb1u8; 200]].concat();
        let frag2 = [V6_END.as_slice(), &[0xc1u8; 80]].concat();
        assert_eq!(frag0.len(), 204);
        assert_eq!(frag1.len(), 204);
        assert_eq!(frag2.len(), 84);

        let five = page_v6(5, 512, &[&frag0, &frag1, &frag2]);
        // The oracle's own entries before this delete: 0xc, 0xd8, 0x1a4, 0x1f8.
        assert_eq!(entry(&five, 0), Ok(0x0c));
        assert_eq!(entry(&five, 1), Ok(0xd8));
        assert_eq!(entry(&five, 2), Ok(0x1a4));
        assert_eq!(entry(&five, 3), Ok(0x1f8));

        let mut pages = Held(vec![blank(512), blank(512), blank(512), blank(512), blank(512), five]);

        free_fragment_v6(&mut pages, Pointer { page: 5, fragment: 0 }, None)
            .expect("an unchained fragment on a page with siblings after it");

        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 3, "interior free leaves the count alone");
        assert_eq!(entry(after, 0), Ok(UNUSED), "the freed entry, in place");
        assert_eq!(entry(after, 1), Ok(0x0c), "0xd8 - 0xcc, the oracle's own number");
        assert_eq!(entry(after, 2), Ok(0xd8), "0x1a4 - 0xcc");
        assert_eq!(entry(after, 3), Ok(0x12c), "0x1f8 - 0xcc, matches the ladder's \"free 204\"");
        assert_eq!(&after[0x0c..0x0c + 204], frag1.as_slice(), "fragment 1's own bytes, shifted down");
        assert_eq!(&after[0xd8..0xd8 + 84], frag2.as_slice(), "fragment 2's own bytes, shifted down");
    }

    /// The oracle ladder's second delete, from the same document: freeing
    /// the *last* live fragment on a page drops the count instead of leaving
    /// a trailing hole -- derived from the entry array's own invariant (see
    /// `free_fragment_v6`'s doc comment), not a byte-for-byte transcription,
    /// because the document does not give exact bytes for this step.
    #[test]
    fn freeing_the_last_v6_fragment_shrinks_the_count_instead_of_leaving_a_hole() {
        let frag0 = [V6_END.as_slice(), &[0xd1u8; 50]].concat();
        let frag1 = [V6_END.as_slice(), &[0xd2u8; 30]].concat();
        let seven = page_v6(7, 256, &[&frag0, &frag1]);
        let mut pages = Held({
            let mut v = vec![blank(256); 7];
            v.push(seven);
            v
        });

        free_fragment_v6(&mut pages, Pointer { page: 7, fragment: 1 }, None)
            .expect("the last of two fragments, unchained");

        let after = &pages.0[7];
        assert_eq!(fragment_count(after), 1, "the trailing slot is dropped, not marked 0xffff");
        assert_eq!(entry(after, 0), Ok(FIRST_FRAGMENT), "fragment 0's own entry, untouched");
        assert_eq!(
            entry(after, 1),
            Ok(FIRST_FRAGMENT + frag0.len() as u32),
            "the new boundary is where the freed fragment used to start"
        );
        assert_eq!(&after[0x0c..0x0c + frag0.len()], frag0.as_slice(), "the surviving fragment, untouched");
    }

    /// Freeing the only fragment on a page would leave it reporting 0
    /// fragments, a shape `Header::read` itself refuses -- so this refuses
    /// before writing rather than producing a page nothing here can read
    /// back. No oracle ladder reaches this case either (every delete
    /// measured left at least one fragment behind).
    #[test]
    fn freeing_the_only_fragment_on_a_page_is_refused() {
        let frag0 = [V6_END.as_slice(), &[0xe1u8; 40]].concat();
        let nine = page_v6(9, 128, &[&frag0]);
        let mut pages = Held({
            let mut v = vec![blank(128); 9];
            v.push(nine);
            v
        });
        let before = pages.0[9].clone();

        let e = free_fragment_v6(&mut pages, Pointer { page: 9, fragment: 0 }, None)
            .expect_err("the only fragment on its page");
        assert!(e.contains("the only one on its page"), "{e}");
        assert_eq!(pages.0[9], before, "a refused free must not touch the page");
    }

    /// A chained fragment's own leading bytes name where the record's body
    /// continues -- freeing it without freeing the rest of the chain would
    /// leak those pages, and this host has not measured what genuine
    /// Btrieve does across a multi-hop free. Refused, the same standard
    /// `rewrite_fragment_in_place_v6` already holds itself to.
    #[test]
    fn freeing_a_chained_v6_fragment_is_refused() {
        let frag0 = [v6_next(3, 2).as_slice(), &[0xf1u8; 10]].concat();
        let frag1 = [V6_END.as_slice(), &[0xf2u8; 10]].concat();
        let four = page_v6(4, 128, &[&frag0, &frag1]);
        let mut pages = Held(vec![blank(128), blank(128), blank(128), blank(128), four]);
        let before = pages.0[4].clone();

        let e = free_fragment_v6(&mut pages, Pointer { page: 4, fragment: 0 }, None)
            .expect_err("fragment 0 continues onto page 3");
        assert!(e.contains("continues onto another page"), "{e}");
        assert_eq!(pages.0[4], before, "a refused free must not touch the page");
    }

    /// A second delete on a page that already has an interior hole is
    /// refused rather than rebasing an already-`0xffff` entry into garbage
    /// -- no corpus file (first-generation, harvest 5 SS6.3) or oracle rig
    /// exercises two deletes on the same page.
    #[test]
    fn freeing_past_an_already_freed_entry_is_refused() {
        let frag0 = [V6_END.as_slice(), &[0xa1u8; 40]].concat();
        let frag1 = [V6_END.as_slice(), &[0xb1u8; 40]].concat();
        let frag2 = [V6_END.as_slice(), &[0xc1u8; 40]].concat();
        let mut six = page_v6(6, 256, &[&frag0, &frag1, &frag2]);
        set_entry(&mut six, 1, UNUSED).expect("entry 1 exists"); // a prior interior free
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), blank(256), six]);
        let before = pages.0[6].clone();

        let e = free_fragment_v6(&mut pages, Pointer { page: 6, fragment: 0 }, None)
            .expect_err("entry 1, between fragment 0 and the boundary, is already freed");
        assert!(e.contains("already a freed slot"), "{e}");
        assert_eq!(pages.0[6], before, "a refused free must not touch the page");
    }

    /// **The Critical review finding, made concrete.** `Self::insert_v6`
    /// (`lib.rs`) has called [`Space::place`] for every v6 variable-length
    /// insert since before this task -- so a page a delete gives real room
    /// back to, but never rejoins to the chain, is permanently unreachable
    /// to that insert path: a claimed-but-unreachable leak. This builds
    /// exactly that page by hand (two fragments, packed until it is off the
    /// chain -- the same shape
    /// `a_page_that_fills_up_is_taken_off_the_free_space_chain` builds with
    /// one), frees the trailing fragment, and checks that a `Space` seeded
    /// with the head this returns lands its next `place` call on the same
    /// page rather than claiming a new one.
    #[test]
    fn a_delete_on_a_previously_full_page_leaves_it_reachable_to_a_later_insert() {
        let mut source = Scratch::new(512, Version::V6);

        // First fragment: 200 bytes, 204 with its pointer. Leaves the page
        // roomy, so it joins the chain.
        let mut space = Space::new(&mut source, Version::V6, None);
        let first = space.place(&[0xa1u8; 200]).expect("200 fits fresh");
        let head = space.head();
        assert_eq!(head, Some(first.page), "roomy after one fragment, offered");

        // Second fragment: 270 bytes, 274 with its pointer -- 494 - (204 +
        // 274) = 16 bytes left, under the 512 / 20 = 25 threshold. Fills the
        // page and takes it off the chain, `reoffer`'s own unlink path.
        let mut space = Space::new(&mut source, Version::V6, head);
        let second = space.place(&[0xa2u8; 270]).expect("270 still fits, same page");
        assert_eq!(second.page, first.page, "the second fragment shares the first's page");
        assert_eq!(space.head(), None, "full now, and taken off the chain");
        assert_eq!(source.claimed(), 1, "one page for both fragments");

        let page = source.page(first.page).expect("reads");
        let header = Header::read(page, first.page, Version::V6).expect("a header");
        assert_eq!(header.free_chain, FreeChain::Off, "confirmed full and unreachable");

        // Delete the trailing fragment. The page has real room again --
        // 16 + 274 = 290 free of 512 -- and was off the chain, so this must
        // rejoin it.
        let new_head = free_fragment_v6(&mut source, second, None)
            .expect("the trailing fragment, unchained, on a page with a sibling");
        assert_eq!(new_head, Some(first.page), "the freed page becomes the new head");

        let page = source.page(first.page).expect("reads");
        let header = Header::read(page, first.page, Version::V6).expect("a header");
        assert_eq!(header.free_chain, FreeChain::Last, "on the chain, and the only member");

        // The property under test: a `Space` seeded with the head this
        // delete returned reuses the page rather than claiming a fresh one.
        let mut space = Space::new(&mut source, Version::V6, new_head);
        let third = space.place(&[0xa3u8; 50]).expect("50 fits in the reclaimed room");
        assert_eq!(third.page, first.page, "landed on the page the delete just freed");
        assert_eq!(source.claimed(), 1, "no new page was needed -- the freed one was reachable");
    }

    /// A page already reachable from the chain (`Next`/`Last`) is left
    /// exactly where it is -- moving it to the head from the middle needs an
    /// unlink this host has not measured, `Space::reoffer`'s own restriction
    /// for the symmetric insert-side case.
    #[test]
    fn a_page_already_on_the_chain_is_not_moved_when_it_is_freed_further() {
        let mut source = Scratch::new(512, Version::V6);

        let mut space = Space::new(&mut source, Version::V6, None);
        let first = space.place(&[0xb1u8; 200]).expect("200 fits");
        let head_after_first = space.head();
        assert_eq!(head_after_first, Some(first.page), "roomy, on the chain");

        let mut space = Space::new(&mut source, Version::V6, head_after_first);
        let second = space.place(&[0xb2u8; 30]).expect("30 more, plenty of room left");
        let head = space.head();
        assert_eq!(head, Some(first.page), "still the only page, still the head");

        // Freeing the second (trailing) fragment leaves the page even
        // roomier, but it was already `Last`, not `Off` -- nothing to rejoin.
        let new_head = free_fragment_v6(&mut source, second, head).expect("trailing, unchained");
        assert_eq!(new_head, head, "unchanged -- it was already reachable");

        let page = source.page(first.page).expect("reads");
        let header = Header::read(page, first.page, Version::V6).expect("a header");
        assert_eq!(header.free_chain, FreeChain::Last, "still exactly what it was");
    }

    /// **The Important review finding, made concrete.** The interior-branch
    /// guard only refuses rebasing across a pre-existing `0xffff`; a page
    /// that already took a *trailing* free leaves no such marker, so a
    /// second delete against it hits no guard at all. This proves that is
    /// correct rather than merely unrefused: two deletes against the same
    /// three-fragment page -- trailing, then interior on what remains --
    /// leave exactly the bytes a single delete against the smaller page
    /// would, checked directly rather than only asserting success.
    #[test]
    fn a_second_delete_after_a_trailing_free_is_not_a_special_case() {
        let frag0 = [V6_END.as_slice(), &[0xc1u8; 40]].concat();
        let frag1 = [V6_END.as_slice(), &[0xc2u8; 40]].concat();
        let frag2 = [V6_END.as_slice(), &[0xc3u8; 40]].concat();
        assert_eq!(frag0.len(), 44);

        let ten = page_v6(10, 256, &[&frag0, &frag1, &frag2]);
        let mut pages = Held({
            let mut v = vec![blank(256); 10];
            v.push(ten);
            v
        });

        // First: free the trailing fragment (index 2 of 3). No `0xffff`
        // results -- the count just drops to 2.
        free_fragment_v6(&mut pages, Pointer { page: 10, fragment: 2 }, None)
            .expect("the last of three, unchained");
        assert_eq!(fragment_count(&pages.0[10]), 2, "trailing free drops the count");
        assert_eq!(entry(&pages.0[10], 0), Ok(FIRST_FRAGMENT));
        assert_eq!(entry(&pages.0[10], 1), Ok(FIRST_FRAGMENT + frag0.len() as u32));

        // Second: free fragment 0, now interior (fragment 1 still follows
        // it) on a page that has already had one delete. Nothing refuses
        // this, and the result below is checked against what a page that
        // *always* held exactly two fragments would produce.
        free_fragment_v6(&mut pages, Pointer { page: 10, fragment: 0 }, None)
            .expect("fragment 0 is interior now that fragment 2 is gone");

        let after = &pages.0[10];
        assert_eq!(fragment_count(after), 2, "interior free leaves the count alone");
        assert_eq!(entry(after, 0), Ok(UNUSED), "the freed entry, in place");
        assert_eq!(entry(after, 1), Ok(FIRST_FRAGMENT), "fragment 1 shifted down to close the gap");
        assert_eq!(
            entry(after, 2),
            Ok(FIRST_FRAGMENT + frag1.len() as u32),
            "the boundary, rebased by fragment 0's length"
        );
        assert_eq!(
            &after[FIRST_FRAGMENT as usize..FIRST_FRAGMENT as usize + frag1.len()],
            frag1.as_slice(),
            "fragment 1's own bytes, shifted down -- exactly what a two-fragment page's \
             own first delete would produce, because nothing distinguishes this page from \
             one that always held two fragments"
        );
    }


    // `free_fragment` -- the version 5 delete. Every number below is
    // `v5_variable_delete.fixture`'s own; see that function's doc comment
    // for the recorded bytes and for which parts of the intermediate state
    // are inferred from them.

    /// The fixture's own delete, reproduced on a page built by hand: page 5
    /// of a 1,024-byte file holding `Sysop`'s 17-byte body and `Test`'s
    /// 4-byte one, with the first freed.
    ///
    /// The freed entry becomes `0xffff` in place, the survivor slides down
    /// to `0x0c` (which is what keeps the page's *first live* entry at
    /// `FIRST_FRAGMENT` -- the engine's own status 54 rule), every entry
    /// after the freed one is rebased by its length, the fragment count does
    /// not move, and the bytes the shift vacated are zeroed.
    #[test]
    fn freeing_an_interior_v5_fragment_compacts_the_page_and_tombstones_its_entry() {
        let sysop = b"EMO NORMAL SYSOP\0".to_vec();
        let test = b"EMO\0".to_vec();
        assert_eq!(sysop.len(), 17);
        assert_eq!(test.len(), 4);

        let five = page(5, 1024, &[(&sysop, false), (&test, false)]);
        assert_eq!(entry(&five, 0), Ok(0x0c));
        assert_eq!(entry(&five, 1), Ok(0x1d));
        assert_eq!(entry(&five, 2), Ok(0x21));

        let mut pages = Held(vec![blank(1024), blank(1024), blank(1024), blank(1024), blank(1024), five]);

        let head = free_fragment(&mut pages, pointer(5, 0), Some(5))
            .expect("an unchained fragment with a sibling after it");
        assert_eq!(head, Some(5), "the page was already on the chain and stays where it is");

        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 2, "an interior free leaves the count alone");
        assert_eq!(entry(after, 0), Ok(UNUSED), "the freed entry, tombstoned in place");
        assert_eq!(entry(after, 1), Ok(0x0c), "0x1d - 17: the survivor is now the first live entry");
        assert_eq!(entry(after, 2), Ok(0x10), "0x21 - 17: the new free-space boundary");
        assert_eq!(&after[0x0c..0x10], test.as_slice(), "the survivor's bytes, shifted down");
        assert!(
            after[0x10..0x21].iter().all(|b| *b == 0),
            "the bytes the shift vacated are zeroed, not left stale: {:02x?}",
            &after[0x10..0x21]
        );
        // The page still reads as a variable page, which the status 54 rule
        // is what would otherwise refuse.
        let header = Header::read(after, 5, Version::V5).expect("still a readable page");
        let survivor = fragment(after, 1, header, Version::V5).expect("still findable");
        assert_eq!(&after[survivor.at..survivor.at + survivor.length], test.as_slice());
    }

    /// Freeing the *last* fragment of a page drops the entry and the count
    /// rather than leaving a trailing `0xffff`, and zeroes the fragment's own
    /// bytes. `W32MKDE_decompiled.c:19737`'s trailing branch; no recording
    /// reaches it, so this is the engine's text rather than measured bytes.
    #[test]
    fn freeing_the_last_v5_fragment_drops_its_entry_and_the_count() {
        let first = b"EMO NORMAL SYSOP\0".to_vec();
        let last = b"EMO\0".to_vec();
        let five = page(5, 256, &[(&first, false), (&last, false)]);
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five]);

        free_fragment(&mut pages, pointer(5, 1), None).expect("the last of two, unchained");

        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 1, "the trailing slot is dropped, not tombstoned");
        assert_eq!(entry(after, 0), Ok(FIRST_FRAGMENT), "fragment 0's entry, untouched");
        assert_eq!(
            entry(after, 1),
            Ok(FIRST_FRAGMENT + first.len() as u32),
            "the new boundary is where the freed fragment used to start"
        );
        assert_eq!(entry(after, 2), Ok(0), "the old boundary entry is zeroed");
        assert_eq!(&after[0x0c..0x0c + first.len()], first.as_slice(), "the survivor, untouched");
        assert!(
            after[0x0c + first.len()..0x0c + first.len() + last.len()].iter().all(|b| *b == 0),
            "the freed fragment's own bytes are zeroed"
        );
    }

    /// The trailing branch's own collapse: a page whose middle slot was
    /// already tombstoned loses both entries when the fragment behind it is
    /// freed, because the engine repeats the drop while the entry before the
    /// one it just took is `0xffff` (`W32MKDE_decompiled.c:19737`).
    #[test]
    fn freeing_a_trailing_v5_fragment_collapses_the_freed_slots_before_it() {
        let a = vec![0xa1u8; 20];
        let b = vec![0xb1u8; 10];
        let c = vec![0xc1u8; 6];
        let five = page(5, 256, &[(&a, false), (&b, false), (&c, false)]);
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five]);

        free_fragment(&mut pages, pointer(5, 1), None).expect("interior");
        assert_eq!(entry(&pages.0[5], 1), Ok(UNUSED), "the middle slot is a hole now");
        assert_eq!(fragment_count(&pages.0[5]), 3);

        free_fragment(&mut pages, pointer(5, 2), None).expect("trailing, with a hole before it");

        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 1, "both the freed slot and the hole before it go");
        assert_eq!(entry(after, 0), Ok(FIRST_FRAGMENT), "fragment 0's entry, untouched");
        assert_eq!(
            entry(after, 1),
            Ok(FIRST_FRAGMENT + a.len() as u32),
            "the boundary, back to where fragment 0 ends"
        );
        assert_eq!(entry(after, 2), Ok(0), "the entries past the new boundary are zeroed");
        assert_eq!(entry(after, 3), Ok(0), "both of them");
        assert_eq!(&after[0x0c..0x0c + a.len()], a.as_slice(), "the survivor, untouched");
    }

    /// The page is left holding nothing, and stays exactly where it is.
    /// `v5_variable_release_empty.fixture`'s own shape, in miniature: the
    /// count reaches zero, the boundary entry goes back to
    /// [`FIRST_FRAGMENT`], the entry above it is zeroed, the body is zeroed,
    /// and the free-space chain field is not touched.
    #[test]
    fn freeing_the_only_v5_fragment_on_a_page_empties_it_and_leaves_it_in_place() {
        let only = vec![0x5au8; 40];
        let mut five = page(5, 256, &[(&only, false)]);
        // On the chain and last, the way genuine's page 5 is
        // (`ff 00 ff ff` at `0x1406`) before the delete that empties it.
        set_chain(&mut five, FreeChain::Last);
        let before = five.clone();
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five]);

        let head = free_fragment(&mut pages, pointer(5, 0), Some(3)).expect("the only fragment");

        assert_eq!(head, Some(3), "the page was already on the chain, so the head does not move");
        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 0, "the page holds nothing");
        assert_eq!(entry(after, 0), Ok(FIRST_FRAGMENT), "the boundary, back to where bodies start");
        assert_eq!(entry(after, 1), Ok(0), "the entry the boundary used to sit in is zeroed");
        assert!(
            after[FIRST_FRAGMENT as usize..FIRST_FRAGMENT as usize + only.len()]
                .iter()
                .all(|b| *b == 0),
            "the freed body is zeroed"
        );
        assert_eq!(&after[..FREE_CHAIN + 4], &before[..FREE_CHAIN + 4], "number and chain untouched");

        let header = Header::read(after, 5, Version::V5).expect("an emptied v5 page still reads");
        assert_eq!(header.fragments, 0);
        assert_eq!(header.free_chain, FreeChain::Last, "still offered for new fragments");
    }

    /// The same, reached the other way: an interior free leaves a hole, and
    /// the trailing free that follows collapses the hole with it and takes
    /// the count to zero.
    #[test]
    fn freeing_a_trailing_v5_fragment_that_empties_the_page_collapses_every_entry() {
        let a = vec![0xa1u8; 20];
        let b = vec![0xb1u8; 10];
        let five = page(5, 256, &[(&a, false), (&b, false)]);
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five]);

        free_fragment(&mut pages, pointer(5, 0), None).expect("interior");
        free_fragment(&mut pages, pointer(5, 1), None).expect("the hole before it collapses too");

        let after = &pages.0[5];
        assert_eq!(fragment_count(after), 0, "both entries went");
        assert_eq!(entry(after, 0), Ok(FIRST_FRAGMENT), "the boundary");
        assert_eq!(entry(after, 1), Ok(0), "zeroed");
        assert_eq!(entry(after, 2), Ok(0), "zeroed");
        assert!(
            after[FIRST_FRAGMENT as usize..FIRST_FRAGMENT as usize + a.len() + b.len()]
                .iter()
                .all(|b| *b == 0),
            "both bodies are zeroed"
        );
    }

    /// The insert that follows an emptying delete goes back onto the same
    /// page rather than claiming a new one --
    /// `v5_variable_release_reinsert.fixture`'s own answer, and it needs no
    /// branch of its own in [`Space::place`]: the emptied page is still on
    /// the free-space chain, so [`Space::room_for`] simply finds it.
    #[test]
    fn a_v5_insert_goes_back_onto_a_page_a_delete_emptied() {
        let only = b"EMO\0".to_vec();
        let mut five = page(5, 1024, &[(&only, false)]);
        set_chain(&mut five, FreeChain::Last);
        let mut source = Scratch::new(1024, Version::V5);
        for _ in 0..4 {
            source.claim(&blank_page(1024, Version::V5)).expect("filler");
        }
        source.claim(&five).expect("the page under test");

        // Empty it the way a delete does, through the free side.
        let head = free_fragment(&mut source, pointer(5, 0), Some(5)).expect("the only one");
        assert_eq!(head, Some(5), "the page was already on the chain; the head does not move");

        let body = b"EMO NORMAL\0".to_vec();
        let mut space = Space::new(&mut source, Version::V5, head);
        let placed = space.place(&body).expect("the emptied page takes it");

        assert_eq!(placed, pointer(5, 0), "fragment 0 of the same page; nothing was claimed");
        assert_eq!(source.claimed(), 5, "still five pages past the control record");
        let after = source.pages[5].clone();
        assert_eq!(fragment_count(&after), 1);
        assert_eq!(entry(&after, 0), Ok(FIRST_FRAGMENT));
        assert_eq!(entry(&after, 1), Ok(FIRST_FRAGMENT + body.len() as u32));
        assert_eq!(&after[0x0c..0x0c + body.len()], body.as_slice(), "the new body");
    }

    /// The v5 allowance is v5's alone: nothing has recorded what a version 6
    /// engine leaves behind, so [`Header::read`] still refuses the shape
    /// there.
    #[test]
    fn a_v6_page_reporting_no_fragments_is_still_refused() {
        let mut six = page_v6(7, 256, &[&[0xff, 0xff, 0xff, 0xff, 0x11]]);
        set_fragment_count(&mut six, 0);
        set_entry(&mut six, 0, FIRST_FRAGMENT).expect("the boundary");

        let e = Header::read(&six, 7, Version::V6).expect_err("v6 has no measurement for this");
        assert!(e.contains("0 fragments"), "{e}");

        let mut five = page(7, 256, &[(&[0x11u8][..], false)]);
        set_fragment_count(&mut five, 0);
        set_entry(&mut five, 0, FIRST_FRAGMENT).expect("the boundary");
        let header = Header::read(&five, 7, Version::V5).expect("v5 reads it");
        assert_eq!(header.fragments, 0);
    }

    /// A chained fragment is refused, the same way the v6 free and both
    /// in-place rewrites refuse one: freeing every hop is a walk this host
    /// has not measured.
    #[test]
    fn freeing_a_chained_v5_fragment_is_refused() {
        let chained = [pointer(6, 0).encode().as_slice(), &[0x11u8; 12]].concat();
        let plain = vec![0x22u8; 8];
        let five = page(5, 256, &[(&chained, true), (&plain, false)]);
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five.clone()]);

        let e = free_fragment(&mut pages, pointer(5, 0), None)
            .expect_err("a chain that spans pages is refused");
        assert!(e.contains("continues onto another page"), "{e}");
        assert_eq!(pages.0[5], five, "a refused free writes nothing");
    }

    /// A page that is off the free-space chain and gains real room by a
    /// delete joins the chain at the head, the same threading
    /// `free_fragment_v6` does and `Space::reoffer` does for the insert
    /// side.
    #[test]
    fn a_freed_v5_page_with_room_rejoins_the_free_space_chain_at_the_head() {
        let a = vec![0xa1u8; 100];
        let b = vec![0xb1u8; 100];
        let mut five = page(5, 256, &[(&a, false), (&b, false)]);
        set_chain(&mut five, FreeChain::Off);
        let mut pages = Held(vec![blank(256), blank(256), blank(256), blank(256), blank(256), five]);

        let head = free_fragment(&mut pages, pointer(5, 0), Some(3))
            .expect("an unchained interior fragment");

        assert_eq!(head, Some(5), "the page this delete gave room to is the new head");
        let after = Header::read(&pages.0[5], 5, Version::V5).expect("readable");
        assert_eq!(after.free_chain, FreeChain::Next(3), "the old head follows it");
    }

    /// The other half of the fixture's delete: the insert that follows fills
    /// the slot the delete freed rather than appending past the last
    /// fragment. `v5_variable_delete.fixture`'s own numbers -- a 30-byte
    /// body into a page whose entry 0 is a hole and whose fragment 1 is
    /// `"EMO\0"` at `0x0c` -- and the answer is genuine Btrieve's own page:
    /// two fragments, entries `0x0c, 0x2a, 0x2e`, the new body first.
    #[test]
    fn a_v5_insert_fills_the_slot_a_delete_freed_rather_than_appending() {
        let survivor = b"EMO\0".to_vec();
        let mut five = page(5, 1024, &[(&survivor, false)]);
        // What the fixture's delete leaves: the survivor is fragment 1, and
        // fragment 0's entry is a hole. Built by hand rather than by calling
        // `free_fragment`, so this test fails on its own if `place` stops
        // reusing the slot even when the free side is right.
        set_fragment_count(&mut five, 2);
        set_entry(&mut five, 2, FIRST_FRAGMENT + survivor.len() as u32).expect("boundary");
        set_entry(&mut five, 1, FIRST_FRAGMENT).expect("the survivor");
        set_entry(&mut five, 0, UNUSED).expect("the hole");

        let mut source = Scratch::new(1024, Version::V5);
        for _ in 0..4 {
            source.claim(&blank_page(1024, Version::V5)).expect("filler");
        }
        source.claim(&five).expect("the page under test");

        let body = b"EMO NORMAL MODERATE MASS_MAIL\0".to_vec();
        assert_eq!(body.len(), 30);
        let mut space = Space::new(&mut source, Version::V5, Some(5));
        let at = space.place(&body).expect("a body that fits the page it is offered");

        assert_eq!(at, pointer(5, 0), "the freed slot, not a third fragment");
        let after = &source.pages[5];
        assert_eq!(fragment_count(after), 2, "reusing a slot does not grow the array");
        assert_eq!(entry(after, 0), Ok(0x0c), "the new fragment starts where the header ends");
        assert_eq!(entry(after, 1), Ok(0x2a), "the survivor, shifted up by the new body");
        assert_eq!(entry(after, 2), Ok(0x2e), "the boundary, shifted with it");
        assert_eq!(&after[0x0c..0x2a], body.as_slice(), "the new body");
        assert_eq!(&after[0x2a..0x2e], survivor.as_slice(), "the survivor's bytes, moved up");
    }

    /// The version 6 half of the rule above: a v6 file **appends past a
    /// hole** rather than filling it, and this is the test that says so.
    ///
    /// `free_fragment_v6`'s interior branch leaves `0xffff` behind, so the
    /// reuse would be reachable for v6 the moment a delete were followed by
    /// an insert -- and no recording pins what genuine Btrieve does there.
    /// The four committed v6 fixtures were recorded against a host that
    /// appended, and this keeps that until a v6 delete-then-insert recording
    /// exists. Deliberately the same page shape as
    /// [`tests::a_v5_insert_fills_the_slot_a_delete_freed_rather_than_appending`],
    /// so the only difference between the two answers is the version.
    #[test]
    fn a_v6_insert_appends_past_a_freed_slot_rather_than_filling_it() {
        let survivor = [V6_END.as_slice(), b"survivor".as_slice()].concat();
        let mut five = page_v6(5, 512, &[&survivor]);
        // What a v6 interior free leaves: the survivor is fragment 1, and
        // fragment 0's entry is a hole.
        set_fragment_count(&mut five, 2);
        set_entry(&mut five, 2, FIRST_FRAGMENT + survivor.len() as u32).expect("boundary");
        set_entry(&mut five, 1, FIRST_FRAGMENT).expect("the survivor");
        set_entry(&mut five, 0, UNUSED).expect("the hole");
        let boundary = FIRST_FRAGMENT + survivor.len() as u32;

        let mut source = Scratch::new(512, Version::V6);
        for _ in 0..4 {
            source.claim(&blank_page(512, Version::V6)).expect("filler");
        }
        source.claim(&five).expect("the page under test");

        let body = b"a new body".to_vec();
        let mut space = Space::new(&mut source, Version::V6, Some(5));
        let at = space.place(&body).expect("a body that fits the page it is offered");

        assert_eq!(at, pointer(5, 2), "appended as a third fragment, not into the hole");
        let after = &source.pages[5];
        assert_eq!(fragment_count(after), 3, "appending grows the array");
        assert_eq!(entry(after, 0), Ok(UNUSED), "the hole is left exactly where it was");
        assert_eq!(entry(after, 1), Ok(FIRST_FRAGMENT), "the survivor did not move");
        assert_eq!(entry(after, 2), Ok(boundary), "the new fragment starts at the old boundary");
        assert_eq!(
            entry(after, 3),
            Ok(boundary + (POINTER + body.len()) as u32),
            "the new boundary, past the new fragment and its leading pointer"
        );
        assert_eq!(
            &after[FIRST_FRAGMENT as usize..boundary as usize],
            survivor.as_slice(),
            "the survivor's own bytes, untouched"
        );
        let at = boundary as usize;
        assert_eq!(&after[at..at + POINTER], V6_END.as_slice(), "every v6 fragment leads with one");
        assert_eq!(&after[at + POINTER..at + POINTER + body.len()], body.as_slice());
    }

    /// [`FilePages`] is what a real `Block::update` runs against -- every
    /// test above uses [`Held`], a `Vec` in memory, which cannot by itself
    /// prove the disk-facing implementation seeks, reads and writes the
    /// right bytes.
    #[test]
    fn file_pages_reads_and_writes_a_real_file_on_disk() {
        let dir = crate::testing::scratch("variable-file-pages-round-trip");
        let path = dir.join("SCRATCH.DAT");

        let body = b"on disk, not held in memory".to_vec();
        let mut file_bytes = blank(64); // page 0, standing in for the FCR
        file_bytes.extend_from_slice(&page(1, 64, &[(&body, false)]));
        std::fs::write(&path, &file_bytes).expect("write the fixture");

        let mut new_body = body.clone();
        new_body[0] = b'O';

        let mut pages = FilePages::new(&path, 64, 2);
        rewrite_fragment_in_place(&mut pages, Version::V5, pointer(1, 0), &new_body)
            .expect("matches the shape");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(&after[..64], &blank(64)[..], "page 0 is untouched");
        let at = 64 + FIRST_FRAGMENT as usize;
        assert_eq!(&after[at..at + new_body.len()], new_body.as_slice(), "the payload landed on disk");
    }

    /// A v5 claim appends: the page lands at the end of the file, carries
    /// its own physical number, and the file is one page longer. Genuine
    /// Btrieve's own answer -- see [`V5Pages`]'s doc comment on where the
    /// insert scenario's first variable page went.
    #[test]
    fn a_v5_claim_appends_a_page_stamped_with_its_own_number() {
        let dir = crate::testing::scratch("variable-v5-claim");
        let path = dir.join("CLAIM.DAT");
        // Two pages: page 0 standing in for the file control record, page 1
        // for anything else the file already has.
        std::fs::write(&path, vec![0u8; 128]).expect("write the fixture");

        let mut source = V5Pages::new(&path, 64, 2);
        let number = source
            .claim(&blank_page(64, Version::V5))
            .expect("appends rather than refusing");
        assert_eq!(number, 2, "the claim takes the page one past the last");
        assert_eq!(source.pages(), 3, "and the file is a page longer");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after.len(), 192, "the file really grew on disk");
        let page = &after[128..];
        assert_eq!(
            super::super::pages::long(&page[PAGE_NUMBER..PAGE_NUMBER + 4]),
            2,
            "the page names itself, which is what `Header::read` checks for v5"
        );
        assert_eq!(
            super::super::pages::long(&page[FREE_CHAIN..FREE_CHAIN + 4]),
            NO_PAGE,
            "a page with no fragments on it yet is not offered to anyone"
        );
    }

    /// The v5 free-space head reads and writes at `0x3a`, with `0xffff`
    /// meaning "nothing offered" -- and setting it clears the virgin flag at
    /// `0x39` in the same breath, which is what the genuine engine did.
    #[test]
    fn the_v5_head_round_trips_through_the_control_record() {
        use super::super::format::fcr::at::{VARIABLE_HIGHEST, VARIABLE_SUBFLAG};

        let mut fcr = vec![0u8; 512];
        fcr[VARIABLE_SUBFLAG] = 0xff;
        fcr[VARIABLE_HIGHEST..VARIABLE_HIGHEST + 2].copy_from_slice(&NO_V5_HEAD.to_le_bytes());
        assert_eq!(v5_head_of(&fcr), None, "a virgin file offers no page");

        set_v5_head(&mut fcr, Some(5)).expect("5 fits a u16");
        assert_eq!(&fcr[VARIABLE_SUBFLAG..VARIABLE_HIGHEST + 2], &[0x00, 0x05, 0x00]);
        assert_eq!(v5_head_of(&fcr), Some(5));

        set_v5_head(&mut fcr, None).expect("the sentinel always fits");
        assert_eq!(v5_head_of(&fcr), None, "an emptied chain offers no page");
        assert_eq!(fcr[VARIABLE_SUBFLAG], 0x00, "and the file is still not virgin");

        assert!(
            set_v5_head(&mut fcr, Some(0x1_0000)).is_err(),
            "a page number a v5 control record cannot name is refused, not truncated"
        );
    }
}
