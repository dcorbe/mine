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
        if fragments == 0 || fragments > MAX_FRAGMENTS {
            return Err(format!(
                "{fragments} fragments, and a page holds between 1 and {MAX_FRAGMENTS}"
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
        let mut file = std::fs::File::open(self.path)
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
/// through the `"PP"` allocation table, and v5 takes a **physical** page off
/// the file's own free chain or appends one. Folding that into [`PagesMut`]
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

/// A variable page with no fragments on it yet.
///
/// Fragment count zero, [`FREE_CHAIN`] saying the page is not on the chain,
/// and entry 0 already naming [`FIRST_FRAGMENT`] -- the array always holds one
/// more entry than the page has fragments, so even an empty page has entry 0,
/// and it says where fragment 0 will begin.
///
/// [`Header::read`] refuses a page with zero fragments, so this is not
/// readable as a header until its first fragment lands. That is deliberate:
/// [`Space::place`] writes the count and the entry together, and a page that
/// is briefly neither one thing nor the other should not be readable as
/// either.
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
/// [`Header::read`] refuses a page with zero fragments, and a page being built
/// has zero fragments right up until its first one lands, so the allocator
/// cannot reach its entries the way a reader does.
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

        // Where this fragment goes is where the last entry already says the
        // fragments end -- entry `i` names fragment `i`'s start, so the array
        // has one more entry than the page has fragments and the extra one is
        // the free-space boundary.
        let fragments = fragment_count(&page);
        let at = entry(&page, u32::from(fragments))? as usize;
        if at == UNUSED as usize {
            return Err(format!(
                "page {number}'s entry {fragments} is free, so nothing says where its \
                 fragments end"
            ));
        }

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

        set_fragment_count(&mut page, fragments + 1);
        set_entry(&mut page, u32::from(fragments) + 1, (at + needed) as u32)?;

        self.reoffer(number, &mut page, fresh)?;
        self.source.write_page(number, &page)?;

        Ok(Pointer {
            page: number,
            fragment: fragments as u8,
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
        assert!(e.contains("between 1 and 256"), "{e}");
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

    /// Reading a v6 fragment chain is implemented (Task 6) and checked
    /// byte-for-byte against the engine on four committed fixtures; **writing
    /// one is not**, and [`rewrite_fragment_in_place`] still refuses it. The
    /// reason is no longer "there is nothing to check an implementation
    /// against" -- that was true when this test was written and is not now --
    /// but that a v6 write needs the allocation-table maintenance the read
    /// plan puts deliberately out of scope. `Block::writable` refuses every
    /// v6 write upstream of here for the same reason; this is the same
    /// refusal at the layer that would do the damage.
    #[test]
    fn a_btrieve_6_file_is_refused_rather_than_rewritten_by_the_version_5_rule() {
        let mut pages = Held(vec![blank(96), page(1, 96, &[(b"body".as_slice(), false)])]);
        let before = pages.0[1].clone();

        let e = rewrite_fragment_in_place(&mut pages, Version::V6, pointer(1, 0), b"body")
            .expect_err("the 0x8000 bit means something else in a v6 file");
        assert!(e.contains("V6") && e.contains("19045"), "{e}");
        assert_eq!(pages.0[1], before, "refused before the page was even asked for");
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
}
