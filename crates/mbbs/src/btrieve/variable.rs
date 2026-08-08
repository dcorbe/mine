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
/// like every other page pointer in the format.
const PAGE_NUMBER: usize = 0x00;

/// Where a variable page names the next variable page with room in it.
///
/// The **write side's** free list, and `0xffffffff` when there is none, which
/// is what all 3,467 of `WCCTEXT`'s variable pages read. Nothing here follows
/// it -- a read never needs to know where there is space -- but it is decoded
/// rather than skipped so that the four bytes are never mistaken for the
/// fragment count or for payload. `W32MKDE_decompiled.c:19267`
/// (`FUN_00420da0`) is the allocator that maintains it.
const FREE_CHAIN: usize = 0x06;

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

    /// Whether this pointer ends a chain rather than naming a fragment.
    fn is_end(self) -> bool {
        self.page == END_PAGE && self.fragment == END_FRAGMENT
    }
}

/// A variable page's header: everything before fragment 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    /// The page's own number. Checked against the number that was asked for,
    /// which is what makes [`Pointer::decode`]'s scrambled page number a
    /// reading rather than an assumption: a wrong decode lands on a page that
    /// disagrees about which page it is.
    number: u32,

    /// How many fragments the page holds.
    fragments: u16,

    /// The next variable page with free space, if there is one. See
    /// [`FREE_CHAIN`] -- read so that the four bytes are accounted for rather
    /// than mistaken for payload or for the fragment count, never followed.
    #[allow(dead_code, reason = "the write side's free list; decoded so the field is not payload")]
    free_chain: Option<u32>,
}

impl Header {
    /// Read a page's header, and refuse a page that cannot hold one.
    fn read(page: &[u8], asked: u32) -> Result<Self, String> {
        if page.len() < FIRST_FRAGMENT as usize {
            return Err(format!(
                "a {}-byte page, too short for a {FIRST_FRAGMENT}-byte header",
                page.len()
            ));
        }
        let number = super::pages::long(&page[PAGE_NUMBER..PAGE_NUMBER + 4]);
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
                NO_PAGE => None,
                page => Some(page),
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
    /// **A v5 rule.** `W32MKDE_decompiled.c:19045` gates it on the file
    /// version: below `0x600` this bit decides, and at or above it every
    /// fragment carries the pointer whatever the bit says. See
    /// [`Chain::follow`].
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
fn fragment(page: &[u8], which: u8, header: Header) -> Result<Fragment, String> {
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
        continued: entry.continued,
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
    /// # Only Btrieve 5
    ///
    /// `W32MKDE_decompiled.c:19045`:
    ///
    ///
    /// **In a v6 file every fragment carries the pointer**, whatever the
    /// `0x8000` bit says, and the chain ends on `0xffffffff` instead. Applying
    /// the v5 rule to a v6 file would take four bytes of pointer for four
    /// bytes of text on every fragment and then stop early. There is no v6
    /// variable-length file to check an implementation against -- `NEWMP001.VIR`
    /// is the corpus's only v6 file and holds fixed-length records -- so this
    /// refuses rather than guesses. [`Geometry::read`](super::Geometry::read)
    /// refuses the same file at open time; this is the guard that stands
    /// whether or not the caller did.
    ///
    /// # Errors
    ///
    /// If the file is v6, a page cannot be read, a page disagrees about which
    /// page it is, a fragment is not inside its page, a continued fragment is
    /// too short to hold the pointer it promises, or the chain revisits a
    /// fragment it has already been to. The last is in neither the engine nor
    /// MBBSEmu, both of which would follow such a chain until they ran out of
    /// memory; a file whose chain re-enters itself is corrupt rather than
    /// merely long, and the same check guards the free list in
    /// [`records`](super::records).
    pub(crate) fn follow(
        pages: &mut impl Pages,
        version: Version,
        first: Pointer,
        into: &mut Vec<u8>,
    ) -> Result<(), String> {
        if version != Version::V5 {
            return Err(format!(
                "{version:?} lays out its fragments differently -- every fragment carries a \
                 next-pointer and the 0x8000 entry bit does not mean what it means in a v5 \
                 file (W32MKDE_decompiled.c:19045) -- and no v6 variable-length file exists \
                 to check an implementation of that against"
            ));
        }

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
            let header = Header::read(page, at.page)?;
            let found = fragment(page, at.fragment, header)
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

    /// A v6 file's fragments carry a pointer unconditionally, so reading one
    /// by the v5 rule would eat four bytes of text per fragment and stop at
    /// the first one whose `0x8000` bit happened to be clear. Refused, because
    /// there is no v6 variable-length file to check an implementation against.
    #[test]
    fn a_btrieve_6_file_is_refused_rather_than_read_by_the_version_5_rule() {
        let mut pages = Held(vec![blank(512), page(1, 512, &[(b"body".as_slice(), false)])]);
        let mut out = Vec::new();
        let e = Chain::follow(&mut pages, Version::V6, pointer(1, 0), &mut out)
            .expect_err("the 0x8000 bit means something else in a v6 file");
        assert!(e.contains("V6") && e.contains("19045"), "{e}");
        assert!(out.is_empty(), "and nothing was appended before it refused");
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
        let header = Header::read(&bytes, 0x1234).expect("a header");
        assert_eq!(header.number, 0x1234);
        assert_eq!(header.fragments, 1);
        assert_eq!(header.free_chain, None, "no page after it has room");
    }
}
