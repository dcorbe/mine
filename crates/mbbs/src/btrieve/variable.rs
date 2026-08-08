//! Variable-length records: the fragment chain behind a fixed record.
//!
//! A Btrieve file whose records vary in length still keeps a fixed-length slot
//! per record in its data pages. What varies lives elsewhere, in *fragments*
//! on other pages, and the slot carries four bytes of pointer to the first of
//! them. The file control record says how to tell: bit 0 of the user flags at
//! `0x106`, corroborated by `0xff` at `0x38`, and the physical record length
//! exceeding the logical one by at least the four bytes that pointer needs.
//!
//! `WCCTEXT` is the one file of the eighteen MajorMUD ships that is like this,
//! and the whole of MajorMUD's character-creation, room and item prose is in
//! it. A reader that stopped at the 22-byte fixed part handed the module
//! `c cls\r\t\r` and then zeros.
//!
//! # A fragment page
//!
//! ```text
//!   0x00  +------------------------------+
//!         | page number, usage count     |
//!   0x0a  | fragment count (u16 LE)      |
//!   0x0c  | fragment 0's bytes           |  <- offsets start at 0x0c, never below
//!         | fragment 1's bytes           |
//!         |            ...               |
//!         |         (free space)         |
//!         | entry[n] ... entry[1] entry[0]|  <- the array, at the END, growing DOWN
//!   page  +------------------------------+
//! ```
//!
//! Entry `i` is the two bytes at `page - 2*(i+1)`. It holds where fragment `i`
//! *starts*; where it *ends* is the next valid entry's offset, which is why
//! there is always one more entry than there are fragments. `ff ff` marks an
//! entry whose fragment has been freed, and the scan for the end skips it.
//!
//! The high bit of an entry's second byte says the fragment begins with four
//! more bytes of pointer, to a fragment on another page -- the chain. Nothing
//! in `WCCTEXT` sets it; see [`Chain::follow`].
//!
//! # Ported, not derived
//!
//! This follows MBBSEmu's `MBBSEmu/Btrieve/BtrieveFile.cs:511-608` (MIT), which
//! is the only independent transcription of the layout there is. Every step of
//! it was re-checked by hand against `tmp/WCCTEXT.DAT` before it was written
//! here, and what that file can and cannot witness is recorded at each site.

use std::collections::HashSet;

/// Where a page says how many fragments it holds.
const FRAGMENT_COUNT: usize = 0x0a;

/// The lowest offset a fragment can start at: straight after the page header
/// and the fragment count. An offset below this is pointing into the header,
/// which no valid file does.
const FIRST_FRAGMENT: u32 = 0x0c;

/// The entry that marks a slot whose fragment is gone.
const UNUSED: u32 = 0xffff;

/// The page number that ends a chain, with [`END_FRAGMENT`].
const END_PAGE: u32 = 0x00ff_ffff;

/// The fragment index that ends a chain, with [`END_PAGE`].
const END_FRAGMENT: u8 = 0xff;

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
    /// record.
    ///
    /// # This byte order is **not** established by anything MajorMUD ships
    ///
    /// The reading below is MBBSEmu's
    /// (`BtrieveFile.cs:606`): a 24-bit page number scrambled as
    /// `[high][low][mid]`, with the fragment index in the fourth byte.
    ///
    /// An independent reading of the same four bytes exists -- `[fragment]
    /// [page number, 16-bit little-endian][unused]`, fragment *first* -- and
    /// **the corpus cannot tell the two apart.** Measured over all 3,467
    /// pointers in `tmp/WCCTEXT.DAT`: byte 0 is `0x00` in every one of them
    /// and so is byte 3. Both readings therefore produce the same page and the
    /// same fragment for every record this host has ever seen.
    ///
    /// They diverge on exactly two inputs, neither of which occurs here:
    ///
    /// - a page number above `0xffff`, where MBBSEmu's byte 0 is the high
    ///   eight bits and the other reading would call it a fragment index;
    /// - a non-zero fragment index, which MBBSEmu reads from byte 3 and the
    ///   other from byte 0.
    ///
    /// A file with either would separate them. MBBSEmu's is taken because it
    /// is a working implementation validated against real Btrieve files this
    /// project does not have, and because a 24-bit scrambled page number is
    /// what Btrieve uses for record pointers elsewhere. **It is a choice, not
    /// a measurement**, and this is the comment that says so.
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

/// One entry of a page's fragment array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// Where in the page the fragment starts, or [`UNUSED`].
    offset: u32,

    /// Whether the fragment starts with four bytes of pointer to the next one.
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

/// Find fragment `which` in `page`.
///
/// The length is *derived*, not stored: it runs to wherever the next fragment
/// starts. The scan for that neighbour goes on past freed slots, and runs to
/// `count` **inclusive** because the entry one past the last fragment is the
/// one that says where the last fragment ends.
///
/// # Errors
///
/// If the entry, or the fragment it names, is not inside the page: an offset
/// below [`FIRST_FRAGMENT`], a fragment running into the fragment array, or a
/// scan that reaches the end of the array without finding a neighbour. All
/// three mean the page is not what it claims to be, and reading on would hand
/// a module bytes out of the middle of something else.
fn fragment(page: &[u8], which: u8, count: u16) -> Result<Fragment, String> {
    let len = page.len() as u32;
    let entry_at = |i: u32| -> Result<usize, String> {
        let back = 2 * (i + 1);
        len.checked_sub(back)
            .map(|at| at as usize)
            .ok_or_else(|| format!("fragment {i}'s entry is before the start of a {len}-byte page"))
    };

    let which = u32::from(which);
    let at = entry_at(which)?;
    let entry = Entry::decode(&page[at..at + 2]);
    if entry.offset == UNUSED {
        return Err(format!("fragment {which} of a page holding {count} is a freed slot"));
    }

    // The neighbour that ends this fragment. `count` inclusive: the array has
    // one more entry than the page has fragments, and it is that last entry
    // that marks the end of the last fragment.
    let mut end = None;
    for i in which + 1..=u32::from(count) {
        let next = Entry::decode(&page[entry_at(i)?..][..2]);
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
    /// # Errors
    ///
    /// If a page cannot be read, a fragment is not inside its page, a
    /// continued fragment is too short to hold the pointer it promises, or the
    /// chain revisits a fragment it has already been to. The last is not in
    /// MBBSEmu, which would follow such a chain until it ran out of memory; a
    /// file whose chain re-enters itself is corrupt rather than merely long,
    /// and the same check guards the free list in
    /// [`records::free_list`](super::records).
    pub(crate) fn follow(
        pages: &mut impl Pages,
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
            if page.len() < FRAGMENT_COUNT + 2 {
                return Err(format!("page {} is too short to hold a fragment count", at.page));
            }
            let count = u16::from_le_bytes([page[FRAGMENT_COUNT], page[FRAGMENT_COUNT + 1]]);
            let found = fragment(page, at.fragment, count)
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
    /// is: bodies from `0x0c` upward, the entry array from the end downward,
    /// and one entry past the last fragment to mark where it ends.
    ///
    /// `continued` is the high bit of an entry's second byte.
    fn page(len: usize, fragments: &[(&[u8], bool)]) -> Vec<u8> {
        let mut out = vec![0u8; len];
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
        Chain::follow(pages, first, &mut out)?;
        Ok(out)
    }

    /// The shape every one of `WCCTEXT`'s 3,467 records has, built by hand
    /// rather than read: a 2,048-byte page holding one fragment, its entry
    /// `0c 00` and the entry past it `dc 07` -- 12 to 2,012, 2,000 bytes.
    ///
    /// Measured off `tmp/WCCTEXT.DAT`, where every variable page is byte-for-byte
    /// this shape, but the bytes here are this test's own.
    #[test]
    fn a_single_fragment_is_the_whole_body() {
        let body: Vec<u8> = (0..2000u32).map(|n| (n % 251) as u8).collect();
        let mut pages = Held(vec![vec![0; 2048], vec![0; 2048], page(2048, &[(&body, false)])]);

        // The entries this fixture builds are the ones the real file holds.
        assert_eq!(&pages.0[2][2046..2048], &[0x0c, 0x00], "entry 0 is offset 12");
        assert_eq!(&pages.0[2][2044..2046], &[0xdc, 0x07], "and the end is 2,012");

        assert_eq!(follow(&mut pages, pointer(2, 0)).expect("follows"), body);
    }

    /// **Synthetic.** No record in `tmp/WCCTEXT.DAT` sets the continuation
    /// bit -- all 3,467 chains are one fragment long -- so this path has no
    /// real input anywhere in the corpus and this hand-built pair of pages is
    /// the only thing that exercises it.
    #[test]
    fn a_continued_fragment_leads_to_the_next_page_and_its_pointer_is_not_data() {
        let mut head = vec![0u8; POINTER];
        head.copy_from_slice(&[0x00, 0x03, 0x00, 0x01]); // page 3, fragment 1
        head.extend_from_slice(b"first half, ");

        let mut pages = Held(vec![
            vec![0; 512],
            vec![0; 512],
            page(512, &[(&head, true)]),
            page(512, &[(b"not this one".as_slice(), false), (b"second half".as_slice(), false)]),
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
        let mut bytes = page(512, &[(b"one".as_slice(), false), (b"two".as_slice(), false)]);
        // Free fragment 1 -- the entry, not the bytes.
        let entry = 512 - 2 * 2;
        bytes[entry] = 0xff;
        bytes[entry + 1] = 0xff;
        let mut pages = Held(vec![vec![0; 512], bytes]);

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

    #[test]
    fn a_fragment_reaching_into_the_fragment_array_is_refused() {
        let mut bytes = page(512, &[(b"body".as_slice(), false)]);
        // Move the end marker past the array: 0x01fe = 510, and the array of
        // two entries starts at 508.
        bytes[512 - 4] = 0xfe;
        bytes[512 - 3] = 0x01;
        let mut pages = Held(vec![vec![0; 512], bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("that leaves the page");
        assert!(e.contains("must lie within"), "{e}");
    }

    #[test]
    fn a_fragment_starting_inside_the_page_header_is_refused() {
        let mut bytes = page(512, &[(b"body".as_slice(), false)]);
        bytes[512 - 2] = 0x02; // offset 2, inside the header
        let mut pages = Held(vec![vec![0; 512], bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("that is the header");
        assert!(e.contains("must lie within"), "{e}");
    }

    #[test]
    fn a_page_whose_array_ends_before_a_neighbour_is_found_is_refused() {
        // One fragment claimed, and its own entry freed as well as the one
        // that should end it -- so the scan runs out.
        let mut bytes = page(512, &[(b"body".as_slice(), false)]);
        bytes[512 - 4] = 0xff;
        bytes[512 - 3] = 0xff;
        let mut pages = Held(vec![vec![0; 512], bytes]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("nothing ends it");
        assert!(e.contains("no entry after it"), "{e}");
    }

    #[test]
    fn a_named_fragment_that_is_a_freed_slot_is_refused() {
        let mut bytes = page(512, &[(b"one".as_slice(), false), (b"two".as_slice(), false)]);
        let entry = 512 - 2 * 2;
        bytes[entry] = 0xff;
        bytes[entry + 1] = 0xff;
        let mut pages = Held(vec![vec![0; 512], bytes]);

        let e = follow(&mut pages, pointer(1, 1)).expect_err("fragment 1 is gone");
        assert!(e.contains("freed slot"), "{e}");
    }

    /// **Synthetic**, and not a case MBBSEmu handles at all: it would follow
    /// this until it ran out of memory. A chain is a linked list in a file a
    /// module can corrupt, so it gets the same cycle check the free list has.
    #[test]
    fn a_chain_that_returns_to_itself_is_refused_rather_than_followed_forever() {
        let head: Vec<u8> = [0x00, 0x01, 0x00, 0x00]
            .into_iter()
            .chain(b"round and round".iter().copied())
            .collect();
        let mut pages = Held(vec![vec![0; 512], page(512, &[(&head, true)])]);

        let e = follow(&mut pages, pointer(1, 0)).expect_err("it points at itself");
        assert!(e.contains("returns to fragment"), "{e}");
    }

    #[test]
    fn a_continued_fragment_too_short_to_hold_its_pointer_is_refused() {
        let mut pages = Held(vec![vec![0; 512], page(512, &[(b"ab".as_slice(), true)])]);
        let e = follow(&mut pages, pointer(1, 0)).expect_err("two bytes is not four");
        assert!(e.contains("too short for a 4-byte pointer"), "{e}");
    }

    /// The scrambled order, spelled out on a number where all three bytes
    /// differ. `0x123456` is byte 0 = `0x12`, byte 1 = `0x56`, byte 2 = `0x34`
    /// -- high, low, mid -- and the fragment index is the fourth byte.
    ///
    /// **The corpus cannot confirm this**; see [`Pointer::decode`]. This test
    /// pins the reading the host chose, not a measurement of Btrieve.
    #[test]
    fn the_pointers_page_number_is_high_low_mid_and_its_fragment_is_last() {
        let decoded = Pointer::decode([0x12, 0x56, 0x34, 0x07]);
        assert_eq!(decoded.page, 0x0012_3456);
        assert_eq!(decoded.fragment, 7);
        assert!(!decoded.is_end());
        assert!(Pointer::decode([0xff, 0xff, 0xff, 0xff]).is_end());
    }
}
