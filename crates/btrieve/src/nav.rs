//! A lazy cursor over a v6 key's on-disk B-tree.
//!
//! [`pages::walk_with`] is the reference: it reads a whole tree into one
//! [`pages::Walk`], in order. This is its lazy equivalent -- an explicit
//! stack of `(page, entry index)` frames, one page fetched at a time through
//! a caller-supplied cache and logical-to-physical resolver, so a single
//! [`TreeCursor::seek`] costs a root-to-leaf descent rather than the whole
//! tree.
//!
//! # This is a plain B-tree, not a B+-tree
//!
//! An interior node's own entries are real records, not just separators --
//! `docs/2026-08-25-btree-split-oracle.md` measured that a promoted key is
//! *removed* from the child it split out of and lives only in the parent.
//! So in-order traversal has to emit interior entries between the subtrees
//! either side of them, exactly as [`pages::walk_with`] already does; a
//! cursor that only ever looked at leaves would silently drop every
//! promoted key.
//!
//! # Duplicate chains are walked, and re-sorted to match `Records`
//!
//! A duplicate-permitting key's tree entry names only the two *ends* of its
//! value's chain (`head`, `tail`); the records between them are reachable
//! only by following the `[prev][next]` links [`pages::chain_pair`] reads
//! out of each record's own slot. `records.rs`'s own `reindex` breaks ties
//! between same-valued records by **physical position**, not by that
//! insertion-order chain -- a deliberate, documented difference from the
//! file's own index. So [`TreeCursor`] discovers a group's membership by
//! walking the chain (there is no other way to enumerate it), then sorts the
//! result by position before stepping through it, to agree with
//! [`super::records::Records::ordered`] byte for byte rather than with the
//! chain's own insertion order.
//!
//! # Only `next()`-after-`seek()` and `prev()`-after-`seek()` are proven
//!
//! [`TreeCursor`] commits to one direction on the call that first produces a
//! position ([`Bias::Lowest`]/[`Bias::Equal`]/[`Bias::AtLeast`]/
//! [`Bias::Greater`] prime it for [`TreeCursor::next`];
//! [`Bias::Highest`]/[`Bias::AtMost`]/[`Bias::Less`] prime it for
//! [`TreeCursor::prev`]) and the differential test only ever calls one of
//! the two after a given `seek`. Calling the *other* method afterward is not
//! rejected, but its correctness has not been measured -- a future caller
//! that needs a true bidirectional cursor (a keyed `Get` followed by a `Get
//! Previous`) should treat that combination as unproven until it is.
//!
//! Not yet reachable from `Block::query`/`Block::get` -- that cutover is a
//! later task. This module and [`super::Block::nav_root`] exist to be
//! provable on their own first.

use std::cell::RefCell;

use super::cache::PageCache;
use super::pages::{self, IndexPage, Layout, Shape};

/// The seven positioning rules `ops::Op`'s Query/Get family both use, minus
/// `Next`/`Previous` -- those are [`TreeCursor::next`]/[`TreeCursor::prev`]
/// here instead of a bias, because they act on an already-positioned cursor
/// rather than a fresh search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Greater`/`AtLeast`/`Less`/`AtMost` are exercised by hand (see this
// module's own doc comment on what is and is not differentially proven),
// not by the corpus test -- Task 7's cutover is what gives them a caller.
#[allow(dead_code)]
pub(crate) enum Bias {
    Equal,
    Greater,
    AtLeast,
    Less,
    AtMost,
    Lowest,
    Highest,
}

/// What [`TreeCursor`] needs to walk a duplicate-permitting key's in-record
/// chain -- `None` on a [`TreeCursor`] built for a key that forbids
/// duplicates, since [`Key::chain`](super::keys::Key::chain) is `None` too
/// and there is no chain to walk.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Duplicates {
    /// This file's page geometry, for turning a record `position` into a
    /// (logical page, slot) pair ([`Layout::slot_of`]).
    pub(crate) layout: Layout,
    /// Byte offset of the `[prev][next]` pair within a record's own
    /// physical slot -- [`Key::chain`](super::keys::Key::chain), which
    /// [`pages::chain_pair`] already measures from the slot's first byte.
    pub(crate) offset: usize,
}

/// The stored root for key definition `keynum`, straight off the file
/// control record. `None` when there is no tree yet: a virgin file, or an
/// `ANOSEG` continuation definition, both read a bare zero at
/// [`pages::fcr::KEY_ROOT`] (`format::fcr`'s own module doc).
///
/// Returned **still decorated** -- top byte `0x80|keynum`, low 24 bits the
/// logical root page ([`pages::fcr::ROOT_PAGE`]'s own doc comment is the
/// authority this mirrors: the code `Block::v6_reindex` uses to *write* this
/// same field reads it back the identical way, masking only once the value
/// is actually used as a logical id). Every child pointer inside the tree
/// ([`IndexPage::leftmost`]/[`IndexPage::rightmost`]/each entry's own child)
/// is stored the same decorated way, so [`TreeCursor`] applies one mask to
/// all of them rather than treating the root as a special case.
///
/// # Errors
///
/// If `fcr` is too short to hold definition `keynum`'s root field, or the
/// stored value does not carry the v6 marker bit (`0x8000_0000`) every v6
/// key root measured so far has set.
pub(crate) fn root_of(fcr: &[u8], keynum: usize) -> Result<Option<u32>, String> {
    let at = pages::fcr::KEYS + keynum * pages::fcr::KEY_WIDTH + pages::fcr::KEY_ROOT;
    let end = at + 4;
    if end > fcr.len() {
        return Err(format!(
            "key {keynum}'s root field would occupy {at:#x}..{end:#x}, past the \
             {}-byte file control record",
            fcr.len()
        ));
    }
    let raw = pages::long(&fcr[at..end]);
    if raw == 0 {
        return Ok(None);
    }
    if raw & 0x8000_0000 == 0 {
        return Err(format!(
            "key {keynum}'s root {raw:#010x} does not carry the v6 marker bit \
             (0x80000000) every v6 key root measured so far has set"
        ));
    }
    Ok(Some(raw))
}

/// One page on the descent path, and how far a traversal has got through it.
///
/// `at`'s meaning depends on which direction last touched this frame: a
/// forward step ([`TreeCursor::advance_entry_forward`]) reads it as
/// "entries `[0, at)` already emitted"; a backward step
/// ([`TreeCursor::advance_entry_backward`]) reads it as "entries `[at,
/// len)` already emitted". A single [`TreeCursor`] only ever uses one
/// direction's convention on frames it built itself -- see this module's
/// own doc comment.
struct Frame {
    page: IndexPage,
    at: usize,
}

/// One tree entry's duplicate-chain membership, discovered and re-sorted by
/// [`TreeCursor::chain_members`], with a cursor into it.
struct Group {
    /// Record positions, ascending -- matching `Records`'s own tie-break.
    members: Vec<u32>,
    /// Index of the member most recently returned.
    at: usize,
}

/// Child slot `k` of a page with `n` entries, `k` in `0..=n`: `leftmost` at
/// `k == 0`, `rightmost` at `k == n`, and entry `k - 1`'s own stored child
/// field everywhere between.
///
/// **`entries[n - 1].2` is not child slot `n`.** [`IndexPage::entries`]'s own
/// doc comment says the last entry's child field is a placeholder nothing
/// reads; the real subtree after the last entry is `rightmost`, stored
/// separately. A first version of the two binary searches below read
/// `entries[idx - 1].2` unconditionally whenever `idx > 0`, which reads that
/// placeholder (`0`) instead of `rightmost` the moment a search lands past
/// every entry on a page -- caught immediately by the differential test
/// (`ELWWDMON.DAT` key 0: "a B-tree pointer reads 0x00000000"), which is
/// exactly the corruption-looking symptom a wrong child slot produces.
fn child_slot(page: &IndexPage, k: usize) -> u32 {
    if k == 0 {
        page.leftmost
    } else if k == page.entries.len() {
        page.rightmost
    } else {
        page.entries[k - 1].2
    }
}

/// Fetch, tag-check and decode the page a raw (still-tagged) pointer names.
///
/// Two checks, both refusals rather than silent decoding: the pointer's own
/// top byte must be this key's tag (a child cannot belong to a different
/// key's tree -- `read.rs`'s `v6_enter_child` makes the identical check for
/// the eager reader this mirrors), and the *page's own header tag*, once
/// fetched, must match too. The second is what catches a page this cursor
/// should never land on at all: unclaimed (marker `0x0000`) or
/// merge-retired (marker `0x4500`, `docs/2026-08-25-btree-split-oracle.md`)
/// -- either reads back as *some* tag other than this key's own, so the one
/// comparison below refuses both by construction rather than needing a
/// marker-specific case for each.
fn fetch_page(
    cache: &RefCell<PageCache>,
    resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
    shape: Shape,
    key_tag: u8,
    raw_pointer: u32,
) -> Result<IndexPage, String> {
    let top = (raw_pointer >> 24) as u8;
    if top != key_tag {
        return Err(format!(
            "a B-tree pointer reads {raw_pointer:#010x}, whose top byte {top:#04x} is \
             not this key's own tag {key_tag:#04x} -- a page cannot belong to a \
             different key's tree"
        ));
    }
    let logical = raw_pointer & pages::fcr::ROOT_PAGE;
    let physical = resolve(logical)?;
    let bytes = {
        let mut guard = cache.borrow_mut();
        guard.page(physical)?.to_vec()
    };
    if bytes.len() < 2 {
        return Err(format!(
            "physical page {physical} is {} bytes, too short to hold a page header",
            bytes.len()
        ));
    }
    let actual_tag = u16::from_le_bytes([bytes[0], bytes[1]]);
    let expected_tag = u16::from(key_tag) << 8;
    if actual_tag != expected_tag {
        return Err(format!(
            "logical page {logical} (physical {physical}) is claimed by this key's \
             tree, but its own header tag reads {actual_tag:#06x}, not \
             {expected_tag:#06x} -- refusing rather than decoding a page that is \
             unclaimed (marker 0x0000), merge-retired (marker 0x4500), or claimed \
             by some other key"
        ));
    }
    pages::decode_index_page(&bytes, shape)
        .map_err(|e| format!("logical page {logical} (physical {physical}): {e}"))
}

/// A lazy in-order cursor over one key's v6 B-tree. See this module's own
/// doc comment for the shape of the tree it walks and the limits of what is
/// proven about it.
pub(crate) struct TreeCursor {
    /// This tree's own tag, read once off the root's top byte at
    /// [`Self::seek`] and checked against every page reached from there --
    /// see [`fetch_page`].
    key_tag: u8,
    stack: Vec<Frame>,
    /// A child pointer (still tagged, not yet resolved) to descend into on
    /// the next step -- leftmost-first for a forward-primed cursor,
    /// rightmost-first for a backward-primed one.
    pending: Option<u32>,
    group: Option<Group>,
    dup: Option<Duplicates>,
}

impl TreeCursor {
    /// Position a new cursor on `root`'s tree, per `bias`.
    ///
    /// `target` is the key value `Equal`/`Greater`/`AtLeast`/`Less`/`AtMost`
    /// compare against (ignored, and may be `None`, for `Lowest`/`Highest`).
    /// `dup` is `None` for a key that forbids duplicates. `cmp(a, b)` orders
    /// two extracted key values -- an entry's own bytes as `a`, `target` as
    /// `b` -- and must agree with the comparator the tree was actually built
    /// with ([`super::keys::Key::compare_extracted`] is that comparator for
    /// a real key; a plain `Ord::cmp` on the bytes is wrong the moment a key
    /// collates through an alternate sequence or a descending/numeric
    /// segment, which is not a hypothetical -- `ELWWDOBJ.DAT` key 0 in this
    /// repository's own corpus is exactly such a key, measured directly by
    /// this module's differential test).
    ///
    /// Returns the cursor alongside the record position found, or `None` if
    /// nothing satisfies `bias` (an empty tree for `Lowest`/`Highest`; no
    /// entry that qualifies, otherwise).
    ///
    /// # Errors
    ///
    /// If `target` is required (every bias but `Lowest`/`Highest`) and
    /// absent, or if the descent hits a page [`fetch_page`] refuses.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seek(
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        root: u32,
        shape: Shape,
        target: Option<&[u8]>,
        bias: Bias,
        dup: Option<Duplicates>,
        cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
    ) -> Result<(Self, Option<u32>), String> {
        let mut cursor = Self {
            key_tag: (root >> 24) as u8,
            stack: Vec::new(),
            pending: Some(root),
            group: None,
            dup,
        };
        let position = match bias {
            Bias::Lowest => cursor.next(cache, resolve, shape)?,
            Bias::Highest => cursor.prev(cache, resolve, shape)?,
            Bias::Equal | Bias::AtLeast | Bias::Greater => {
                let target = target
                    .ok_or_else(|| "Equal/AtLeast/Greater need a target key value".to_owned())?;
                cursor.seek_lower_bound(cache, resolve, shape, target, cmp)?;
                let found = cursor.advance_entry_forward(cache, resolve, shape)?;
                cursor.settle_forward_bound(cache, resolve, shape, bias, target, cmp, found)?
            }
            Bias::Less | Bias::AtMost => {
                let target =
                    target.ok_or_else(|| "Less/AtMost need a target key value".to_owned())?;
                let inclusive = matches!(bias, Bias::AtMost);
                cursor.seek_upper_bound(cache, resolve, shape, target, inclusive, cmp)?;
                match cursor.advance_entry_backward(cache, resolve, shape)? {
                    Some((_key, head, tail)) => {
                        cursor.begin_group_backward(cache, resolve, head, tail)?
                    }
                    None => None,
                }
            }
        };
        Ok((cursor, position))
    }

    /// The `Equal`/`AtLeast`/`Greater` half of [`Self::seek`]'s bias switch,
    /// pulled out only because the three share the same lower-bound search
    /// and disagree solely in what they do with its answer.
    #[allow(clippy::too_many_arguments)]
    fn settle_forward_bound(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
        bias: Bias,
        target: &[u8],
        cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
        found: Option<(Vec<u8>, u32, u32)>,
    ) -> Result<Option<u32>, String> {
        match bias {
            Bias::Equal => match found {
                Some((key, head, tail)) if cmp(&key, target) == std::cmp::Ordering::Equal => {
                    self.begin_group_forward(cache, resolve, head, tail)
                }
                _ => Ok(None),
            },
            Bias::AtLeast => match found {
                Some((_key, head, tail)) => self.begin_group_forward(cache, resolve, head, tail),
                None => Ok(None),
            },
            Bias::Greater => match found {
                // An exact match is the whole group `Greater` must skip --
                // duplicates included -- so the answer is whatever entry
                // comes after it, not a member of this one.
                Some((key, _, _)) if cmp(&key, target) == std::cmp::Ordering::Equal => {
                    match self.advance_entry_forward(cache, resolve, shape)? {
                        Some((_key2, head2, tail2)) => {
                            self.begin_group_forward(cache, resolve, head2, tail2)
                        }
                        None => Ok(None),
                    }
                }
                Some((_key, head, tail)) => self.begin_group_forward(cache, resolve, head, tail),
                None => Ok(None),
            },
            Bias::Less | Bias::AtMost | Bias::Lowest | Bias::Highest => {
                unreachable!("Self::seek only calls this for Equal/AtLeast/Greater")
            }
        }
    }

    /// The next record in this key's order, or `None` past the last one.
    ///
    /// # Errors
    ///
    /// If continuing the descent hits a page [`fetch_page`] refuses, or a
    /// duplicate chain does not check out (see [`Self::chain_members`]).
    pub(crate) fn next(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<u32>, String> {
        if let Some(group) = &mut self.group {
            if group.at + 1 < group.members.len() {
                group.at += 1;
                return Ok(Some(group.members[group.at]));
            }
            self.group = None;
        }
        match self.advance_entry_forward(cache, resolve, shape)? {
            Some((_key, head, tail)) => self.begin_group_forward(cache, resolve, head, tail),
            None => Ok(None),
        }
    }

    /// The previous record in this key's order, or `None` before the first.
    ///
    /// # Errors
    ///
    /// See [`Self::next`].
    pub(crate) fn prev(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<u32>, String> {
        if let Some(group) = &mut self.group {
            if group.at > 0 {
                group.at -= 1;
                return Ok(Some(group.members[group.at]));
            }
            self.group = None;
        }
        match self.advance_entry_backward(cache, resolve, shape)? {
            Some((_key, head, tail)) => self.begin_group_backward(cache, resolve, head, tail),
            None => Ok(None),
        }
    }

    /// One step of [`pages::walk_with`]'s own loop, forward, unrolled so it
    /// can return after a single entry instead of collecting every one.
    ///
    /// Resolves any pending leftmost descent (pushing a frame per page,
    /// `at: 0`), then either pops a frame whose entries are exhausted or
    /// emits its current entry and arranges the next pending descent (the
    /// entry's own child, or `rightmost` past the last entry) -- the
    /// identical shape `pages::walk_with`'s loop body has, just returning
    /// after one entry instead of looping to collect them all.
    fn advance_entry_forward(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<(Vec<u8>, u32, u32)>, String> {
        loop {
            while let Some(raw) = self.pending.take() {
                let page = fetch_page(cache, resolve, shape, self.key_tag, raw)?;
                let leftmost = (!page.leaf()).then_some(page.leftmost);
                self.stack.push(Frame { page, at: 0 });
                self.pending = leftmost;
            }
            let Some(frame) = self.stack.last_mut() else {
                return Ok(None);
            };
            let len = frame.page.entries.len();
            if frame.at == len {
                self.stack.pop();
                continue;
            }
            let (key, head, child) = frame.page.entries[frame.at].clone();
            let tail = frame.page.tails.get(frame.at).copied().unwrap_or(head);
            let leaf = frame.page.leaf();
            let rightmost = frame.page.rightmost;
            frame.at += 1;
            let new_at = frame.at;
            if !leaf {
                self.pending = Some(if new_at == len { rightmost } else { child });
            }
            return Ok(Some((key, head, tail)));
        }
    }

    /// [`Self::advance_entry_forward`]'s mirror: descend rightmost instead
    /// of leftmost, and read each frame's entries back to front.
    fn advance_entry_backward(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<(Vec<u8>, u32, u32)>, String> {
        loop {
            while let Some(raw) = self.pending.take() {
                let page = fetch_page(cache, resolve, shape, self.key_tag, raw)?;
                let rightmost = (!page.leaf()).then_some(page.rightmost);
                let at = page.entries.len();
                self.stack.push(Frame { page, at });
                self.pending = rightmost;
            }
            let Some(frame) = self.stack.last_mut() else {
                return Ok(None);
            };
            if frame.at == 0 {
                self.stack.pop();
                continue;
            }
            frame.at -= 1;
            let idx = frame.at;
            let (key, head, _) = frame.page.entries[idx].clone();
            let tail = frame.page.tails.get(idx).copied().unwrap_or(head);
            let leaf = frame.page.leaf();
            let leftmost = frame.page.leftmost;
            if !leaf {
                self.pending =
                    Some(if idx == 0 { leftmost } else { frame.page.entries[idx - 1].2 });
            }
            return Ok(Some((key, head, tail)));
        }
    }

    /// Build the descent path to the smallest entry not less than `target`
    /// (a lower bound), leaving `self.stack`/`self.pending` such that
    /// [`Self::advance_entry_forward`] produces it next -- or produces
    /// `None` if every entry in the tree is less than `target`.
    ///
    /// One binary search per page (`partition_point`, matching
    /// `Records::seek`'s own "first record not before value" rule), and an
    /// early stop the instant a page's own entry equals `target` outright:
    /// a value appears exactly once in the whole tree, so nothing in the
    /// subtree strictly between it and its neighbour could also match, and
    /// descending there would only cost a page fetch for no reason.
    fn seek_lower_bound(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
        target: &[u8],
        cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
    ) -> Result<(), String> {
        use std::cmp::Ordering;
        loop {
            let Some(raw) = self.pending.take() else {
                return Ok(());
            };
            let page = fetch_page(cache, resolve, shape, self.key_tag, raw)?;
            let idx = page.entries.partition_point(|e| cmp(&e.0, target) == Ordering::Less);
            let exact = idx < page.entries.len() && cmp(&page.entries[idx].0, target) == Ordering::Equal;
            let leaf = page.leaf();
            let child_before = child_slot(&page, idx);
            self.stack.push(Frame { page, at: idx });
            if exact || leaf {
                self.pending = None;
                return Ok(());
            }
            self.pending = Some(child_before);
        }
    }

    /// [`Self::seek_lower_bound`]'s mirror for `Less`/`AtMost`: build the
    /// path to the largest entry that is `<= target` (`inclusive`) or `<
    /// target`, ready for [`Self::advance_entry_backward`] to produce it.
    ///
    /// No exact-match short circuit here: unlike the forward search, both
    /// callers want the search to keep going right up to the leaf level
    /// regardless (there is nothing past an exact match on this side worth
    /// skipping), so this stays the plain, unconditional descent.
    fn seek_upper_bound(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
        target: &[u8],
        inclusive: bool,
        cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
    ) -> Result<(), String> {
        use std::cmp::Ordering;
        loop {
            let Some(raw) = self.pending.take() else {
                return Ok(());
            };
            let page = fetch_page(cache, resolve, shape, self.key_tag, raw)?;
            let idx = if inclusive {
                page.entries.partition_point(|e| cmp(&e.0, target) != Ordering::Greater)
            } else {
                page.entries.partition_point(|e| cmp(&e.0, target) == Ordering::Less)
            };
            let leaf = page.leaf();
            let child_before = child_slot(&page, idx);
            self.stack.push(Frame { page, at: idx });
            if leaf {
                self.pending = None;
                return Ok(());
            }
            self.pending = Some(child_before);
        }
    }

    /// Discover a tree entry's full duplicate-chain membership and sort it
    /// by position, matching `Records`'s own tie-break
    /// (`records.rs::reindex`'s doc comment: ties broken by physical
    /// position, not by the chain's insertion order).
    ///
    /// `head == tail` (always true for a key that forbids duplicates, and
    /// for a duplicate-permitting key's value that only one record carries)
    /// needs no chain walk at all. Otherwise this reads each member's own
    /// slot to find the next link, bounded so a corrupt or cyclic chain
    /// refuses rather than loops forever.
    ///
    /// # Errors
    ///
    /// If `head != tail` but this cursor has no [`Duplicates`] to walk with,
    /// a position does not land on a slot boundary, resolving or reading a
    /// member's page fails, or the chain runs `1,000,000` links without
    /// reaching `tail`.
    fn chain_members(
        &self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        head: u32,
        tail: u32,
    ) -> Result<Vec<u32>, String> {
        if head == tail {
            return Ok(vec![head]);
        }
        let Some(dup) = &self.dup else {
            return Err(format!(
                "entry head {head} and tail {tail} differ, but this cursor was built \
                 for a key that forbids duplicates -- a unique key's entry should \
                 never have two different ends"
            ));
        };
        const MAX_CHAIN: usize = 1_000_000;
        let mut members = Vec::new();
        let mut at = head;
        loop {
            members.push(at);
            if at == tail {
                break;
            }
            if members.len() > MAX_CHAIN {
                return Err(format!(
                    "the duplicate chain from head {head} did not reach its stored \
                     tail {tail} within {MAX_CHAIN} records -- refusing rather than \
                     looping forever"
                ));
            }
            let (logical, slot) = dup.layout.slot_of(at).ok_or_else(|| {
                format!("duplicate chain: record position {at} is not on a slot boundary")
            })?;
            let physical = resolve(logical)?;
            let bytes = {
                let mut guard = cache.borrow_mut();
                guard.page(physical)?.to_vec()
            };
            let slot_start = dup.layout.position(0, slot) as usize;
            let slot_bytes = bytes
                .get(slot_start..)
                .ok_or_else(|| format!("record {at}'s slot starts past the end of its own page"))?;
            let [_, next] = pages::chain_pair(slot_bytes, dup.offset).ok_or_else(|| {
                format!(
                    "record {at}'s slot is too short to hold a duplicate-chain link \
                     at offset {}",
                    dup.offset
                )
            })?;
            if next == pages::NOWHERE {
                return Err(format!(
                    "the duplicate chain from head {head} ended at record {at} \
                     without reaching its stored tail {tail}"
                ));
            }
            at = next;
        }
        members.sort_unstable();
        Ok(members)
    }

    fn begin_group_forward(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        head: u32,
        tail: u32,
    ) -> Result<Option<u32>, String> {
        let members = self.chain_members(cache, resolve, head, tail)?;
        let first = members.first().copied();
        self.group = Some(Group { members, at: 0 });
        Ok(first)
    }

    fn begin_group_backward(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        head: u32,
        tail: u32,
    ) -> Result<Option<u32>, String> {
        let members = self.chain_members(cache, resolve, head, tail)?;
        let at = members.len().saturating_sub(1);
        let last = members.get(at).copied();
        self.group = Some(Group { members, at });
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    //! The differential test the task brief calls `tests/nav_differential.rs`.
    //!
    //! It lives here, as a unit test, rather than under `tests/`, because
    //! `TreeCursor`/`Bias`/`root_of` are `pub(crate)` and `nav` itself is a
    //! private module (`lib.rs`'s `mod nav;`) -- a genuine external
    //! integration-test crate under `tests/` cannot name either, regardless
    //! of what the items inside them are marked. `pages`/`keys`/`records`
    //! are the crate's own precedent for the alternative (making everything
    //! plain `pub`, so `tests/*.rs` can reach them) -- deliberately not
    //! followed here, since it would make this cursor's internals part of
    //! the crate's public surface a whole task before Task 7 wires it up.
    //! `Block::nav_root`, this module's one entry point from `lib.rs`, has
    //! the same visibility for the same reason.
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::keys::Key;
    use crate::records::Records;
    use crate::testing::{Flat, FlatHeap, FlatMem, FlatPtr};
    use crate::{Btrieve, Geometry, Version};

    /// Every v6 file worth differentially testing: whatever `corpus::walk`
    /// finds under `archive/` (absent in a fresh checkout) plus a fixed list
    /// of small, committed fixtures this repository keeps under version
    /// control -- present regardless, and the only guaranteed source of a
    /// duplicate-permitting key with more than one record sharing a value
    /// (`DUPKEY30.DAT`'s ten groups of three, `pages.rs`'s own module doc).
    fn v6_candidate_paths() -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = crate::corpus::walk().into_iter().map(|e| e.path).collect();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        for extra in [
            "tests/data/variable/V6DUP.DAT",
            "tests/data/variable/V6SHRINK.DAT",
            "tests/data/variable/V6VAR.DAT",
            "tests/data/variable/IDXPROBE.DAT",
            "tests/data/variable/WGSGEN2.VIR",
            "../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT",
            "../../tools/btrieve-oracle/fixtures/DUPKEY30SWAPPED.DAT",
            "../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT",
        ] {
            let path = manifest_dir.join(extra);
            if path.is_file() {
                paths.push(path);
            }
        }
        paths
    }

    /// Open `path` the way a real `opnbtv` would (`Btrieve::open`, so a v6
    /// file gets the same page cache [`Block::nav_root`] requires) and hand
    /// back the harness plus the block's own handle. `None` when the file
    /// is not v6, or [`Geometry::read`]/`Btrieve::open` itself refuses it --
    /// either is "not this task's problem", the same stance
    /// `roundtrip.rs`'s own corpus walk takes toward a file its own read
    /// side cannot yet describe.
    fn open_v6(path: &Path) -> Option<(Btrieve<Flat>, FlatPtr)> {
        let name = path.file_name()?.to_string_lossy().into_owned();
        let geometry = Geometry::read(&name, path).ok()?;
        if geometry.version != Version::V6 {
            return None;
        }
        let maxlen = geometry.reclen;
        let mut mem = FlatMem::new(usize::from(maxlen) + 8192);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let at = btrieve.open(&mut mem, &mut heap, &name, path, geometry, maxlen).ok()?;
        Some((btrieve, at))
    }

    /// For every v6 file this box has (`archive/` plus the committed
    /// fixtures), for every key with at least one record: enumerate
    /// positions through [`TreeCursor`] (`Lowest` + `next` until `None`,
    /// then `Highest` + `prev` until `None`) and through
    /// `Records::ordered`, and require the forward sequence equal and the
    /// backward sequence its reverse. Then, for every distinct value the key
    /// holds, `seek(Equal)` must land on the same record `Records::seek`
    /// finds.
    ///
    /// Duplicate-permitting keys are not special-cased: their tree entries
    /// group several records under one value, and both sequences above are
    /// per-*record*, so a cursor that silently collapsed a group to one
    /// position would already fail the length check -- confirmed separately
    /// by asserting this run actually saw at least one such group.
    #[test]
    fn tree_cursor_matches_records_over_the_v6_corpus() {
        let mut files_compared = 0usize;
        let mut keys_compared = 0usize;
        let mut records_compared = 0usize;
        let mut dup_group_hit = false;
        let mut dup_files = 0usize;

        for path in v6_candidate_paths() {
            let Some((btrieve, at)) = open_v6(&path) else { continue };
            let block = btrieve.block(at).expect("just opened");
            let keys: Vec<Key> = block.keys().to_vec();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let records = match Records::read(&name, &path, block.geometry(), &keys) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let mut file_had_dup = false;

            for key in &keys {
                let count = match records.ordered_len(key.number) {
                    Some(n) if n > 0 => n,
                    _ => continue,
                };

                let (root, shape, dup, cache, mut resolve) = match block
                    .nav_root(key.number)
                    .unwrap_or_else(|e| panic!("{name} key {}: nav_root: {e}", key.number))
                {
                    Some(bundle) => bundle,
                    None => panic!(
                        "{name} key {}: Records counts {count} records but nav_root found no \
                         tree at all",
                        key.number
                    ),
                };
                // The same comparator the tree was built with and
                // `Records`'s own order is sorted by -- not a raw byte
                // comparison, which disagrees with both the moment a key
                // collates through an alternate sequence (see
                // `Key::compare_extracted`'s own doc comment).
                let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);

                let expected: Vec<u32> = (0..count)
                    .map(|at| records.ordered(key.number, at).expect("in range").position)
                    .collect();

                // Forward: Lowest, then next() until exhausted.
                let (mut forward_cursor, first) = TreeCursor::seek(
                    cache,
                    &mut *resolve,
                    root,
                    shape,
                    None,
                    Bias::Lowest,
                    dup,
                    &cmp,
                )
                .unwrap_or_else(|e| panic!("{name} key {}: seek(Lowest): {e}", key.number));
                let mut forward = Vec::with_capacity(count);
                let mut pos = first;
                while let Some(p) = pos {
                    forward.push(p);
                    pos = forward_cursor
                        .next(cache, &mut *resolve, shape)
                        .unwrap_or_else(|e| panic!("{name} key {}: next: {e}", key.number));
                }
                assert_eq!(forward, expected, "{name} key {}: forward sequence", key.number);

                // Backward: Highest, then prev() until exhausted -- must be
                // the forward sequence reversed.
                let (mut backward_cursor, first_back) = TreeCursor::seek(
                    cache,
                    &mut *resolve,
                    root,
                    shape,
                    None,
                    Bias::Highest,
                    dup,
                    &cmp,
                )
                .unwrap_or_else(|e| panic!("{name} key {}: seek(Highest): {e}", key.number));
                let mut backward = Vec::with_capacity(count);
                let mut pos = first_back;
                while let Some(p) = pos {
                    backward.push(p);
                    pos = backward_cursor
                        .prev(cache, &mut *resolve, shape)
                        .unwrap_or_else(|e| panic!("{name} key {}: prev: {e}", key.number));
                }
                let mut reversed = expected.clone();
                reversed.reverse();
                assert_eq!(backward, reversed, "{name} key {}: backward sequence", key.number);

                // Equal, for every distinct value this key holds.
                let mut at = 0usize;
                while at < count {
                    let anchor = records.ordered(key.number, at).expect("in range").clone();
                    let value = key.extract(&records.keyed(&anchor.bytes));

                    let expected_at = records.seek(&keys, key.number, &value);
                    let expected_position =
                        records.ordered(key.number, expected_at).expect("in range").position;

                    let (_cursor, found) = TreeCursor::seek(
                        cache,
                        &mut *resolve,
                        root,
                        shape,
                        Some(&value),
                        Bias::Equal,
                        dup,
                        &cmp,
                    )
                    .unwrap_or_else(|e| {
                        panic!("{name} key {}: seek(Equal) at {at}: {e}", key.number)
                    });
                    assert_eq!(
                        found,
                        Some(expected_position),
                        "{name} key {}: seek(Equal) disagrees with Records::seek at distinct \
                         value {at}",
                        key.number
                    );

                    // Advance past every record sharing this value -- the
                    // same comparator `Records::reindex` groups ties with,
                    // so a group here is exactly the group the tree itself
                    // was built from.
                    let mut next_at = at + 1;
                    while next_at < count {
                        let candidate = records.ordered(key.number, next_at).expect("in range");
                        if key.compare(&records.keyed(&candidate.bytes), &records.keyed(&anchor.bytes))
                            != std::cmp::Ordering::Equal
                        {
                            break;
                        }
                        next_at += 1;
                    }
                    if next_at - at > 1 {
                        file_had_dup = true;
                        dup_group_hit = true;
                    }
                    records_compared += next_at - at;
                    at = next_at;
                }

                keys_compared += 1;
            }

            files_compared += 1;
            if file_had_dup {
                dup_files += 1;
            }
        }

        assert!(
            files_compared > 0,
            "no v6 file was compared at all -- this test verified nothing"
        );
        assert!(
            dup_group_hit,
            "no duplicatable key was hit across the whole run -- a cursor that silently \
             collapsed a duplicate group to one position could otherwise pass"
        );
        println!(
            "nav differential: {files_compared} v6 files, {keys_compared} keys, \
             {records_compared} records compared, {dup_files} files exercised a real \
             duplicate group"
        );
    }
}
