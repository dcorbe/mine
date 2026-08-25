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
//! # A cursor is one-directional, and a flip is a hard refusal
//!
//! [`Frame::at`] means "`[0, at)` emitted" when a forward step
//! ([`TreeCursor::advance_entry_forward`]) built the frame, and "`[at,
//! len)` emitted" when a backward step built it instead -- two genuinely
//! different conventions sharing one field, with no per-frame marker of
//! which one applies. [`TreeCursor::seek`] commits a whole cursor to one of
//! them from `bias` alone ([`Bias::Lowest`]/[`Bias::Equal`]/
//! [`Bias::AtLeast`]/[`Bias::Greater`] -> forward, for [`TreeCursor::next`];
//! [`Bias::Highest`]/[`Bias::AtMost`]/[`Bias::Less`] -> backward, for
//! [`TreeCursor::prev`]) and remembers the choice as [`Direction`]. Calling
//! the *other* method reinterprets every frame on the stack under the
//! convention it was not built with, which would silently re-emit or skip
//! entries rather than merely fail loudly -- so `next`/`prev` each check
//! [`Direction`] first and return `Err` naming the mismatch instead of ever
//! attempting it. A true bidirectional cursor (a keyed `Get` followed by a
//! `Get Previous`) is not implemented, and a caller that needs one gets a
//! clean refusal to build on rather than a silent wrong answer.
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

/// The stored root for key **definition** `definition`, straight off the
/// file control record, for key **number** `number`. `None` when there is
/// no tree yet: a virgin file, or an `ANOSEG` continuation definition, both
/// read a bare zero at [`pages::fcr::KEY_ROOT`] (`format::fcr`'s own module
/// doc).
///
/// **`definition` and `number` are not the same quantity, and a real corpus
/// file can make them differ.** A key's root and per-key record count live
/// at `fcr::KEYS + definition*KEY_WIDTH` -- `definition` is this key's
/// ordinal among the file's *definitions*, one per segment
/// (`Key::definition`'s own doc comment) -- but the tag the root and every
/// descendant page actually carry is `0x80 + number`, this key's ordinal
/// among the file's *keys* (`Key::number`), which only equals `definition`
/// when every earlier key is single-segment. `GALTELA.DAT`'s own key 1
/// (`number == 1`) starts at definition 2, and passing `2` for both purposes
/// -- this function's very first version -- refused every real lookup with
/// "carries tag 0x81, not 0x82", a false positive caught by the
/// differential test, not a hypothetical. `v6_reindex`'s write side
/// (`Self::v6_decorate`, `tag_high = 0x80 + key.number`) already keeps the
/// two separate for exactly this reason; this is its read-side mirror.
///
/// Returned **still decorated** -- top byte `0x80|number`, low 24 bits the
/// logical root page ([`pages::fcr::ROOT_PAGE`]'s own doc comment is the
/// authority this mirrors). Every child pointer inside the tree
/// ([`IndexPage::leftmost`]/[`IndexPage::rightmost`]/each entry's own child)
/// is stored the same decorated way, so [`TreeCursor`] applies one mask to
/// all of them rather than treating the root as a special case.
///
/// # Errors
///
/// If `fcr` is too short to hold definition `definition`'s root field, the
/// stored value does not carry the v6 marker bit (`0x8000_0000`) every v6
/// key root measured so far has set, or **the stored tag disagrees with
/// `number`** -- `(raw >> 24) != 0x80 | number`. This last check is not
/// optional: without it, a corrupted FCR or a caller that passed the wrong
/// `definition`/`number` pair would hand [`TreeCursor::seek`] a root whose
/// top byte it then trusts for every page-tag check for the rest of the
/// walk ([`TreeCursor::key_tag`]) -- the walk would stay perfectly
/// self-consistent while silently reading a *different* key's entire tree.
/// Refusing here, at the one point this crate is told which key it meant to
/// ask for, is what makes that impossible instead of merely unlikely.
pub(crate) fn root_of(fcr: &[u8], definition: usize, number: u16) -> Result<Option<u32>, String> {
    let at = pages::fcr::KEYS + definition * pages::fcr::KEY_WIDTH + pages::fcr::KEY_ROOT;
    let end = at + 4;
    if end > fcr.len() {
        return Err(format!(
            "key definition {definition}'s root field would occupy \
             {at:#x}..{end:#x}, past the {}-byte file control record",
            fcr.len()
        ));
    }
    let raw = pages::long(&fcr[at..end]);
    if raw == 0 {
        return Ok(None);
    }
    if raw & 0x8000_0000 == 0 {
        return Err(format!(
            "key {number} (definition {definition})'s root {raw:#010x} does not \
             carry the v6 marker bit (0x80000000) every v6 key root measured so \
             far has set"
        ));
    }
    // `v6_reindex`'s own write side (the authority this function's doc
    // comment cites) computes this identical `0x80 + number` tag when it
    // builds a fresh root; reading it back is the read-side mirror of that,
    // not a new rule.
    let expected_tag = 0x80u8
        .checked_add(u8::try_from(number).map_err(|_| {
            format!("key {number}: does not fit a page tag's low byte")
        })?)
        .ok_or_else(|| {
            format!(
                "key {number}: a page tag's high byte is 0x80 plus the key's own \
                 number, and this key's number does not fit"
            )
        })?;
    let actual_tag = (raw >> 24) as u8;
    if actual_tag != expected_tag {
        return Err(format!(
            "key {number} (definition {definition})'s root {raw:#010x} carries tag \
             {actual_tag:#04x}, not the {expected_tag:#04x} (0x80|number) this key's \
             own root must carry -- refusing rather than walking what would silently \
             be a different key's tree"
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
/// Three checks, all refusals rather than silent decoding or an unbounded
/// loop: the pointer's own top byte must be this key's tag (a child cannot
/// belong to a different key's tree -- `read.rs`'s `v6_enter_child` makes
/// the identical check for the eager reader this mirrors); this logical
/// page must not already be in `seen` (a cycle -- `pages::walk_with`'s own
/// `HashSet`, mirrored here because this cursor is `walk_with`'s lazy
/// equivalent and a corrupted or cyclic tree is exactly what a *production*
/// read path, unlike a one-shot test walk, cannot be allowed to spin
/// forever on); `depth` must be under `pages::MAX_DEPTH` (the same bound,
/// for the same reason -- a cycle through more than `MAX_DEPTH` distinct
/// pages would pass the `seen` check every time yet still never
/// terminate); and the *page's own header tag*, once fetched, must match
/// too. The last is what catches a page this cursor should never land on
/// at all: unclaimed (marker `0x0000`) or merge-retired (marker `0x4500`,
/// `docs/2026-08-25-btree-split-oracle.md`) -- either reads back as *some*
/// tag other than this key's own, so the one comparison below refuses both
/// by construction rather than needing a marker-specific case for each.
///
/// # Errors
///
/// See above: a tag mismatch (pointer or page), a repeated logical page, or
/// `depth >= pages::MAX_DEPTH`, in addition to whatever `resolve` or the
/// cache itself refuse.
fn fetch_page(
    cache: &RefCell<PageCache>,
    resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
    shape: Shape,
    key_tag: u8,
    raw_pointer: u32,
    seen: &mut std::collections::HashSet<u32>,
    depth: usize,
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
    if !seen.insert(logical) {
        return Err(format!(
            "logical page {logical} appears twice in this key's own tree -- the tree \
             does not terminate cleanly (a cycle)"
        ));
    }
    if depth >= pages::MAX_DEPTH {
        return Err(format!(
            "this key's tree is more than {} levels deep at logical page {logical} -- \
             not a real B-tree (pages::MAX_DEPTH, the same bound pages::walk_with uses)",
            pages::MAX_DEPTH
        ));
    }
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

/// Which of [`Frame::at`]'s two conventions this cursor's own frames use --
/// set once, from `bias`, at [`TreeCursor::seek`] and never changed
/// afterward. [`TreeCursor::next`]/[`TreeCursor::prev`] each refuse outright
/// when called against the wrong one, rather than silently reinterpreting
/// `at` under a convention the frame was not built with -- see this
/// module's own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Forward,
    Backward,
}

/// A lazy in-order cursor over one key's v6 B-tree. See this module's own
/// doc comment for the shape of the tree it walks and the limits of what is
/// proven about it.
pub(crate) struct TreeCursor {
    /// This tree's own tag, read once off the root's top byte at
    /// [`Self::seek`] and checked against every page reached from there --
    /// see [`fetch_page`].
    key_tag: u8,
    /// Which `bias` this cursor was seeded with committed it to -- see
    /// [`Direction`].
    direction: Direction,
    stack: Vec<Frame>,
    /// A child pointer (still tagged, not yet resolved) to descend into on
    /// the next step -- leftmost-first for a forward-primed cursor,
    /// rightmost-first for a backward-primed one.
    pending: Option<u32>,
    group: Option<Group>,
    dup: Option<Duplicates>,
    /// Every logical page this cursor has fetched so far, across its whole
    /// lifetime (one `seek` plus however many `next`/`prev` calls follow) --
    /// [`fetch_page`]'s cycle guard. Never pruned, matching
    /// `pages::walk_with`'s own `seen`: a well-formed tree visits each page
    /// at most once in a single walk, so nothing here should ever need to
    /// forget one.
    seen: std::collections::HashSet<u32>,
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
        let direction = match bias {
            Bias::Lowest | Bias::Equal | Bias::AtLeast | Bias::Greater => Direction::Forward,
            Bias::Highest | Bias::Less | Bias::AtMost => Direction::Backward,
        };
        let mut cursor = Self {
            key_tag: (root >> 24) as u8,
            direction,
            stack: Vec::new(),
            pending: Some(root),
            group: None,
            dup,
            seen: std::collections::HashSet::new(),
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
    /// If this cursor was primed backward (`Highest`/`AtMost`/`Less` at
    /// [`Self::seek`]) -- see [`Direction`] and this module's own doc
    /// comment: its frames' own `at` means "`[at, len)` emitted", and
    /// reinterpreting them under `next`'s "`[0, at)` emitted" convention
    /// would silently re-emit or skip entries rather than fail loudly, so
    /// this refuses instead of ever attempting it. Also if continuing the
    /// descent hits a page [`fetch_page`] refuses, or a duplicate chain does
    /// not check out (see [`Self::chain_members`]).
    pub(crate) fn next(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<u32>, String> {
        if self.direction != Direction::Forward {
            return Err(
                "this cursor was primed backward (Highest/AtMost/Less) -- next() would \
                 reinterpret its frames under the wrong convention, so it is refused \
                 rather than risking a silently wrong position"
                    .to_owned(),
            );
        }
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
    /// See [`Self::next`] -- the mirror refusal fires here when this cursor
    /// was primed forward (`Lowest`/`Equal`/`AtLeast`/`Greater`).
    pub(crate) fn prev(
        &mut self,
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        shape: Shape,
    ) -> Result<Option<u32>, String> {
        if self.direction != Direction::Backward {
            return Err(
                "this cursor was primed forward (Lowest/Equal/AtLeast/Greater) -- \
                 prev() would reinterpret its frames under the wrong convention, so \
                 it is refused rather than risking a silently wrong position"
                    .to_owned(),
            );
        }
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
                let page =
                    fetch_page(cache, resolve, shape, self.key_tag, raw, &mut self.seen, self.stack.len())?;
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
                let page =
                    fetch_page(cache, resolve, shape, self.key_tag, raw, &mut self.seen, self.stack.len())?;
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
            let page =
                    fetch_page(cache, resolve, shape, self.key_tag, raw, &mut self.seen, self.stack.len())?;
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
            let page =
                    fetch_page(cache, resolve, shape, self.key_tag, raw, &mut self.seen, self.stack.len())?;
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

/// One page on the path [`descend_for_write`] took from a key's root down
/// to wherever it stopped -- like [`TreeCursor`]'s own `Frame`, but the
/// whole path is kept rather than only the frames a lazy walk still needs,
/// because an insert's split or a delete's underflow may have to rewrite
/// its way back UP through any number of these, not just step through them
/// once the way `Get`/`Step` do.
pub(crate) struct WriteFrame {
    /// This page's own logical id, undecorated (top-byte tag masked off).
    pub(crate) logical: u32,
    pub(crate) page: IndexPage,
    /// The child slot (0..=entries.len()) the descent followed FROM this
    /// frame to reach the next one -- meaningless (always `0`) on the last
    /// frame, since nothing descends further from it. A split that
    /// propagates up into this frame's own parent needs this to know which
    /// of the parent's children it is replacing.
    pub(crate) descended_via: usize,
}

/// What [`descend_for_write`] found: the whole path from a key's root to
/// either an exact match (at any level -- a duplicate-permitting key's
/// already-present value lives wherever it was promoted to, split rules §0/
/// §9) or the leaf a genuinely new value belongs on.
pub(crate) struct Located {
    /// Root first, whatever `descend_for_write` stopped at last.
    pub(crate) path: Vec<WriteFrame>,
    /// `target`'s sorted position within `path`'s own last entries -- where
    /// it already sits, if `exact`, or where it belongs if not.
    pub(crate) at: usize,
    pub(crate) exact: bool,
}

/// Descend from `root` toward `target`, keeping every page the descent
/// passes through -- [`TreeCursor::seek_lower_bound`]'s identical search
/// (one `partition_point` per page, the same early stop on an exact match),
/// but collecting the whole path instead of leaving only the frames a lazy
/// walk still needs on the stack, since a write may have to edit any
/// number of them afterward.
///
/// # Errors
///
/// Whatever [`fetch_page`] refuses.
pub(crate) fn descend_for_write(
    cache: &RefCell<PageCache>,
    resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
    root: u32,
    shape: Shape,
    target: &[u8],
    cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
) -> Result<Located, String> {
    use std::cmp::Ordering;
    let key_tag = (root >> 24) as u8;
    let mut seen = std::collections::HashSet::new();
    let mut path: Vec<WriteFrame> = Vec::new();
    let mut pending = root;
    loop {
        let page = fetch_page(cache, resolve, shape, key_tag, pending, &mut seen, path.len())?;
        let idx = page.entries.partition_point(|e| cmp(&e.0, target) == Ordering::Less);
        let exact = idx < page.entries.len() && cmp(&page.entries[idx].0, target) == Ordering::Equal;
        let leaf = page.leaf();
        let logical = pending & pages::fcr::ROOT_PAGE;
        let child_before = child_slot(&page, idx);
        path.push(WriteFrame { logical, page, descended_via: idx });
        if exact || leaf {
            return Ok(Located { path, at: idx, exact });
        }
        pending = child_before;
    }
}

/// Every child pointer of a page, `leftmost` first and `rightmost` last --
/// [`child_slot`] applied at every slot, so a caller editing an interior
/// page's own entries can edit its children the same uniform way, rather
/// than hand-rolling the leftmost/entries/rightmost cases itself. Empty for
/// a leaf (`page.leaf()`), the same convention [`IndexPage::entries`]'s own
/// child field uses.
pub(crate) fn children_of(page: &IndexPage) -> Vec<u32> {
    if page.leaf() {
        return Vec::new();
    }
    (0..=page.entries.len()).map(|k| child_slot(page, k)).collect()
}

/// Fetch and decode one page by its decorated pointer, standalone -- for a
/// sibling an underflow's merge/redistribute (split rules §6/§7) needs to
/// inspect, which [`descend_for_write`]'s own path never includes (a
/// sibling is never on the direct root-to-target descent). A fresh `seen`
/// set each call: this is one page, not a walk, so there is nothing for a
/// cycle guard to catch across calls.
///
/// # Errors
///
/// Whatever [`fetch_page`] refuses.
pub(crate) fn fetch_one(
    cache: &RefCell<PageCache>,
    resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
    shape: Shape,
    key_tag: u8,
    decorated: u32,
) -> Result<IndexPage, String> {
    let mut seen = std::collections::HashSet::new();
    fetch_page(cache, resolve, shape, key_tag, decorated, &mut seen, 0)
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

    /// `ops::Block::query`'s own per-`Op` semantics (`ops.rs`'s `match op {
    /// ... }` inside `Block::query`), mirrored directly against `Records`
    /// instead of a live `Block::query` call -- no lock table or module ABI
    /// needed, and this is the reference every bias check below is measured
    /// against, not this cursor's own idea of what it should do. `target`
    /// is required for every bias but `Lowest`/`Highest`.
    fn reference_answer(
        records: &Records,
        keys: &[Key],
        key: u16,
        bias: Bias,
        target: Option<&[u8]>,
    ) -> Option<u32> {
        let count = records.ordered_len(key).unwrap_or(0);
        let at = match bias {
            Bias::Lowest => (count > 0).then_some(0),
            Bias::Highest => count.checked_sub(1),
            Bias::Equal => {
                let target = target.expect("Equal needs a target");
                let at = records.seek(keys, key, target);
                records.matches(keys, key, at, target).then_some(at)
            }
            Bias::AtLeast => {
                let target = target.expect("AtLeast needs a target");
                Some(records.seek(keys, key, target)).filter(|at| *at < count)
            }
            Bias::Greater => {
                let target = target.expect("Greater needs a target");
                let mut at = records.seek(keys, key, target);
                while records.matches(keys, key, at, target) {
                    at += 1;
                }
                Some(at).filter(|at| *at < count)
            }
            Bias::AtMost => {
                let target = target.expect("AtMost needs a target");
                let mut at = records.seek(keys, key, target);
                while records.matches(keys, key, at, target) {
                    at += 1;
                }
                at.checked_sub(1)
            }
            Bias::Less => {
                let target = target.expect("Less needs a target");
                records.seek(keys, key, target).checked_sub(1)
            }
        };
        at.map(|at| records.ordered(key, at).expect("in range").position)
    }

    /// Try small byte-level mutations of `base` until one is both (a) not
    /// an exact match for any record and (b) `Records::seek` places its
    /// lower bound at exactly `want_seek` -- i.e. genuinely between
    /// whatever sits at indices `want_seek - 1` and `want_seek` in this
    /// key's own order (or below everything, for `want_seek == 0`; or
    /// above everything, for `want_seek == count`).
    ///
    /// `None` is an expected, non-failing answer, not a weakened check: a
    /// tightly packed key space (dense sequential integers, a one-byte
    /// enumerated field near exhaustion) can have no value between two
    /// adjacent ones at all, and this must not fabricate one. The caller
    /// tracks how often a probe actually was constructed
    /// (`probes_found`/`probes_attempted`) and fails the whole run if that
    /// count is ever zero, so a version of this function that stopped
    /// finding anything would not silently pass.
    fn probe_absent(
        records: &Records,
        keys: &[Key],
        key: u16,
        base: &[u8],
        want_seek: usize,
    ) -> Option<Vec<u8>> {
        const DELTAS: [i16; 14] = [1, -1, 2, -2, 3, -3, 5, -5, 7, -7, 16, -16, 64, -64];
        for byte in (0..base.len()).rev() {
            for delta in DELTAS {
                let mut candidate = base.to_vec();
                let v = i16::from(candidate[byte]) + delta;
                if !(0..=255).contains(&v) {
                    continue;
                }
                candidate[byte] = v as u8;
                let at = records.seek(keys, key, &candidate);
                if at == want_seek && !records.matches(keys, key, at, &candidate) {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// For every v6 file this box has (`archive/` plus the committed
    /// fixtures), for every key with at least one record:
    ///
    /// 1. Enumerate positions through [`TreeCursor`] (`Lowest` + `next`
    ///    until `None`, then `Highest` + `prev` until `None`) and through
    ///    `Records::ordered`, and require the forward sequence equal and
    ///    the backward sequence its reverse.
    /// 2. For every one of `Bias`'s five comparison variants
    ///    (`Equal`/`AtLeast`/`Greater`/`Less`/`AtMost` -- `Lowest`/`Highest`
    ///    need no target and are already covered by (1)), at every distinct
    ///    value the key holds, `seek(bias, value)` must equal
    ///    [`reference_answer`]'s mirror of what `ops::Block::query` would
    ///    do against `Records` for the identical `(bias, value)`.
    /// 3. The same five biases again, at an absent value between each pair
    ///    of adjacent distinct values (via [`probe_absent`]) plus one below
    ///    the minimum and one above the maximum -- exercising the "no exact
    ///    match anywhere in the tree" path through `seek_lower_bound`/
    ///    `seek_upper_bound` that (2) alone cannot reach, since every (2)
    ///    target is an exact match by construction.
    ///
    /// Duplicate-permitting keys are not special-cased: their tree entries
    /// group several records under one value, and every sequence/bias check
    /// above is per-*record*, so a cursor that silently collapsed a group to
    /// one position would already fail -- confirmed separately by asserting
    /// this run actually saw at least one such group.
    #[test]
    fn tree_cursor_matches_records_over_the_v6_corpus() {
        let mut files_compared = 0usize;
        let mut keys_compared = 0usize;
        let mut records_compared = 0usize;
        let mut dup_group_hit = false;
        let mut dup_files = 0usize;
        let mut bias_checks = 0usize;
        let mut probes_attempted = 0usize;
        let mut probes_found = 0usize;

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

                // All five comparison biases (`Lowest`/`Highest` need no
                // target and are already covered above), for every distinct
                // value this key holds, plus an absent probe between each
                // pair of adjacent distinct values and one below the
                // minimum / above the maximum -- each checked against
                // `reference_answer`'s own mirror of `ops::Block::query`'s
                // per-bias `Records` semantics, not against this cursor's
                // own idea of what it should do.
                const COMPARISON_BIASES: [Bias; 5] =
                    [Bias::Equal, Bias::AtLeast, Bias::Greater, Bias::Less, Bias::AtMost];
                let mut check_bias = |bias: Bias, target: &[u8], where_: &str| {
                    let expected = reference_answer(&records, &keys, key.number, bias, Some(target));
                    let (_cursor, found) = TreeCursor::seek(
                        cache,
                        &mut *resolve,
                        root,
                        shape,
                        Some(target),
                        bias,
                        dup,
                        &cmp,
                    )
                    .unwrap_or_else(|e| {
                        panic!("{name} key {}: seek({bias:?}) at {where_}: {e}", key.number)
                    });
                    assert_eq!(
                        found, expected,
                        "{name} key {}: seek({bias:?}) disagrees with Records at {where_}",
                        key.number
                    );
                };

                let mut at = 0usize;
                let mut previous_group: Option<(usize, Vec<u8>)> = None;
                while at < count {
                    let anchor = records.ordered(key.number, at).expect("in range").clone();
                    let value = key.extract(&records.keyed(&anchor.bytes));

                    for bias in COMPARISON_BIASES {
                        check_bias(bias, &value, &format!("distinct value index {at}"));
                    }
                    bias_checks += COMPARISON_BIASES.len();

                    if let Some((prev_at, prev_value)) = &previous_group {
                        probes_attempted += 1;
                        if let Some(probe) =
                            probe_absent(&records, &keys, key.number, prev_value, at)
                        {
                            probes_found += 1;
                            for bias in COMPARISON_BIASES {
                                check_bias(
                                    bias,
                                    &probe,
                                    &format!("an absent value between indices {prev_at} and {at}"),
                                );
                            }
                            bias_checks += COMPARISON_BIASES.len();
                        }
                    }

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
                    previous_group = Some((at, value));
                    at = next_at;
                }

                // Below the minimum and above the maximum -- the two edges
                // no "between two adjacent values" probe can reach.
                let min_value =
                    key.extract(&records.keyed(&records.ordered(key.number, 0).expect("in range").bytes));
                probes_attempted += 1;
                if let Some(probe) = probe_absent(&records, &keys, key.number, &min_value, 0) {
                    probes_found += 1;
                    for bias in COMPARISON_BIASES {
                        check_bias(bias, &probe, "a probe below this key's minimum value");
                    }
                    bias_checks += COMPARISON_BIASES.len();
                }
                let max_value = key.extract(
                    &records.keyed(&records.ordered(key.number, count - 1).expect("in range").bytes),
                );
                probes_attempted += 1;
                if let Some(probe) = probe_absent(&records, &keys, key.number, &max_value, count) {
                    probes_found += 1;
                    for bias in COMPARISON_BIASES {
                        check_bias(bias, &probe, "a probe above this key's maximum value");
                    }
                    bias_checks += COMPARISON_BIASES.len();
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
        assert!(
            bias_checks > 0,
            "no bias was checked against any distinct value -- this test verified nothing \
             about Equal/AtLeast/Greater/Less/AtMost"
        );
        assert!(
            probes_found > 0,
            "not one absent-value probe (between/below/above) was constructible across the \
             whole run -- the 'no exact match' code path in seek_lower_bound/seek_upper_bound \
             went completely untested"
        );
        println!(
            "nav differential: {files_compared} v6 files, {keys_compared} keys, \
             {records_compared} records compared, {dup_files} files exercised a real \
             duplicate group, {bias_checks} (bias, target) checks across all seven biases, \
             {probes_found}/{probes_attempted} absent-value probes constructed and checked"
        );
    }

    /// A page whose own `leftmost` names itself is a one-page cycle.
    /// `pages::walk_with`'s own `a_cycle_in_the_tree_is_refused` proves the
    /// eager reader this cursor mirrors refuses exactly this shape; this
    /// proves the lazy cursor does too, rather than looping forever on a
    /// corrupt tree reached from what would become a production read path.
    /// No real corpus file is cyclic, so this is a synthetic fixture, not a
    /// corpus finding -- built the same way `pages.rs`'s own cycle test
    /// builds its v5 fixture, adapted to v6's decorated addressing.
    #[test]
    fn a_self_referencing_page_is_refused_not_looped_forever() {
        let dir = crate::testing::scratch("nav-cycle");
        let path = dir.join("LOOP.DAT");
        let page_size = 512usize;

        // Physical page 0 is padding, never resolved to. Physical page 1 is
        // the self-referencing index page: v6 tag word 0x8000 (key 0's own
        // tag), zero entries, `leftmost` naming decorated logical
        // `0x80000001` -- itself, since the identity resolver below maps
        // logical 1 to physical 1.
        let mut file = vec![0u8; page_size * 2];
        let page1 = &mut file[page_size..page_size * 2];
        page1[0..2].copy_from_slice(&[0x00, 0x80]);
        page1[6..8].copy_from_slice(&0u16.to_le_bytes());
        page1[8..12].copy_from_slice(&pages::to_long(pages::NOWHERE));
        page1[12..16].copy_from_slice(&pages::to_long(0x8000_0001));
        std::fs::write(&path, &file).expect("writes");

        let cache = RefCell::new(
            crate::cache::PageCache::open(&path, page_size as u16).expect("opens"),
        );
        let shape = Shape { length: 4, duplicates: false };
        let mut resolve = |logical: u32| -> Result<u32, String> { Ok(logical) };
        let cmp = |a: &[u8], b: &[u8]| a.cmp(b);

        // `TreeCursor` derives no `Debug` (it holds a decoded page per
        // frame, not worth a derive for one test), so the error is pulled
        // out by hand rather than via `Result::expect_err`.
        let err = match TreeCursor::seek(
            &cache,
            &mut resolve,
            0x8000_0001,
            shape,
            None,
            Bias::Lowest,
            None,
            &cmp,
        ) {
            Err(e) => e,
            Ok(_) => panic!("a page that names itself as its own leftmost child must not loop forever"),
        };
        assert!(err.contains("twice"), "{err}");
    }

    /// [`Direction`]'s refusal, proven rather than merely argued: a cursor
    /// primed by one direction refuses the other outright instead of
    /// silently reinterpreting its own frames under the wrong convention.
    /// Uses the first real v6 file and key this box has with more than one
    /// record, so both directions have somewhere real to go before the
    /// guard is expected to fire.
    #[test]
    fn a_cursor_refuses_the_direction_it_was_not_primed_for() {
        for path in v6_candidate_paths() {
            let Some((btrieve, at)) = open_v6(&path) else { continue };
            let block = btrieve.block(at).expect("just opened");
            let keys: Vec<Key> = block.keys().to_vec();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let Ok(records) = Records::read(&name, &path, block.geometry(), &keys) else {
                continue;
            };
            for key in &keys {
                if records.ordered_len(key.number).unwrap_or(0) < 2 {
                    continue;
                }
                let Some((root, shape, dup, cache, mut resolve)) =
                    block.nav_root(key.number).expect("nav_root")
                else {
                    continue;
                };
                let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);

                let (mut forward, _) = TreeCursor::seek(
                    cache,
                    &mut *resolve,
                    root,
                    shape,
                    None,
                    Bias::Lowest,
                    dup,
                    &cmp,
                )
                .expect("seek(Lowest)");
                let err = forward
                    .prev(cache, &mut *resolve, shape)
                    .expect_err("a forward-primed cursor must refuse prev()");
                assert!(err.contains("forward"), "{err}");

                let (mut backward, _) = TreeCursor::seek(
                    cache,
                    &mut *resolve,
                    root,
                    shape,
                    None,
                    Bias::Highest,
                    dup,
                    &cmp,
                )
                .expect("seek(Highest)");
                let err = backward
                    .next(cache, &mut *resolve, shape)
                    .expect_err("a backward-primed cursor must refuse next()");
                assert!(err.contains("backward"), "{err}");
                return;
            }
        }
        panic!("no v6 file/key with at least two records was found to run this test against");
    }
}
