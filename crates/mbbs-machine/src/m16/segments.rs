//! A module's address space, separate from the machine that executes in it.
//!
//! `mbbs32` already draws this line -- its `Machine` is thunk table, TIB and
//! fault recovery, while `Image` owns memory. `crate::m16::Machine` conflated the
//! two, which is why `crates/mbbs` could only ever be handed a whole `Machine`
//! to read one pointer through.

use std::collections::HashSet;
use std::io;

use crate::m16::farptr::ldt_index;
use crate::m16::seg::Segment;
// `SEGMENT_BYTES` bounds `alloc_segment`'s `len`; reached directly rather than
// re-stated, since this module lives in the same crate as its definition.
use crate::m16::{FarPtr, FarPtrError, SEGMENT_BYTES};

/// Every segment a module owns, and the three selectors execution needs to
/// name them: the scratch code and stack segments, and whichever segment `DS`
/// currently points at.
///
/// What is *not* here is everything about running code: no thunk table, no
/// watchdog, no call frame. Those stay on [`crate::m16::Machine`], which holds one
/// of these rather than being one.
pub struct Segments {
    /// Every segment this module owns, in no particular order. Lookup is by
    /// selector, because that is the only thing a far pointer carries -- and a
    /// loaded NE image appends 82 more of them here, so an index would be a
    /// second way of naming a segment that the module itself cannot use.
    pub(crate) segments: Vec<Segment>,

    /// The scratch code segment [`crate::m16::Machine::load_code`] fills. Unused
    /// once an NE image is loaded, which brings 34 code segments of its own.
    code: u16,
    stack: u16,

    /// The segment `DS` is loaded from: the scratch one until an NE image is
    /// loaded, and that image's `DGROUP` afterwards.
    pub(crate) data: u16,

    /// Every selector [`Segments::alloc_segment`]/[`Segments::alloc_tiled`]
    /// has minted and not yet freed -- the **allowlist**
    /// [`Segments::free_segment`] checks before it lets anything go.
    ///
    /// An allowlist, not a denylist naming `code`/`stack`/`data`: this
    /// crate already has a ruling on that exact shape
    /// (`crates/dos/tests/independence.rs`'s own module comment) -- "a
    /// denylist cannot fail safe, because the entry you did not write is
    /// the one that lets a dependency in." The same failure mode applies
    /// here in the opposite direction: `code`/`stack`/`data` are the three
    /// selectors `Segments` itself can name, but `Machine::new` also
    /// builds a fourth, `bridge` (the thunk-table segment), which
    /// `Segments` cannot see at all -- a denylist keyed on the three
    /// accessors this file has would have missed it silently. Tracking
    /// what *was* issued, rather than guessing at what must not be freed,
    /// cannot have that gap: anything not in this set was not this
    /// allocator's to begin with, full stop.
    allocator_issued: HashSet<u16>,
}

impl Segments {
    /// Assemble a module's address space from its already-mapped segments and
    /// the three selectors execution needs.
    ///
    /// Not `pub`: `code` and `stack` are private fields (unlike `segments` and
    /// `data`, which the NE loader in `ne.rs` still writes to directly), so
    /// [`crate::m16::Machine::new`] -- the only caller -- reaches this rather than
    /// building the struct literal itself.
    pub(crate) fn new(segments: Vec<Segment>, code: u16, stack: u16, data: u16) -> Self {
        Self {
            segments,
            code,
            stack,
            data,
            allocator_issued: HashSet::new(),
        }
    }

    /// Map `len` bytes of writable memory the module can address, and return
    /// the selector naming it.
    ///
    /// This is how the host owns memory a module can reach. It needs it twice
    /// over: for the globals a module addresses directly -- `usrnum`, `margv`,
    /// `prfbuf` and their like are imports the module never *calls*, so their
    /// fixups have to name real memory -- and later for whatever the host's
    /// allocator hands out.
    ///
    /// The segment lives as long as this machine and is not otherwise
    /// distinguished: a far pointer into it resolves through
    /// [`resolve`](Segments::resolve) and [`write`](Segments::write) like any
    /// other, and a stray far pointer that lands outside it is bounded by the
    /// same descriptor limit.
    ///
    /// # Errors
    ///
    /// If `len` is zero or larger than a 16-bit segment can address, or if the
    /// mapping or its descriptor cannot be made.
    pub fn alloc_segment(&mut self, len: usize) -> io::Result<u16> {
        if len == 0 || len > SEGMENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a 16-bit segment is 1..={SEGMENT_BYTES} bytes, not {len}"),
            ));
        }
        let segment = Segment::new(len, false)?;
        let selector = segment.selector();
        self.segments.push(segment);
        // Recorded so `free_segment` can tell this selector apart from
        // `code`/`stack`/`data`/`bridge`, none of which came through here.
        self.allocator_issued.insert(selector);
        Ok(selector)
    }

    /// One region of `qty * size` bytes, described by `qty` consecutive LDT
    /// entries of `size` bytes each.
    ///
    /// The far pointer names the first tile; **tile `n` is at
    /// `selector + n * `[`crate::m16::SELECTOR_STEP`]**. That is what makes this
    /// different from `qty` separate segments, and it is not a convenience:
    /// `ptrtile` in Galacticomm's `PLSTUFF.C` is `(long)bigptr + (index << 19)`,
    /// which is the module computing a tile's address *itself*, on the
    /// selector, without telling the host. Every descriptor has to exist and
    /// be adjacent before it does.
    ///
    /// Each tile's descriptor windows only its own tile, so 16-bit code that
    /// runs off the end of one is stopped rather than sliding into the next --
    /// which is also what the real hardware did, `pltile` having passed the
    /// tile size as both the stride and the limit.
    ///
    /// # Errors
    ///
    /// If `qty` or `size` is zero, if the region cannot be mapped, or if the
    /// LDT has no run of `qty` free entries.
    pub fn alloc_tiled(&mut self, qty: u16, size: u16) -> io::Result<FarPtr> {
        let tiles = Segment::tiled(qty, size)?;
        let selector = tiles[0].selector();
        // Every tile individually, not just the first -- `ptrtile` hands a
        // module a selector for tile `n` computed from the base by adding
        // `n * SELECTOR_STEP` on its own (this file's own doc comment on
        // `alloc_tiled`), so a module holding tile 3's selector genuinely
        // holds a selector this allocator issued, not merely one that looks
        // adjacent to one it did.
        for tile in &tiles {
            self.allocator_issued.insert(tile.selector());
        }
        self.segments.extend(tiles);
        Ok(FarPtr {
            offset: 0,
            selector,
        })
    }

    /// Selector of the scratch code segment [`crate::m16::Machine::load_code`]
    /// fills.
    pub fn code_selector(&self) -> u16 {
        self.code
    }

    /// Selector of the module's stack segment.
    ///
    /// Worth having separately from the code one: under `DS != SS` a module
    /// hands out pointers to its own locals, and this is the segment they name.
    pub fn stack_selector(&self) -> u16 {
        self.stack
    }

    /// Selector of the module's data segment: its `DGROUP`.
    ///
    /// The scratch one until [`crate::m16::Machine::load_ne`] replaces it with the
    /// loaded module's own.
    pub fn data_selector(&self) -> u16 {
        self.data
    }

    /// The module's stack segment. Not `pub`: "the stack" is an execution-side
    /// notion (arguments and the call frame live there), so this exists for
    /// `Machine`'s facade to reach through, not as part of `Segments`' own
    /// API -- a caller with only a [`FarPtr`] uses [`Segments::resolve`].
    pub(crate) fn stack(&self) -> &Segment {
        self.segment(self.stack)
            .expect("the stack segment is this machine's own")
    }

    /// Find the segment a selector names.
    pub(crate) fn segment(&self, selector: u16) -> Result<&Segment, FarPtrError> {
        let index = ldt_index(selector)?;
        self.segments
            .iter()
            .find(|s| s.entry() == u32::from(index))
            .ok_or(FarPtrError::NoSuchSegment { selector })
    }

    /// Find the segment a selector names, to write to.
    pub(crate) fn segment_mut(&mut self, selector: u16) -> Result<&mut Segment, FarPtrError> {
        let index = ldt_index(selector)?;
        self.segments
            .iter_mut()
            .find(|s| s.entry() == u32::from(index))
            .ok_or(FarPtrError::NoSuchSegment { selector })
    }

    /// Release a segment [`Segments::alloc_segment`] (or, one tile at a time,
    /// [`Segments::alloc_tiled`]) previously handed out.
    ///
    /// # This checks an allowlist, not merely "does a segment exist here"
    ///
    /// `code`/`stack`/`data`/`bridge` (`Machine::new`) live in the same
    /// `segments` vec every allocator-issued segment does -- lookup by LDT
    /// entry alone cannot tell them apart, and a module trivially holds its
    /// own stack selector (`MOV AX,SS`). Freeing one of those out from under
    /// a running module does not merely corrupt module state: the very next
    /// [`crate::m16::Machine`] dispatch that reaches [`Segments::stack`]
    /// (`.expect("the stack segment is this machine's own")`) panics the
    /// *host* process, not just the guest. [`Segments::allocator_issued`]
    /// exists to make that structurally unreachable: only a selector this
    /// allocator itself minted can be freed at all, so `selector` naming
    /// `code`/`stack`/`data`/`bridge` -- or anything else this allocator
    /// never handed out -- answers the identical error an unrecognised
    /// selector already does, rather than ever reaching the removal below.
    ///
    /// # `selector` may be reused after this returns
    ///
    /// This does **not** mean `selector` is guaranteed to name nothing for
    /// the rest of this module's life. `crate::ldt`'s free list is
    /// first-fit-lowest-first (its own module comment: "a freed slot is
    /// handed out again before a fresh one"), and
    /// `an_ldt_slot_is_reused_once_its_segment_is_gone` (`seg.rs`) already
    /// exercises exactly that reuse. So a stale far pointer built from a
    /// selector this call freed can resolve *successfully* again, into
    /// whatever a later [`Segments::alloc_segment`]/[`Segments::alloc_tiled`]
    /// call is handed the same LDT entry for -- silently reading or writing
    /// the wrong segment's memory, not failing loudly. Real OS/2 has the
    /// identical hazard (`DosFreeSeg` says nothing about a selector's
    /// lifetime beyond "no longer describes what it did"), so reproducing it
    /// is not a bug to fix here; it is a real, load-bearing reason a module
    /// must not keep a far pointer alive past freeing what it points into --
    /// the same discipline `free()`/`malloc()` require in C.
    ///
    /// # Real reclamation, not bookkeeping alone
    ///
    /// [`Segment`] already implements [`Drop`] (`seg.rs`), which clears the
    /// LDT entry and, once nothing else shares the underlying mapping,
    /// `munmap`s it -- `remove` here is what runs that drop. No new teardown
    /// had to be written; this is the first caller that reaches the existing
    /// one deliberately rather than only incidentally, when a whole
    /// [`crate::m16::Machine`] is itself dropped.
    ///
    /// # Errors
    ///
    /// If `selector` was never issued by [`Segments::alloc_segment`]/
    /// [`Segments::alloc_tiled`] -- including a selector already freed
    /// (removed from [`Segments::allocator_issued`] the instant it is, so a
    /// double free is not a special case, only the same case again) and
    /// including `code`/`stack`/`data`/`bridge`, which were never in that
    /// set to begin with.
    pub fn free_segment(&mut self, selector: u16) -> Result<(), FarPtrError> {
        if !self.allocator_issued.remove(&selector) {
            return Err(FarPtrError::NoSuchSegment { selector });
        }
        let index = ldt_index(selector)?;
        let pos = self
            .segments
            .iter()
            .position(|s| s.entry() == u32::from(index))
            .ok_or(FarPtrError::NoSuchSegment { selector })?;
        self.segments.remove(pos);
        Ok(())
    }

    /// Borrow `len` bytes of module memory through a far pointer.
    ///
    /// This is the only correct way to follow a pointer a module gave you. The
    /// segment is found by selector -- never by adding a base -- and the access
    /// is bounds-checked against that segment's own length, which is the only
    /// place the limit is known.
    ///
    /// # Errors
    ///
    /// If the selector names nothing of this module's, or the access would run
    /// past the end of what it names. Both are things a module can do, so
    /// neither is a panic.
    pub fn resolve(&self, ptr: FarPtr, len: usize) -> Result<&[u8], FarPtrError> {
        let segment = self.segment(ptr.selector)?;
        let start = usize::from(ptr.offset);
        let end = start.checked_add(len).ok_or(FarPtrError::OutOfBounds {
            ptr,
            len,
            limit: segment.len(),
        })?;
        if end > segment.len() {
            return Err(FarPtrError::OutOfBounds {
                ptr,
                len,
                limit: segment.len(),
            });
        }
        Ok(segment.slice(start, len))
    }

    /// The length of the segment `ptr` names -- the actual bound
    /// [`Segments::resolve`] and [`Segments::read_cstr`] already check every
    /// access against, exposed so a caller can compare what
    /// [`Segments::alloc_segment`] was asked for against what the segment it
    /// returned really holds, rather than trusting the two never drifted
    /// apart.
    ///
    /// # Errors
    ///
    /// If `ptr`'s selector names no segment of this module's.
    pub fn region_len(&self, ptr: FarPtr) -> Result<usize, FarPtrError> {
        self.segment(ptr.selector).map(Segment::len)
    }

    /// Read a NUL-terminated string through a far pointer, without the NUL.
    ///
    /// Most of the MajorBBS API is shaped this way. The scan stops at the end
    /// of the segment rather than running on, so a module that forgets its
    /// terminator gets an error instead of handing the host whatever follows.
    ///
    /// # Errors
    ///
    /// As [`Segments::resolve`], plus [`FarPtrError::Unterminated`].
    pub fn read_cstr(&self, ptr: FarPtr) -> Result<&[u8], FarPtrError> {
        let limit = self.segment(ptr.selector)?.len();
        let start = usize::from(ptr.offset);

        // Everything from the pointer to the end of its segment is the most a
        // string could possibly be. Going through `resolve` rather than
        // reaching for the segment directly keeps one bounds check and one
        // lookup in the crate, instead of two that can drift apart.
        let avail = limit
            .checked_sub(start)
            .filter(|n| *n > 0)
            .ok_or(FarPtrError::OutOfBounds { ptr, len: 1, limit })?;
        let tail = self.resolve(ptr, avail)?;

        let n = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(FarPtrError::Unterminated { ptr })?;
        Ok(&tail[..n])
    }

    /// `len` bytes at `ptr`, bounds-checked against its segment.
    pub fn read(&self, ptr: FarPtr, len: usize) -> Result<&[u8], FarPtrError> {
        self.resolve(ptr, len)
    }

    /// Write into module memory through a far pointer.
    ///
    /// The same rules as [`Segments::resolve`]: found by selector, bounds
    /// checked. Real shims need this for the API calls that fill a caller's
    /// buffer.
    ///
    /// # Errors
    ///
    /// As [`Segments::resolve`].
    pub fn write(&mut self, ptr: FarPtr, bytes: &[u8]) -> Result<(), FarPtrError> {
        // Resolve first so the bounds check and the error are shared.
        self.resolve(ptr, bytes.len())?;
        self.segment_mut(ptr.selector)?
            .write(usize::from(ptr.offset), bytes)
            .expect("bounds already checked by resolve");
        Ok(())
    }
}
