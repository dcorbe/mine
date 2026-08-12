//! Segments: memory below 4 GiB, and the LDT descriptors that name it.

use std::io;
use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

/// `modify_ldt(2)` function code for writing an entry.
const LDT_WRITE: i32 = 1;

/// How many entries an LDT has. One module load takes 82 of them, so this is
/// not a limit only a pathological caller could reach.
const LDT_ENTRIES: u32 = 8192;

/// Segment contents, as `struct user_desc` encodes it.
const CONTENTS_DATA: u32 = 0;
const CONTENTS_CODE: u32 = 2;

/// `struct user_desc`, with the kernel's bitfield word spelled out.
#[repr(C)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: u32,
}

/// Layout of `UserDesc::flags`, which is the kernel's bitfield word:
/// `seg_32bit:1, contents:2, read_exec_only:1, limit_in_pages:1,
/// seg_not_present:1, useable:1`.
const CONTENTS_SHIFT: u32 = 1;
const F_READ_EXEC_ONLY: u32 = 1 << 3;
const F_SEG_NOT_PRESENT: u32 = 1 << 5;
const F_USEABLE: u32 = 1 << 6;

/// `u64`s needed to give every LDT entry a bit.
const WORDS: usize = LDT_ENTRIES as usize / 64;

/// Which LDT entries are spoken for.
///
/// A bitmap rather than a counter and a free list, because **a tiled region
/// needs its descriptors to be adjacent** and neither of those can promise it.
/// `alctile` hands the module one far pointer and the module computes the rest
/// itself by stepping the selector, so if entry `n + 1` belongs to something
/// else the module writes through it and nothing reports anything.
///
/// A bump allocator *happens* to hand out consecutive entries, which is worse
/// than not doing so: it holds until the first free and then quietly stops.
///
/// One kilobyte, and a process has exactly one LDT -- so this is process-wide
/// even though a `Machine` feels local.
static IN_USE: Mutex<[u64; WORDS]> = Mutex::new([0; WORDS]);

fn in_use() -> std::sync::MutexGuard<'static, [u64; WORDS]> {
    // Nothing inside the critical section can panic in a way that matters, and
    // failing an allocation because an unrelated thread died is worse than
    // carrying on with a table that is merely correct.
    IN_USE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn taken(bits: &[u64; WORDS], entry: u32) -> bool {
    bits[entry as usize / 64] & (1 << (entry % 64)) != 0
}

/// Reserve `count` adjacent entries and return the first.
///
/// First fit, lowest first, so a freed slot is handed out again before a fresh
/// one -- the LDT is a fixed 8,192 entries and a module load takes 82, so
/// loading and unloading the same module a hundred times would otherwise run
/// the table out.
fn take_ldt_run(count: u32) -> io::Result<u32> {
    let mut bits = in_use();
    let mut run = 0;
    for entry in 0..LDT_ENTRIES {
        if taken(&bits, entry) {
            run = 0;
            continue;
        }
        run += 1;
        if run == count {
            let start = entry + 1 - count;
            for e in start..start + count {
                bits[e as usize / 64] |= 1 << (e % 64);
            }
            return Ok(start);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!("no run of {count} free entries in the LDT's {LDT_ENTRIES}"),
    ))
}

/// Hand `count` entries starting at `start` back.
fn give_ldt_run(start: u32, count: u32) {
    let mut bits = in_use();
    for e in start..start + count {
        bits[e as usize / 64] &= !(1 << (e % 64));
    }
}

/// Write `desc` into the LDT.
fn write_ldt(desc: &UserDesc) -> io::Result<()> {
    // SAFETY: `desc` is a correctly shaped user_desc living long enough for the
    // call, which copies it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_modify_ldt,
            LDT_WRITE,
            std::ptr::from_ref(desc),
            size_of::<UserDesc>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Make an LDT entry name nothing at all.
///
/// The exact shape matters: Linux clears an entry only for a descriptor its
/// `LDT_empty()` recognises, which is every field zero *except* a set
/// `read_exec_only` and `seg_not_present`. Anything else is written as an
/// ordinary descriptor, and a not-present descriptor over a freed mapping is
/// the very thing this exists to prevent.
fn clear_ldt_entry(entry: u32) -> io::Result<()> {
    write_ldt(&UserDesc {
        entry_number: entry,
        base_addr: 0,
        limit: 0,
        flags: F_READ_EXEC_ONLY | F_SEG_NOT_PRESENT,
    })
}

/// One anonymous mapping below 4 GiB.
///
/// The 4 GiB limit is not a preference. A descriptor's base is a 32-bit field,
/// so anything higher cannot be named at all.
///
/// Separate from the descriptors over it because a **tiled** region is one
/// mapping described by several: `PLSTUFF.C`'s `pltile` allocates one linear
/// region and lays consecutive DPMI descriptors across it, and `alctile` is
/// built on that. Shared, so the mapping outlives whichever descriptor is
/// dropped last.
struct Mapping {
    base: *mut u8,
    len: usize,
}

impl Mapping {
    fn new(len: usize, executable: bool) -> io::Result<Rc<Self>> {
        let mut prot = libc::PROT_READ | libc::PROT_WRITE;
        if executable {
            prot |= libc::PROT_EXEC;
        }

        // SAFETY: an ordinary anonymous mapping. MAP_32BIT is what keeps the
        // result addressable by a 32-bit descriptor base.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Rc::new(Self {
            base: base.cast::<u8>(),
            len,
        }))
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: our own mapping, dropped exactly once -- the `Rc` is what
        // guarantees the "once", and every descriptor over it is already gone
        // because each holds one of the references being counted.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

/// A window onto a mapping, with an LDT descriptor naming it.
///
/// Usually the whole of a mapping of its own. For a tile it is one `size`-byte
/// slice of a larger region, and the descriptor's limit is the tile's -- so 16-bit
/// code that runs off the end of tile `n` is stopped by the same bound as any
/// other segment, rather than sliding into tile `n + 1`.
pub(crate) struct Segment {
    mapping: Rc<Mapping>,
    /// Where this window starts within the mapping.
    at: usize,
    len: usize,
    entry: u32,
}

/// Point LDT `entry` at `len` bytes of memory starting at `base`.
fn describe(entry: u32, base: *const u8, len: usize, executable: bool) -> io::Result<()> {
    let contents = if executable {
        CONTENTS_CODE
    } else {
        CONTENTS_DATA
    };
    write_ldt(&UserDesc {
        entry_number: entry,
        base_addr: base as usize as u32,
        limit: (len - 1) as u32,

        // Every other bit is deliberately zero. seg_32bit clear is the
        // whole point: for code it clears D, making the default operand and
        // address size 16-bit; for a stack segment the same field is B,
        // declaring the stack pointer to be SP rather than ESP.
        // read_exec_only clear leaves code readable and data writable,
        // limit_in_pages clear keeps the limit in bytes, and
        // seg_not_present clear makes the descriptor live.
        flags: (contents << CONTENTS_SHIFT) | F_USEABLE,
    })
}

impl Segment {
    /// Map `len` bytes below 4 GiB and describe them as a 16-bit segment.
    ///
    /// `executable` picks between a readable code segment and a writable data
    /// segment; the latter is what `SS` requires.
    pub(crate) fn new(len: usize, executable: bool) -> io::Result<Self> {
        let mapping = Mapping::new(len, executable)?;
        let entry = take_ldt_run(1)?;

        if let Err(e) = describe(entry, mapping.base, len, executable) {
            give_ldt_run(entry, 1);
            return Err(e);
        }
        Ok(Self {
            mapping,
            at: 0,
            len,
            entry,
        })
    }

    /// One region of `qty * size` bytes, described by `qty` **consecutive**
    /// descriptors of `size` bytes each.
    ///
    /// This is `PLSTUFF.C`'s `pltile`, which is what `alctile` is: one
    /// `DosAllocLinMem`, then DPMI *Allocate LDT Descriptors* for `qty + 1`
    /// consecutive slots, then one `DosMapLinMemToSelector` per tile stepping
    /// the address by the tile size.
    ///
    /// Adjacency is the whole contract. The module reaches tile `n` by adding
    /// `n * `[`SELECTOR_STEP`](crate::SELECTOR_STEP) to the selector itself --
    /// `ptrtile` is `(long)bigptr + (index << 19)`, which is exactly that -- so
    /// the host is never told when a tile is used and cannot check it after
    /// the fact.
    pub(crate) fn tiled(qty: u16, size: u16) -> io::Result<Vec<Self>> {
        let qty = usize::from(qty);
        let size = usize::from(size);
        if qty == 0 || size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a tiled region of {qty} tiles of {size} bytes is nothing"),
            ));
        }

        let mapping = Mapping::new(qty * size, false)?;
        let start = take_ldt_run(qty as u32)?;

        let mut tiles = Vec::with_capacity(qty);
        for n in 0..qty {
            // SAFETY: `n * size` is within the mapping, which is `qty * size`.
            let base = unsafe { mapping.base.add(n * size) };
            if let Err(e) = describe(start + n as u32, base, size, false) {
                // Whatever was described already is in `tiles` and clears
                // itself; the rest of the run was never used, so it goes back
                // here.
                give_ldt_run(start + n as u32, (qty - n) as u32);
                return Err(e);
            }
            tiles.push(Self {
                mapping: Rc::clone(&mapping),
                at: n * size,
                len: size,
                entry: start + n as u32,
            });
        }
        Ok(tiles)
    }

    /// The selector naming this segment: index in bits 3..15, TI set to select
    /// the LDT rather than the GDT, RPL 3.
    ///
    /// The shift is [`crate::SELECTOR_STEP`]'s reason for existing, and the two
    /// have to agree: a host that steps selectors by a different amount walks
    /// off the end of the LDT rather than onto the next entry.
    pub(crate) fn selector(&self) -> u16 {
        ((self.entry as u16) * crate::SELECTOR_STEP) | 0x7
    }

    /// The LDT slot describing this segment.
    pub(crate) fn entry(&self) -> u32 {
        self.entry
    }

    /// The segment's length, which is also its bound.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Borrow `len` bytes at `offset`.
    ///
    /// # Panics
    ///
    /// If the range leaves the segment. Callers bounds-check first and report
    /// that as an error; reaching the panic is a host bug, not a module one.
    ///
    /// The check is `checked_add` rather than `offset + len`, because this
    /// guard stands directly in front of a `from_raw_parts` and a plain
    /// addition wraps in release. A caller that arrives with a length already
    /// underflowed to near `usize::MAX` makes `offset + len` wrap back to
    /// something small, and the assertion then *passes* on the way to
    /// constructing an unbounded slice at an out-of-bounds address. That is
    /// undefined behaviour reached through a bounds check, which is worse than
    /// having no bounds check at all -- it reads as safe. `Machine::arg_frame`
    /// could reach it before it was fixed to use `checked_sub`.
    pub(crate) fn slice(&self, offset: usize, len: usize) -> &[u8] {
        assert!(
            offset.checked_add(len).is_some_and(|end| end <= self.len),
            "slice past the end of the segment: {offset:#x} + {len:#x} \
             leaves a {} byte segment",
            self.len
        );
        // SAFETY: bounds checked, and the mapping is readable for its whole
        // length and outlives the borrow.
        unsafe { std::slice::from_raw_parts(self.at(offset), len) }
    }

    /// The mapping's linear address, for the far-jump targets that need one.
    pub(crate) fn linear(&self, offset: usize) -> u32 {
        debug_assert!(offset < self.len);
        self.at(offset) as usize as u32
    }

    /// Where `offset` within this segment is in the mapping underneath.
    fn at(&self, offset: usize) -> *mut u8 {
        // SAFETY: `self.at + self.len` is within the mapping by construction,
        // and every caller has bounds-checked `offset` against `self.len`.
        unsafe { self.mapping.base.add(self.at + offset) }
    }

    /// Write `bytes` at `offset` within the segment.
    pub(crate) fn write(&mut self, offset: usize, bytes: &[u8]) -> io::Result<()> {
        if offset + bytes.len() > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write past the end of the segment",
            ));
        }
        // SAFETY: bounds checked immediately above, and the mapping is writable.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.at(offset), bytes.len());
        }
        Ok(())
    }

    /// Read a little-endian `u16` at `offset`.
    pub(crate) fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= self.len, "read past the end of the segment");
        // SAFETY: bounds checked, and the mapping is readable. `read_unaligned`
        // because 16-bit code has no alignment obligations whatsoever.
        unsafe { self.at(offset).cast::<u16>().read_unaligned() }
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        // Descriptor first, mapping second, and the slot last of all. The order
        // is the whole point: a present descriptor over unmapped address space
        // is a selector that names memory which no longer exists, which is
        // precisely what the far-pointer bounds checks cannot catch. And the
        // slot must not become reusable until it describes nothing, or the next
        // allocation's descriptor could be overwritten by this one's clear.
        //
        // A failed clear therefore leaks both, on purpose: the mapping stays
        // ours, so the stale descriptor names memory we still hold rather than
        // whatever the allocator hands out next. There is no entry number this
        // can fail for that `take_ldt_run` could have produced, so reaching
        // here is a host bug and worth the abort.
        clear_ldt_entry(self.entry)
            .expect("could not clear an LDT entry; leaking its mapping rather than dangling it");

        // The mapping goes when the last descriptor over it does, which for a
        // tiled region is the last tile rather than this one -- so it is the
        // `Rc` that unmaps, after this.
        give_ldt_run(self.entry, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The LDT is process-wide, and so is the free list. These tests assert on
    /// *which* slot comes back, so they cannot run beside each other.
    static SERIALISE: Mutex<()> = Mutex::new(());

    /// `modify_ldt(2)` function code for reading the table back.
    const LDT_READ: i32 = 0;

    /// Bytes per LDT entry, as the CPU stores it -- not `user_desc`'s shape.
    const LDT_ENTRY_SIZE: usize = 8;

    /// The raw descriptor the kernel holds for `entry`.
    fn descriptor(entry: u32) -> [u8; LDT_ENTRY_SIZE] {
        let bytes = (entry as usize + 1) * LDT_ENTRY_SIZE;
        let mut table = vec![0u8; bytes];

        // SAFETY: the buffer is `bytes` long and the kernel is told so.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_modify_ldt,
                LDT_READ,
                table.as_mut_ptr(),
                bytes as libc::c_ulong,
            )
        };
        assert!(rc >= 0, "read_ldt: {}", io::Error::last_os_error());

        table[bytes - LDT_ENTRY_SIZE..].try_into().unwrap()
    }

    #[test]
    fn a_dropped_segment_leaves_no_live_descriptor() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let segment = Segment::new(4096, false).expect("a segment");
        let entry = segment.entry();
        assert_ne!(
            descriptor(entry),
            [0u8; LDT_ENTRY_SIZE],
            "a live segment has a live descriptor"
        );

        drop(segment);

        assert_eq!(
            descriptor(entry),
            [0u8; LDT_ENTRY_SIZE],
            "the descriptor still names the memory that was just unmapped"
        );
    }

    #[test]
    fn an_ldt_slot_is_reused_once_its_segment_is_gone() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let first = Segment::new(4096, false).expect("a segment");
        let entry = first.entry();
        drop(first);

        let second = Segment::new(4096, false).expect("another segment");
        assert_eq!(
            second.entry(),
            entry,
            "a freed slot should be handed out again before a fresh one"
        );
    }

    #[test]
    fn a_tiled_region_gets_consecutive_descriptors() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let tiles = Segment::tiled(6, 4096).expect("a tiled region");
        assert_eq!(tiles.len(), 6);
        for (n, tile) in tiles.iter().enumerate() {
            assert_eq!(
                tile.entry(),
                tiles[0].entry() + n as u32,
                "tile {n} is not adjacent to its neighbour"
            );
            // Which is the same thing said the way the module says it: step the
            // selector, because that is all `ptrtile` does.
            assert_eq!(
                tile.selector(),
                tiles[0].selector() + n as u16 * crate::SELECTOR_STEP
            );
        }
    }

    #[test]
    fn a_tile_windows_only_its_own_slice_of_the_region() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let mut tiles = Segment::tiled(3, 4096).expect("a tiled region");
        for (n, tile) in tiles.iter_mut().enumerate() {
            tile.write(0, &[n as u8; 16]).expect("in bounds");
        }

        // One region underneath: tile n's bytes are at n * size from the start.
        let start = tiles[0].linear(0) as usize;
        for (n, tile) in tiles.iter().enumerate() {
            assert_eq!(
                tile.slice(0, 1)[0],
                n as u8,
                "tile {n} reads back what was written through it"
            );
            assert_eq!(
                tile.linear(0) as usize,
                start + n * 4096,
                "tile {n} is not where the mapping says it is"
            );
        }

        // And the descriptor's limit is the tile's, not the region's, so
        // running off the end of one does not reach the next.
        assert_eq!(tiles[0].len(), 4096);
        assert!(tiles[0].write(4090, &[0; 16]).is_err());
    }

    #[test]
    fn a_run_stays_contiguous_after_the_table_is_fragmented() {
        // The reason the bump allocator had to go. It hands out consecutive
        // entries too -- right up until the first free, after which nothing
        // would have reported that it had stopped.
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let mut held: Vec<Option<Segment>> = (0..8)
            .map(|_| Some(Segment::new(4096, false).expect("a segment")))
            .collect();

        // Punch a two-entry hole, then ask for four.
        let hole = [
            held[2].as_ref().expect("held").entry(),
            held[3].as_ref().expect("held").entry(),
        ];
        held[2] = None;
        held[3] = None;

        let tiles = Segment::tiled(4, 4096).expect("a run of four");
        for (n, tile) in tiles.iter().enumerate() {
            assert_eq!(
                tile.entry(),
                tiles[0].entry() + n as u32,
                "tile {n} landed away from the run"
            );
            assert!(
                !hole.contains(&tile.entry()),
                "tile {n} took an entry from a hole too small for the run"
            );
        }
        drop(held);
    }

    #[test]
    fn a_tiled_region_of_nothing_is_refused() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(Segment::tiled(0, 4096).is_err());
        assert!(Segment::tiled(4, 0).is_err());
    }

    #[test]
    fn dropping_a_tiled_region_leaves_no_live_descriptor() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let tiles = Segment::tiled(4, 4096).expect("a tiled region");
        let entries: Vec<u32> = tiles.iter().map(Segment::entry).collect();
        drop(tiles);

        for entry in entries {
            assert_eq!(
                descriptor(entry),
                [0u8; LDT_ENTRY_SIZE],
                "entry {entry} still names the region that was just unmapped"
            );
        }
    }

    /// The bounds check must not be defeatable by the arithmetic inside it.
    ///
    /// `Machine::arg_frame` computed its length as `stack.len() - start`, which
    /// underflows once the frame begins past the end of the segment. In release
    /// that wraps to nearly `usize::MAX`, and with a plain `offset + len` the
    /// assertion then wraps *back* to exactly `self.len` and passes -- handing
    /// `from_raw_parts` an unbounded slice at an out-of-bounds address. The
    /// numbers here are that case: a 64 KiB segment, a frame starting three
    /// bytes past its end.
    #[test]
    #[should_panic(expected = "slice past the end of the segment")]
    fn a_length_that_has_already_wrapped_cannot_pass_the_bounds_check() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let segment = Segment::new(0x10000, false).expect("a 64 KiB segment");
        let start = 0x10003usize;
        let wrapped = segment.len().wrapping_sub(start);

        // The defeat, stated as an assertion so this test fails loudly if the
        // premise ever stops holding rather than passing for the wrong reason.
        assert_eq!(
            start.wrapping_add(wrapped),
            segment.len(),
            "the wrapped length must land back on len, or this tests nothing"
        );

        let _ = segment.slice(start, wrapped);
    }

    #[test]
    fn many_load_and_unload_cycles_do_not_exhaust_the_ldt() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        // Four times the whole table, in batches the size of a module load.
        // Without recycling this runs out on the hundredth batch.
        for _ in 0..400 {
            let batch: Vec<Segment> = (0..82)
                .map(|_| Segment::new(4096, false).expect("a segment"))
                .collect();
            drop(batch);
        }
    }
}
