//! `int 7Bh` -- Galacticomm's own Btrieve entry point, answered rather than
//! emulated.
//!
//! Task 8 seated the vector: `crate::kvm`'s stub table places `0x7B`'s trap
//! at the exact offset (`0x33`) `DFAAPI.C:925`'s presence probe requires. This
//! is what answers it once it fires -- the third edge onto
//! `btrieve::btrcall::btrcall`, after the Win32 one (`crate::win32::btrieve`)
//! and the in-process test harness (`crates/btrieve/src/btrcall.rs`'s own
//! tests).
//!
//! # The parameter block
//!
//! `re/wg33src/SRC/api/gcommlib/DFAAPI.C:119-130` declares `struct btvdat`,
//! 16-bit large model, every pointer far, 28 bytes:
//!
//! | off | field | size | note |
//! |---:|---|---:|---|
//! | 0 | `datbuf` | 4 | data buffer |
//! | 4 | `dbflen` | 2 | record length, **in and out** |
//! | 6 | `posp38` | 4 | `posblk + 38` -- a convenience sub-pointer the caller
//!   computes for its own later use; nothing here reads it, because
//!   [`field::POSBLK`] already resolves the whole 128-byte block |
//! | 10 | `posblk` | 4 | 128-byte position block |
//! | 14 | `funcno` | 2 | operation code |
//! | 16 | `key` | 4 | key buffer |
//! | 20 | `keylen` | 1 | `DFAAPI.C` always passes `255` |
//! | 21 | `keyno` | 1 | signed key number |
//! | 22 | `statpt` | 4 | pointer to a `USHORT` -- **the status is returned
//!   here, not in a register** |
//! | 26 | `magic` | 2 | `24950` |
//!
//! `DFAAPI.C:944-947` sets `DX = &btvdat`, forces `DS = SS`, then `int 7Bh` --
//! so the block lives on the guest's own stack and [`Regs::ds_dx`] is the
//! right way to find it.
//!
//! # `dbflen` is not `AX`
//!
//! Every other vector this crate answers reports its outcome in registers.
//! This one does not: the status word goes through `statpt`, a pointer
//! *inside the block itself*, and `dbflen` -- the record length -- is read
//! before the call and overwritten with what the engine actually used
//! afterward. Both are easy to get backwards, which is why [`dispatch`]
//! writes every field back explicitly rather than leaving anything to a
//! register the caller never asked to use.
//!
//! # A `Gap` is not a status, and an unrecognised block is not a Btrieve call
//!
//! [`btrieve::btrcall::Gap`] never becomes a plausible status word here, the
//! same rule `crate::win32::btrieve` already follows -- see that module's own
//! doc comment. And a block whose `magic` is not `24950` (`24950` is not a
//! forgeable accident: nothing else on this vector's other paths would
//! produce it) is not a Btrieve call at all, so it goes back the way
//! [`crate::fossil::Fossil`] reports a function it does not model: unclaimed,
//! not serviced, nothing written.

use dos::guest::{Fault, Guest, Ptr};
use dos::service::{Serviced, Service};

use btrieve::btrcall::{btrcall as engine_btrcall, Call, Gap};
use btrieve::mem::{Alloc, Mem};

/// What `DFAAPI.C:130` stamps into every `btvdat` it builds. Nothing else on
/// this vector's calling convention could plausibly produce this value by
/// accident, so it is the one honest way to tell "a Btrieve call we do not
/// yet answer correctly" from "not a Btrieve call at all".
const MAGIC: u16 = 24950;

/// Byte offsets within the 28-byte `btvdat`, `DFAAPI.C:119-130`. `POSP38`
/// (offset 6) is deliberately absent -- see this module's own doc comment on
/// why nothing here reads it.
mod field {
    pub const DATBUF: u16 = 0;
    pub const DBFLEN: u16 = 4;
    pub const POSBLK: u16 = 10;
    pub const FUNCNO: u16 = 14;
    pub const KEY: u16 = 16;
    pub const KEYLEN: u16 = 20;
    pub const KEYNO: u16 = 21;
    pub const STATPT: u16 = 22;
    pub const MAGIC: u16 = 26;
    pub const SIZE: u16 = 28;
}

/// Read a far pointer out of four bytes the way the 8086 itself stores one in
/// memory: the offset word at the lower address, the segment word above it.
fn ptr_from_far_bytes(b: &[u8]) -> Ptr {
    Ptr::new(u16::from_le_bytes([b[2], b[3]]), u16::from_le_bytes([b[0], b[1]]))
}

/// `field::AT + delta`, staying inside the same segment `at` already names.
///
/// Every use here is a fixed field offset within the one 28-byte block the
/// guest handed over, never an address a program computed and might have
/// let carry past a segment boundary, so the two possible readings of
/// "advance a real-mode offset" cannot disagree at any call site in this
/// file. `wrapping_add` is still the one that is *honest* about which
/// reading this is: real 8086 offset arithmetic never touches the segment
/// half on its own, so an offset that did run past `0xffff` would wrap
/// within the segment rather than spill into it, and silently normalising
/// into the segment instead would be inventing carry behaviour real mode
/// does not have.
fn field_ptr(at: Ptr, delta: u16) -> Ptr {
    Ptr::new(at.seg, at.off.wrapping_add(delta))
}

/// The [`btrieve::mem::Mem`] implementation over a DOS guest's real-mode
/// memory.
///
/// A marker type, never constructed: every method [`Mem`] declares is an
/// associated function, so nothing here needs an instance -- the same shape
/// [`crate::win32::btrieve::Win32Mem`] and `crates/btrieve/src/testing.rs`'s
/// `Flat` already use. Generic over `G` because that is where the *real*
/// memory lives: a DOS guest exposes its memory only through
/// [`dos::guest::Guest`]'s `read`/`write`, not as a separate owned buffer a
/// `Mem::Memory` type could name on its own, so `Self::Memory` is `G` itself
/// and [`Mem::resolve`]/[`Mem::write`] delegate straight to it -- which is
/// also where the required bounds check actually happens: `G::read`/`G::write`
/// already refuse a span that runs past the guest's own memory, so nothing
/// here needs to re-derive that from a caller-supplied length.
#[derive(Debug)]
pub struct DosMem<G>(std::marker::PhantomData<G>);

impl<G: Guest> Mem for DosMem<G> {
    type Ptr = Ptr;
    type Memory = G;
    type Error = Fault;

    /// A far pointer: two words, but they are a segment and an offset, not
    /// one 32-bit linear address -- see [`Mem::ptr_offset`]'s doc comment for
    /// why that distinction is not academic here.
    const PTR_WIDTH: usize = 4;

    fn null_ptr() -> Ptr {
        Ptr::new(0, 0)
    }

    fn ptr_to_bytes(p: Ptr) -> Vec<u8> {
        // Offset word first, segment word second -- the same layout a real
        // 8086 `far *` occupies in memory, and the layout `ptr_from_bytes`
        // below must invert exactly.
        let mut v = p.off.to_le_bytes().to_vec();
        v.extend_from_slice(&p.seg.to_le_bytes());
        v
    }

    fn ptr_from_bytes(b: &[u8]) -> Ptr {
        ptr_from_far_bytes(b)
    }

    /// `base`'s offset advanced by `delta`, wrapping within `base`'s segment.
    ///
    /// **Deliberately wrap, not normalise into the segment.** The one caller
    /// of this in `crates/btrieve/src/lib.rs` (`M::ptr_offset(at, field::FILNAM)`)
    /// is always a fixed field offset inside one just-allocated `struct
    /// btvblk` -- at most `field::SIZE` (196) bytes -- so a real overflow
    /// past `0xffff` can never actually happen at that call site. What
    /// matters is which *reading* of real-mode arithmetic this claims to be:
    /// on real 8086 hardware, advancing a 16-bit offset with an ordinary
    /// `add` never touches the segment register on its own -- there is no
    /// carry out of the offset into the segment, ever, for register
    /// arithmetic. Normalising here (`seg += carry, off = wrapped`) would be
    /// a segment:offset *pointer normalisation* a DOS memory manager might
    /// perform, not what this call site's own arithmetic does; picking it
    /// silently would make this function correct today and quietly wrong the
    /// day a caller relies on real 8086 wraparound instead.
    fn ptr_offset(base: Ptr, delta: u16) -> Ptr {
        field_ptr(base, delta)
    }

    fn resolve<'m>(p: Ptr, memory: &'m G, len: usize) -> Result<&'m [u8], Fault> {
        memory.read(p, len)
    }

    fn write(p: Ptr, memory: &mut G, bytes: &[u8]) -> Result<(), Fault> {
        memory.write(p, bytes)
    }
}

/// A bump allocator over a fixed window of a DOS guest's memory, for
/// `btrieve::mem::Alloc<DosMem<G>>`.
///
/// `Guest` has no allocator of its own to delegate to -- unlike
/// [`crate::win32::btrieve::Win32Heap`], which wraps a real bump allocator
/// already living on `mbbs_machine::m32::Memory`, a DOS guest here is just
/// bytes a loader (`crate::mz`) placed a program and a stack into. Where this
/// heap's window sits in a *running* guest's address space is Task 10's
/// concern (composing this service into `bin/runexe.rs`); this type only
/// needs a base and a size to hand out non-overlapping spans within one
/// segment.
///
/// Never frees, for the same reason `Win32Heap` never does: this crate opens
/// a bounded number of Btrieve files and the window's fixed capacity is what
/// says so loudly -- by refusing an allocation -- if that assumption ever
/// breaks, rather than quietly handing back a block still in use.
#[derive(Debug)]
pub struct DosHeap {
    base: Ptr,
    capacity: u16,
    cursor: u16,
}

impl DosHeap {
    /// A heap of `capacity` bytes, all within `base`'s segment.
    #[must_use]
    pub fn new(base: Ptr, capacity: u16) -> Self {
        Self { base, capacity, cursor: 0 }
    }
}

impl<G: Guest> Alloc<DosMem<G>> for DosHeap {
    fn reserve(&mut self, _memory: &mut G, size: u16) -> Result<Ptr, String> {
        let end = self
            .cursor
            .checked_add(size)
            .ok_or_else(|| format!("allocation of {size} bytes overflows this heap's cursor"))?;
        if end > self.capacity {
            return Err(format!(
                "no room for {size} bytes: {} of {} left",
                self.capacity - self.cursor,
                self.capacity
            ));
        }
        let at = field_ptr(self.base, self.cursor);
        self.cursor = end;
        Ok(at)
    }

    fn free(&mut self, _at: Ptr) -> Result<(), String> {
        Ok(())
    }
}

/// What became of one `int 7Bh`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// Answered: the position block, data buffer, `dbflen` and key buffer
    /// were all written back, and the status went through `statpt`.
    Done,
    /// Not serviced -- either the block's `magic` did not match, so this was
    /// never a Btrieve call, or it did match and named an operation code
    /// [`btrieve::btrcall::btrcall`] does not model (a [`Gap`]). Neither case
    /// writes anything back: see this module's own doc comment on why a
    /// `Gap` must never be laundered into a status word. Carries the block's
    /// own `funcno` so a caller can report which operation this was, the
    /// same way [`crate::fossil::Answer::Unsupported`] carries its function
    /// number.
    Unclaimed(u16),
}

/// Answer one `int 7Bh`.
///
/// # Errors
///
/// [`Fault`] if the guest handed over a pointer that does not name real
/// memory -- the 28-byte block itself, its position block, data buffer, key
/// buffer or `statpt`.
pub fn dispatch<G: Guest>(
    guest: &mut G,
    session: &mut btrieve::Btrieve<DosMem<G>>,
    heap: &mut DosHeap,
) -> Result<Answer, Fault> {
    let at = guest.regs().ds_dx();
    let block = guest.read(at, usize::from(field::SIZE))?.to_vec();

    let field_u16 = |off: u16| {
        let i = usize::from(off);
        u16::from_le_bytes([block[i], block[i + 1]])
    };
    let field_ptr_at = |off: u16| {
        let i = usize::from(off);
        ptr_from_far_bytes(&block[i..i + 4])
    };

    let funcno = field_u16(field::FUNCNO);

    let magic = field_u16(field::MAGIC);
    if magic != MAGIC {
        // Not a Btrieve call. Nothing is read further and nothing is
        // written -- see this module's own doc comment.
        return Ok(Answer::Unclaimed(funcno));
    }

    let datbuf_ptr = field_ptr_at(field::DATBUF);
    let dbflen = field_u16(field::DBFLEN);
    let posblk_ptr = field_ptr_at(field::POSBLK);
    let key_ptr = field_ptr_at(field::KEY);
    let keylen = block[usize::from(field::KEYLEN)];
    let keyno = block[usize::from(field::KEYNO)] as i8;
    let statpt_ptr = field_ptr_at(field::STATPT);

    let mut posblk = [0u8; 128];
    posblk.copy_from_slice(guest.read(posblk_ptr, 128)?);

    // `dbflen` is the length *offered*; `datbuf` is only worth resolving if
    // there is something to resolve, the same guard the Win32 edge's
    // `read_args` applies to its own `dataLength`.
    let mut databuf: Vec<u8> = if dbflen == 0 {
        Vec::new()
    } else {
        guest.read(datbuf_ptr, usize::from(dbflen))?.to_vec()
    };
    let mut datalen: u32 = u32::from(dbflen);

    // `keylen` alone is not a reliable "is there a key buffer" signal --
    // `DFAAPI.C` passes the blanket `255` unconditionally, key buffer or not
    // -- so this checks the pointer first, exactly as
    // `crate::win32::btrieve::read_args` already does for the identical
    // reason.
    let mut keybuf: Vec<u8> = if keylen == 0 || key_ptr == Ptr::new(0, 0) {
        Vec::new()
    } else {
        guest.read(key_ptr, usize::from(keylen))?.to_vec()
    };

    let outcome = engine_btrcall(
        session,
        guest,
        heap,
        Call {
            op: funcno,
            posblk: &mut posblk,
            databuf: &mut databuf,
            datalen: &mut datalen,
            keybuf: &mut keybuf,
            keylen,
            keynum: keyno,
        },
    );

    let status = match outcome {
        Ok(status) => status,
        // A gap is never a status -- see this module's own doc comment.
        Err(Gap { what: _ }) => return Ok(Answer::Unclaimed(funcno)),
    };

    // Write every field an operation might have touched back -- the same
    // "always write all four" discipline `crate::win32::btrieve::btrcall`
    // documents and for the identical reason: there is no cheaper way to
    // know which of them changed than to always write them all.
    guest.write(posblk_ptr, &posblk)?;
    if !databuf.is_empty() {
        guest.write(datbuf_ptr, &databuf)?;
    }
    let dbflen_out = u16::try_from(datalen).unwrap_or(u16::MAX);
    guest.write(field_ptr(at, field::DBFLEN), &dbflen_out.to_le_bytes())?;
    if !keybuf.is_empty() {
        guest.write(key_ptr, &keybuf)?;
    }

    // The status does not go in a register -- it goes through `statpt`.
    guest.write(statpt_ptr, &(status.0 as u16).to_le_bytes())?;

    Ok(Answer::Done)
}

/// `int 7Bh`, composed the way `bin/runexe.rs` will use it (Task 10): a
/// [`Service`] wrapping a persistent Btrieve session and heap, so a caller
/// never has to know [`dispatch`] exists.
pub struct Btrieve<G: Guest> {
    session: btrieve::Btrieve<DosMem<G>>,
    heap: DosHeap,
}

impl<G: Guest> Btrieve<G> {
    /// A fresh session -- nothing open -- backed by `heap` for whatever an
    /// `Open` allocates.
    #[must_use]
    pub fn new(heap: DosHeap) -> Self {
        Self { session: btrieve::Btrieve::default(), heap }
    }
}

impl<G: Guest + 'static> Service<G> for Btrieve<G> {
    fn claims(&self) -> &[u8] {
        &[0x7b]
    }

    fn service(&mut self, vector: u8, g: &mut G) -> Serviced {
        match dispatch(g, &mut self.session, &mut self.heap) {
            Ok(Answer::Done) => Serviced::Continue,
            Ok(Answer::Unclaimed(op)) => Serviced::Unclaimed { vector, ah: op as u8 },
            Err(f) => Serviced::Fault(f),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dos::testguest::TestGuest;

    /// Every region this test writes into, spaced 4096 bytes apart in linear
    /// terms (`0x10` paragraphs) so none can ever overlap another, however
    /// large a single field's buffer is.
    const BLOCK_SEG: u16 = 0x1000;
    const POSBLK_SEG: u16 = 0x1010;
    const KEY_SEG: u16 = 0x1020;
    const STATPT_SEG: u16 = 0x1030;
    const DATABUF_SEG: u16 = 0x1040;
    const HEAP_SEG: u16 = 0x2000;

    /// The absolute path to a real Btrieve fixture -- the same
    /// `SAMPLE.DAT` `crates/btrieve/src/btrcall.rs`'s own
    /// `a_file_opens_reads_and_closes_through_numbers_alone` test opens.
    fn sample_dat() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../mbbs/tests/data/SAMPLE.DAT")
    }

    /// Lay out a 28-byte `btvdat` asking for `funcno` (Open, by default) on
    /// `SAMPLE.DAT`, and point the guest's `DS:DX` at it.
    ///
    /// **Deliberately does not use `field::*`.** If it did, a mutation that
    /// swapped two offsets in `field` would move the exact same way on both
    /// sides -- this helper would keep writing "posblk" wherever
    /// `field::POSBLK` currently says it lives, and `dispatch` would keep
    /// reading it from the same place, so the two could never disagree. The
    /// offsets below are copied straight out of `DFAAPI.C:119-130` -- the
    /// wire format itself, independent of whatever this module currently
    /// believes it is -- so a mutation to `field` has something fixed to
    /// contradict. `crate::win32::btrieve`'s own `read_args_puts_each_of_the_seven_in_its_own_field`
    /// test docments the identical trap for that edge.
    fn setup_open(guest: &mut TestGuest, magic: u16) {
        const DATBUF: usize = 0;
        const DBFLEN: usize = 4;
        const POSBLK: usize = 10;
        const FUNCNO: usize = 14;
        const KEY: usize = 16;
        const KEYLEN: usize = 20;
        const KEYNO: usize = 21;
        const STATPT: usize = 22;
        const MAGIC_OFF: usize = 26;

        let path = sample_dat();
        let mut key_bytes = path.to_string_lossy().into_owned().into_bytes();
        key_bytes.push(0);
        assert!(key_bytes.len() <= 255, "the fixture path must fit the key buffer");
        guest.poke(Ptr::new(KEY_SEG, 0), &key_bytes);

        // A sentinel so a test can tell "never written" from "written zero".
        guest.poke(Ptr::new(STATPT_SEG, 0), &0xdeadu16.to_le_bytes());

        let mut block = [0u8; 28];
        let put_ptr = |block: &mut [u8; 28], off: usize, p: Ptr| {
            block[off..off + 2].copy_from_slice(&p.off.to_le_bytes());
            block[off + 2..off + 4].copy_from_slice(&p.seg.to_le_bytes());
        };
        put_ptr(&mut block, DATBUF, Ptr::new(DATABUF_SEG, 0));
        block[DBFLEN..DBFLEN + 2].copy_from_slice(&64u16.to_le_bytes());
        put_ptr(&mut block, POSBLK, Ptr::new(POSBLK_SEG, 0));
        block[FUNCNO..FUNCNO + 2].copy_from_slice(&0u16.to_le_bytes()); // Open
        put_ptr(&mut block, KEY, Ptr::new(KEY_SEG, 0));
        block[KEYLEN] = 255;
        block[KEYNO] = 0;
        put_ptr(&mut block, STATPT, Ptr::new(STATPT_SEG, 0));
        block[MAGIC_OFF..MAGIC_OFF + 2].copy_from_slice(&magic.to_le_bytes());

        guest.poke(Ptr::new(BLOCK_SEG, 0), &block);

        let mut regs = guest.regs();
        regs.ds = BLOCK_SEG;
        regs.dx = 0;
        guest.set_regs(regs);
    }

    fn service() -> Btrieve<TestGuest> {
        Btrieve::new(DosHeap::new(Ptr::new(HEAP_SEG, 0), 4096))
    }

    #[test]
    fn open_answers_status_zero_through_statpt() {
        let mut guest = TestGuest::new(1 << 20);
        setup_open(&mut guest, MAGIC);
        let mut svc = service();

        assert_eq!(svc.service(0x7b, &mut guest), Serviced::Continue);

        let status = u16::from_le_bytes(guest.peek(Ptr::new(STATPT_SEG, 0), 2).try_into().unwrap());
        assert_eq!(status, 0, "Open succeeded, and the status went through statpt");

        let posblk = guest.peek(Ptr::new(POSBLK_SEG, 0), 4);
        assert_ne!(posblk, [0, 0, 0, 0], "Open recorded a handle in the position block");
    }

    #[test]
    fn a_block_whose_magic_does_not_match_is_refused_not_serviced() {
        let mut guest = TestGuest::new(1 << 20);
        setup_open(&mut guest, MAGIC.wrapping_add(1));
        let mut svc = service();

        assert_eq!(
            svc.service(0x7b, &mut guest),
            Serviced::Unclaimed { vector: 0x7b, ah: 0 }
        );

        let status = u16::from_le_bytes(guest.peek(Ptr::new(STATPT_SEG, 0), 2).try_into().unwrap());
        assert_eq!(status, 0xdead, "a refused block must not write a status anywhere");

        let posblk = guest.peek(Ptr::new(POSBLK_SEG, 0), 4);
        assert_eq!(posblk, [0, 0, 0, 0], "and must not touch the position block either");
    }

    #[test]
    fn btrieve_claims_only_int_7bh() {
        let svc = service();
        assert_eq!(Service::<TestGuest>::claims(&svc), &[0x7b]);
    }
}
