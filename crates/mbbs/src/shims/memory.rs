//! Memory: the heap, the tiles, and the four leaves that move bytes about.
//!
//! Every memory-related import `WCCMMUD.DLL` has, with call-site counts:
//!
//! ```text
//! galfree      90    alctile      12    memcpy       4
//! setmem       59    ptrtile      12    movmem       3
//! alczer       51    farcoreleft  11    alcmem       3
//!                                       memcmp       2
//! ```
//!
//! That is the whole surface. **No `alcrsz`, no `alcdup`, no `alcblok`, no
//! `malloc`**, so realloc, strdup and the block API are all out of scope and
//! stay unimplemented, poisoning by name.
//!
//! What backs the heap, and why the block sizes are kept out of the module's
//! reach, is [`crate::heap`].
//!
//! # Two argument orders that corrupt silently
//!
//! `GCOMM.H` defines two of these as macros over the C library, and both
//! reverse an order everyone has memorised:
//!
//!
//! Neither mistake fails; both write the wrong bytes and are noticed much
//! later, somewhere else. So their tests use a count and a fill value that
//! differ, and a source and destination that differ -- a test written
//! `setmem(p, 4, 4)` would pass either way.

use mbbs_machine::m16::FarPtr;
use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16, Wg32};
use crate::shims::ShimError;

// # Argument width
//
// `A::Int` is `u16` under `Wg16` and `u32` under `Wg32`, the same shape
// `shims::gsbl` already audited in full
// (`docs/2026-08-14-gsbl-width-audit.md`). This file has the same two
// surviving buckets that document names: a byte count with nothing
// narrower behind it (`memcpy`, `memcmp`, `movmem` and `setmem`'s `count`
// -- "genuinely wide", read whole with [`count_arg`]) and a size this
// crate's own [`Heap`](crate::heap::Heap) already commits to sixteen bits
// regardless of `A` (`alcmem`/`alczer`'s `size` -- "16-bit host model",
// read with [`heap_size_arg`], which refuses rather than truncates).
// `setmem`'s fill byte is the third, "genuinely narrow" bucket -- a `char`
// argument that only ever contributes its low byte, exactly like
// `memset`'s own `c` parameter -- and needs no checked reader because
// every value of that byte is already valid.

/// Read a byte count at `A`'s own int width, never narrowed.
///
/// `memcpy`, `memcmp`, `movmem` and `setmem`'s counts are not stored in any
/// field narrower than the `usize`
/// [`ModulePtr::resolve`]/[`ModulePtr::write`] already take -- there is
/// nothing to refuse, so this widens rather than truncates. Same shape as
/// `shims::gsbl`'s `usize_arg`; extracted here because four call sites read
/// it, not one.
fn count_arg<A: Abi>(v: A::Int) -> usize {
    Into::<u32>::into(v) as usize
}

/// Read a `size`/`nbytes` argument, refusing rather than truncating if it
/// does not fit the `u16` [`Heap::reserve`](crate::heap::Heap::reserve)
/// takes regardless of `A` -- this crate's own heap model, committed to
/// sixteen bits independent of what `Wg32`'s `int` can carry, the same
/// shape `shims::gsbl`'s `u16_arg` documents
/// (`docs/2026-08-14-gsbl-width-audit.md`).
fn heap_size_arg<A: Abi>(v: A::Int) -> Option<u16> {
    u16::try_from(Into::<u32>::into(v)).ok()
}

/// `VOID *alcmem(UINT size)` -- `GCOMM.H:256-258` -- reserve memory the
/// module will free.
///
/// A `size` of zero, or a heap with no room, is a refusal. The real host
/// returned null for both, and step 7's trace is what that costs: `alczer`
/// answered null at call 183 and the module dereferenced it eighteen calls
/// later, where the fault named module code rather than the lie.
///
/// Generic (Task 5): [`Heap::reserve`](crate::heap::Heap::reserve) is
/// already `impl<A: Abi> Heap<A>` -- unlike the `Wg16`-only `alloc` facade
/// this used to call (deleted in Task 13 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`, once nothing else
/// called it), it takes `&mut A::Mem` straight from [`Call::mem`] rather
/// than a whole `&mut Machine`.
pub fn alcmem<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = heap_size_arg::<A>(call.int())
        .ok_or_else(|| ShimError::Failed("alcmem: size does not fit this heap's u16 block size".to_owned()))?;
    let at = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("alcmem: {e}")))?;
    Ok(abi::Ret::Ptr(at))
}

/// `VOID *galmalloc(UINT size)` -- `GCOMM.H:768-769` -- "Galacticomm's
/// malloc() for debugging."
///
/// Task 5's question: does this differ observably from [`alcmem`]? Reading
/// `re/wg33src/SRC/api/gcommlib/GALMEMDB.C` in full says no. Its body forks
/// on `#ifdef GCWINNT` and `#ifdef DEBUG`, but neither fork is the one a
/// shipped, non-debug module links against. That branch -- `DEBUG` and
/// `GCWINNT` both undefined, which is every `GCDOSP`/RTSLORD-class build --
/// is exactly:
///
///
/// `nmalloc`/`lstalcsiz` are `GCOMMLIB`'s own static counters; the only thing
/// that reads them, `memdbgrpt`, is not among the 49 symbols this track
/// serves -- no surveyed build imports it -- so a module calling `galmalloc`
/// cannot observe them at all. Strip the bookkeeping a module can never see
/// and what is left is `malloc(size)`, which is [`alcmem`]'s entire body too
/// (`ALCMEM.C`: `malloc(size)`, `memcata()` on failure). So this delegates
/// rather than duplicating a body that would be identical, per this task's
/// own instruction.
///
/// The one place the two vendor bodies genuinely disagree is the failure
/// path: `galmalloc` returns the raw `NULL` `malloc` gave it, `alcmem` calls
/// `memcata()` (a catastrophic-error path). This host's own [`alcmem`]
/// already turns a failed [`Heap::reserve`] into a `ShimError` rather than a
/// null pointer -- "No plausible zeros" -- which is closer in spirit to
/// `memcata()`'s own catastrophic intent than to `galmalloc`'s bare `NULL`.
/// Delegating means `galmalloc` inherits that refusal too.
pub fn galmalloc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    alcmem(call, host)
}

/// `VOID *alczer(UINT nbytes)` -- `GCOMM.H:274-276` -- reserve memory, zeroed.
///
/// Zeroed here rather than assumed: reused space holds whatever the last owner
/// left, and a module that trusts `alczer` and gets `alcmem` finds out slowly.
///
/// Generic (Task 5): same [`Heap::reserve`](crate::heap::Heap::reserve) core
/// as [`alcmem`], and the zero-fill writes through
/// [`mbbs_machine::ptr::ModulePtr::write`] on [`Call::mem`] rather than
/// `Machine::write`.
pub fn alczer<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = heap_size_arg::<A>(call.int())
        .ok_or_else(|| ShimError::Failed("alczer: size does not fit this heap's u16 block size".to_owned()))?;
    let at = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("alczer: {e}")))?;
    // `A::Ptr::Error` has no `From` into `ShimError` for an arbitrary `A` --
    // only `Wg16`'s `FarPtrError` does -- so this is `map_err`, not `?`,
    // unlike the `Wg16`-only original (`shims::user::haskey`'s own comment
    // has the same note).
    at.write(call.mem(), &vec![0u8; usize::from(size)])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `VOID galfree(VOID *block)` -- `GCOMM.H:771-773` -- give memory back.
///
/// Generic (Task 5): [`Heap::free`](crate::heap::Heap::free) never touched a
/// `Machine`, so this was already `impl<A: Abi> Heap<A>` before this task.
///
/// # A null block is a no-op, not a refusal
///
/// `GALMEMDB.C:183` does carry `ASSERTM(block != NULL,"Can't free() a NULL
/// pointer!")` -- but it sits inside `#ifdef DEBUG`, and the 16-bit branch a
/// shipped host compiles is `free(block); nmfree++;` with nothing in front of
/// it. ANSI C defines `free(NULL)` as doing nothing, so the real host
/// swallowed a null free silently and carried on.
///
/// Refusing it made this host stricter than the one it reproduces, and the
/// cost was not theoretical: on a live board a background `rtkick` freed a
/// null, `galfree` refused, and the refusal stopped the whole module --
/// which from a player's seat is an unexplained disconnect. Everything
/// *else* still refuses, including a stray pointer into the middle of a live
/// block and a double free; only the vendor's own documented no-op is
/// allowed through.
pub fn galfree<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    if at == A::null_ptr() {
        return Ok(abi::Ret::Void);
    }
    host.heap
        .free(at)
        .map_err(|e| ShimError::Failed(format!("galfree: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `LONG farcoreleft(VOID)` -- `GCOMM.H:147` -- how much memory is left.
///
/// A policy, not a fact: modules size their caches off this. See
/// [`Config::heap`](crate::Config::heap) for what the number is and why.
///
/// Generic (Task 5): [`Heap::left`](crate::heap::Heap::left) never touched a
/// `Machine` either, and reads no argument -- the `call` parameter is unused.
pub fn farcoreleft<A: Abi>(
    _call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    let left = host.heap.left();
    Ok(abi::Ret::Long(u32::try_from(left).unwrap_or(u32::MAX)))
}

/// `ULONG sizmem(VOID)` -- `GCOMM.H:706-707` -- "gets available memory."
///
/// `re/wg33src/SRC/api/gcommlib/SIZMEM.C` (Worldgroup 3.3) forks the same
/// way [`galmalloc`]'s source does: `#ifdef GCDOS` is `return
/// farcoreleft();` -- an exact alias, nothing new to write. The `#else`
/// (`GCWINNT`) branch calls `GlobalMemoryStatus` and returns the real
/// Windows NT host's available physical RAM, which has no honest answer
/// here: this host is not a process sharing physical memory with anything a
/// module could observe, and [`farcoreleft`]'s own doc comment already
/// states what the number is *for* -- "modules size their caches off it," a
/// policy, not a fact. Answering with this module's own remaining heap,
/// exactly what `farcoreleft` already answers, is the honest number for
/// both branches: it is what SIZMEM.C's GCDOS branch always did, and it is
/// the only figure the GCWINNT branch's real answer was ever a proxy for
/// (how much a module may still allocate) rather than a fact about a
/// physical machine this host does not have.
///
/// Generic, even though the survey found `sizmem` imported only by a
/// 32-bit build ("sizmem is 32-bit-only (Rose32)" -- Task 5, Step 1): the
/// body is not ABI-specific, so there is nothing to withhold from `Wg16`.
pub fn sizmem<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    farcoreleft(call, host)
}

/// `void *alctile(int qty, int size)` -- one region of `qty` tiles.
///
/// `PLSTUFF.C`: `bigptr = MK_FP(pltile(qty*(long)size, 0, size, size), 0)`. One
/// linear region, `qty` consecutive LDT descriptors across it, each a `size`
/// window. The module walks between tiles itself, so every descriptor has to
/// exist first -- see [`Machine::alloc_tiled`](mbbs_machine::m16::Machine::alloc_tiled).
pub fn alctile(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
) -> Result<abi::Ret<Wg16>, ShimError> {
    // No vendor prototype: `alctile` is not declared anywhere in
    // re/wg33src/INC's 125 headers. It is genuinely 16-bit-only -- segment
    // tiling has no flat-memory counterpart -- and the 32-bit module imports
    // `alcblok`/`ptrblok` instead, which are among the 56 unimplemented
    // symbols and out of scope here.
    let qty = call.int();
    let size = call.int();
    let at = host
        .heap
        .alloc_tiled(call.cpu, qty, size)
        .map_err(|e| ShimError::Failed(format!("alctile({qty}, {size}): {e}")))?;
    Ok(abi::Ret::Ptr(at))
}

/// [`Heap::alloc_tiled`](crate::heap::Heap::alloc_tiled)'s `Wg16` facade --
/// `alctile`'s host half, kept beside its one production caller now that
/// [`Heap`](crate::heap::Heap) itself is generic top to bottom (Task 13 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`; see that module's
/// doc comment). No generic core to delegate into: LDT tile chaining
/// (`Machine::alloc_tiled`) has no 32-bit counterpart -- `alcblok`/`ptrblok`
/// are a different mechanism entirely, out of scope here, the same reason
/// `alctile`/`ptrtile` above are concrete rather than `<A: Abi>`.
impl crate::heap::Heap<Wg16> {
    /// # Errors
    ///
    /// If the region cannot be mapped or the LDT has no run that long.
    pub fn alloc_tiled(
        &mut self,
        machine: &mut mbbs_machine::m16::Machine,
        qty: u16,
        size: u16,
    ) -> Result<mbbs_machine::m16::FarPtr, String> {
        let at = machine.alloc_tiled(qty, size).map_err(|e| e.to_string())?;
        self.push_tile(crate::heap::Region {
            selector: at.selector,
            qty,
            size,
        });
        Ok(at)
    }
}

/// `void *ptrtile(void *bigptr, int index)` -- the `index`th tile of a region.
///
///
/// A far pointer is a 32-bit value with the selector in the high word, so
/// `+ (index << 19)` is `+ index * 8` **on the selector** -- which is
/// [`SELECTOR_STEP`](mbbs_machine::m16::SELECTOR_STEP), and the same shift `DOSCALLS.135`
/// hands the module to fold inline.
///
/// The module computes this itself at most of the twelve call sites and only
/// calls through here at some, so this must agree with the arithmetic exactly.
/// An index past the last tile is refused: without the region's shape the host
/// would hand back a selector belonging to something else entirely.
pub fn ptrtile(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
) -> Result<abi::Ret<Wg16>, ShimError> {
    // No vendor prototype either, for the same reason as `alctile` above.
    let base = call.ptr();
    let index = call.int();

    let region = host.heap.region(base.selector).ok_or_else(|| {
        ShimError::Failed(format!("ptrtile: {base:?} is not a tiled region"))
    })?;
    if index >= region.qty {
        return Err(ShimError::Failed(format!(
            "ptrtile: tile {index} of a {}-tile region",
            region.qty
        )));
    }

    Ok(abi::Ret::Ptr(FarPtr {
        offset: base.offset,
        selector: base.selector + index * mbbs_machine::m16::SELECTOR_STEP,
    }))
}

// # alcblok/ptrblok/freblok: two byte-compatible headers, not one generic one
//
// The first version of this trio used one generic header shape (a `u32`
// `qty` regardless of `A`) for both ABIs, on the reasoning that every
// primitive underneath -- Heap::reserve, Abi::ptr_to_bytes/ptr_from_bytes,
// Abi::ptr_checked_add -- is already generic. That was true and still is,
// but it missed something the vendor's own two bodies do not miss: a
// hand-rolled `Wg32` module *can* compute `bigptr+8+size*idx` itself rather
// than calling ptrblok (`ALCBLOK.C`'s flat branch is exactly that
// expression), and the generic header put `size` at byte offset 4 -- not
// offset 0, where the vendor's own flat header puts it -- so such a module
// would silently read the low half of a `qty` field it does not know
// exists. Nothing in this track's survey shows a module doing that, but
// "we found no evidence" is not the same claim as "the layouts agree," and
// the second one is free to have here: both vendor branches leave dead
// space this host's own extra bookkeeping (`qty`, for the bounds check the
// vendor cannot do) fits into exactly, at the offsets that were already
// spare. So each ABI's header is now **byte-for-byte identical to that
// ABI's own vendor branch**, and `alcblok`/`ptrblok`/`freblok` are three
// pairs of ABI-concrete functions -- like `alctile`/`ptrtile`, not the
// generic `routines()` shape -- rather than one generic trio. See
// [`wg16_blok_header`] and [`wg32_blok_header`] for the two layouts, and
// the "layout" tests in this module for byte-exact assertions of both.

/// `ALCBLOK.C`: `size=(size+1)&0xFFFE;` -- round an element size up to the
/// next even boundary, in both vendor branches (the DOS branch does it
/// explicitly; the flat branch's own `USHORT` element size field has the
/// same shape). `None` for a raw size of 0, or the one pathological input
/// (`0xFFFF`) that rounds *down* to 0 -- computed in `u32` so `0xFFFF + 1`
/// does not wrap back to itself first.
fn rounded_blok_size(raw: u16) -> Option<u16> {
    let rounded = ((u32::from(raw) + 1) & 0xFFFE) as u16;
    (rounded != 0).then_some(rounded)
}

/// `ALCBLOK.C`: `each=MAXMALLOC/size;` -- the most `size`-byte elements
/// that fit in one allocation. `MAXMALLOC` there is a DOS `malloc()`'s own
/// empirical ceiling (65,524); here it is this crate's own
/// [`Heap::reserve`] ceiling, `u16::MAX` -- the most either ABI's single
/// `reserve` call can ever hand back, since `heap.rs`'s `SEGMENT` constant
/// is not `Abi`-scoped (see that module's doc comment). `size >= 2` always
/// holds by the time this is called ([`rounded_blok_size`] guarantees it),
/// so the result is always at least 1 and always fits `u16`.
fn elements_per_glob(size: u16) -> usize {
    usize::from(u16::MAX) / usize::from(size)
}

/// Encode `alcblok`'s `Wg16` header, byte-for-byte identical to
/// `ALCBLOK.C`'s own `struct blokhdr`:
///
///
/// `numblk` is a plain `USHORT` in the struct **and** `qty` is a `USHORT`
/// parameter to `alcblok` itself (`GCOMM.H:485`) -- a `Wg16` module cannot
/// pass more than 65,535 in the first place, so storing it any wider than
/// the vendor does would carry a value no caller can ever supply. (This
/// undoes the first version's `u32 qty`, which bought nothing and put
/// every field at the wrong offset besides.)
fn wg16_blok_header(qty: u16, size: u16, each: u16, globs: &[FarPtr]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + globs.len() * 4);
    bytes.extend_from_slice(&qty.to_le_bytes()); // numblk, offset 0
    bytes.extend_from_slice(&size.to_le_bytes()); // sizblk, offset 2
    bytes.extend_from_slice(&each.to_le_bytes()); // each, offset 4
    for glob in globs {
        bytes.extend_from_slice(&glob.to_bytes()); // segarray[..], offset 6..
    }
    bytes
}

/// Encode `alcblok`'s `Wg32` header, byte-for-byte identical to
/// `ALCBLOK.C`'s own flat (non-`GCDOS`) branch at the one offset it ever
/// writes:
///
///
/// `size` sits at offset 0, exactly where the vendor puts it, so a `Wg32`
/// module computing `size = *(USHORT *)bigptr` itself -- bypassing
/// [`ptrblok32`] -- reads the value it expects to. `qty` (a `u32`: `alcblok`'s
/// `qty` is `unsigned`, 32 bits wide under `Wg32`, so unlike `Wg16` a caller
/// really can pass more than 65,535) lives at offset 2, in the six bytes
/// `alczer` already zeroed and the vendor's own body never writes to again
/// -- this host's only addition, needed for the bounds check the vendor's
/// flat branch cannot do (see this module's own "byte-compatible headers"
/// note). Bytes 6..8 stay zero, matching the vendor's own untouched dead
/// space; element 0 sits at `bigptr+8` either way.
fn wg32_blok_header(size: u16, qty: u32) -> [u8; 6] {
    let mut bytes = [0u8; 6];
    bytes[0..2].copy_from_slice(&size.to_le_bytes());
    bytes[2..6].copy_from_slice(&qty.to_le_bytes());
    bytes
}

/// `void *alcblok(unsigned qty, unsigned size)` -- `GCOMM.H:485`, `Wg16`
/// side -- an array of `qty` elements of `size` bytes, together bigger
/// than one selector can window.
///
/// From `re/wg33src/SRC/api/gcommlib/ALCBLOK.C` (Worldgroup 3.3)'s
/// `#ifdef GCDOS` branch (DOS Large Model or DOS Protected Mode,
/// `GCCUROS.H:18-19,36-38` -- this host's `Wg16`). See [`alcblok32`] for
/// the `Wg32` counterpart and this module's "byte-compatible headers" note
/// for why these are two functions, not one generic one.
///
/// # No element ever spans a 64 KiB boundary -- that is the reason this branch is shaped the way it is
///
/// `alctile`'s own doc comment explains why a *region* spanning many tiles
/// needs one LDT descriptor per tile: the module walks between tiles
/// itself by adding to the selector, so every tile has to start at offset
/// 0. `alcblok` shares none of that -- a module never walks a blocked
/// region, it always asks [`ptrblok`] -- and `ALCBLOK.C`'s own file header
/// says as much: "more efficient with selectors than alctile()/ptrtile(),
/// but the latter assures 0-offsets on all pieces." `alcblok` deliberately
/// trades that guarantee away: [`elements_per_glob`] computes the most
/// `size`-byte elements that fit in one allocation, and that many are
/// packed into each of a chain of "globs" (`segarray[]`). An element's
/// offset inside its glob (`blokoff * sizblk`) can never reach `0x10000`,
/// because `each * sizblk` is bounded by construction -- so within one glob
/// the near-pointer arithmetic is safe for the same reason [`ptrtile`]'s
/// far-pointer arithmetic is, by a different mechanism. Only the
/// *aggregate* -- `qty * size`, arbitrarily larger than 64 KiB -- ever
/// spans more than one region, across as many globs as it takes. That
/// aggregate-spans-many-segments-but-no-element-ever-does shape is
/// `alcblok`'s whole reason to exist over `alcmem`.
///
/// # The header
///
/// See [`wg16_blok_header`] for the byte-exact layout: `numblk`/`sizblk`/
/// `each` as `USHORT`s at offsets 0/2/4, `segarray` (this host's own
/// [`FarPtr`]s, 4 bytes each) from offset 6 -- `ALCBLOK.C`'s own
/// `struct blokhdr`, field for field. `alcblok`'s return value is that
/// header's own address, not element 0's: the DOS branch's `bigptr` is a
/// `blokhdr*`, never inside any glob at all.
///
/// A zero `qty` or `size` is refused rather than answered with a block
/// nothing can index -- "No plausible zeros" -- where the vendor's own
/// `ASSERT(qty != 0)`/`ASSERT(size != 0)` compile to `(VOID)0` outside
/// `DEBUG` and a shipped host would have divided by zero computing `each`.
///
/// # The one remaining, deliberate divergence: bounds-checking
///
/// With the layout now byte-identical to the vendor's own, the only
/// behavioural difference left is that [`ptrblok`] always bounds-checks
/// `idx` against `numblk` -- something this branch's own vendor body also
/// does (`if (idx >= thptr->numblk) return(NULL);`), so `Wg16` was never
/// actually diverging here. See [`alcblok32`]'s own doc comment for where
/// the real divergence lives: the flat branch's header has no `numblk` at
/// all, so its own `ptrblok` cannot check anything.
pub fn alcblok(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let qty = call.int();
    let raw_size = call.int();

    if qty == 0 {
        return Err(ShimError::Failed("alcblok: 0 elements".to_owned()));
    }
    let size = rounded_blok_size(raw_size).ok_or_else(|| {
        ShimError::Failed(format!(
            "alcblok: an element size of {raw_size} bytes cannot be blocked"
        ))
    })?;

    let each = elements_per_glob(size);
    let glob_count = usize::from(qty).div_ceil(each);

    let header_len = glob_count
        .checked_mul(4) // FarPtr::to_bytes() is 4 bytes
        .and_then(|n| n.checked_add(6))
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "alcblok: {qty} elements of {raw_size} bytes needs a header bigger than this heap can give in one piece"
            ))
        })?;

    let header = host
        .heap
        .reserve(call.mem(), header_len)
        .map_err(|e| ShimError::Failed(format!("alcblok: {e}")))?;

    let mut globs = Vec::with_capacity(glob_count);
    let mut remaining = usize::from(qty);
    for _ in 0..glob_count {
        let n = remaining.min(each);
        let bytes = u16::try_from(n * usize::from(size))
            .expect("n <= each, and each * size <= u16::MAX by construction");
        let glob = host
            .heap
            .reserve(call.mem(), bytes)
            .map_err(|e| ShimError::Failed(format!("alcblok: {e}")))?;
        // ALCBLOK.C's DOS branch fills each glob through alczer, not
        // alcmem -- zeroed, for the same reason this file's own alczer is.
        glob.write(call.mem(), &vec![0u8; usize::from(bytes)])
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        globs.push(glob);
        remaining -= n;
    }

    let header_bytes = wg16_blok_header(qty, size, each as u16, &globs);
    header
        .write(call.mem(), &header_bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Ptr(header))
}

/// `void *ptrblok(void *bigptr, unsigned idx)` -- `GCOMM.H:486`, `Wg16`
/// side -- the address of element `idx` of an [`alcblok`] region. See
/// [`ptrblok32`] for the `Wg32` counterpart.
///
/// Reads the header [`alcblok`] wrote -- [`wg16_blok_header`]'s layout --
/// and repeats `ALCBLOK.C`'s own arithmetic exactly: `glob = idx / each;
/// blokoff = idx - glob * each`, then the glob's own base pointer offset by
/// `blokoff * size`.
///
/// # `NULL` is the vendor's own documented answer, not an absence of one
///
///
/// "No plausible zeros" forbids *inventing* a value this host does not
/// know -- it does not forbid returning the value the vendor's own body
/// returns when the vendor's own body is right there to read. A `NULL`
/// `bigptr` or an out-of-range `idx` answers `NULL` here, faithfully,
/// exactly like [`fsdfxt`](crate::shims::fsd::fsdfxt) took the same
/// correction. (The `ASSERT` fires ahead of the `NULL` check only in a
/// `DEBUG` build, which this is not, so a `NULL` `bigptr` reaches the
/// `NULL`-returning branch in every shipped build too.)
///
/// This is *not* the same case as a `bigptr` that is non-`NULL` but names no
/// segment of this module at all -- a stray or corrupted selector -- for
/// which the vendor's own body has no defined answer either (it would
/// simply dereference garbage). That case still refuses: there is nowhere
/// even to read a header from, the same way a `ptrtile` region the host
/// never tiled refuses. A `bigptr` that resolves fine but was never an
/// [`alcblok`] header at all (a stray pointer *into* real, readable module
/// memory) has no such clean discriminator, and is not specially detected.
pub fn ptrblok(call: &mut Call<Wg16>, _: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    // No host state: everything ptrblok needs -- qty, size, each and the
    // glob pointers -- lives in the module memory alcblok wrote.
    let bigptr = call.ptr();
    let idx = call.int();

    // ALCBLOK.C: `ASSERT(bigptr != NULL); ... if (thptr == NULL ...)
    // return(NULL);` -- outside DEBUG the ASSERT is `(VOID)0`, so a NULL
    // bigptr reaches the NULL check and answers NULL, not a crash and not
    // a refusal.
    if bigptr == FarPtr::NULL {
        return Ok(abi::Ret::Ptr(FarPtr::NULL));
    }

    let head = bigptr.resolve(call.mem(), 6).map_err(|e| {
        ShimError::Failed(format!("ptrblok: {bigptr:?} is not an alcblok header ({e})"))
    })?;
    let qty = u16::from_le_bytes(head[0..2].try_into().expect("resolved exactly 6 bytes"));
    let size = u16::from_le_bytes(head[2..4].try_into().expect("resolved exactly 6 bytes"));
    let each = usize::from(u16::from_le_bytes(head[4..6].try_into().expect("resolved exactly 6 bytes")));

    // ALCBLOK.C: `if (... idx >= thptr->numblk) return(NULL);` -- the
    // vendor's own documented answer, not a gap this host is filling in.
    if idx >= qty {
        return Ok(abi::Ret::Ptr(FarPtr::NULL));
    }
    let idx = usize::from(idx);

    let glob_index = idx / each;
    let blokoff = idx - glob_index * each;

    let glob_at = 6 + glob_index * 4;
    let with_glob = bigptr
        .resolve(call.mem(), glob_at + 4)
        .map_err(|e| ShimError::Failed(format!("ptrblok: {e}")))?;
    let glob = FarPtr::from_bytes(
        with_glob[glob_at..glob_at + 4]
            .try_into()
            .expect("resolved exactly 4 bytes"),
    );

    Wg16::ptr_checked_add(glob, blokoff * usize::from(size))
        .map(abi::Ret::Ptr)
        .ok_or_else(|| ShimError::Failed(format!("ptrblok: element {idx} overflows its glob")))
}

/// `VOID freblok(VOID *bigptr)` -- `Wg16` side. See [`freblok32`] for the
/// `Wg32` counterpart. Declared beside `alcblok`/`ptrblok` in `GCOMM.H` and
/// exported by the real host (`re/wg33src/LIB/WGSERVER.DEF:1460`,
/// `_freblok@1516`) even though no surveyed build imports it by name -- it
/// is the only thing that keeps [`alcblok`] from leaking, and the scope
/// rule this track runs under is explicit that "no surveyed build imports
/// it" does not justify leaving a genuine vendor export unimplemented.
///
/// `ALCBLOK.C`'s own `GCDOS` body:
///
///
/// Frees every glob first, with the same `n = ceil(numblk/each)` this
/// host's [`alcblok`] already uses to decide how many globs to make:
/// recompute `glob_count` from the header's own `qty`/`each`, free each
/// glob through [`Heap::free`], then free the header itself.
///
/// # A `NULL` `bigptr` is a no-op, not a crash
///
/// The body above has no `NULL` guard at all -- `thptr->numblk` on a
/// `NULL` `thptr` would fault -- but the vendor's *other* branch
/// (`freblok32`'s own doc comment) is nothing but `free(bigptr)`, which is
/// `free(NULL)`, ANSI C's documented no-op and the same fact [`galfree`]'s
/// own doc comment already leans on. This host answers one way for both
/// ABIs everywhere else in this pair, so the no-op is the consistent
/// choice here too, not this branch's incidental crash.
pub fn freblok(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let bigptr = call.ptr();
    if bigptr == FarPtr::NULL {
        return Ok(abi::Ret::Void);
    }

    let head = bigptr.resolve(call.mem(), 6).map_err(|e| {
        ShimError::Failed(format!("freblok: {bigptr:?} is not an alcblok header ({e})"))
    })?;
    let qty = u16::from_le_bytes(head[0..2].try_into().expect("resolved exactly 6 bytes"));
    let each = usize::from(u16::from_le_bytes(head[4..6].try_into().expect("resolved exactly 6 bytes")));
    let glob_count = usize::from(qty).div_ceil(each);

    let glob_bytes = bigptr
        .resolve(call.mem(), 6 + glob_count * 4)
        .map_err(|e| ShimError::Failed(format!("freblok: {e}")))?
        .to_vec();

    for i in 0..glob_count {
        let at = 6 + i * 4;
        let glob = FarPtr::from_bytes(
            glob_bytes[at..at + 4]
                .try_into()
                .expect("resolved exactly 4 bytes"),
        );
        host.heap
            .free(glob)
            .map_err(|e| ShimError::Failed(format!("freblok: {e}")))?;
    }

    host.heap
        .free(bigptr)
        .map_err(|e| ShimError::Failed(format!("freblok: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `void *alcblok(unsigned qty, unsigned size)` -- `GCOMM.H:485`, `Wg32`
/// side -- `ALCBLOK.C`'s non-`GCDOS` (`GCWINNT`) branch:
///
///
/// One allocation, no chaining, no bounds record -- a flat 32-bit
/// `malloc()` has no 64 KiB ceiling to work around, so the vendor never
/// needed `Wg16`'s glob machinery ([`alcblok`]'s own doc comment) at all.
/// See [`wg32_blok_header`] for the byte-exact header this writes into the
/// first 8 bytes of that one allocation -- `size` at offset 0, exactly
/// where the vendor puts it, `qty` in the six bytes of dead space the
/// vendor's own `alczer` already zeroed and never reads again.
///
/// # The one real divergence: this host's allocator has a ceiling the vendor's never did
///
/// `qty*size+8` can be arbitrarily large under a genuine flat 32-bit
/// `malloc()`. This host's own [`Heap::reserve`] cannot answer more than
/// `u16::MAX` bytes in one call, regardless of `A` (`heap.rs`'s `SEGMENT`
/// constant is not `Abi`-scoped). The vendor's flat header has no chaining
/// concept to fall back on the way `Wg16`'s `segarray` does -- inventing
/// one here would mean a byte layout with no vendor counterpart at all, the
/// opposite of what this pass is for -- so an aggregate that does not fit
/// one `reserve` call is refused outright rather than represented some
/// other way. Nothing in this track's ten-build survey shows a `Wg32`
/// aggregate anywhere near that size.
pub fn alcblok32(call: &mut Call<Wg32>, host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let qty = count_arg::<Wg32>(call.int());
    let raw_size = heap_size_arg::<Wg32>(call.int()).ok_or_else(|| {
        ShimError::Failed("alcblok: element size does not fit this heap's u16 block size".to_owned())
    })?;

    if qty == 0 {
        return Err(ShimError::Failed("alcblok: 0 elements".to_owned()));
    }
    let size = rounded_blok_size(raw_size).ok_or_else(|| {
        ShimError::Failed(format!(
            "alcblok: an element size of {raw_size} bytes cannot be blocked"
        ))
    })?;

    let total = qty
        .checked_mul(usize::from(size))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "alcblok: {qty} elements of {raw_size} bytes needs more than this heap gives in one piece -- the vendor's own flat layout has no chaining to fall back on"
            ))
        })?;

    let block = host
        .heap
        .reserve(call.mem(), total)
        .map_err(|e| ShimError::Failed(format!("alcblok: {e}")))?;

    // ALCBLOK.C's flat branch gets its zero-fill from calling alczer for
    // the whole allocation; this host's alczer is `Heap::reserve` plus an
    // explicit zero-write, done the same way here.
    block
        .write(call.mem(), &vec![0u8; usize::from(total)])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    block
        .write(call.mem(), &wg32_blok_header(size, qty as u32))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Ptr(block))
}

/// `void *ptrblok(void *bigptr, unsigned idx)` -- `GCOMM.H:486`, `Wg32`
/// side -- `ALCBLOK.C`'s non-`GCDOS` branch:
///
///
/// # The vendor's own flat branch cannot bounds-check `idx` -- this host does
///
/// `numblk` is never written anywhere in the flat header ([`wg32_blok_header`]'s
/// own doc comment), so the vendor's own `ptrblok` here has no `idx` to
/// compare against and none of this branch's own callers get one -- an
/// out-of-range `idx` is unchecked pointer arithmetic over a `CHAR*`, full
/// stop, the kind of thing this crate calls undefined behaviour elsewhere
/// and refuses to reproduce ("Runtime crashes are better than undefined
/// behavior"). This host's own header carries `qty` in the vendor's own
/// dead space, so [`ptrblok32`] can and does check -- a genuine
/// behavioural improvement over the vendor's own flat branch, not a side
/// effect of anything else, and the one place `Wg16`/`Wg32` truly diverge
/// in this pair (`alcblok`'s own doc comment: `Wg16`'s vendor branch
/// already checked `numblk`, so it never diverged here at all). A `NULL`
/// `bigptr` still answers `NULL`, the same as [`ptrblok`]'s own `Wg16` side.
pub fn ptrblok32(call: &mut Call<Wg32>, _: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let bigptr = call.ptr();
    let idx = count_arg::<Wg32>(call.int());

    if bigptr == Wg32::null_ptr() {
        return Ok(abi::Ret::Ptr(Wg32::null_ptr()));
    }

    let head = bigptr.resolve(call.mem(), 6).map_err(|e| {
        ShimError::Failed(format!("ptrblok: {bigptr:?} is not an alcblok header ({e})"))
    })?;
    let size = u16::from_le_bytes(head[0..2].try_into().expect("resolved exactly 6 bytes"));
    let qty = u32::from_le_bytes(head[2..6].try_into().expect("resolved exactly 6 bytes")) as usize;

    if idx >= qty {
        return Ok(abi::Ret::Ptr(Wg32::null_ptr()));
    }

    let offset = 8usize
        .checked_add(idx * usize::from(size))
        .ok_or_else(|| ShimError::Failed(format!("ptrblok: element {idx} overflows its block")))?;

    Wg32::ptr_checked_add(bigptr, offset)
        .map(abi::Ret::Ptr)
        .ok_or_else(|| ShimError::Failed(format!("ptrblok: element {idx} overflows its block")))
}

/// `VOID freblok(VOID *bigptr)` -- `Wg32` side. `ALCBLOK.C`'s non-`GCDOS`
/// body is nothing but `free(bigptr)` -- the flat layout is one contiguous
/// allocation, so freeing it needs no `segarray` walk at all, unlike
/// [`freblok`]'s `Wg16` side. A `NULL` `bigptr` is `free(NULL)`, ANSI C's
/// documented no-op, the same choice [`freblok`] and [`galfree`] make.
pub fn freblok32(call: &mut Call<Wg32>, host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let bigptr = call.ptr();
    if bigptr == Wg32::null_ptr() {
        return Ok(abi::Ret::Void);
    }
    host.heap
        .free(bigptr)
        .map_err(|e| ShimError::Failed(format!("freblok: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `#define setmem(p,n,c) memset(p,c,n)` -- `GCOMM.H:143` -- fill.
///
/// Not a function prototype -- `setmem` is a macro over the ANSI C runtime's
/// `memset`, and `memset` itself is declared nowhere in `re/wg33src/INC`. But
/// the macro is the vendor's own statement of the argument order, which is
/// this file's whole reason for existing: **count then fill**, `memset`'s
/// arguments the other way round.
///
/// Generic (Task 5): the fill and the write go through [`Call::mem`] and
/// [`mbbs_machine::ptr::ModulePtr::write`] rather than a whole `&mut Machine`.
pub fn setmem<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    let count = count_arg::<A>(call.int());
    // A `char` argument still arrives as a whole word; the fill is its low
    // byte -- genuinely narrow, not this file's width bug: every value of
    // a fill byte is already valid, exactly like `memset`'s own `c`.
    let fill = Into::<u32>::into(call.int()) as u8;
    at.write(call.mem(), &vec![fill; count])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `VOID galmovmem(VOID *src, VOID *dst, USHORT nbytes)` -- `GCOMM.H:163-164`,
/// behind `#define movmem(s,d,n) galmovmem(s,d,n)` (`:166`) -- copy,
/// overlapping allowed.
///
/// **Source first**, which is the opposite of `memcpy` immediately below.
///
/// Generic (Task 5): reads through [`mbbs_machine::ptr::ModulePtr::resolve`] and
/// writes through [`mbbs_machine::ptr::ModulePtr::write`], both against [`Call::mem`].
pub fn movmem<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let src = call.ptr();
    let dst = call.ptr();
    let count = count_arg::<A>(call.int());
    let bytes = src
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `void *memcpy(void *dst, const void *src, size_t n)` -- destination
/// first. Borland's; no Galacticomm header redeclares it (see this file's
/// commit message).
///
/// Generic (Task 5): same shape as [`movmem`], with `dst`/`src` read in the
/// other order.
pub fn memcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let count = count_arg::<A>(call.int());
    let bytes = src
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `void *memmove(void *dst, const void *src, size_t n)` -- [`memcpy`], safe
/// when the two ranges overlap.
///
/// Borland's; no Galacticomm header redeclares it -- not to be confused with
/// `GCOMM.H`'s `movmem(s,d,n)` macro (this file's own module doc, "Two
/// argument orders that corrupt silently"), which expands to
/// `memmove(d,s,n)` and is [`movmem`] above, a *different* import with its
/// arguments in the other order. LunatiX imports `_memmove` directly --
/// Stage 3's Task 8 (`docs/plans/2026-08-14-stage3-channel-entry-implementation.md`)
/// -- so this is the plain, dst-first C library routine, not the macro.
///
/// # Overlap is handled for free
///
/// `src` is read whole into an owned `Vec` before anything is written to
/// `dst`, exactly as [`memcpy`] already does -- so there is no forward/
/// backward copy direction to get right for an overlapping range the way a
/// byte-at-a-time C implementation of `memmove` has to choose one. Reading
/// the whole source first is what makes the choice moot.
///
/// # Width
///
/// `count` is read with [`count_arg`], `A`'s own int width widened rather
/// than narrowed to a `usize` outright -- **not** the `as u16` `memcpy` and
/// `memcmp` above used to carry (see this module's "Argument width" note
/// and `docs/2026-08-14-gsbl-width-audit.md`, which found and fixed the
/// same shape eleven times over in `shims/gsbl.rs`). Both are fixed now,
/// through the same helper, so there is no bug left here for a new sibling
/// to have copied -- consistent with `fread`, `fwrite` and `toupper`, which
/// this crate already fixed elsewhere.
pub fn memmove<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let count = count_arg::<A>(call.int());
    let bytes = src
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `int memcmp(const void *a, const void *b, size_t n)`. Borland's; no
/// Galacticomm header redeclares it.
///
/// Generic (Task 5): both reads go through [`mbbs_machine::ptr::ModulePtr::resolve`]
/// on [`Call::mem`]; the answer is built through [`Abi::Int`]'s `From<u16>`
/// the same way [`shims::user::haskey`](crate::shims::user::haskey) builds
/// its boolean answer.
pub fn memcmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let a = call.ptr();
    let b = call.ptr();
    let count = count_arg::<A>(call.int());

    let left = a
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let right = b
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let answer = match left.as_slice().cmp(right) {
        std::cmp::Ordering::Less => -1i16,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    Ok(abi::Ret::Int(A::Int::from(answer as u16)))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Wg16-only, and used by these fixtures alone -- the
    // production code above reaches memory through the ABI.
    use mbbs_machine::m16::Ret;
    use crate::testing::Fixture;
    // `Wg32` only, for the two width-checked readers below: no `Call`, no
    // `Cpu`, no `Machine` needed to exercise them, and building a real
    // `Wg32Cpu` in this file's own test module would arm the process-wide
    // fault claim every `Wg16` test in this binary shares -- see
    // `docs/2026-08-14-gsbl-width-audit.md`'s "Why the tests exercise the
    // four helper functions rather than a full `Call<Wg32>`" for the
    // incident that discipline exists to prevent.
    use crate::abi::Wg32;

    /// The bug this task exists to close: a `Wg32` module's byte count
    /// above 65535 must survive `count_arg` whole, not wrap.
    ///
    /// `70_000u32` is bit-for-bit what `call.int()` hands back for a
    /// genuine `Wg32` module -- `Wg32::Int` is `u32` and `int_from_bytes`
    /// is exactly `u32::from_le_bytes` -- so naming `Wg32` here is not a
    /// stand-in, it selects which `Into<u32>` the read goes through.
    #[test]
    fn count_arg_does_not_truncate_a_32_bit_byte_count() {
        assert_eq!(count_arg::<Wg32>(70_000), 70_000);
    }

    /// Every count a genuine `Wg16` module could produce still round-trips.
    /// The regression guard for the fix above: it must not narrow a
    /// legitimate `Wg32` count, but it also must not change what a `Wg16`
    /// module -- whose `A::Int` is already only two bytes -- has always
    /// gotten.
    #[test]
    fn count_arg_still_accepts_everything_wg16_could_produce() {
        assert_eq!(count_arg::<Wg16>(0), 0);
        assert_eq!(count_arg::<Wg16>(u16::MAX), usize::from(u16::MAX));
    }

    /// `heap_size_arg` refuses a size `Heap::reserve`'s own `u16` cannot
    /// hold, rather than silently allocating a block far smaller than the
    /// module asked for -- the truncation this task exists to close, one
    /// call site earlier than `count_arg`'s (there is a narrower field
    /// behind this one: `Heap::reserve(size: u16)`, unlike `memcpy` et al).
    #[test]
    fn heap_size_arg_refuses_a_size_that_does_not_fit_the_heaps_u16_block() {
        assert_eq!(heap_size_arg::<Wg32>(70_000), None);
        assert_eq!(heap_size_arg::<Wg32>(4096), Some(4096));
        assert_eq!(heap_size_arg::<Wg16>(u16::from(u8::MAX)), Some(255));
    }

    fn far(at: FarPtr) -> [u16; 2] {
        [at.offset, at.selector]
    }

    /// Pins `wg16_blok_header`'s byte layout to `ALCBLOK.C`'s own
    /// `struct blokhdr` field for field: `numblk`/`sizblk`/`each` as
    /// `USHORT`s at offsets 0/2/4, `segarray` from offset 6. A future
    /// refactor that reorders these fields, or widens one of them, fails
    /// this test loudly rather than corrupting element addresses silently.
    #[test]
    fn wg16_blok_header_matches_the_vendors_blokhdr_byte_for_byte() {
        let globs = [
            FarPtr { offset: 0x1234, selector: 0x0056 },
            FarPtr { offset: 0x9abc, selector: 0x00de },
        ];
        let header = wg16_blok_header(10, 16, 4095, &globs);

        assert_eq!(header.len(), 6 + 4 * globs.len(), "no padding, no surprise bytes");
        assert_eq!(&header[0..2], &10u16.to_le_bytes(), "numblk (qty) at offset 0");
        assert_eq!(&header[2..4], &16u16.to_le_bytes(), "sizblk (the rounded size) at offset 2");
        assert_eq!(&header[4..6], &4095u16.to_le_bytes(), "each at offset 4");
        assert_eq!(&header[6..10], &globs[0].to_bytes(), "segarray[0] at offset 6");
        assert_eq!(&header[10..14], &globs[1].to_bytes(), "segarray[1] at offset 10");
    }

    /// Pins `wg32_blok_header`'s byte layout to `ALCBLOK.C`'s own flat
    /// branch: `size` at offset 0 (the one field the vendor's own body
    /// writes), `qty` at offset 2 (this host's own addition, in the
    /// vendor's dead space), nothing past offset 6. A future refactor that
    /// moves `size` off offset 0 -- the one byte position a hand-rolled
    /// `Wg32` module could plausibly read without calling `ptrblok32` at
    /// all -- fails this test loudly.
    #[test]
    fn wg32_blok_header_matches_the_vendors_flat_layout_byte_for_byte() {
        let header = wg32_blok_header(100, 700);

        assert_eq!(header.len(), 6, "offset 6..8 stays spare, matching the vendor's own dead space");
        assert_eq!(
            &header[0..2],
            &100u16.to_le_bytes(),
            "size at offset 0, exactly where ALCBLOK.C's own `*((USHORT *)retptr)=size;` puts it"
        );
        assert_eq!(
            &header[2..6],
            &700u32.to_le_bytes(),
            "qty at offset 2, in the six bytes the vendor's own alczer zeroed and never wrote to again"
        );
    }

    #[test]
    fn alcmem_hands_out_distinct_memory_that_galfree_takes_back() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[256]).expect("a") else {
            panic!("alcmem returns a pointer")
        };
        let Ret::Far(b) = f.invoke(alcmem, &[256]).expect("b") else {
            panic!("alcmem returns a pointer")
        };
        assert_ne!(a, b);

        f.invoke(galfree, &far(a)).expect("freed");
        let Ret::Far(c) = f.invoke(alcmem, &[256]).expect("c") else {
            panic!("alcmem returns a pointer")
        };
        assert_eq!(a, c, "the freed space came back");
    }

    #[test]
    fn alczer_is_zeroed_even_in_space_that_was_used() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[64]).expect("a") else {
            panic!("pointer")
        };
        f.machine.write(a, &[0xcc; 64]).expect("dirtied");
        f.invoke(galfree, &far(a)).expect("freed");

        let Ret::Far(b) = f.invoke(alczer, &[64]).expect("b") else {
            panic!("pointer")
        };
        assert_eq!(b, a, "the same space, so the test means something");
        assert_eq!(
            f.machine.resolve(b, 64).expect("readable"),
            &[0u8; 64],
            "alczer left what the last owner wrote"
        );
    }

    /// `GALMEMDB.C:183` asserts a non-NULL block, but that `ASSERTM` sits
    /// inside `#ifdef DEBUG`; what a shipped host compiles is `free(block);`
    /// on its own, and ANSI C defines `free(NULL)` as doing nothing. So the
    /// real host swallowed this silently, and a refusal here is this host
    /// being stricter than the thing it reproduces.
    ///
    /// Found on a live board: a background `rtkick` freed a null and the
    /// module stopped, which from a player's seat is being disconnected for
    /// no visible reason.
    #[test]
    fn galfree_of_a_null_pointer_does_nothing_the_way_free_null_does() {
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(galfree, &far(FarPtr { offset: 0, selector: 0 }))
                .expect("free(NULL) is a no-op, not an error"),
            Ret::Void
        );
    }

    #[test]
    fn galfree_of_something_never_allocated_refuses_by_name() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[64]).expect("a") else {
            panic!("pointer")
        };
        let stray = FarPtr {
            offset: a.offset + 8,
            selector: a.selector,
        };
        let e = f.invoke(galfree, &far(stray)).expect_err("not a block");
        assert!(e.to_string().contains("galfree"), "{e}");

        f.invoke(galfree, &far(a)).expect("this one is");
        assert!(f.invoke(galfree, &far(a)).is_err(), "but not twice");
    }

    #[test]
    fn the_heap_crosses_a_segment_and_still_works_from_16_bit_code() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[40_000]).expect("a") else {
            panic!("pointer")
        };
        let Ret::Far(b) = f.invoke(alcmem, &[40_000]).expect("b") else {
            panic!("pointer")
        };
        assert_ne!(a.selector, b.selector, "two of these need two segments");

        // And both are memory a module can actually reach.
        f.machine.write(b, b"past the boundary\0").expect("writes");
        assert_eq!(f.read(b), "past the boundary");
    }

    #[test]
    fn farcoreleft_falls_by_what_was_taken_and_rises_when_it_is_given_back() {
        let mut f = Fixture::new();
        let Ret::U32(before) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("farcoreleft returns a long")
        };
        let Ret::Far(a) = f.invoke(alcmem, &[1000]).expect("a") else {
            panic!("pointer")
        };
        let Ret::U32(during) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("long")
        };
        assert_eq!(during, before - 1000);

        f.invoke(galfree, &far(a)).expect("freed");
        let Ret::U32(after) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("long")
        };
        assert_eq!(after, before);
    }

    #[test]
    fn ptrtile_agrees_with_the_arithmetic_the_module_does_itself() {
        // The invariant that ties this to step 7. `DOSCALLS.135` is the shift
        // the module folds into its own code, so a region walked by calling
        // `ptrtile` and one walked by shifting must land on the same tiles --
        // the module does both and they cannot disagree.
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[8, 4096]).expect("tiled") else {
            panic!("alctile returns a pointer")
        };

        let shift = mbbs_machine::m16::SELECTOR_STEP.ilog2();
        for index in 0..8u16 {
            let Ret::Far(asked) = f.invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };

            // What the module computes: the far pointer as one 32-bit value,
            // plus index << (16 + AHSHIFT).
            let flat = (u32::from(base.selector) << 16) | u32::from(base.offset);
            let computed = flat + (u32::from(index) << (16 + shift));
            assert_eq!(
                ((u32::from(asked.selector) << 16) | u32::from(asked.offset)),
                computed,
                "tile {index}"
            );
        }
    }

    #[test]
    fn each_tile_is_its_own_memory_and_16_bit_code_can_reach_it() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[4, 4096]).expect("tiled") else {
            panic!("pointer")
        };
        for index in 0..4u16 {
            let Ret::Far(tile) = f
                .invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };
            f.machine.write(tile, &[index as u8; 32]).expect("writes");
        }
        // Written through four different selectors, read back through them.
        for index in 0..4u16 {
            let Ret::Far(tile) = f
                .invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };
            assert_eq!(
                f.machine.resolve(tile, 1).expect("readable")[0],
                index as u8,
                "tile {index} does not hold what was written through it"
            );
        }
    }

    #[test]
    fn ptrtile_past_the_last_tile_refuses_rather_than_naming_someone_elses() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[3, 4096]).expect("tiled") else {
            panic!("pointer")
        };
        assert!(
            f.invoke(ptrtile, &[base.offset, base.selector, 3]).is_err(),
            "tile 3 of three"
        );

        // And a pointer that is not a region at all.
        let heap = f.invoke(alcmem, &[64]).expect("a");
        let Ret::Far(heap) = heap else { panic!("pointer") };
        assert!(f.invoke(ptrtile, &[heap.offset, heap.selector, 0]).is_err());
    }

    #[test]
    fn ptrblok_indexes_a_block_by_element_size() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alcblok, &[10, 16]).expect("10 x 16") else {
            panic!("alcblok returns a far pointer")
        };
        let Ret::Far(e0) = f.invoke(ptrblok, &[base.offset, base.selector, 0]).expect("element 0")
        else {
            panic!("ptrblok returns a far pointer")
        };
        let Ret::Far(e3) = f.invoke(ptrblok, &[base.offset, base.selector, 3]).expect("element 3")
        else {
            panic!("ptrblok returns a far pointer")
        };
        assert_eq!(e3.selector, e0.selector, "10 elements of 16 bytes fits in one glob");
        assert_eq!(
            e3.offset - e0.offset,
            3 * 16,
            "element 3 of a 16-byte block sits 48 bytes past element 0"
        );

        // A difference check alone cannot catch a constant offset applied
        // to every element -- e.g. `(blokoff + 1) * size` -- since the gap
        // between two elements stays right even when both are shifted the
        // same way. Heap::block only recognises the exact pointer a
        // Heap::reserve call handed out as a key; 10 elements of 16 bytes
        // fits one glob (10*16 = 160 <= 65,535), so element 0 must be that
        // glob's own base pointer, not some byte offset into it.
        assert_eq!(
            f.host.heap.block(e0),
            Some(10 * 16),
            "element 0 must be the glob's own base pointer, not shifted into it"
        );
    }

    #[test]
    fn ptrblok_elements_are_writable_and_distinct() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alcblok, &[4, 32]).expect("4 x 32") else {
            panic!("far")
        };
        for i in 0..4u16 {
            let Ret::Far(e) = f.invoke(ptrblok, &[base.offset, base.selector, i]).expect("in range")
            else {
                panic!("far")
            };
            f.machine.write(e, &[i as u8; 32]).expect("writes");
        }
        for i in 0..4u16 {
            let Ret::Far(e) = f.invoke(ptrblok, &[base.offset, base.selector, i]).expect("in range")
            else {
                panic!("far")
            };
            assert_eq!(
                f.machine.resolve(e, 1).expect("readable")[0],
                i as u8,
                "element {i} does not hold what was written through it"
            );
        }
    }

    #[test]
    fn ptrblok_answers_null_for_an_index_past_qty() {
        // ALCBLOK.C: `if (... idx >= thptr->numblk) return(NULL);` -- the
        // vendor's own documented answer, not a refusal this host invents.
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alcblok, &[4, 32]).expect("4 x 32") else {
            panic!("far")
        };
        assert_eq!(
            f.invoke(ptrblok, &[base.offset, base.selector, 4])
                .expect("NULL, not a refusal"),
            Ret::Far(FarPtr::NULL),
            "element 4 of a 4-element block is NULL, faithfully"
        );
    }

    #[test]
    fn ptrblok_of_a_null_bigptr_answers_null() {
        // ALCBLOK.C: `ASSERT(bigptr != NULL); ... if (thptr == NULL ...)
        // return(NULL);` -- the ASSERT is (VOID)0 outside DEBUG, so a NULL
        // bigptr reaches the NULL check in every shipped build.
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(ptrblok, &[0, 0, 0]).expect("NULL, not a refusal"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn ptrblok_still_refuses_a_bigptr_that_does_not_resolve_at_all() {
        // Different from the two NULL/out-of-range cases above: a selector
        // naming no segment of this module at all cannot be given a NULL-
        // or-in-range answer, because there is nowhere to even read a
        // header from. This host refuses, the same way a ptrtile region the
        // host never tiled refuses. (A non-NULL pointer into memory that
        // merely isn't a *real* alcblok header has no such clean discriminator
        // -- see alcblok's own doc comment, "Could a Wg32 module observe the
        // difference" -- so this test does not attempt that case.)
        let mut f = Fixture::new();
        assert!(f.invoke(ptrblok, &[0, 0x7ffc, 0]).is_err());
    }

    #[test]
    fn freblok_frees_every_glob_and_the_header() {
        // Heap::left(), not an address-reuse assertion: the fixture's own
        // setup already occupies part of region 0 before this test's own
        // alcblok call, so "the same region comes back whole" would be
        // measuring the fixture, not freblok. What freblok owes back is
        // exactly what alcblok took -- no more, no less.
        let mut f = Fixture::new();
        let before = f.host.heap.left();
        let Ret::Far(base) = f.invoke(alcblok, &[4, 16]).expect("4 x 16") else {
            panic!("far")
        };
        f.invoke(freblok, &far(base)).expect("freed");
        assert_eq!(
            f.host.heap.left(),
            before,
            "the header and its one glob both came back"
        );
    }

    #[test]
    fn freblok_frees_every_glob_across_a_multi_glob_block() {
        let mut f = Fixture::new();
        let before = f.host.heap.left();
        let Ret::Far(base) = f.invoke(alcblok, &[700, 100]).expect("700 x 100, two globs") else {
            panic!("far")
        };
        f.invoke(freblok, &far(base)).expect("freed");
        assert_eq!(
            f.host.heap.left(),
            before,
            "the header and both globs came back"
        );
    }

    #[test]
    fn freblok_of_a_null_pointer_does_nothing_the_way_free_null_does() {
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(freblok, &far(FarPtr { offset: 0, selector: 0 }))
                .expect("free(NULL) is a no-op, not an error"),
            Ret::Void
        );
    }

    #[test]
    fn alcblok_of_zero_elements_is_refused_not_answered_with_a_null() {
        let mut f = Fixture::new();
        let e = f.invoke(alcblok, &[0, 16]).expect_err("a refusal");
        assert!(e.to_string().contains('0'), "{e}");
    }

    #[test]
    fn alcblok_of_a_zero_byte_element_is_refused() {
        let mut f = Fixture::new();
        let e = f.invoke(alcblok, &[5, 0]).expect_err("a refusal");
        assert!(e.to_string().contains("0 bytes"), "{e}");
    }

    #[test]
    fn alcblok_elements_are_zeroed_even_in_space_that_was_used() {
        // ALCBLOK.C's DOS branch fills each glob through alczer, not
        // alcmem -- matches this file's own
        // alczer_is_zeroed_even_in_space_that_was_used.
        //
        // alcblok(4, 16) needs a 10-byte header (wg16_blok_header: numblk,
        // sizblk, each -- three u16 -- then one Wg16 glob pointer, 4 bytes)
        // plus a 64-byte glob (4 * 16). Dirtying and freeing exactly 74
        // bytes first, on a fresh heap with nothing else allocated, makes
        // the header claim the front 10 bytes and the glob claim the
        // remaining 64 -- the same 64 bytes this test dirtied and never
        // touched again except through alcblok's own zero-fill.
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[74]).expect("a") else {
            panic!("pointer")
        };
        f.machine.write(a, &[0xcc; 74]).expect("dirtied");
        f.invoke(galfree, &far(a)).expect("freed");

        let Ret::Far(base) = f.invoke(alcblok, &[4, 16]).expect("4 x 16, 64 bytes total") else {
            panic!("far")
        };
        let Ret::Far(e0) = f.invoke(ptrblok, &[base.offset, base.selector, 0]).expect("element 0")
        else {
            panic!("far")
        };
        assert_eq!(e0.selector, a.selector);
        assert_eq!(
            e0.offset,
            a.offset + 10,
            "the glob sits right after the 10-byte header"
        );
        assert_eq!(
            f.machine.resolve(e0, 64).expect("readable"),
            &[0u8; 64],
            "alcblok left what the last owner wrote"
        );
    }

    #[test]
    fn alcblok_spans_multiple_globs_when_the_aggregate_outgrows_one_reserve_call() {
        // 700 elements of 100 bytes: each = 65_535 / 100 = 655, so element
        // 654 is the last one in the first glob and element 655 is the
        // first one in a second -- "the aggregate spans, no element does",
        // this function's own doc comment. 700 * 100 = 70,000 bytes, which
        // could never come out of one Heap::reserve call at all.
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alcblok, &[700, 100]).expect("700 x 100") else {
            panic!("far")
        };

        let Ret::Far(first_of_first_glob) =
            f.invoke(ptrblok, &[base.offset, base.selector, 0]).expect("0")
        else {
            panic!("far")
        };
        let Ret::Far(last_of_first_glob) =
            f.invoke(ptrblok, &[base.offset, base.selector, 654]).expect("654")
        else {
            panic!("far")
        };
        assert_eq!(
            last_of_first_glob.selector, first_of_first_glob.selector,
            "0 and 654 share a glob"
        );
        assert_eq!(last_of_first_glob.offset - first_of_first_glob.offset, 654 * 100);

        let Ret::Far(first_of_second_glob) =
            f.invoke(ptrblok, &[base.offset, base.selector, 655]).expect("655")
        else {
            panic!("far")
        };
        assert_ne!(
            first_of_second_glob.selector, first_of_first_glob.selector,
            "element 655 crossed into a second glob -- a different selector"
        );

        let Ret::Far(last) = f.invoke(ptrblok, &[base.offset, base.selector, 699]).expect("699")
        else {
            panic!("far")
        };
        assert_eq!(last.selector, first_of_second_glob.selector, "0..44 of the second glob");
        assert_eq!(last.offset - first_of_second_glob.offset, 44 * 100);

        // And every element, on both sides of the boundary, is real
        // writable memory -- not an address that merely looks plausible.
        f.machine.write(first_of_first_glob, b"first glob\0").expect("writes");
        f.machine.write(first_of_second_glob, b"second glob\0").expect("writes");
        assert_eq!(f.read(first_of_first_glob), "first glob");
        assert_eq!(f.read(first_of_second_glob), "second glob");
    }

    #[test]
    fn galmalloc_hands_out_distinct_memory_that_galfree_takes_back() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(galmalloc, &[64]).expect("a") else {
            panic!("galmalloc returns a pointer")
        };
        let Ret::Far(b) = f.invoke(galmalloc, &[64]).expect("b") else {
            panic!("galmalloc returns a pointer")
        };
        assert_ne!(a, b, "two allocations must not overlap");
        f.invoke(galfree, &far(a)).expect("galfree must accept what galmalloc gave out");
    }

    #[test]
    fn sizmem_agrees_with_farcoreleft() {
        let mut f = Fixture::new();
        let Ret::U32(left) = f.invoke(farcoreleft, &[]).expect("farcoreleft") else {
            panic!("farcoreleft returns a long")
        };
        let Ret::U32(mem) = f.invoke(sizmem, &[]).expect("sizmem") else {
            panic!("sizmem returns a long")
        };
        assert_eq!(mem, left, "sizmem is farcoreleft under both branches SIZMEM.C forks on");
    }

    #[test]
    fn setmem_takes_the_count_before_the_fill() {
        // The count and the fill differ, so swapping them fails. Written
        // `setmem(p, 4, 4)` this test would pass either way round.
        let mut f = Fixture::new();
        let at = f.bytes(&[0xff; 16], false);
        f.invoke(setmem, &[at.offset, at.selector, 4, 0x41])
            .expect("filled");
        assert_eq!(
            f.machine.resolve(at, 6).expect("readable"),
            &[0x41, 0x41, 0x41, 0x41, 0xff, 0xff],
            "four bytes of 'A', not sixty-five bytes of 4"
        );
    }

    #[test]
    fn movmem_takes_the_source_before_the_destination() {
        let mut f = Fixture::new();
        let src = f.bytes(b"source", false);
        let dst = f.bytes(b"DEST!!", false);
        f.invoke(movmem, &[src.offset, src.selector, dst.offset, dst.selector, 6])
            .expect("moved");
        assert_eq!(
            f.machine.resolve(dst, 6).expect("readable"),
            b"source",
            "movmem copies src to dst, not the other way"
        );
        assert_eq!(f.machine.resolve(src, 6).expect("readable"), b"source");
    }

    #[test]
    fn memcpy_takes_the_destination_first_which_is_the_other_way_round() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"DEST!!", false);
        let src = f.bytes(b"source", false);
        assert_eq!(
            f.invoke(memcpy, &[dst.offset, dst.selector, src.offset, src.selector, 6])
                .expect("copied"),
            Ret::Far(dst)
        );
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"source");
    }

    #[test]
    fn memmove_takes_the_destination_first_same_as_memcpy() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"DEST!!", false);
        let src = f.bytes(b"source", false);
        assert_eq!(
            f.invoke(memmove, &[dst.offset, dst.selector, src.offset, src.selector, 6])
                .expect("moved"),
            Ret::Far(dst)
        );
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"source");
    }

    #[test]
    fn memmove_is_correct_when_the_ranges_overlap() {
        // A byte-at-a-time forward copy corrupts this: by the time it reaches
        // the tail of `dst`, it would be reading bytes it had already
        // overwritten rather than the originals. Reading `src` whole before
        // writing anything -- this shim's own doc comment -- sidesteps the
        // question rather than answering it correctly by luck.
        let mut f = Fixture::new();
        let buf = f.bytes(b"abcdefgh", false);
        let dst = FarPtr {
            offset: buf.offset + 2,
            selector: buf.selector,
        };
        f.invoke(memmove, &[dst.offset, dst.selector, buf.offset, buf.selector, 6])
            .expect("moved");
        assert_eq!(f.machine.resolve(buf, 8).expect("readable"), b"ababcdef");
    }

    #[test]
    fn memcmp_orders_the_way_c_does() {
        let mut f = Fixture::new();
        let a = f.bytes(b"abc", false);
        let b = f.bytes(b"abd", false);
        let c = f.bytes(b"abc", false);

        let args = |x: FarPtr, y: FarPtr| [x.offset, x.selector, y.offset, y.selector, 3];
        assert_eq!(f.invoke(memcmp, &args(a, c)).expect("same"), Ret::U16(0));
        assert_eq!(
            f.invoke(memcmp, &args(a, b)).expect("less"),
            Ret::U16((-1i16) as u16)
        );
        assert_eq!(f.invoke(memcmp, &args(b, a)).expect("more"), Ret::U16(1));
    }

    /// Manual measurement, not a correctness check -- `#[ignore]`d so a
    /// normal `cargo test` run stays deterministic and fast. Run with
    /// `cargo test --release -p mbbs --lib shims::memory::tests::ptrtile_round_trip_cost \
    /// -- --ignored --nocapture`.
    ///
    /// Written for `docs/2026-08-14-ptrtile-hot-path.md`'s "what one dispatch
    /// actually costs" question, which the doc says to measure rather than
    /// assume. Two loops, same tile, same index, same iteration count:
    ///
    /// - **round trip**: [`Fixture::invoke`], which loads real 16-bit `push`/
    ///   `lcall` bytes into the machine and runs them until the thunk traps
    ///   out (`Machine::call` to `Exit::Call`) -- the same trap every real
    ///   `ptrtile` call in a running module goes through -- and then runs the
    ///   shim over the frame that trap left behind. It does not additionally
    ///   pay for `shims::entry`'s ordinal lookup or `Abi::resume`'s write-back
    ///   into `AX`/`DX` and continuation to `retf`; both are one match arm and
    ///   a handful of register writes; on this crate's own numbers the
    ///   surrounding I/O-bound emulation dwarfs them, so the round trip
    ///   measured here is a lower bound on the real per-dispatch cost, not an
    ///   over-count.
    /// - **shim body**: the same [`ptrtile`] call, direct, over a `Call` built
    ///   once outside the timed loop -- no trap, no thunk, just the region
    ///   lookup and the arithmetic.
    ///
    /// The gap between the two is what a host round trip costs beyond the
    /// arithmetic itself, which is `shims/memory.rs`'s own leaf cost and (per
    /// `heap.rs`) a linear scan of `Heap::tiles` -- twelve entries on
    /// MajorMUD's own boot (`wccmmud.rs`'s "twelve regions" measurement), so
    /// `O(twelve)` word comparisons, not a hash lookup.
    #[test]
    #[ignore = "manual timing, not a correctness assertion -- see this test's own doc comment"]
    fn ptrtile_round_trip_cost() {
        use std::time::Instant;

        const ITERATIONS: u32 = 200_000;

        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[8, 4096]).expect("tiled") else {
            panic!("alctile returns a pointer")
        };

        // The round trip: real 16-bit trap-out, once per iteration.
        let started = Instant::now();
        for i in 0..ITERATIONS {
            let index = (i % 8) as u16;
            f.invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range");
        }
        let round_trip = started.elapsed();

        // The shim body alone: one trap, reused as the frame for every
        // iteration, so what is timed is only `ptrtile`'s own region lookup
        // and arithmetic -- no `Machine::call`, no thunk.
        f.call(&[base.offset, base.selector, 0]);
        let frame = f.machine.arg_frame().to_vec();
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let mut call = Call::<Wg16>::new(&mut f.machine, &frame);
            ptrtile(&mut call, &mut f.host).expect("in range");
        }
        let shim_body = started.elapsed();

        eprintln!(
            "ptrtile: {ITERATIONS} calls -- round trip {round_trip:?} ({:.0} ns/call), \
             shim body alone {shim_body:?} ({:.0} ns/call), overhead {:.0} ns/call",
            round_trip.as_nanos() as f64 / f64::from(ITERATIONS),
            shim_body.as_nanos() as f64 / f64::from(ITERATIONS),
            (round_trip.as_nanos() as f64 - shim_body.as_nanos() as f64) / f64::from(ITERATIONS),
        );
    }
}
