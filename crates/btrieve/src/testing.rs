//! Test support: a scratch directory, a key-attribute edit, and a memory that
//! is not a module ABI.
//!
//! Public rather than `#[cfg(test)]` because two crates need it. This crate's
//! own tests use it, and so does the MajorBBS host, whose `testing` module
//! re-exports [`scratch`] and [`make_keys_modifiable`] so that its ~90 call
//! sites did not have to move when the engine did.
//!
//! [`Flat`] is here for a different reason. Every fixture in this crate used to
//! build a `Block<Wg16>` out of `FarPtr::NULL`, which meant the tests could
//! only run somewhere a WGSERVER ABI existed -- exactly the coupling the
//! extraction was for. `Flat` is the smallest thing that satisfies
//! [`crate::mem::Mem`]: one address space, a four-byte pointer, no segments and
//! no machine.

use std::path::PathBuf;

use crate::mem::{Alloc, Mem};

/// Set every key's "modifiable" attribute in a Btrieve file, in place.
///
/// **The bit's meaning is measured, so setting it is configuration and not
/// invention** -- see `Block::unmodifiable_key_changed`. Both halves of a v6
/// file's shadowed control record are written, so this does not depend on
/// which one is live.
///
/// # Panics
///
/// If the file cannot be read or written, or is too short to hold the key
/// definitions it claims.
pub fn make_keys_modifiable(path: &std::path::Path) {
    const PAGE: usize = 0x08;
    const KEYS: usize = 0x14;
    const BASE: usize = 0x110;
    const WIDTH: usize = 0x1e;
    const ATTRIBUTES: usize = 0x08;
    const MODIFIABLE: u16 = 1 << 1;

    let mut file = std::fs::read(path).expect("a Btrieve file to read");
    let word = |file: &[u8], at: usize| u16::from_le_bytes([file[at], file[at + 1]]);

    let page = usize::from(word(&file, PAGE));
    let count = usize::from(word(&file, KEYS));
    // v6 shadows the control record across physical pages 0 and 1; v5 has only
    // page 0. Writing both is right either way -- a v5 file's page 1 is an
    // ordinary page whose first bytes are not key definitions, so it is only
    // touched when the file really is shadowed.
    let copies: &[usize] = if file.len() >= 2 * page && &file[..2] == b"FC" {
        &[0, 1]
    } else {
        &[0]
    };

    for &copy in copies {
        for key in 0..count {
            let at = copy * page + BASE + key * WIDTH + ATTRIBUTES;
            assert!(at + 2 <= file.len(), "{}: too short for {count} keys", path.display());
            let attributes = word(&file, at) | MODIFIABLE;
            file[at..at + 2].copy_from_slice(&attributes.to_le_bytes());
        }
    }

    std::fs::write(path, &file).expect("a Btrieve file to write back");
}

/// An empty directory a test may write into, under `target/`.
///
/// Some of what a host does is *install* a file rather than read one, and a
/// test of that has to have somewhere to put it that is neither the checked-in
/// sample directory nor the system temporary one. `target/` is both inside the
/// repository and already ignored by git.
///
/// Cleared on each call, so a test never sees what the last run left.
///
/// # Why the thread is part of the path
///
/// `name` alone is not unique. Callers derive it from data rather than from
/// the test -- `records`' own helper is `scratch(&format!("btv-rec-{name}"))`,
/// keyed on the `.DAT` filename -- so four tests sharing `FREESLOT.DAT` shared
/// one directory. Under the default parallel harness that is a race against
/// this function's own opening `remove_dir_all`: one test deletes the
/// directory between another's `create_dir_all` and its first `write`, and the
/// write fails `NotFound`, or succeeds into a directory that is then removed
/// and reads back as 0 bytes.
///
/// Both failures were observed, intermittently, in
/// `splicing_matches_a_full_reindex_over_a_long_run_of_writes`, which is not
/// itself one of the colliding tests -- it just shares the helper. That is
/// what made it look like a flaky Btrieve test for weeks rather than a broken
/// test fixture, and every parallel agent working in this crate hit it and was
/// told to ignore it.
///
/// Keying on the thread as well makes collision impossible without changing
/// the contract: a single test still gets one directory, still cleared on each
/// call. Directory names stay readable because [`std::thread::ThreadId`]
/// renders as `ThreadId(N)` and only the digits are kept.
///
/// # Panics
///
/// If the directory cannot be created.
pub fn scratch(name: &str) -> PathBuf {
    let thread = format!("{:?}", std::thread::current().id())
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    let at = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-scratch")
        .join(format!("t{thread}"))
        .join(name);
    let _ = std::fs::remove_dir_all(&at);
    std::fs::create_dir_all(&at).expect("a scratch directory");
    at
}

/// Zero [`crate::FILE_OPENS`] so a measurement window starts clean.
///
/// A test that wants to prove a read path opens its file once, not once per
/// page, calls this immediately before the window it is timing -- the same
/// role `write_cost.rs`'s own `reset_peak`/`proc_io` baseline plays for heap
/// growth and `/proc/self/io`.
pub fn reset_file_opens() {
    crate::FILE_OPENS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// How many times this process has opened a file to serve a Btrieve read
/// since the last [`reset_file_opens`]. See [`crate::FILE_OPENS`]'s own doc
/// comment for exactly which call sites this counts.
pub fn file_opens() -> u64 {
    crate::FILE_OPENS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Zero [`crate::PAGE_FETCHES`] so a measurement window starts clean. Same
/// role as [`reset_file_opens`], for a [`crate::cache::PageCache`]'s own
/// choke point instead of [`crate::FILE_OPENS`]'s.
pub fn reset_page_fetches() {
    crate::PAGE_FETCHES.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// How many times this process has read a page from disk into a
/// [`crate::cache::PageCache`] since the last [`reset_page_fetches`]. See
/// [`crate::PAGE_FETCHES`]'s own doc comment for exactly which call site
/// this counts.
pub fn page_fetches() -> u64 {
    crate::PAGE_FETCHES.load(std::sync::atomic::Ordering::SeqCst)
}

/// Zero [`crate::ORDER_BUILDS`] so a measurement window starts clean. Same
/// role as [`reset_page_fetches`], for a v6 key's `OrderIndex` rebuild
/// instead of a page cache miss -- see that counter's own doc comment for
/// why [`page_fetches`] cannot tell a rebuild apart from a reuse once the
/// pages either would touch are already warm.
pub fn reset_order_builds() {
    crate::ORDER_BUILDS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// How many times this process has rebuilt a v6 key's `OrderIndex` since
/// the last [`reset_order_builds`].
pub fn order_builds() -> u64 {
    crate::ORDER_BUILDS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Zero [`crate::RECORD_WALKS`] so a measurement window starts clean. Same
/// role as [`reset_order_builds`], for [`crate::records::Records::read`]'s
/// whole-file walk -- see that counter's own doc comment for why neither
/// [`file_opens`] nor bytes read can discriminate it from an ordinary open.
pub fn reset_record_walks() {
    crate::RECORD_WALKS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// How many times this process has run a full [`crate::records::Records::read`]
/// walk since the last [`reset_record_walks`].
pub fn record_walks() -> u64 {
    crate::RECORD_WALKS.load(std::sync::atomic::Ordering::SeqCst)
}

/// A pointer into [`FlatMem`]: one number, no segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct FlatPtr(pub u32);

impl FlatPtr {
    /// The pointer that addresses nothing.
    ///
    /// Spelled as a constant because that is how the fixtures this replaced
    /// spelled `FarPtr::NULL`, and a fixture is easier to read when the null
    /// pointer is a name rather than a call.
    pub const NULL: Self = Self(0);
}

/// What [`FlatPtr`] addresses: one flat span of bytes.
#[derive(Debug, Default)]
pub struct FlatMem {
    /// The bytes themselves.
    pub bytes: Vec<u8>,
}

impl FlatMem {
    /// A zeroed span `len` bytes long.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self { bytes: vec![0u8; len] }
    }
}

/// A read or write that fell outside [`FlatMem`].
#[derive(Debug)]
pub struct FlatFault(String);

impl std::fmt::Display for FlatFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for FlatFault {}

/// A memory that is not a module ABI.
///
/// The point of the seam, made concrete: if only an `Abi` could satisfy
/// [`Mem`], the extraction would have bought nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flat;

impl Mem for Flat {
    type Ptr = FlatPtr;
    type Memory = FlatMem;
    type Error = FlatFault;

    const PTR_WIDTH: usize = 4;

    // `Flat` stands in for a 16-bit module's memory in this crate's own tests
    // -- four-byte far pointers, two-byte ints -- so it takes the packed
    // layout. The `WinNt32` layout is exercised through `mbbs`'s `AbiMem<Wg32>`
    // and by `Layout`'s own tests below.
    const BLOCK: crate::mem::BlockAbi = crate::mem::BlockAbi::Packed16;

    fn null_ptr() -> Self::Ptr {
        FlatPtr::NULL
    }

    fn ptr_to_bytes(p: Self::Ptr) -> Vec<u8> {
        p.0.to_le_bytes().to_vec()
    }

    fn ptr_from_bytes(b: &[u8]) -> Self::Ptr {
        FlatPtr(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        FlatPtr(base.0 + u32::from(delta))
    }

    fn resolve<'m>(
        p: Self::Ptr,
        memory: &'m Self::Memory,
        len: usize,
    ) -> Result<&'m [u8], Self::Error> {
        let at = p.0 as usize;
        memory
            .bytes
            .get(at..at + len)
            .ok_or_else(|| FlatFault(format!("{at:#x}+{len} is past this memory")))
    }

    fn write(p: Self::Ptr, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error> {
        let at = p.0 as usize;
        let room = memory
            .bytes
            .get_mut(at..at + bytes.len())
            .ok_or_else(|| FlatFault(format!("{at:#x}+{} is past this memory", bytes.len())))?;
        room.copy_from_slice(bytes);
        Ok(())
    }
}

/// A bump allocator, which is all [`Alloc`] asks for.
///
/// Never reuses an address, so a test that frees and reserves again gets a
/// different pointer -- unlike the host's own heap, whose span reuse is itself
/// under test over in `mbbs`.
#[derive(Debug, Default)]
pub struct FlatHeap {
    next: u32,
}

impl FlatHeap {
    /// An allocator handing out addresses from `first` upward.
    #[must_use]
    pub fn new(first: u32) -> Self {
        Self { next: first }
    }
}

impl Alloc<Flat> for FlatHeap {
    fn reserve(&mut self, memory: &mut FlatMem, size: u16) -> Result<FlatPtr, String> {
        let at = self.next;
        let end = at + u32::from(size);
        if end as usize > memory.bytes.len() {
            return Err(format!("no room for {size} bytes at {at:#x}"));
        }
        self.next = end;
        Ok(FlatPtr(at))
    }

    fn free(&mut self, _at: FlatPtr) -> Result<(), String> {
        Ok(())
    }
}
