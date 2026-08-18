//! Btrieve, as this host reaches it.
//!
//! The engine and its session live in the [`btrieve`](::btrieve) crate, which
//! depends on nothing but `std` so that the DOS and Win32 offline-utility hosts
//! can use the same implementation this board does. See
//! `docs/plans/2026-08-17-offline-utilities-design.md` for why there are three
//! consumers and no two of them agree on anything else.
//!
//! What remains here is this host's own binding: the [`AbiMem`] wrapper that
//! lets a WGSERVER ABI satisfy the engine's memory seam, the [`Alloc`] impl
//! that lets the module heap satisfy its allocator seam, and re-exports so
//! every `crate::btrieve::…` path in this crate keeps resolving.
//!
//! Note the leading `::` on every re-export. This module is named `btrieve` and
//! shadows the crate of the same name at crate root, so `pub use btrieve::…`
//! resolves to *this* module and fails with `E0432`.

pub use ::btrieve::mem::{self, Alloc, Mem};
pub use ::btrieve::{
    create, keys, pages, records, BlockId, Block, Btrieve, BtvError, Cursor, Delivery, FileSpec,
    Geometry, Key, KeySpec, LockMode, LockTable, Op, OpError, Record, Records, SegmentSpec, Stat,
    StatKey, Step, TransactionError, Version, deliver,
};

/// This host's ABIs, seen as memory and nothing else.
///
/// A wrapper rather than `impl<A: Abi> Mem for A`, and the reason is the orphan
/// rule, measured rather than guessed. The blanket impl compiles perfectly well
/// while [`Mem`] lives in this crate -- it was tried, and it does not even
/// conflict with the `Flat` test below, which the plan predicted it would. It
/// stops compiling the moment `Mem` moves to the `btrieve` crate:
///
/// ```text
/// error[E0210]: type parameter `A` must be used as the type parameter for some
///               local type (e.g. `MyStruct<A>`)
///   = note: only traits defined in the current crate can be implemented for a
///           type parameter
/// ```
///
/// The message names its own fix, and `AbiMem<A>` is it: a local type, so the
/// impl stays legal across the crate boundary, and generic enough that no
/// consumer needs a second bound. `Host<A>` holds a `Btrieve<AbiMem<A>>` and
/// every `A: Abi` still works.
///
/// It carries no data. `Btrieve` only ever names `M::Ptr` and `M::Memory`, so
/// the wrapper exists purely to give the impl a local type to hang on.
pub struct AbiMem<A>(std::marker::PhantomData<A>);

impl<A: crate::abi::Abi> Mem for AbiMem<A> {
    type Ptr = A::Ptr;
    type Memory = A::Mem;
    type Error = <A::Ptr as mbbs_machine::ptr::ModulePtr>::Error;

    const PTR_WIDTH: usize = <A as crate::abi::Abi>::PTR_WIDTH;

    // Which `struct dfablk`/`btvblk` the module was compiled against, decided
    // by the width of its own `int` -- that is precisely the question
    // `BlockAbi` asks, because the padding before `key` exists only when the
    // compiler aligns a pointer to four. `Wg16`'s `INT_WIDTH` is 2 and
    // `Wg32`'s is 4; there is no third answer to fall through to, so this
    // matches exhaustively rather than defaulting.
    const BLOCK: btrieve::mem::BlockAbi = match <A as crate::abi::Abi>::INT_WIDTH {
        2 => btrieve::mem::BlockAbi::Packed16,
        4 => btrieve::mem::BlockAbi::WinNt32,
        _ => panic!("an ABI whose int is neither 2 nor 4 bytes has no known dfablk layout"),
    };

    fn null_ptr() -> Self::Ptr {
        <A as crate::abi::Abi>::null_ptr()
    }

    fn ptr_to_bytes(p: Self::Ptr) -> Vec<u8> {
        <A as crate::abi::Abi>::ptr_to_bytes(p)
    }

    fn ptr_from_bytes(b: &[u8]) -> Self::Ptr {
        <A as crate::abi::Abi>::ptr_from_bytes(b)
    }

    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        <A as crate::abi::Abi>::ptr_offset(base, delta)
    }

    fn resolve<'m>(
        p: Self::Ptr,
        memory: &'m Self::Memory,
        len: usize,
    ) -> Result<&'m [u8], Self::Error> {
        mbbs_machine::ptr::ModulePtr::resolve(&p, memory, len)
    }

    fn write(p: Self::Ptr, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error> {
        mbbs_machine::ptr::ModulePtr::write(&p, memory, bytes)
    }
}

/// The module heap, seen as an allocator and nothing else.
///
/// `Heap` is this crate's own type, so this impl is orphan-legal for the same
/// reason [`AbiMem`] is.
impl<A: crate::abi::Abi> Alloc<AbiMem<A>> for crate::Heap<A> {
    fn reserve(&mut self, memory: &mut A::Mem, size: u16) -> Result<A::Ptr, String> {
        crate::Heap::<A>::reserve(self, memory, size)
    }

    fn free(&mut self, at: A::Ptr) -> Result<(), String> {
        crate::Heap::<A>::free(self, at)
    }
}
