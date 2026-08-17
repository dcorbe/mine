//! What the Btrieve session needs from whoever owns the memory.
//!
//! `Btrieve` was `Btrieve<A: Abi>`, which read as though the engine were
//! entangled with module hosting. It is not: nothing it asks for is about
//! calling conventions, shims or the WGSERVER ABI. It was parameterised by
//! `Abi` only because `Abi` was the nearest type that happened to supply a
//! pointer, and `Abi` brings a machine, a CPU and a shim table along with it.
//!
//! # What it actually needs, measured
//!
//! The design document that preceded this counted seven items, from
//! `grep -c 'A::'` over the session. That undercounts, in two ways a reader
//! should know about before trusting the number:
//!
//! - **The pattern cannot match `Abi`.** `A::Ptr` matches; `impl<A: Abi>` does
//!   not, and neither does `<A as Abi>::Ptr`. `btrieve/ops.rs` has nine
//!   `impl<A: Abi> Block<A>` blocks and `btrieve/stat.rs` one, all invisible to
//!   that grep, which is why both files import `crate::abi::Abi` while
//!   reporting zero uses.
//! - **It cannot see methods called on pointer *values*.** `Abi::Ptr` is bound
//!   by [`mbbs_machine::ptr::ModulePtr`], so `ptr.resolve(mem, len)` and
//!   `ptr.write(mem, bytes)` are ABI surface that never spells `A::` at all.
//!
//! And one dependency is not on `Abi` at all: `Btrieve::open` and
//! `Btrieve::close_at` take `&mut crate::Heap<A>`, because opening a file
//! allocates the module's block, name, record buffer and key buffer, and
//! closing frees them. A crate that depends on nothing but `std` can name
//! neither `ModulePtr` nor `Heap`, so both cross the seam here.
//!
//! Eleven items, then: [`Mem`] carries ten and [`Alloc`] the last two, split
//! because a caller that only reads a block should not have to supply an
//! allocator. Every one is a pointer, memory or allocation concern. That is
//! the whole of it, and it is what lets a DOS guest and a Win32 host satisfy
//! this without pretending to be a module ABI.

/// A pointer-and-memory provider for the Btrieve session.
///
/// Implemented by whoever owns the memory a module's pointers address: this
/// host does it for both WGSERVER ABIs, and the offline-utility hosts will do
/// it for a DOS guest's real mode and a Win32 process's flat address space.
pub trait Mem {
    /// A pointer as this consumer's programs write one.
    type Ptr: Copy + Eq + std::hash::Hash + std::fmt::Debug;

    /// The memory those pointers address.
    type Memory;

    /// What resolving or writing through a pointer can fail with.
    ///
    /// Kept as an associated type rather than flattened to `String` so that a
    /// consumer's own fault type survives the crossing; the session only ever
    /// renders it with `to_string`.
    type Error: std::error::Error;

    /// The width of `Ptr` in bytes, as stored in a program's memory.
    const PTR_WIDTH: usize;

    /// The pointer that addresses nothing.
    fn null_ptr() -> Self::Ptr;

    /// Encode a pointer as a program's own memory stores one.
    fn ptr_to_bytes(p: Self::Ptr) -> Vec<u8>;

    /// Decode a pointer from exactly [`PTR_WIDTH`](Mem::PTR_WIDTH) bytes.
    fn ptr_from_bytes(b: &[u8]) -> Self::Ptr;

    /// A pointer `delta` bytes past `base`.
    ///
    /// `delta` is a `u16` because every use is a field offset within one
    /// structure, and because a 16-bit far pointer cannot be advanced past a
    /// segment anyway.
    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr;

    /// Borrow `len` bytes of memory at `p`.
    ///
    /// # Errors
    ///
    /// If `p` does not address `len` readable bytes.
    fn resolve<'m>(
        p: Self::Ptr,
        memory: &'m Self::Memory,
        len: usize,
    ) -> Result<&'m [u8], Self::Error>;

    /// Write `bytes` to memory at `p`.
    ///
    /// # Errors
    ///
    /// If `p` does not address `bytes.len()` writable bytes.
    fn write(p: Self::Ptr, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Where the session gets the memory a module sees its own Btrieve blocks in.
///
/// Separate from [`Mem`] because it is needed by exactly two operations --
/// opening a file and closing one -- while everything else in the session only
/// reads and writes through pointers it was handed. A consumer that never opens
/// a file on a module's behalf need not implement this at all.
///
/// Errors are `String` because that is what this host's heap already returns
/// and what the session already renders; there is no structure here worth
/// preserving across the seam.
pub trait Alloc<M: Mem + ?Sized> {
    /// Allocate `size` bytes and return a pointer a module can hold.
    ///
    /// # Errors
    ///
    /// If there is no room for `size` bytes in one piece.
    fn reserve(&mut self, memory: &mut M::Memory, size: u16) -> Result<M::Ptr, String>;

    /// Release an allocation made by [`reserve`](Alloc::reserve).
    ///
    /// # Errors
    ///
    /// If `at` was not allocated here, or was freed already.
    fn free(&mut self, at: M::Ptr) -> Result<(), String>;
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam must be satisfiable by something that is not an `Abi`.
    ///
    /// That is the whole point of it: if only `Abi` can implement `Mem`, the
    /// extraction has bought nothing and the DOS and Win32 hosts are no closer
    /// to using this engine. `Flat` is deliberately the shape those hosts have
    /// -- one flat address space, a four-byte pointer, no segments and no
    /// machine.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    struct FlatPtr(u32);

    #[derive(Debug)]
    struct FlatFault(String);

    impl std::fmt::Display for FlatFault {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for FlatFault {}

    struct FlatMem {
        bytes: Vec<u8>,
    }

    struct Flat;

    impl Mem for Flat {
        type Ptr = FlatPtr;
        type Memory = FlatMem;
        type Error = FlatFault;

        const PTR_WIDTH: usize = 4;

        fn null_ptr() -> Self::Ptr {
            FlatPtr(0)
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
    struct FlatHeap {
        next: u32,
    }

    impl Alloc<Flat> for FlatHeap {
        fn reserve(&mut self, memory: &mut FlatMem, size: u16) -> Result<FlatPtr, String> {
            let at = self.next;
            self.next += u32::from(size);
            if self.next as usize > memory.bytes.len() {
                return Err(format!("no room for {size} bytes"));
            }
            Ok(FlatPtr(at))
        }

        fn free(&mut self, _at: FlatPtr) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_non_abi_type_can_satisfy_the_seam() {
        assert_eq!(<Flat as Mem>::PTR_WIDTH, 4);
        assert_eq!(<Flat as Mem>::null_ptr(), FlatPtr(0));
        assert_eq!(<Flat as Mem>::ptr_offset(FlatPtr(16), 4), FlatPtr(20));
        let round = <Flat as Mem>::ptr_from_bytes(&<Flat as Mem>::ptr_to_bytes(FlatPtr(0xdead)));
        assert_eq!(
            round,
            FlatPtr(0xdead),
            "a pointer must survive the byte round trip"
        );
    }

    #[test]
    fn a_non_abi_type_can_resolve_and_write() {
        let mut mem = FlatMem {
            bytes: vec![0u8; 64],
        };
        <Flat as Mem>::write(FlatPtr(8), &mut mem, b"BTRIEVE").expect("a write inside memory");
        let seen = <Flat as Mem>::resolve(FlatPtr(8), &mem, 7).expect("a read inside memory");
        assert_eq!(seen, b"BTRIEVE");

        <Flat as Mem>::write(FlatPtr(60), &mut mem, b"BTRIEVE")
            .expect_err("a write past the end must fail rather than grow the memory");
        <Flat as Mem>::resolve(FlatPtr(60), &mem, 7)
            .expect_err("a read past the end must fail rather than return short");
    }

    #[test]
    fn a_non_abi_allocator_can_satisfy_the_seam() {
        let mut mem = FlatMem {
            bytes: vec![0u8; 64],
        };
        let mut heap = FlatHeap { next: 0 };
        let first = heap.reserve(&mut mem, 16).expect("room for 16 bytes");
        let second = heap.reserve(&mut mem, 16).expect("room for 16 more");
        assert_ne!(
            first, second,
            "two live allocations must not share an address"
        );
        heap.reserve(&mut mem, u16::MAX)
            .expect_err("an allocation larger than the memory must be refused");
        heap.free(first).expect("a free of a live allocation");
    }
}
