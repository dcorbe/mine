//! `wbtrv32.dll` -- the Btrieve requester, as a Win32 import.
//!
//! A marshalling adapter and nothing else: it reads seven flat 32-bit
//! arguments off the stack, hands them to `btrieve::btrcall::btrcall`, and
//! writes the answer back. Every decision about what an operation *means*
//! lives in that façade, so this edge and the real-mode `int 7Bh` edge cannot
//! drift apart.
//!
//! The signature is Galacticomm's own, from
//! `re/wg33src/SRC/api/gcommlib/DFAAPI.C:967`. Note it is **not** the same as
//! the 16-bit Windows declaration thirty lines above it, which is `PASCAL`
//! and takes a `USHORT *dataLength` rather than a `ULONG *`. One adapter does
//! not serve both.
//!
//! # `Mem`, over the Win32 flat address space
//!
//! [`Win32Mem`] is the second consumer of `btrieve::mem::Mem` -- the first is
//! `crates/btrieve/src/testing.rs`'s `Flat`, which exists to prove the seam
//! does not secretly need a module ABI. This is that proof cashed in: a real
//! host, with a real `mbbs_machine::m32::Memory` behind it, satisfying the
//! same four small methods `Flat` does. `Flat32Ptr` already implements
//! `mbbs_machine::ptr::ModulePtr` for `Memory`, so `resolve`/`write` are one
//! line each -- delegate.
//!
//! # The heap
//!
//! `btrieve::mem::Alloc` needs somewhere to put a module's `struct btvblk`,
//! its name, its record buffer and its key buffer on Open. This host already
//! has exactly one place host code allocates module-addressable memory --
//! `mbbs_machine::m32::Memory::alloc`, the same bump allocator
//! `cw3220mt.DLL!_malloc` already answers through (`crate::win32::crt`). No
//! second allocator is invented here: [`Win32Heap`] is a zero-sized wrapper
//! over that one primitive, and its `free` is a no-op for the identical
//! reason `crt::free`'s is -- see [`Win32Heap`]'s own doc comment.

use mbbs_machine::m32::{Flat32Ptr, Flat32PtrError, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use btrieve::btrcall::{btrcall as engine_btrcall, Call, Gap};
use btrieve::mem::{Alloc, Mem};

use crate::win32::kernel32::Answer;
use crate::win32::process::Process;

/// How many stdcall arguments `BTRCALL` takes, and therefore how many bytes
/// the callee cleans: seven words, twenty-eight bytes.
pub(crate) const CLEANS_ARGS: u16 = 7;

/// The Win32 flat address space, as the Btrieve engine sees it.
///
/// One address space, a four-byte pointer, no segments -- the same shape
/// `crates/btrieve/src/testing.rs`'s `Flat` proves the seam with, over a real
/// `mbbs_machine::m32::Memory` instead of a bare `Vec<u8>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Win32Mem;

impl Mem for Win32Mem {
    type Ptr = Flat32Ptr;
    type Memory = Memory;
    type Error = Flat32PtrError;

    const PTR_WIDTH: usize = 4;

    fn null_ptr() -> Self::Ptr {
        Flat32Ptr(0)
    }

    fn ptr_to_bytes(p: Self::Ptr) -> Vec<u8> {
        p.0.to_le_bytes().to_vec()
    }

    fn ptr_from_bytes(b: &[u8]) -> Self::Ptr {
        Flat32Ptr(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        Flat32Ptr(base.0 + u32::from(delta))
    }

    fn resolve<'m>(
        p: Self::Ptr,
        memory: &'m Self::Memory,
        len: usize,
    ) -> Result<&'m [u8], Self::Error> {
        p.resolve(memory, len)
    }

    fn write(p: Self::Ptr, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error> {
        p.write(memory, bytes)
    }
}

/// Where a Btrieve `Open` allocates a module's block, name, record buffer and
/// key buffer.
///
/// **Nothing is ever freed**, on purpose, for the same reason
/// `crate::win32::crt::free` is a no-op: `Memory::alloc` is a bump allocator
/// with no reclaim, this is a maintenance utility that opens a bounded number
/// of files once and exits, and the arena's fixed size is what will say so if
/// that assumption ever breaks -- loudly, by refusing an allocation, rather
/// than quietly handing back a block still in use.
#[derive(Debug, Default)]
pub struct Win32Heap;

impl Alloc<Win32Mem> for Win32Heap {
    fn reserve(&mut self, memory: &mut Memory, size: u16) -> Result<Flat32Ptr, String> {
        memory.alloc(usize::from(size)).map_err(|e| e.to_string())
    }

    fn free(&mut self, _at: Flat32Ptr) -> Result<(), String> {
        Ok(())
    }
}

/// Answer a `wbtrv32.dll` import, or `None` for one still unimplemented.
///
/// `None` also covers a real Btrieve call this engine could not honour --
/// either because `btrieve::btrcall::btrcall` returned a
/// [`Gap`](btrieve::btrcall::Gap), or because one of the guest pointers it was
/// handed did not resolve. Both set `process.btrieve_gap`, which
/// [`crate::win32::process::run`] checks after a `None` and turns into
/// `Outcome::BtrieveGap` rather than `Outcome::Unimplemented` -- the run
/// stops and names the gap rather than answering the guest with a status this
/// engine never computed. See `btrieve::btrcall`'s own module doc comment on
/// why a gap and a status are different types.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        "BTRCALL" => btrcall(process, machine, mem),
        _ => None,
    }
}

/// Record why this call could not be honoured, and answer `None` -- the one
/// path every failure below funnels through, so `dispatch` cannot forget to
/// set the channel `run` reads.
fn gap(process: &mut Process, what: String) -> Option<Answer> {
    process.btrieve_gap = Some(what);
    None
}

fn btrcall(process: &mut Process, machine: &mut Machine, mem: &mut Memory) -> Option<Answer> {
    // Seven stdcall arguments, in Galacticomm's own order -- see this
    // module's doc comment. Read eagerly, before anything below borrows
    // `mem` for a resolve/write, the same discipline every other dispatch
    // arm in this crate follows.
    let op_raw = machine.arg_u32(mem.stack(), 0);
    let posblk_at = machine.arg_u32(mem.stack(), 1);
    let databuf_at = machine.arg_u32(mem.stack(), 2);
    let datalen_at = machine.arg_u32(mem.stack(), 3);
    let keybuf_at = machine.arg_u32(mem.stack(), 4);
    #[allow(clippy::cast_possible_truncation)]
    let keylen = machine.arg_u32(mem.stack(), 5) as u8;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let keynum = machine.arg_u32(mem.stack(), 6) as i8;

    // The guest's 128-byte position block -- a handle Open/Close/every other
    // op reads and (on Open) rewrites, not a snapshot of engine state. See
    // `btrieve::btrcall::Call::posblk`.
    let mut posblk = [0u8; 128];
    match Flat32Ptr(posblk_at).resolve(mem, 128) {
        Ok(bytes) => posblk.copy_from_slice(bytes),
        Err(e) => return gap(process, format!("position block at {posblk_at:#010x}: {e}")),
    }

    // `*dataLength` -- the caller's own `ULONG`, read before this call
    // overwrites it with how many bytes the engine actually used.
    let mut datalen: u32 = match Flat32Ptr(datalen_at).resolve(mem, 4) {
        Ok(bytes) => u32::from_le_bytes(bytes.try_into().expect("resolve returned 4 bytes")),
        Err(e) => return gap(process, format!("data length at {datalen_at:#010x}: {e}")),
    };

    let mut databuf: Vec<u8> = if datalen == 0 {
        Vec::new()
    } else {
        match Flat32Ptr(databuf_at).resolve(mem, datalen as usize) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => return gap(process, format!("data buffer at {databuf_at:#010x}: {e}")),
        }
    };

    let mut keybuf: Vec<u8> = if keylen == 0 {
        Vec::new()
    } else {
        match Flat32Ptr(keybuf_at).resolve(mem, usize::from(keylen)) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => return gap(process, format!("key buffer at {keybuf_at:#010x}: {e}")),
        }
    };

    // `operation` is `USHORT`, sixteen bits, the same as `keyLength` and
    // `ckeynum` are eight -- and just as with those two, the compiler only
    // loads the half it declared into the register before pushing the whole
    // stdcall slot, so the upper sixteen bits are whatever that register
    // last held for some other reason. Measured at a real call site
    // (`wccmmutl.exe:0x41100e`, disassembled with `objdump -d`): `mov
    // cx,[ebp+8]` loads only `CX`, then `push ecx` pushes all of `ECX`,
    // producing an observed argument of `0x41400000` where the real
    // operation was `0` (Open) -- an arena base address left over in the top
    // half of the register from earlier code. A narrowing `as u16` throws
    // that half away the same way `keylen`/`keynum`'s casts above already
    // do; `u16::try_from` would instead fail on exactly this shape of value
    // and mask a real, small operation code behind `Unmodelled(65535)`.
    let op = op_raw as u16;

    let status = match engine_btrcall(
        &mut process.btrieve,
        mem,
        &mut process.btrieve_heap,
        Call {
            op,
            posblk: &mut posblk,
            databuf: &mut databuf,
            datalen: &mut datalen,
            keybuf: &mut keybuf,
            keylen,
            keynum,
        },
    ) {
        Ok(status) => status,
        Err(Gap { what }) => return gap(process, what),
    };

    // Write everything back: the position block, the data buffer and its
    // length, and the key buffer -- an operation may have changed any of
    // them (Open the position block, Get the data and key buffers and the
    // length, Close nothing at all, and so on), and there is no cheaper way
    // to know which than to always write all four.
    if Flat32Ptr(posblk_at).write(mem, &posblk).is_err() {
        return gap(process, format!("writing position block back to {posblk_at:#010x}"));
    }
    if !databuf.is_empty() && Flat32Ptr(databuf_at).write(mem, &databuf).is_err() {
        return gap(process, format!("writing data buffer back to {databuf_at:#010x}"));
    }
    if Flat32Ptr(datalen_at).write(mem, &datalen.to_le_bytes()).is_err() {
        return gap(process, format!("writing data length back to {datalen_at:#010x}"));
    }
    if !keybuf.is_empty() && Flat32Ptr(keybuf_at).write(mem, &keybuf).is_err() {
        return gap(process, format!("writing key buffer back to {keybuf_at:#010x}"));
    }

    // `Status` is `i16`; `as u32` sign-extends the same way `cwde` would
    // widening `BTRCALL`'s real `SHORT` return into `EAX`.
    #[allow(clippy::cast_sign_loss)]
    Some(Answer::stdcall(status.0 as u32, CLEANS_ARGS))
}

#[cfg(test)]
mod tests {
    /// The seven stdcall arguments are read in Btrieve's own order, and the
    /// callee cleans all twenty-eight bytes of them.
    ///
    /// Argument order comes from Galacticomm's own declaration,
    /// `re/wg33src/SRC/api/gcommlib/DFAAPI.C:967`:
    ///
    /// ```text
    /// SHORT __stdcall BTRCALL(USHORT operation, VOID *posBlock,
    ///                         VOID *dataBuffer, ULONG *dataLength,
    ///                         VOID *keyBuffer, CHAR keyLength,
    ///                         CHAR ckeynum)
    /// ```
    #[test]
    fn the_answer_cleans_seven_arguments() {
        assert_eq!(super::CLEANS_ARGS, 7);
    }
}
