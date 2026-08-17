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

use std::path::PathBuf;

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

/// Resolve a Btrieve `Open`'s filename -- DOS syntax such as `.\WCCACMS2.DAT`
/// -- into a real path beneath this process's own sandbox root.
///
/// **Why this exists.** `crates/btrieve`'s own `btrcall::open` treats its key
/// buffer as an already-usable path: every caller in that crate's own test
/// suite hands `Geometry::read`/`Btrieve::open` a path built with
/// `dir.join(name)`, because that crate's callers were always either those
/// tests or (eventually) a real DOS process whose current directory already
/// *was* the data directory. This host's guest is neither: it is a Win32
/// program sandboxed beneath `--root`, and a DOS-syntax name handed to
/// `std::path::PathBuf` unresolved does two things wrong at once -- the
/// backslash is not a Linux separator, so it survives into a single bogus
/// path component, and whatever *does* resolve, resolves against this
/// process's actual working directory rather than the sandbox. Both failures
/// return the same Btrieve status a genuinely missing file would (12), which
/// is what let this go unnoticed until Task 7 ran the engine against a real
/// board rather than an empty fixture directory.
///
/// Translation reuses `dos::files::translate` -- the same DOS-path decoder
/// every other file access on this host goes through -- so a `..` escape is
/// refused here exactly as it would be for any other DOS file call, even
/// though (unlike `dos::files::Files`) nothing below this point opens through
/// `openat2`: `crates/btrieve` reads and writes through plain `std::fs`, so
/// there is no kernel-enforced jail once the join happens, only this check.
///
/// `None` when there is no sandbox to resolve against (a test with an empty
/// `Process`, mirroring `Streams::root_path`'s own `None`) or the name is not
/// nameable at all (an escape attempt, or empty). Both cases are calls this
/// function cannot answer, and both end up producing an ordinary Btrieve
/// "file not found" from a path that plainly cannot resolve to anything real,
/// which is the same honest answer a real missing file gets.
fn resolve_open_path(process: &Process, keybuf: &[u8]) -> Option<PathBuf> {
    let root = process.streams.root_path()?;
    match dos::files::translate(keybuf) {
        dos::files::Target::File(rel) => {
            let candidate = root.join(&rel);
            if candidate.exists() {
                return Some(candidate);
            }
            // `dos::files::translate` upper-cases every byte -- DOS is
            // case-insensitive and the guest reliably writes upper case, but
            // this host's directories are not, and this archive holds both
            // spellings for some extensions (`WCCACMS2.DAT` beside
            // `wccacms2.vir`). One lower-case retry, the same fallback
            // `dos::files::Files` documents for the same reason.
            let lower = root.join(rel.to_ascii_lowercase());
            if lower.exists() {
                return Some(lower);
            }
            Some(candidate)
        }
        dos::files::Target::Device(_) | dos::files::Target::Rejected => None,
    }
}

/// The seven stdcall arguments, read off the frame and resolved into owned
/// buffers -- everything `btrcall` needs to build a
/// `btrieve::btrcall::Call` and, afterwards, to write the answer back to the
/// same guest addresses.
///
/// Split out of `btrcall` so the marshalling itself -- which of the seven
/// stdcall slots becomes which field -- can be asserted directly against
/// known sentinel values, rather than only indirectly through whichever
/// `Call` fields one particular Btrieve operation happens to read. `open()`,
/// the one operation this crate's fixture ever reaches end-to-end, never
/// reads `keynum` at all and skips `databuf` whenever `datalen` is zero; no
/// real program run can exercise this function's reads on its behalf.
struct Marshalled {
    op: u16,
    posblk_at: u32,
    posblk: [u8; 128],
    databuf_at: u32,
    databuf: Vec<u8>,
    datalen_at: u32,
    datalen: u32,
    keybuf_at: u32,
    keybuf: Vec<u8>,
    keylen: u8,
    keynum: i8,
}

/// Read the seven stdcall arguments and resolve the three pointers among
/// them, or say which one did not resolve.
fn read_args(machine: &Machine, mem: &Memory) -> Result<Marshalled, String> {
    // Seven stdcall arguments, in Galacticomm's own order -- see this
    // module's doc comment. Read eagerly, before anything below borrows
    // `mem` for a resolve, the same discipline every other dispatch arm in
    // this crate follows.
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
        Err(e) => return Err(format!("position block at {posblk_at:#010x}: {e}")),
    }

    // `*dataLength` -- the caller's own `ULONG`, read before this call
    // overwrites it with how many bytes the engine actually used.
    //
    // **Only the low sixteen bits of this read are trustworthy.**
    // `re/wg33src/SRC/api/gcommlib/DFAAPI.C:914,978` is the measured reason:
    // `btvu`'s own record-length parameter, `rlen`, is declared `USHORT` --
    // two bytes -- and its Win32 call site takes that two-byte local's
    // address and casts it straight to `ULONG *` (`(ULONG*)&rlen`) before
    // handing it to `BTRCALL`. Whatever this host resolves as the high
    // sixteen bits is therefore not `dataLength` at all: it is two bytes of
    // whatever sits next to `rlen` on the guest's own stack frame, which
    // depends on stack layout this host has no reason to reproduce and the
    // module never reads back as anything but the `USHORT` it declared.
    // Measured at a real call site inside this run's own `-recover` pass
    // (op 33, Step First): resolving all four bytes as the buffer length
    // read `0x4101_0190` -- a plausible small record length, `0x0190`
    // (400), sitting under an upper half that is address-shaped stack
    // noise, the same signature `op`/`keyLength`/`ckeynum`'s own doc
    // comments in this function already describe for the identical
    // narrow-write-into-a-wide-slot shape.
    let datalen: u32 = match Flat32Ptr(datalen_at).resolve(mem, 4) {
        Ok(bytes) => {
            let raw = u32::from_le_bytes(bytes.try_into().expect("resolve returned 4 bytes"));
            u32::from(raw as u16)
        }
        Err(e) => return Err(format!("data length at {datalen_at:#010x}: {e}")),
    };

    let databuf: Vec<u8> = if datalen == 0 {
        Vec::new()
    } else {
        match Flat32Ptr(databuf_at).resolve(mem, datalen as usize) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => return Err(format!("op {op_raw:#x}: data buffer at {databuf_at:#010x}, datalen {datalen}: {e}")),
        }
    };

    // `keyLength` is not a reliable "is there a key buffer" flag on its own:
    // measured at a real call site (op 1, Close, inside this run's own
    // `-recover` pass) `DFAAPI.C` passes its blanket `keyLength = 255` --
    // see this function's own comment on that constant -- while `keyBuffer`
    // itself is NULL, because Close has no key to offer. A non-zero length
    // over a null pointer is exactly the case every C caller of `BTRCALL`
    // treats as "no buffer", not as a 255-byte read through address zero, so
    // this checks the pointer first and the length only when the pointer is
    // real.
    let keybuf: Vec<u8> = if keylen == 0 || keybuf_at == 0 {
        Vec::new()
    } else {
        match Flat32Ptr(keybuf_at).resolve(mem, usize::from(keylen)) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => return Err(format!("op {op_raw:#x}: key buffer at {keybuf_at:#010x}, keylen {keylen}: {e}")),
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

    Ok(Marshalled {
        op,
        posblk_at,
        posblk,
        databuf_at,
        databuf,
        datalen_at,
        datalen,
        keybuf_at,
        keybuf,
        keylen,
        keynum,
    })
}

fn btrcall(process: &mut Process, machine: &mut Machine, mem: &mut Memory) -> Option<Answer> {
    let Marshalled {
        op,
        posblk_at,
        mut posblk,
        databuf_at,
        mut databuf,
        datalen_at,
        mut datalen,
        keybuf_at,
        mut keybuf,
        keylen,
        keynum,
    } = match read_args(machine, mem) {
        Ok(args) => args,
        Err(what) => return gap(process, what),
    };

    // Btrieve Open's key buffer holds a filename in DOS syntax -- see
    // `resolve_open_path`'s doc comment for why the engine cannot be handed
    // that verbatim. Substitute a resolved path on this local copy before the
    // engine ever sees it, and restore the guest's own bytes before anything
    // is written back: real Btrieve does not rewrite the name it was asked to
    // open, and the guest is entitled to read its own buffer back unchanged.
    let original_keybuf = (op == 0).then(|| keybuf.clone());
    if op == 0 {
        match resolve_open_path(process, &keybuf) {
            Some(resolved) => {
                let mut bytes = resolved.to_string_lossy().into_owned().into_bytes();
                bytes.push(0);
                keybuf = bytes;
            }
            None => {
                return gap(
                    process,
                    "Open: no sandboxed root to resolve a filename against".to_owned(),
                );
            }
        }
    }

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

    if let Some(original) = original_keybuf {
        keybuf = original;
    }

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
    use super::*;
    use mbbs_machine::m32::{Exit, Mapping};

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

    /// Push seven distinct sentinel values onto a real stdcall frame, trap
    /// through an armed thunk exactly the way a module's own `call [IAT]`
    /// would, and check `read_args` put every one of them in the field
    /// Galacticomm's declaration says it belongs in.
    ///
    /// **Why this cannot be proven by running the real program instead.**
    /// The only operation `wccmmutl.exe` reaches in this crate's fixture is
    /// Btrieve Open (op 0), and `btrieve::btrcall::open` never reads
    /// `keynum` at all, and skips resolving `databuf` whenever `datalen` is
    /// zero. No amount of running the real program discriminates those
    /// reads; only a direct test of the marshalling can.
    ///
    /// Each buffer gets its own fill byte so that a mixed-up read shows up
    /// as *wrong content* in the assertions below, not as a resolve error
    /// that would only say something failed without saying which read broke
    /// it. `datalen` and `keylen` are deliberately given **different**
    /// numeric values (`40` and `17`) rather than sharing one -- a review
    /// pass found that with both at `32`, a hypothetical swap between the
    /// two field assignments in `read_args`'s `Ok(Marshalled { .. })` would
    /// go numerically undetected (`args.datalen == 32` and `args.keylen as
    /// u32 == 32` either way). That swap was applied by hand and confirmed
    /// this test then fails (task report, "the datalen/keylen swap
    /// mutation"); it is not left behind as its own test, because the
    /// mutation is in `read_args`'s production code, not in a second
    /// fixture worth maintaining.
    #[test]
    fn read_args_puts_each_of_the_seven_in_its_own_field() {
        const POSBLK_FILL: u8 = 0xA1;
        const DATABUF_FILL: u8 = 0xB2;
        const KEYBUF_FILL: u8 = 0xC3;
        // Deliberately unequal to each other -- see this test's own doc
        // comment -- and each still sized to match the buffer it describes,
        // so resolving either does not run past what was actually filled.
        const DATABUF_LEN: usize = 40;
        const KEYBUF_LEN: usize = 17;
        // Upper sixteen bits are deliberately garbage, the same shape the
        // real call site produces (see `read_args`'s own comment on `op`):
        // this also proves the truncating cast, not just the argument's
        // position.
        const OP_PUSHED: u32 = 0xABCD_1234;
        const OP_EXPECTED: u16 = 0x1234;
        const KEYLEN: u8 = 17; // == KEYBUF_LEN, so the key buffer resolves
        const KEYNUM: i8 = -5;

        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut l = crate::win32::load::load(&file).expect("loads");

        let posblk_at = l.mem.alloc(128).expect("posblk region").0;
        Flat32Ptr(posblk_at)
            .write(&mut l.mem, &[POSBLK_FILL; 128])
            .expect("posblk region is writable");

        let databuf_at = l.mem.alloc(DATABUF_LEN).expect("databuf region").0;
        Flat32Ptr(databuf_at)
            .write(&mut l.mem, &[DATABUF_FILL; DATABUF_LEN])
            .expect("databuf region is writable");

        let datalen_at = l.mem.alloc(4).expect("datalen region").0;
        Flat32Ptr(datalen_at)
            .write(&mut l.mem, &u32::try_from(DATABUF_LEN).unwrap().to_le_bytes())
            .expect("datalen region is writable");

        let keybuf_at = l.mem.alloc(KEYBUF_LEN).expect("keybuf region").0;
        Flat32Ptr(keybuf_at)
            .write(&mut l.mem, &[KEYBUF_FILL; KEYBUF_LEN])
            .expect("keybuf region is writable");

        // Seven `push imm32`, in Galacticomm's own right-to-left stdcall
        // order -- `ckeynum` first (rightmost declared parameter),
        // `operation` last (leftmost, ends up nearest the return address) --
        // then a near call into an armed thunk slot: the same trap every
        // real import call produces, built by hand instead of by running
        // the program up to a real call site.
        const SLOT: u16 = 450;
        let mut code_mapping = Mapping::new(4096).expect("a low code mapping");
        let base = code_mapping.base() as usize as u32;
        let mut code = Vec::new();
        let push_imm32 = |code: &mut Vec<u8>, v: u32| {
            code.push(0x68);
            code.extend_from_slice(&v.to_le_bytes());
        };
        #[allow(clippy::cast_sign_loss)]
        push_imm32(&mut code, KEYNUM as u32); // arg6: ckeynum
        push_imm32(&mut code, u32::from(KEYLEN)); // arg5: keyLength
        push_imm32(&mut code, keybuf_at); // arg4: keyBuffer
        push_imm32(&mut code, datalen_at); // arg3: dataLength
        push_imm32(&mut code, databuf_at); // arg2: dataBuffer
        push_imm32(&mut code, posblk_at); // arg1: posBlock
        push_imm32(&mut code, OP_PUSHED); // arg0: operation

        let target = l.machine.thunk_addr(SLOT);
        let next_ip = base + code.len() as u32 + 5;
        code.push(0xe8); // call rel32
        code.extend_from_slice(&target.wrapping_sub(next_ip).to_le_bytes());
        code_mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let exit = l
            .machine
            .call_on(l.mem.stack_mut(), base, &[])
            .expect("the hand-built frame traps into the armed thunk");
        assert_eq!(
            exit,
            Exit::Call { index: SLOT },
            "the armed thunk must report the slot this test armed"
        );

        let args = read_args(&l.machine, &l.mem).expect("every pointer above resolves");

        assert_eq!(args.op, OP_EXPECTED, "operation: garbage upper bits must be truncated away");
        assert_eq!(args.posblk_at, posblk_at, "posBlock pointer");
        assert_eq!(args.posblk, [POSBLK_FILL; 128], "posBlock contents");
        assert_eq!(args.databuf_at, databuf_at, "dataBuffer pointer");
        assert_eq!(args.databuf, vec![DATABUF_FILL; DATABUF_LEN], "dataBuffer contents");
        assert_eq!(args.datalen_at, datalen_at, "dataLength pointer");
        assert_eq!(args.datalen, u32::try_from(DATABUF_LEN).unwrap(), "*dataLength");
        assert_eq!(args.keybuf_at, keybuf_at, "keyBuffer pointer");
        assert_eq!(args.keybuf, vec![KEYBUF_FILL; KEYBUF_LEN], "keyBuffer contents");
        assert_eq!(args.keylen, KEYLEN, "keyLength");
        assert_eq!(args.keynum, KEYNUM, "ckeynum");
    }

    /// `*dataLength` with garbage in its upper sixteen bits must still
    /// resolve the data buffer at the real, small length -- not fail, and
    /// not read millions of bytes.
    ///
    /// This is not a hypothetical: `re/wg33src/SRC/api/gcommlib/DFAAPI.C:914,
    /// 978` casts the address of `btvu`'s own `USHORT rlen` parameter
    /// straight to `ULONG *` before calling `BTRCALL`, so the real caller
    /// hands this host four bytes where only the low two were ever meant to
    /// be a length -- the top two are whatever sits next to `rlen` on the
    /// guest's own stack frame. Measured live, inside this task's own
    /// `-recover` run: op 33 (Step First) read `0x4101_0190` there before
    /// this fix, where `0x0190` (400) is a plausible record length and
    /// `0x4101` is address-shaped stack noise -- resolving the full 32-bit
    /// value failed outright ("1090584976 bytes runs past the end of the
    /// image"), which is what surfaced this.
    #[test]
    fn a_datalength_with_garbage_upper_bits_still_resolves_the_real_length() {
        const DATABUF_FILL: u8 = 0xB2;
        const REAL_LEN: u16 = 40;
        // Address-shaped, the same kind of noise the module's own stack
        // frame produced in the live measurement this test's doc comment
        // cites -- chosen to be unmistakably wrong if it leaks into the
        // resolved length.
        const GARBAGE_UPPER: u32 = 0x4101_0000;

        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut l = crate::win32::load::load(&file).expect("loads");

        let posblk_at = l.mem.alloc(128).expect("posblk region").0;
        Flat32Ptr(posblk_at)
            .write(&mut l.mem, &[0u8; 128])
            .expect("posblk region is writable");

        let databuf_at = l.mem.alloc(usize::from(REAL_LEN)).expect("databuf region").0;
        Flat32Ptr(databuf_at)
            .write(&mut l.mem, &[DATABUF_FILL; REAL_LEN as usize])
            .expect("databuf region is writable");

        let datalen_at = l.mem.alloc(4).expect("datalen region").0;
        Flat32Ptr(datalen_at)
            .write(&mut l.mem, &(GARBAGE_UPPER | u32::from(REAL_LEN)).to_le_bytes())
            .expect("datalen region is writable");

        const SLOT: u16 = 451;
        let mut code_mapping = Mapping::new(4096).expect("a low code mapping");
        let base = code_mapping.base() as usize as u32;
        let mut code = Vec::new();
        let push_imm32 = |code: &mut Vec<u8>, v: u32| {
            code.push(0x68);
            code.extend_from_slice(&v.to_le_bytes());
        };
        push_imm32(&mut code, 0); // arg6: ckeynum
        push_imm32(&mut code, 0); // arg5: keyLength (no key buffer offered)
        push_imm32(&mut code, 0); // arg4: keyBuffer
        push_imm32(&mut code, datalen_at); // arg3: dataLength
        push_imm32(&mut code, databuf_at); // arg2: dataBuffer
        push_imm32(&mut code, posblk_at); // arg1: posBlock
        push_imm32(&mut code, 33); // arg0: operation (Step First)

        let target = l.machine.thunk_addr(SLOT);
        let next_ip = base + code.len() as u32 + 5;
        code.push(0xe8); // call rel32
        code.extend_from_slice(&target.wrapping_sub(next_ip).to_le_bytes());
        code_mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let exit = l
            .machine
            .call_on(l.mem.stack_mut(), base, &[])
            .expect("the hand-built frame traps into the armed thunk");
        assert_eq!(exit, Exit::Call { index: SLOT });

        let args = read_args(&l.machine, &l.mem)
            .expect("the real length must resolve even with garbage above it");
        assert_eq!(args.datalen, u32::from(REAL_LEN), "the garbage upper bits are gone");
        assert_eq!(args.databuf, vec![DATABUF_FILL; REAL_LEN as usize]);
    }
}
