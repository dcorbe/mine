//! Call the genuine MajorBBS host's `opnbtv`, routing its low-level Btrieve
//! call through the real engine instead of this project's own inference
//! about what the real host would do.
//!
//! ```sh
//! cargo run -p mbbs16 --example btv_oracle
//! ```
//!
//! # The tap point is `btvu`, not the interrupt
//!
//! `docs/plans/2026-08-09-btrieve-engine-in-the-loop.md`'s Task 6 measured
//! `btvu` at NE segment 31, offset `0xf5e`: the one place in this binary the
//! full Btrieve call (operation, buffers, key, position) is assembled before
//! anything about *how* the interrupt gets issued is decided. The same
//! technique `fsd_oracle.rs` uses for the video BIOS -- a `JMP FAR` written
//! over the routine's entry, serviced as `Exit::Call` -- installs there.
//!
//! `btvu`'s own calling convention, read from the `[bp+N]` arguments its body
//! stores into `struct btvdat`'s fields (`crates/mbbs/tests/btv_statics.rs`'s
//! header names the struct), matches `PLBTVSTF.C:94`'s declared
//! `btvuptr` prototype exactly: `funcno, datbufseg, keyseg, keyno, dbflen`.
//! Two things this binary's `btvu` does that the declared C prototype does
//! not say: it always sends `keylen = 0xFF` regardless of the actual key
//! width (measured, not the source's business -- the source doesn't show this
//! function's body at all), and for `B_OPEN` the "key" argument carries the
//! filename, matching `btrvprobe.c`'s `open_file()` doing the same thing
//! against the real DLL directly.
//!
//! # `opnbtv`'s preamble does real hardware and DOS-extender work
//!
//! Calling `opnbtv` cold -- without ever running the module's own
//! initialization -- reaches four things this machine has no model for
//! before it ever gets near `btvu`:
//!
//! - **`DosBlockIntr`/`DosUnblockIntr`** (`PLSTUFF.C`), NE segment 33 offsets
//!   `0x119c`/`0x11ae`: inline `cli` / `in al,21h` / `out 21h,al` critical-
//!   section guards. No `Exit` variant covers a raw `IN`/`OUT`/`CLI`
//!   instruction -- there is nothing to intercept a *call* into, because they
//!   are not calls -- so both routines are tapped exactly like `btvu`, with
//!   the tap doing nothing at all. A single-threaded sandbox with no other
//!   client has nothing these guards protect against.
//! - **`PHAPI.DosAllocRealSeg`**, **`DOSCALLS.DosAllocHuge`** (ordinal 40):
//!   real-mode segment allocation. Answered with
//!   [`Machine::alloc_segment`] -- there is no real/protected-mode
//!   distinction here, so the one kind of memory this machine has is the
//!   right answer for both.
//! - **`DOSCALLS.DosGetHugeShift`** (ordinal 41): already modelled by this
//!   project, `crates/mbbs/src/shims/mod.rs`'s `ABSOLUTES` table
//!   (`mbbs16::SELECTOR_STEP.ilog2()`) -- reused here rather than
//!   re-derived. Its signature takes a far-pointer output argument
//!   (`PHAPI.H:569`); missing that argument's stack cleanup on a first pass
//!   left every call after it four bytes out of alignment, which is the
//!   debugging story behind this file's `resume_cleaning` calls all being
//!   measured against the real call site rather than assumed from the header
//!   alone.
//! - **`DOSCALLS.DosFreeSeg`** (ordinal 39): a no-op. This rig makes one call
//!   and exits; it does not run low on selectors.
//!
//! None of these five ever appears in `docs/plans/2026-08-09-btrieve-engine-in-the-loop.md`'s
//! own text -- they are what stood between `opnbtv` and `btvu`, found by
//! running the call and reading the fault or the unhandled `Exit::Call` each
//! one produced, in order, the same way `fsd_oracle.rs`'s BIOS was found.
//!
//! # `posblk` is tracked here, not through the module's own table
//!
//! `btvu`'s own housekeeping reads/writes the position block through an
//! indirection (`es:[bx+0xc0]` after `les bx,[157:0x4c]`) that some routine
//! earlier than `opnbtv` normally initializes. Calling `opnbtv` directly
//! skips whatever that is, and the indirection is null on this cold-start
//! path. The wire protocol between this process and the real engine already
//! carries `posblk` on every call for exactly this reason -- the caller owns
//! cursor state -- so this loop is that caller: it keeps the last response's
//! `posblk` and feeds it into the next request, which is what makes the
//! `B_OPEN` this rig issues and the `B_STAT` `opnbtv` issues right after it
//! agree that they are talking about the same open file.
//!
//! # Acceptance
//!
//! `opnbtv("WCCSPELS.VIR", 253)` returns a non-null `struct btvblk*` whose
//! `reclen` field (`BTVSTF.H`, offset `0x84`: 128 bytes of `posblk` plus a
//! 4-byte `filnam`) reads 253 -- and the file was opened by two real
//! `BTRCALL`s (`B_OPEN` then `opnbtv`'s own follow-up `B_STAT`) through the
//! genuine engine, not assumed.

use btrieve_engine::{Engine, Request};
use mbbs16::{Exit, FarPtr, Import, Machine, Ret, Symbol};

/// NE segment 31: `btvu` and its callers.
const BTV_CODE: u16 = 31;
/// `btvu`, `docs/plans/2026-08-09-btrieve-engine-in-the-loop.md` Task 6.
const BTVU_OFFSET: u16 = 0xf5e;
/// `opnbtv`, `python3 re/ne_exports.py re/hosts/MAJORBBS-mbbstd.EXE --list`.
const OPNBTV_ORDINAL: u16 = 455;

/// NE segment 33: `PLSTUFF.C`.
const PLSTUFF_SEGMENT: u16 = 33;
const DOS_BLOCK_INTR_OFFSET: u16 = 0x119c;
const DOS_UNBLOCK_INTR_OFFSET: u16 = 0x11ae;

/// NE segment 157: `btvu`'s own DGROUP-like statics, shared with the string
/// literal `crates/mbbs/tests/btv_statics.rs` is found by.
const BTVU_STATICS_SEGMENT: u16 = 157;
/// `statptseg`: the segment of a 2-byte real-mode buffer the low-level call
/// writes its status word into. `btvu`'s body reads this from a fixed
/// DS-relative offset, so every call shares it.
const STATPTSEG_OFFSET: u16 = 0x16;

/// `struct btvblk`'s `reclen`, `BTVSTF.H`: `posblk[32 longs]` (128 bytes)
/// then `filnam` (a far pointer, 4 bytes), then `reclen`.
const BTVBLK_RECLEN_OFFSET: u16 = 128 + 4;

fn main() -> std::io::Result<()> {
    let path = "re/hosts/MAJORBBS-mbbstd.EXE";
    let file = std::fs::read(path)?;

    let mut machine = Machine::new()?;
    let module = machine.load_ne(&file, &|_: &str, _: &Symbol| Some(Import::Routine))?;

    let opnbtv = module.entry(OPNBTV_ORDINAL).expect("opnbtv exported at 455");

    let btvu = FarPtr {
        offset: BTVU_OFFSET,
        selector: module.segment_selector(BTV_CODE).expect("segment 31 is mapped"),
    };
    let block_intr = FarPtr {
        offset: DOS_BLOCK_INTR_OFFSET,
        selector: module.segment_selector(PLSTUFF_SEGMENT).expect("segment 33 is mapped"),
    };
    let unblock_intr = FarPtr {
        offset: DOS_UNBLOCK_INTR_OFFSET,
        selector: module.segment_selector(PLSTUFF_SEGMENT).expect("segment 33 is mapped"),
    };

    // Spare thunk slots, dense from `imports().len()` -- the same convention
    // `fsd_oracle.rs` uses for the video BIOS.
    let btvu_thunk = module.imports().len() as u16;
    let block_thunk = btvu_thunk + 1;
    let unblock_thunk = btvu_thunk + 2;

    for (at, idx) in [
        (btvu, btvu_thunk),
        (block_intr, block_thunk),
        (unblock_intr, unblock_thunk),
    ] {
        let to = machine.thunk_address(idx);
        let mut jmp_far = vec![0xea];
        jmp_far.extend_from_slice(&to.to_bytes());
        machine.write(at, &jmp_far)?;
    }
    println!("btvu at {btvu} -> thunk {btvu_thunk}");

    // Stage a fresh copy. The Microkernel caches pages by path and outlives
    // its clients -- see the warning in every file under tools/btrieve-oracle/.
    let prefix = std::env::var("BTRIEVE_WINEPREFIX")
        .unwrap_or_else(|_| format!("{}/.btrieve-wine", std::env::var("HOME").unwrap()));
    let staged_name = format!("{}WCCSPELS.VIR", std::process::id());
    std::fs::copy("tmp/WCCSPELS.VIR", format!("{prefix}/drive_c/btrieve/{staged_name}"))?;
    let dos_path = format!("C:\\btrieve\\{staged_name}\0");

    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");

    let work = machine.alloc_segment(dos_path.len())?;
    machine.write(FarPtr { offset: 0, selector: work }, dos_path.as_bytes())?;
    let filnam = FarPtr { offset: 0, selector: work };

    println!("calling opnbtv(\"WCCSPELS.VIR\", 253) ...");
    let mut exit = machine.call(opnbtv, &[filnam.offset, filnam.selector, 253])?;

    // The caller owns cursor state, same as over the wire to btrvprobe
    // serve -- see this file's header for why the module's own table can't
    // be used instead.
    let mut posblk = [0u8; 128];

    loop {
        exit = match exit {
            Exit::Call { index } if index == block_thunk || index == unblock_thunk => {
                machine.resume(Ret::Void)?
            }

            Exit::Call { index } if index == btvu_thunk => {
                let funcno = machine.arg_u16(0);
                let datbufseg = machine.arg_u16(1);
                let keyseg = machine.arg_u16(2);
                let keyno = machine.arg_u16(3) as i8;
                let dbflen = machine.arg_u16(4);

                let mut keybuf = Vec::new();
                loop {
                    let b = machine.resolve(FarPtr { offset: keybuf.len() as u16, selector: keyseg }, 1)?[0];
                    keybuf.push(b);
                    if b == 0 || keybuf.len() > 260 {
                        break;
                    }
                }
                println!(
                    "btvu: funcno={funcno} keyno={keyno} dbflen={dbflen} keybuf={:?}",
                    String::from_utf8_lossy(&keybuf)
                );

                let response = engine
                    .call(Request {
                        op: funcno,
                        posblk,
                        datalen: u32::from(dbflen),
                        databuf: Vec::new(),
                        keylen: 255,
                        keynum: keyno,
                        keybuf,
                    })
                    .expect("BTRCALL over the real engine");
                println!("  -> engine status {}", response.status);
                posblk = response.posblk;

                let statptseg_at = FarPtr {
                    offset: STATPTSEG_OFFSET,
                    selector: module.segment_selector(BTVU_STATICS_SEGMENT).expect("segment 157 is mapped"),
                };
                let statptseg = u16::from_le_bytes(machine.resolve(statptseg_at, 2)?.try_into().unwrap());
                machine.write(FarPtr { offset: 0, selector: statptseg }, &response.status.to_le_bytes())?;
                if datbufseg != 0 && !response.databuf.is_empty() {
                    machine.write(FarPtr { offset: 0, selector: datbufseg }, &response.databuf)?;
                }

                machine.resume(Ret::U16(0))?
            }

            Exit::Call { index } => {
                let who = module
                    .import(index)
                    .map(|i| format!("{}.{:?}", i.module, i.symbol))
                    .unwrap_or_else(|| format!("thunk {index}, no import site"));

                match who.as_str() {
                    "PHAPI.Name(\"DOSALLOCREALSEG\")" => {
                        // USHORT APIENTRY DosAllocRealSeg(ULONG size, PUSHORT
                        // parap, PSEL selp); Pascal: args pushed left to
                        // right, so index 0 is the LAST declared parameter.
                        let selp = machine.arg_far(0);
                        let parap = machine.arg_far(2);
                        let size = u32::from(machine.arg_u16(4)) | (u32::from(machine.arg_u16(5)) << 16);
                        let seg = machine.alloc_segment((size as usize).max(1))?;
                        machine.write(selp, &seg.to_le_bytes())?;
                        machine.write(parap, &seg.to_le_bytes())?;
                        machine.resume_cleaning(Ret::U16(0), 12)?
                    }
                    "DOSCALLS.Ordinal(41)" => {
                        // USHORT APIENTRY DosGetHugeShift(PUSHORT countp);
                        let shift = mbbs16::SELECTOR_STEP.ilog2() as u16;
                        let countp = machine.arg_far(0);
                        machine.write(countp, &shift.to_le_bytes())?;
                        machine.resume_cleaning(Ret::U16(0), 4)?
                    }
                    "DOSCALLS.Ordinal(40)" => {
                        // USHORT APIENTRY DosAllocHuge(USHORT nseg, USHORT
                        // lcount, PSEL selp, USHORT maxsel, USHORT flags);
                        // Pascal, and selp's segment half is passed in ES --
                        // a register, not an argument word -- so it is read
                        // from the module's DGROUP rather than the arg
                        // stack; measured against the real call site
                        // (segment 1, ~0x5951), not assumed from the header.
                        let selp = FarPtr { offset: 0x1a08, selector: module.data_selector() };
                        let seg = machine.alloc_segment(65536)?;
                        machine.write(selp, &seg.to_le_bytes())?;
                        machine.resume_cleaning(Ret::U16(0), 12)?
                    }
                    "DOSCALLS.Ordinal(39)" => {
                        // USHORT APIENTRY DosFreeSeg(SEL sel); -- no-op, this
                        // rig makes one call and exits.
                        machine.resume_cleaning(Ret::U16(0), 2)?
                    }
                    _ => {
                        println!("Call out to an unhandled import: {who}");
                        println!(
                            "  args as u16: {:?}",
                            (0..8).map(|n| machine.arg_u16(n)).collect::<Vec<_>>()
                        );
                        return Ok(());
                    }
                }
            }

            Exit::Returned { ax, dx } => {
                let btvblk = FarPtr { offset: ax, selector: dx };
                println!("opnbtv returned {btvblk}");
                assert_ne!(dx, 0, "opnbtv should not return a null btvblk");
                let reclen = u16::from_le_bytes(
                    machine
                        .resolve(
                            FarPtr { offset: btvblk.offset + BTVBLK_RECLEN_OFFSET, selector: btvblk.selector },
                            2,
                        )?
                        .try_into()
                        .unwrap(),
                );
                println!("btvblk->reclen = {reclen}");
                assert_eq!(reclen, 253, "opnbtv(\"WCCSPELS.VIR\", 253) should report reclen 253");
                println!("OK: opnbtv opened WCCSPELS.VIR through the real Btrieve engine");
                return Ok(());
            }

            other => {
                println!("{other:?}");
                return Ok(());
            }
        };
    }
}
