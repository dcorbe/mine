//! The process's one LDT free list.
//!
//! `crates/mbbs-machine/src/m16/seg.rs` had a proven one-shot/tiled
//! allocator for it; `crates/mbbs-machine/src/m32/tib.rs` grew a second,
//! from-scratch one rather than share it, and its own module comment said
//! exactly why that would break:
//!
//! > A process that loads both a 16-bit and a 32-bit module at once could
//! > have `mbbs16` and `mbbs32` each believe entry *N* is theirs and hand it
//! > out independently -- silently overwriting each other's descriptor...
//! > Worth fixing before that day arrives, most simply by putting one
//! > allocator behind a single crate both sides depend on.
//!
//! That day arrived building `crates/mbbs-fault`: a test that constructs a
//! `crate::m16::Machine` and then a `crate::m32::Machine` found this instead of, or
//! rather in addition to, the fault-dispatch bug it was written to catch --
//! `crate::m32::tib::Tib::new`'s call to its own `take_one()` reserved LDT entry
//! 0 with no idea `m16` already owned it, overwrote the descriptor the
//! 16-bit machine's code segment depended on, and the very first far jump
//! into the module faulted before it executed a single instruction, let
//! alone the deliberate one the test needed. No amount of fault-handler
//! arbitration fixes that: the module's memory was gone before anything
//! could fault.
//!
//! The kernel's LDT is one 8,192-entry table per process regardless of how
//! many ABIs carve descriptors out of it, so the free list describing
//! which entries are spoken for has to be one table too. This module is that
//! table and nothing else: `modify_ldt`'s bitfield encoding, `struct
//! user_desc`, and everything about what a *reserved* entry's descriptor
//! contains stay in `crate::m16::seg` and `crate::m32::tib`, which differ in exactly
//! the ways their modules do (16-bit code segments taken in tiled runs vs.
//! one 32-bit data segment per TIB). Only which entry numbers are free is
//! shared.

use std::io;
use std::sync::{Mutex, PoisonError};

/// How many entries an LDT has. Fixed by the kernel, not a choice either ABI
/// makes.
pub const LDT_ENTRIES: u32 = 8192;

/// `u64`s needed to give every LDT entry a bit.
const WORDS: usize = LDT_ENTRIES as usize / 64;

/// Which LDT entries are spoken for, by any ABI.
///
/// A bitmap rather than a counter and a free list, because a tiled region
/// (`m16`'s multi-segment loads) needs its descriptors to be adjacent, and
/// only a bitmap scan can promise that alongside reuse of freed entries.
static IN_USE: Mutex<[u64; WORDS]> = Mutex::new([0; WORDS]);

fn in_use() -> std::sync::MutexGuard<'static, [u64; WORDS]> {
    // Nothing inside the critical section can panic in a way that matters,
    // and failing an allocation because an unrelated thread died is worse
    // than carrying on with a table that is merely correct.
    IN_USE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn taken(bits: &[u64; WORDS], entry: u32) -> bool {
    bits[entry as usize / 64] & (1 << (entry % 64)) != 0
}

/// Reserve `count` adjacent entries and return the first.
///
/// First fit, lowest first, so a freed slot is handed out again before a
/// fresh one -- the LDT is a fixed 8,192 entries, and loading and unloading
/// modules many times over would otherwise run the table out. `count == 1`
/// is an ordinary single-entry reservation, exactly what `crate::m32::tib::Tib`
/// needs; `m16` uses larger counts for a tiled region.
pub fn take_run(count: u32) -> io::Result<u32> {
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
pub fn give_run(start: u32, count: u32) {
    let mut bits = in_use();
    for e in start..start + count {
        bits[e as usize / 64] &= !(1 << (e % 64));
    }
}
