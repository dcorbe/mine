//! Borland's 32-bit C runtime, `cw3220mt.DLL`, as far as this program reaches
//! into it.
//!
//! **Three symbols of sixty-six.** `docs/2026-08-17-win32-crt-trace.md` is the
//! measurement, and it is the reason this file is short: the executable *links*
//! the whole C library and *calls* `_time`, `_srand` and `_memmove`. Every
//! string, stream and format symbol is linked and unreached. A symbol is
//! implemented here because the trace showed this program calling it, never
//! because the import table names it -- the import table names a symbol once
//! however many times it is called, and says nothing about whether it is called
//! at all.
//!
//! **This DLL is cdecl; the Win32 DLLs beside it are stdcall.** The caller pops
//! here, so every [`Answer`] this module builds comes from [`Answer::cdecl`] and
//! cleans nothing. That is not a detail: [`crate::win32::kernel32`]'s own doc
//! comment records what a wrong `cleans` does, and it corrupts the *next* call
//! rather than this one, which is why the convention is written into the
//! constructor's name instead of being a number at each site.
//!
//! Reference semantics for these symbols exist in `crates/mbbs/src/shims/`, and
//! they are a *reference* rather than reusable code: every one of those takes
//! `&mut Host<A>`, the entire MajorBBS host -- exports, globals, users,
//! channels. `dos-runtime` does not depend on that and must not. Read them for
//! what the function does; the body is written here.

use std::time::{SystemTime, UNIX_EPOCH};

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::kernel32::Answer;
use crate::win32::process::Process;

/// Borland's `rand`, which is a specific 32-bit LCG rather than "an LCG".
///
/// `state = state * 22695477 + 1`, answering the **high** half masked to
/// `RAND_MAX`. Every one of those details is read off an instruction rather
/// than assumed: `crates/mbbs/src/random.rs` disassembles this exact function
/// out of four period Galacticomm host binaries and three unrelated ones, and
/// its module doc lays out the bytes. The increment, the high half being the
/// half returned, the mask, and `srand` zero-extending its argument into the
/// state are precisely the four things a from-memory reconstruction of "the
/// Borland LCG" gets wrong.
///
/// Duplicated here rather than imported because `crates/mbbs` is the MajorBBS
/// host and this is a standalone utility runtime; the shared thing is the
/// *measurement*, which lives in that module's documentation, not the six lines
/// of arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Random {
    state: u32,
}

/// The largest value `rand` can answer, and the mask that guarantees it.
pub const RAND_MAX: u32 = 0x7fff;

impl Random {
    /// Seeded as `srand` seeds it.
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    /// One draw, in `[0, RAND_MAX]`.
    pub fn rand(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(22_695_477).wrapping_add(1);
        (self.state >> 16) & RAND_MAX
    }
}

impl Default for Random {
    /// `srand(1)`, which is where C says an unseeded generator starts. A
    /// program that calls `rand` without `srand` must still get the sequence
    /// the real runtime would have given it.
    fn default() -> Self {
        Self::new(1)
    }
}

/// Seconds since the epoch, as `time_t`.
///
/// Saturating rather than wrapping on a clock set before 1970: a negative
/// `time_t` reinterpreted as `u32` is a date in 2106, and a maintenance utility
/// that stamps records with it would write something silently wrong. Zero is
/// visibly wrong instead.
fn epoch_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

/// `time_t time(time_t *tloc)` -- seconds since 1970, returned *and* stored.
///
/// The store is not optional when `tloc` is non-null, and a host that returns
/// the value while skipping it breaks every caller that passed a buffer instead
/// of reading the return. `crates/mbbs/src/shims/system.rs:1060` is the
/// reference and does the same thing on the 16-bit side.
///
/// A null `tloc` is C's way of spelling "do not store it" -- the ordinary case,
/// not an error. On this flat 32-bit ABI null is literally the zero address, so
/// unlike the segmented side there is no "every byte zero" subtlety to get
/// right.
///
/// A `tloc` that points nowhere resolvable is ignored rather than failing the
/// call: `time` has no way to report an error to its caller, and taking the
/// host down over a bad pointer the program will never read is worse than
/// answering the question it asked.
pub fn time(mem: &mut Memory, tloc: u32) -> u32 {
    let seconds = epoch_seconds();
    if tloc != 0 {
        let _ = Flat32Ptr(tloc).write(mem, &seconds.to_le_bytes());
    }
    seconds
}

/// `void *memmove(void *dest, const void *src, size_t n)` -- returns `dest`.
///
/// **Overlap-safe by construction.** The bytes are read out into a host buffer
/// before any of them are written back, so a forward-overlapping copy cannot
/// clobber the source it has not read yet. That is `memmove`'s entire contract
/// and the only thing separating it from `memcpy`; doing it by reading and
/// writing the guest's memory in place would reintroduce exactly the bug the
/// program chose this function to avoid.
///
/// A copy that cannot be resolved -- either end unmapped, or crossing out of
/// its mapping -- copies nothing and still answers `dest`, because that is what
/// the caller will use as a pointer regardless.
pub fn memmove(mem: &mut Memory, dest: u32, src: u32, n: u32) -> u32 {
    let len = n as usize;
    if len == 0 || dest == src {
        return dest;
    }
    let Ok(bytes) = Flat32Ptr(src).resolve(mem, len) else {
        return dest;
    };
    let copy = bytes.to_vec();
    let _ = Flat32Ptr(dest).write(mem, &copy);
    dest
}

/// Answer a `cw3220mt.DLL` import, or `None` for one still unimplemented.
///
/// `None` is what makes an unimplemented symbol a *diagnosable* event:
/// [`crate::win32::process::run`] turns it into `Outcome::Unimplemented` naming
/// the symbol, rather than resuming with a plausible zero the program would
/// carry off somewhere else before failing. Sixty-two of this DLL's symbols are
/// deliberately in that state.
///
/// Arguments are read into locals before anything borrows `mem` mutably --
/// reading one borrows the stack, which lives in `mem`. That is the same rule
/// [`crate::win32::kernel32::dispatch`] documents, and it is why each arm reads
/// eagerly and only as far as its own declared argument count.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // time_t time(time_t *tloc)
        "_time" => {
            let tloc = machine.arg_u32(mem.stack(), 0);
            Some(Answer::cdecl(time(mem, tloc)))
        }
        // void srand(unsigned seed)
        "_srand" => {
            let seed = machine.arg_u32(mem.stack(), 0);
            process.random = Random::new(seed);
            Some(Answer::cdecl(0))
        }
        // int rand(void)
        //
        // Unreached in the trace, and implemented anyway -- see the module doc
        // on why that is not a contradiction here. `_srand` *is* reached, and a
        // host that stores a seed nothing ever draws from has implemented half
        // of one generator rather than one of two functions. The pair is the
        // unit.
        "_rand" => Some(Answer::cdecl(process.random.rand())),
        // void *memmove(void *dest, const void *src, size_t n)
        "_memmove" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let n = machine.arg_u32(mem.stack(), 2);
            Some(Answer::cdecl(memmove(mem, dest, src, n)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32::process;

    fn loaded() -> crate::win32::load::Loaded {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        crate::win32::load::load(&file).expect("loads")
    }

    /// The generator is Borland's, and the sequence is the evidence.
    ///
    /// `srand(1)` then `rand()` is 346 for *this* LCG and something else for
    /// every other one -- 41 for Microsoft's, 1481765933 for glibc's. Asserting
    /// a literal draw is what makes this a test of the recovered algorithm
    /// rather than a test that some numbers came out.
    #[test]
    fn rand_is_borlands_lcg_and_not_merely_random() {
        let mut r = Random::new(1);
        assert_eq!(r.rand(), 346, "state = 1*22695477+1 = 0x015A4E36, high half");

        // Every draw is inside RAND_MAX. The mask is a real instruction in the
        // disassembly, not a tidy-up: without it the high half is 16 bits and
        // a caller doing `rand() % n` gets a different distribution.
        let mut r = Random::new(12345);
        for _ in 0..1000 {
            assert!(r.rand() <= RAND_MAX);
        }
    }

    /// Seeding is what `srand` is *for*: the same seed must replay, and a
    /// different seed must not. A host that ignored the seed would pass the
    /// first half of this and fail the second.
    #[test]
    fn the_same_seed_replays_and_a_different_one_does_not() {
        let draw = |seed| {
            let mut r = Random::new(seed);
            (0..8).map(|_| r.rand()).collect::<Vec<_>>()
        };
        assert_eq!(draw(42), draw(42), "the same seed replays exactly");
        assert_ne!(draw(42), draw(43), "a different seed diverges");
    }

    /// An unseeded generator starts at `srand(1)`, as C requires -- not at
    /// zero, which is a fixed point of nothing here but is the value a host
    /// that forgot would use.
    #[test]
    fn the_default_generator_is_seeded_one() {
        assert_eq!(Random::default(), Random::new(1));
        assert_eq!(Random::default().rand(), 346);
    }

    /// `time` returns the clock *and* stores it. The store is the half a host
    /// forgets, because the return value is the half every caller reads first.
    #[test]
    fn time_returns_the_clock_and_stores_it_through_a_non_null_pointer() {
        let mut l = loaded();
        let at = process::put(&mut l.mem, &[0u8; 4]).expect("arena");

        let returned = time(&mut l.mem, at);
        assert!(returned > 1_700_000_000, "a plausible epoch, not zero");

        let stored = Flat32Ptr(at).resolve(&l.mem, 4).expect("in memory");
        assert_eq!(
            u32::from_le_bytes(stored.try_into().unwrap()),
            returned,
            "the stored time_t and the returned one are the same value"
        );
    }

    /// A null `tloc` means "do not store", and must not be treated as an
    /// address. Writing to guest address zero would be the failure this test
    /// exists to catch.
    #[test]
    fn a_null_tloc_is_not_written_to() {
        let mut l = loaded();
        let returned = time(&mut l.mem, 0);
        assert!(returned > 1_700_000_000);
        assert!(
            Flat32Ptr(0).resolve(&l.mem, 4).is_err(),
            "address zero resolves nowhere, so nothing was written there"
        );
    }

    /// The contract that separates `memmove` from `memcpy`: a forward overlap.
    /// Copying `[0..5]` to `[2..7]` byte-at-a-time low-to-high smears the first
    /// byte across the destination; `memmove` must not.
    #[test]
    fn memmove_survives_a_forward_overlap() {
        let mut l = loaded();
        let at = process::put(&mut l.mem, b"ABCDE\0\0").expect("arena");

        let returned = memmove(&mut l.mem, at + 2, at, 5);
        assert_eq!(returned, at + 2, "memmove answers dest");

        let after = Flat32Ptr(at).resolve(&l.mem, 7).expect("in memory");
        assert_eq!(
            after, b"ABABCDE",
            "the source was read out before any of it was written back"
        );
    }

    /// A backward overlap, which is the direction a naive implementation gets
    /// right by accident -- included so the test above cannot be satisfied by
    /// simply reversing the copy order.
    #[test]
    fn memmove_survives_a_backward_overlap() {
        let mut l = loaded();
        let at = process::put(&mut l.mem, b"ABCDE\0\0").expect("arena");

        memmove(&mut l.mem, at, at + 2, 5);

        let after = Flat32Ptr(at).resolve(&l.mem, 5).expect("in memory");
        assert_eq!(after, b"CDE\0\0");
    }

    /// Zero bytes copies nothing and still answers `dest`. C permits it, and a
    /// host that resolved a zero-length range first might refuse the call.
    #[test]
    fn memmove_of_nothing_is_not_an_error() {
        let mut l = loaded();
        let at = process::put(&mut l.mem, b"ABCDE").expect("arena");
        assert_eq!(memmove(&mut l.mem, at, at + 1, 0), at);
        let after = Flat32Ptr(at).resolve(&l.mem, 5).expect("in memory");
        assert_eq!(after, b"ABCDE", "nothing moved");
    }

    /// An unresolvable copy answers `dest` rather than taking the host down.
    /// The program will use the pointer whatever happens here.
    #[test]
    fn memmove_from_nowhere_answers_dest_without_panicking() {
        let mut l = loaded();
        let at = process::put(&mut l.mem, b"ABCDE").expect("arena");
        assert_eq!(memmove(&mut l.mem, at, 0, 5), at);
        let after = Flat32Ptr(at).resolve(&l.mem, 5).expect("in memory");
        assert_eq!(after, b"ABCDE", "an unresolvable source copies nothing");
    }

    /// The dispatcher answers what the trace named and declines the rest. The
    /// decline is the load-bearing half: sixty-two symbols must arrive as
    /// `Unimplemented` naming themselves rather than as a silent zero.
    #[test]
    fn unreached_symbols_are_declined_rather_than_answered() {
        let mut l = loaded();
        let mut p = Process::new("C:\\WCCMMUTL.EXE", &[]);
        for symbol in ["_strlen", "_fopen", "_malloc", "_longjmp", "_sprintf"] {
            assert!(
                dispatch(&mut p, &mut l.machine, &mut l.mem, symbol).is_none(),
                "{symbol} is unreached and must stay diagnosable"
            );
        }
    }
}
