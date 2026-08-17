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
use crate::win32::process::{self, Process};

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

/// `void *memset(void *dest, int c, size_t n)` -- returns `dest`.
///
/// Only the low byte of `c` is written, which is C's rule and not a
/// simplification: `memset(p, 0x1ff, n)` fills with `0xff`.
pub fn memset(mem: &mut Memory, dest: u32, c: u32, n: u32) -> u32 {
    let len = n as usize;
    if len == 0 {
        return dest;
    }
    #[allow(clippy::cast_possible_truncation)]
    let byte = c as u8;
    let _ = Flat32Ptr(dest).write(mem, &vec![byte; len]);
    dest
}

/// The bytes of a C string at `at`, without its terminator.
///
/// `None` when the address resolves nowhere or the string has no terminator
/// before the end of its mapping. Both are "there is no string here", and no
/// caller in this module distinguishes them.
fn cstr(mem: &Memory, at: u32) -> Option<Vec<u8>> {
    if at == 0 {
        return None;
    }
    Flat32Ptr(at).read_cstr(mem).ok().map(<[u8]>::to_vec)
}

/// Write `bytes` plus a terminator at `at`, and answer `at`.
///
/// The terminator is added here rather than by each caller, because a `strcpy`
/// that forgets it is a bug that shows up in whatever happens to follow the
/// destination in memory.
fn put_cstr_at(mem: &mut Memory, at: u32, bytes: &[u8]) -> u32 {
    let mut owned = bytes.to_vec();
    owned.push(0);
    let _ = Flat32Ptr(at).write(mem, &owned);
    at
}

/// C's three-way comparison as an `int`: negative, zero or positive.
///
/// **The sign is the contract and the magnitude is not.** Callers write
/// `if (strcmp(a, b) < 0)`, so what matters is that unequal strings order
/// consistently -- returning the byte difference, as most implementations do,
/// is one valid choice among many.
fn compare(a: &[u8], b: &[u8]) -> u32 {
    let ord = match a.cmp(b) {
        std::cmp::Ordering::Less => -1i32,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    ord as u32
}

/// `stricmp` -- case-insensitive, and the reason this program can match its own
/// switches however the operator typed them.
pub fn stricmp_bytes(a: &[u8], b: &[u8]) -> u32 {
    let lower = |s: &[u8]| s.to_ascii_lowercase();
    compare(&lower(a), &lower(b))
}

/// `atol` -- leading whitespace, an optional sign, then digits, stopping at the
/// first byte that is not one.
///
/// Never fails: C's `atol` has no error report, and a string with no digits at
/// all is zero. Saturating rather than wrapping on overflow, because a wrapped
/// record number is a plausible-looking wrong answer and a saturated one is
/// visibly wrong.
pub fn atol_bytes(s: &[u8]) -> u32 {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    let negative = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut value: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(s[i] - b'0'));
        i += 1;
    }
    if negative {
        value = -value;
    }
    let clamped = value.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
    #[allow(clippy::cast_possible_truncation)]
    let narrowed = clamped as i32;
    narrowed as u32
}

/// `void *malloc(size_t)` -- a pointer out of the program's own arena.
///
/// **Nothing is ever freed**, and that is a bounded decision rather than an
/// oversight. `Memory::alloc` is a bump allocator; this is a maintenance
/// utility that runs once and exits; and the arena's fixed size is what will
/// say so if that assumption breaks -- loudly, by refusing, rather than quietly,
/// by handing back a block that is still in use. If a run ever exhausts it,
/// raising `ARENA_LEN` is the first response and a real allocator is a decision
/// for whoever hits it, not something to build in advance.
///
/// Zero bytes returns a distinct non-null pointer, as C requires: a `malloc(0)`
/// that answered NULL would be indistinguishable from failure, and the caller
/// would take its out-of-memory path over a request it made deliberately.
///
/// NULL on exhaustion, which is `malloc`'s own way of reporting it.
pub fn malloc(mem: &mut Memory, bytes: u32) -> u32 {
    let want = (bytes.max(1)) as usize;
    mem.alloc(want).map_or(0, |p| p.0)
}

/// `void free(void *)` -- accepted and ignored. See [`malloc`].
///
/// Taking the pointer as an argument rather than being elided at the call site
/// keeps the dispatch arm honest about what the C function's signature is; the
/// argument is read off the frame either way.
pub fn free(_at: u32) {}

/// `char *strdup(const char *)` -- a copy of the string in fresh memory.
///
/// Fails to NULL on either half: an unreadable source or an exhausted arena.
/// C's `strdup` reports both the same way, and a caller checking the result
/// cannot tell them apart either.
pub fn strdup(mem: &mut Memory, at: u32) -> u32 {
    let Ok(bytes) = Flat32Ptr(at).read_cstr(mem) else {
        return 0;
    };
    let mut owned = bytes.to_vec();
    owned.push(0);
    let Ok(dest) = mem.alloc(owned.len()) else {
        return 0;
    };
    if dest.write(mem, &owned).is_err() {
        return 0;
    }
    dest.0
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
        // char *getenv(const char *name)
        //
        // A real lookup that finds nothing, rather than a constant NULL. See
        // `Process::env` for why the environment is empty and why that is the
        // right answer for the one variable this program asks about.
        //
        // The value is copied into the arena on each call rather than cached.
        // C's `getenv` may hand back a pointer the next call invalidates, so
        // nothing is promised by reusing one; and with an empty environment
        // this never allocates at all.
        "_getenv" => {
            let name_at = machine.arg_u32(mem.stack(), 0);
            let name = process::read_cstr(mem, name_at)?;
            let found = process
                .env
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone());
            match found {
                Some(v) => Some(Answer::cdecl(process::put_cstr(mem, &v).unwrap_or(0))),
                None => Some(Answer::cdecl(0)),
            }
        }
        // void *malloc(size_t size)
        "_malloc" => {
            let bytes = machine.arg_u32(mem.stack(), 0);
            Some(Answer::cdecl(malloc(mem, bytes)))
        }
        // void free(void *block)
        "_free" => {
            let at = machine.arg_u32(mem.stack(), 0);
            free(at);
            Some(Answer::cdecl(0))
        }
        // char *strdup(const char *s)
        "_strdup" => {
            let at = machine.arg_u32(mem.stack(), 0);
            Some(Answer::cdecl(strdup(mem, at)))
        }
        // void _exit(int status) / void exit(int status)
        //
        // Sets the code and stops the run, exactly as `ExitProcess` does --
        // `run` returns as soon as `exit_code` is set. Returning a value here
        // would be meaningless: both are declared `noreturn`, and a host that
        // let the program carry on past its own exit produces a trace that
        // looks healthy while being fiction.
        "_exit" => {
            let status = machine.arg_u32(mem.stack(), 0);
            process.exit(status);
            Some(Answer::cdecl(0))
        }
        // void abort(void)
        //
        // Exit code 3, which is what a Borland `abort` leaves behind -- it is
        // the value `_exit(3)` its own implementation calls. Distinct from a
        // clean exit on purpose: a caller looking at the code should be able to
        // tell "the program decided to stop" from "the program gave up".
        "_abort" => {
            process.exit(3);
            Some(Answer::cdecl(0))
        }
        // void clreol(void)
        //
        // conio, and the first of that group this program has ever been
        // measured calling. `_getch`, `_kbhit` and the rest stay unwritten:
        // they are linked and still never reached, and the discipline that
        // left this one alone until now is what makes its arrival meaningful.
        //
        // Takes nothing and returns nothing, so it cleans nothing and its
        // value is never read.
        "_clreol" => {
            process.console.clreol();
            Some(Answer::cdecl(0))
        }
        // int getch(void)
        //
        // Blocks for a key and does not echo it. With no driver -- a batch run
        // -- there is nothing to wait for and nothing will ever arrive, so this
        // answers `\r` rather than blocking or looping: a "press any key"
        // prompt is satisfied and the program moves on. Blocking would hang a
        // run that has no keyboard, and looping on a poll would burn the call
        // budget on a question that can never be answered differently.
        "_getch" => Some(Answer::cdecl(u32::from(
            process.next_key().unwrap_or(b'\r'),
        ))),
        // int kbhit(void)
        //
        // Non-zero if a key is waiting, and **it must not consume one** -- see
        // `Process::pending_key`. False with no driver, which is the honest
        // answer for a run with no keyboard and keeps a polling loop from
        // believing input is arriving.
        "_kbhit" => Some(Answer::cdecl(u32::from(process.key_waiting()))),
        // void *memset(void *dest, int c, size_t n)
        "_memset" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let c = machine.arg_u32(mem.stack(), 1);
            let n = machine.arg_u32(mem.stack(), 2);
            Some(Answer::cdecl(memset(mem, dest, c, n)))
        }
        // size_t strlen(const char *s)
        "_strlen" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let len = cstr(mem, at).map_or(0, |s| u32::try_from(s.len()).unwrap_or(u32::MAX));
            Some(Answer::cdecl(len))
        }
        // char *strcpy(char *dest, const char *src)
        "_strcpy" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let bytes = cstr(mem, src).unwrap_or_default();
            Some(Answer::cdecl(put_cstr_at(mem, dest, &bytes)))
        }
        // char *strncpy(char *dest, const char *src, size_t n)
        //
        // **Not a bounded `strcpy`.** C's `strncpy` writes exactly `n` bytes:
        // it pads with NULs when the source is short, and writes *no*
        // terminator when the source is `n` or longer. A host that terminated
        // anyway would silently truncate a fixed-width record field by a byte,
        // which is precisely the shape of data this program handles.
        "_strncpy" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let n = machine.arg_u32(mem.stack(), 2) as usize;
            let bytes = cstr(mem, src).unwrap_or_default();
            let mut out = vec![0u8; n];
            let copy = bytes.len().min(n);
            out[..copy].copy_from_slice(&bytes[..copy]);
            let _ = Flat32Ptr(dest).write(mem, &out);
            Some(Answer::cdecl(dest))
        }
        // char *strcat(char *dest, const char *src)
        "_strcat" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let head = cstr(mem, dest).unwrap_or_default();
            let tail = cstr(mem, src).unwrap_or_default();
            let mut joined = head;
            joined.extend_from_slice(&tail);
            Some(Answer::cdecl(put_cstr_at(mem, dest, &joined)))
        }
        // int strcmp(const char *a, const char *b)
        "_strcmp" => {
            let a = machine.arg_u32(mem.stack(), 0);
            let b = machine.arg_u32(mem.stack(), 1);
            let (a, b) = (cstr(mem, a).unwrap_or_default(), cstr(mem, b).unwrap_or_default());
            Some(Answer::cdecl(compare(&a, &b)))
        }
        // int stricmp(const char *a, const char *b)
        "_stricmp" => {
            let a = machine.arg_u32(mem.stack(), 0);
            let b = machine.arg_u32(mem.stack(), 1);
            let (a, b) = (cstr(mem, a).unwrap_or_default(), cstr(mem, b).unwrap_or_default());
            Some(Answer::cdecl(stricmp_bytes(&a, &b)))
        }
        // char *strchr(const char *s, int c) -- NULL when absent.
        //
        // Searching for `\0` finds the terminator, which C requires and which
        // a search over the string's bytes alone would miss.
        "_strchr" => {
            let at = machine.arg_u32(mem.stack(), 0);
            #[allow(clippy::cast_possible_truncation)]
            let c = machine.arg_u32(mem.stack(), 1) as u8;
            let found = cstr(mem, at).and_then(|s| {
                if c == 0 {
                    Some(u32::try_from(s.len()).ok()?)
                } else {
                    u32::try_from(s.iter().position(|&b| b == c)?).ok()
                }
            });
            Some(Answer::cdecl(found.map_or(0, |off| at + off)))
        }
        // char *strrchr(const char *s, int c) -- the *last* one.
        "_strrchr" => {
            let at = machine.arg_u32(mem.stack(), 0);
            #[allow(clippy::cast_possible_truncation)]
            let c = machine.arg_u32(mem.stack(), 1) as u8;
            let found = cstr(mem, at).and_then(|s| {
                if c == 0 {
                    Some(u32::try_from(s.len()).ok()?)
                } else {
                    u32::try_from(s.iter().rposition(|&b| b == c)?).ok()
                }
            });
            Some(Answer::cdecl(found.map_or(0, |off| at + off)))
        }
        // char *strlwr(char *s) / char *strupr(char *s) -- in place, answering s.
        "_strlwr" | "_strupr" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let bytes = cstr(mem, at).unwrap_or_default();
            let cased = if symbol == "_strlwr" {
                bytes.to_ascii_lowercase()
            } else {
                bytes.to_ascii_uppercase()
            };
            Some(Answer::cdecl(put_cstr_at(mem, at, &cased)))
        }
        // long atol(const char *s)
        "_atol" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let bytes = cstr(mem, at).unwrap_or_default();
            Some(Answer::cdecl(atol_bytes(&bytes)))
        }
        // int tolower(int c) / int toupper(int c)
        //
        // Values outside `0..=255` pass through unchanged rather than being
        // truncated: C defines these for `EOF` as well as for characters, and
        // narrowing first would turn `EOF` into `0xff`.
        "_tolower" | "_toupper" => {
            let c = machine.arg_u32(mem.stack(), 0);
            let mapped = match u8::try_from(c) {
                Ok(b) if symbol == "_tolower" => u32::from(b.to_ascii_lowercase()),
                Ok(b) => u32::from(b.to_ascii_uppercase()),
                Err(_) => c,
            };
            Some(Answer::cdecl(mapped))
        }
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
        for symbol in ["_longjmp", "_strtok", "_fnsplit", "__fullpath", "_flushall"] {
            assert!(
                dispatch(&mut p, &mut l.machine, &mut l.mem, symbol).is_none(),
                "{symbol} is unreached and must stay diagnosable"
            );
        }
    }
}


