//! Load a real DOS `.EXE` into the real-mode guest and report what it asks
//! DOS for, in the order it asks.
//!
//! This is a probe, not a runtime. `dos::dispatch` implements seven functions;
//! everything else comes back as "invalid function" with CF set. The point is
//! to replace a static byte-scan's *guess* at the required surface with the
//! program's own answer, since a scan cannot tell a reachable call from a
//! string of bytes that happens to read as `CD 21`.
//!
//! Usage: `runexe <program.exe> --root <dir> [options] [command tail]`
//!
//! Arguments are parsed with `clap`, as the rest of this workspace's binaries
//! are. They were hand-rolled while this crate was `dos-poc` and had one user
//! running one game, and the seams showed the first time somebody else used it:
//! the program path had to come first or `--root` was silently taken as the
//! filename, and `--root` defaulted to a LORD-specific relative path behind a
//! `create_dir_all`, so pointing it at nothing did not fail -- it created the
//! wrong directory wherever you happened to be standing.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;

use clap::Parser;

use dos::count::{Counters, Counting};
use dos::service::{Service, Serviced, Services};
use dos_runtime::bios::{Bios, Keyboard, Video, int16, int16_implemented, missing};
use dos_runtime::dos::is_implemented;
use dos_runtime::guest::{Guest, Ptr};
use dos_runtime::kvm::{Stop, VmGuest};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};
use dos_runtime::driver::{Driver, Script};
use dos_runtime::terminal::{RawStdin, Terminal};
use dos_runtime::uart::{COM1_BASE, IRQ4_VECTOR, Pic, Uart};
use dos_runtime::files::Files;
use dos_runtime::fossil::Fossil;
use dos_runtime::mz::{self, MzImage};
use dos_runtime::pit::Pit;
use dos_runtime::screen::Screen;
use dos_runtime::win32;

/// A load-time diagnostic line. In door mode `stdout` is the caller's own
/// terminal, so the report goes to `stderr` -- which a BBS captures into its
/// node log -- rather than onto the player's screen; an attended or local run
/// keeps it on `stdout`, where the report is the whole point. Same split as
/// the `--trace` output, for the same reason.
macro_rules! diag {
    ($door:expr, $($arg:tt)*) => {
        if $door {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    };
}

/// 1 MiB: the whole real-mode address space.
const MEM: usize = 1 << 20;
/// Above the BIOS data area. `hook_all` fills `dos_runtime::kvm::
/// STUB_TABLE_BYTES` bytes from here -- not a plain `256 * 4`, because
/// vector `0x7B`'s stub sits at a fixed, non-stride-aligned offset (see
/// `kvm::stub_offset`) -- so the environment block below must start past
/// that many bytes, checked below rather than restated by hand.
const STUB_SEG: u16 = 0x0060;
/// One paragraph past the end of the stub table's actual high-water mark
/// (`0x600 + STUB_TABLE_BYTES` = physical `0xa03`; `0xa10` is the next
/// paragraph boundary), not the round `0xa0` an old, now-false 1024-byte
/// assumption used -- that placement let `hook_all`'s last stub (vector
/// `0xFF`) get silently overwritten by this segment's own load.
const ENV_SEG: u16 = 0x00a1;
/// Leaves ~576 KiB for the program, which is more than a 1994 config utility
/// was ever going to see.
const PSP_SEG: u16 = 0x1000;

/// The stub table and the environment block share one segment's worth of
/// low memory; if a future change to the table's packing (or to either
/// segment) lets them overlap again, this must fail to compile rather than
/// silently corrupt vector `0xFF`'s stub on every run, the way the old
/// hand-picked `ENV_SEG` did.
const _: () = assert!(
    (ENV_SEG as u32) * 16 >= (STUB_SEG as u32) * 16 + dos_runtime::kvm::STUB_TABLE_BYTES as u32,
    "ENV_SEG must start at or after the stub table hook_all fills"
);

/// Where the Btrieve service's bump-allocator heap ([`dos_runtime::btrieve::
/// DosHeap`]) lives: a segment on its own, in the gap between the
/// environment block and `PSP_SEG` that nothing else in this file's memory
/// map claims.
///
/// Nothing else can land here: the interrupt stub table `hook_all` fills
/// ends at physical `STUB_SEG*16 + STUB_TABLE_BYTES` (`0xa03`), the
/// environment block starts right after at `ENV_SEG*16` (`0xa10`) and is a
/// few dozen bytes, and the loaded program -- PSP, image, and its own stack,
/// all of it -- starts at `PSP_SEG*16` (`0x10000`). `HEAP_SEG` sits well
/// inside that gap, with room on both sides. What actually *enforces* that,
/// rather than merely describing it, is the pair of assertions below this
/// constant plus the runtime check next to where the environment block is
/// built: this file has one already-fixed comment (the old `ENV_SEG`) that
/// quietly stopped being true, and it corrupted a stub silently for as long
/// as nobody read the comment critically -- these are written so the same
/// mistake here fails a build or a run, not a code review.
const HEAP_SEG: u16 = 0x0200;
/// Room for about twenty simultaneous `Open`s (`crates/btrieve`'s
/// `struct btvblk` is 196 bytes, and [`dos_runtime::btrieve::DosHeap`] never
/// frees) -- generous for the synthetic guest this crate's own tests drive,
/// and for any real DOS utility this host runs today.
const HEAP_CAPACITY: u16 = 4096;

/// The heap must start at or after the stub table's own high-water mark --
/// the same discipline, and the same reasoning, as the `ENV_SEG` assertion
/// below.
const _: () = assert!(
    (HEAP_SEG as u32) * 16 >= (STUB_SEG as u32) * 16 + dos_runtime::kvm::STUB_TABLE_BYTES as u32,
    "HEAP_SEG must start at or after the stub table hook_all fills"
);
/// The heap must end at or before the loaded program begins. `HEAP_CAPACITY`
/// bytes are reserved from `HEAP_SEG`'s own offset zero, so this is exactly
/// the same "does the window fit before the next thing" shape as the
/// `ENV_SEG` check, just measured from the other end of the gap.
const _: () = assert!(
    (HEAP_SEG as u32) * 16 + HEAP_CAPACITY as u32 <= (PSP_SEG as u32) * 16,
    "the Btrieve heap must fit entirely below PSP_SEG, where the loaded program begins"
);
/// The third relationship, and the one a review caught missing: neither
/// assert above says anything about where `HEAP_SEG` sits *relative to
/// `ENV_SEG`*, which is exactly the ordering the runtime check just below
/// `main`'s `vm.load(ENV_SEG...)` depends on. Without this, a future repack
/// that moved `ENV_SEG` at or past `HEAP_SEG` would not fail here -- it would
/// only be caught, if at all, by that runtime check, and only in a *debug*
/// build: the check there is `env.len() <= (HEAP_SEG - ENV_SEG) * 16`-shaped
/// arithmetic on plain `u16`s, and this workspace sets no `overflow-checks`
/// override, so in `--release` a negative difference wraps to a huge `u16`
/// and the assert always passes -- silent corruption, not a caught bug,
/// exactly the failure mode every other assert in this file exists to
/// rule out.
const _: () = assert!(
    (HEAP_SEG as u32) * 16 > (ENV_SEG as u32) * 16,
    "HEAP_SEG must start strictly after ENV_SEG, or the environment block \
     could run into a heap that starts at or before it"
);

/// Where the InDOS flag byte lives -- the address `AH=34h` answers with, in
/// `dos::kernel::DosState::indos`. One paragraph, sharing the same
/// environment-block-to-`HEAP_SEG` gap the Btrieve heap claims part of,
/// placed immediately below `HEAP_SEG` so it is the *first* thing a runaway
/// environment block would run into -- and so the runtime check that used to
/// guard only `HEAP_SEG` (next to `main`'s `vm.load(ENV_SEG...)`) is moved to
/// name this segment instead, tightening rather than loosening what it
/// already checked.
const INDOS_SEG: u16 = HEAP_SEG - 1;

/// Same discipline as `HEAP_SEG`'s own first assertion: must not land inside
/// the stub table `hook_all` fills.
const _: () = assert!(
    (INDOS_SEG as u32) * 16 >= (STUB_SEG as u32) * 16 + dos_runtime::kvm::STUB_TABLE_BYTES as u32,
    "INDOS_SEG must start at or after the stub table hook_all fills"
);
/// The InDOS flag's one paragraph must end at or before `HEAP_SEG`, the same
/// "does the window fit before the next thing" shape `HEAP_CAPACITY`'s own
/// assertion uses against `PSP_SEG`.
const _: () = assert!(
    (INDOS_SEG as u32) * 16 + 16 <= (HEAP_SEG as u32) * 16,
    "the InDOS flag's one paragraph must fit entirely below HEAP_SEG"
);
/// And it must start strictly after `ENV_SEG`, for the same reason `HEAP_SEG`
/// itself has to -- otherwise nothing here rules out the environment block
/// landing on top of it before the runtime check below ever runs.
const _: () = assert!(
    (INDOS_SEG as u32) * 16 > (ENV_SEG as u32) * 16,
    "INDOS_SEG must start strictly after ENV_SEG, or the environment block \
     could run into the InDOS flag that starts at or before it"
);

/// An `--unhook` value: one interrupt vector, hex (`0x7b`) or decimal.
///
/// Refuses anything past 255 rather than truncating, because a truncated
/// vector names a real but *different* interrupt, and silently unhooking the
/// wrong one would show up as a TSR that mysteriously never gets called.
fn parse_vector(s: &str) -> Result<u8, String> {
    let t = s.trim();
    let (digits, radix) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (t, 10),
    };
    u16::from_str_radix(digits, radix)
        .ok()
        .filter(|v| *v <= u16::from(u8::MAX))
        .map(|v| v as u8)
        .ok_or_else(|| format!("`{s}` is not an interrupt vector in 0..=0xff"))
}

/// Zero the IVT entry for each vector, handing it back to the guest.
///
/// A function rather than a loop inlined in `main` so the test below drives
/// the same code `main` does. A test that reproduces the write instead of
/// calling it passes against a `main` that never writes at all -- that exact
/// gap was found and closed in this file's InDOS flag earlier the same day.
fn unhook_vectors(vm: &mut dos_runtime::kvm::VmGuest, vectors: &[u8]) -> io::Result<()> {
    for vector in vectors {
        vm.load(usize::from(*vector) * 4, &[0u8; 4])?;
    }
    Ok(())
}

/// Stop rather than spin if the program loops on a call we keep refusing.
const MAX_CALLS: u32 = 2000;

/// Conventional memory's ceiling: the same 640 KiB boundary `dos::kernel::
/// Arena` builds its free list up to (its own `CONV_TOP`, private to that
/// crate) and the same value `mz::load` already burns into every PSP it
/// builds, at offset 0x02, as "top of memory". Restated here rather than
/// imported because neither crate exports it -- the value is fixed by the
/// real-mode DOS memory map, not by either crate's own choices.
const CONV_TOP: u16 = 0xa000;

/// `seg + len` paragraphs, checked against [`CONV_TOP`] rather than left to
/// wrap.
///
/// `--tsr` needs this twice: once for the resident block a TSR leaves behind
/// (`tsr_psp + paragraphs`, where `paragraphs` is a guest-controlled value
/// straight out of `AH=31h`), and once for the main program's own footprint
/// once it loads on top of that block (`main_psp + paragraphs()`). Both are
/// `u16` segment sums that a bare `+` would silently wrap on for a bad or
/// merely large value, landing the next program somewhere inside memory it
/// does not own. Widened `u32` arithmetic, checked against the real ceiling,
/// is the same shape the environment-block-vs-`HEAP_SEG` assertion above
/// already uses, and for the same reason: this workspace sets no
/// `overflow-checks` override, so a release build of a wrapped `u16` sum
/// would silently keep going.
fn checked_seg_add(seg: u16, len: u32, what: &str) -> Result<u16, String> {
    let end = u32::from(seg) + len;
    if end > u32::from(CONV_TOP) {
        return Err(format!(
            "{what} at {seg:#06x} plus {len:#06x} paragraphs would end at \
             {end:#08x}, past conventional memory's ceiling at {CONV_TOP:#06x}"
        ));
    }
    Ok(end as u16)
}

/// Write the InDOS flag byte `AH=34h` answers with, and hand back the
/// pointer [`dos_runtime::dos::DosState::indos`] should be set to.
///
/// Factored out of `main` on purpose: a test that reproduced this write
/// instead of calling it would keep passing even if `main`'s own call to it
/// were deleted, mutated, or never wired to `indos` at all -- it would only
/// be proving the copy correct, not the code that actually runs.
/// `AH=34h`'s dispatch code in
/// `dos::kernel` only ever hands back a pointer -- it never touches the byte
/// at it -- so a test that calls `main`'s logic through anything less than
/// this exact function would still pass with the byte left unwritten, or
/// written non-zero, or never wired to `indos` at all. Sharing the function
/// itself, rather than a copy of what it does, is what makes a mutation to
/// this line something the test below actually has to fail against.
///
/// Written once, here, as zero -- and left that way for the rest of the run.
/// Real DOS increments this byte on entry to a DOS call and decrements it on
/// the way out, so a TSR polling it (as `AH=34h`'s caller always does; see
/// `dos::kernel::dispatch`'s own doc comment on the arm) knows not to pop up
/// mid-call. This host has no window where that matters: `int 21h` is
/// serviced synchronously, to completion, on the same call stack that
/// trapped it -- there is no interrupt-handler re-entry into a DOS call in
/// flight for a TSR to be unsafe during, so zero is the truthful answer, not
/// merely a convenient one. That stops being true the moment this host gains
/// re-entrant DOS servicing (a real hardware interrupt handled *while* an
/// `int 21h` is being serviced, the way a real BIOS timer tick can be) --
/// from then on this byte has to be incremented and decremented around that
/// window like real DOS does, not pinned at zero.
fn write_indos_flag(vm: &mut dos_runtime::kvm::VmGuest) -> io::Result<Ptr> {
    vm.load(INDOS_SEG as usize * 16, &[0u8])?;
    Ok(Ptr::new(INDOS_SEG, 0))
}

/// CPU this process has burned, and how long it has been alive.
///
/// Reported at exit because "what did the CPU look like?" is otherwise
/// unanswerable the moment the process ends -- /proc goes with it, and a
/// session that has already finished cannot be measured retroactively.
fn cpu_report(started: std::time::Instant, calls: u32) -> String {
    // SAFETY: getrusage fills a caller-owned struct.
    let usage = unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, std::ptr::from_mut(&mut u));
        u
    };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    let (user, sys) = (secs(usage.ru_utime), secs(usage.ru_stime));
    let wall = started.elapsed().as_secs_f64().max(1e-9);
    let busy = user + sys;
    let per_call = if calls > 0 {
        format!(", {:.1} us per DOS call", busy / f64::from(calls) * 1e6)
    } else {
        String::new()
    };
    format!(
        "cpu: {busy:.2}s ({user:.2} user + {sys:.2} sys) over {wall:.1}s wall \
         = {:.1}% of one core{per_call}",
        busy / wall * 100.0
    )
}

/// A hex or decimal address, as `--watch` has always accepted it.
fn parse_addr(s: &str) -> Result<u32, String> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).map_err(|e| format!("{t}: {e}")),
        None => u32::from_str_radix(t, 16).map_err(|e| format!("{t}: {e}")),
    }
}

/// `clap`'s `value_parser` wants an owned `String`; `host_library::
/// parse_bturno` borrows from its argument, so this just owns the borrow
/// clap already validated shape for.
fn parse_bturno_arg(s: &str) -> Result<String, String> {
    dos_runtime::host_library::parse_bturno(s).map(str::to_owned)
}

/// Split a `--tsr` value into the program to load and its own command tail.
///
/// DOS 8.3 filenames never contain whitespace, so the first run of it
/// unambiguously separates the program from everything meant for it -- the
/// same distinction the positional `program`/`tail` pair already makes for
/// the main program, just folded into one flag's value instead of clap's own
/// positional-then-trailing-args split.
fn split_tsr_arg(s: &str) -> (String, String) {
    match s.split_once(char::is_whitespace) {
        Some((prog, rest)) => (prog.to_string(), rest.trim_start().to_string()),
        None => (s.to_string(), String::new()),
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "runexe",
    about = "Run a DOS program in a real-mode guest and report what it asks DOS for",
    long_about = None,
)]
struct Cli {
    /// The DOS program to run. Read from the host filesystem, relative to the
    /// current directory -- this is not resolved against `--root`.
    program: String,

    /// Directory the guest sees as its whole filesystem.
    ///
    /// Required, and deliberately so. It used to default to `tmp/lordroot`,
    /// which was one game's data directory in a general-purpose runtime, and
    /// the code behind it calls `create_dir_all` -- so a wrong or forgotten
    /// root did not fail, it quietly built that path wherever you were
    /// standing. Refusing to guess is the whole point of it being required.
    #[arg(long, value_name = "DIR")]
    root: String,

    /// Keystrokes to feed the guest, as a literal string.
    #[arg(long, default_value = "")]
    keys: String,

    /// Drive the guest from a script file instead of `--keys`.
    #[arg(long, value_name = "FILE")]
    script: Option<String>,

    /// Log every DOS and BIOS call as it happens, on stderr.
    ///
    /// Written to stderr, not stdout, so a trace can be captured
    /// (`2>trace.log`) while the report still reads normally on stdout. A
    /// live screen and a trace cannot share one terminal, so this stays
    /// silent under `--interactive` *when stderr is that terminal* -- the
    /// case that wrecks a program's paint. Redirect stderr and an
    /// interactive run traces like any other, rather than the flag silently
    /// doing nothing in a mode it was asked for.
    #[arg(long)]
    trace: bool,

    /// Stop at the first unimplemented call rather than recording it.
    #[arg(long)]
    strict: bool,

    /// Give up after this many trapped interrupts.
    #[arg(long, value_name = "N", default_value_t = MAX_CALLS)]
    max_calls: u32,

    /// Attach a live terminal to the guest.
    #[arg(long, short = 'i')]
    interactive: bool,

    /// Serve the program as a BBS door over stdin/stdout.
    #[arg(long)]
    door: bool,

    /// Line rate for door mode. Overrides the dropfile; 0 means no pacing.
    #[arg(long, value_name = "RATE")]
    baud: Option<u32>,

    /// DOOR.SYS dropfile to read the connect rate from.
    #[arg(long, value_name = "FILE")]
    dropfile: Option<String>,

    /// Break when the guest touches this address (hex, `0x` optional).
    #[arg(long, value_name = "ADDR", value_parser = parse_addr)]
    watch: Option<u32>,

    /// Single-step this many instructions once `--watch` fires.
    #[arg(long, value_name = "N", default_value_t = 0)]
    watch_steps: u32,

    /// Hits to ignore before arming the trace.
    ///
    /// The first accesses to an input variable are the code that *stored* it;
    /// the check reads it later, so skipping past the store is how the trace
    /// lands on the interesting half.
    #[arg(long, value_name = "N", default_value_t = 0)]
    watch_skip: u32,

    /// Scan guest memory for these 16-bit values, comma separated.
    #[arg(long, value_name = "N,N", value_delimiter = ',')]
    scan_u16: Vec<u16>,

    /// Which library generation's GALGSBL to synthesise when the guest opens
    /// `GALGSBL.DLL` and no such file exists under `--root`.
    ///
    /// Names a `mbbs_machine::library::Profile` by its generation tag
    /// (`wg101`, `mbbs625`, `wg2`, `wg3-16`, `layout-c`). Detection is not
    /// run to choose this: see `dos_runtime::host_library`'s module doc for
    /// why there is no import table to detect from here. Unset takes
    /// `library::ANCHOR`; an unrecognised name is refused rather than
    /// silently falling back to it.
    #[arg(long, value_name = "NAME")]
    family: Option<String>,

    /// The eight-digit `BTURNO` serial the synthesised GALGSBL answers with
    /// when its `GETRNO` reads it back.
    ///
    /// Exactly eight ASCII digits, refused otherwise: `GETRNO` reads exactly
    /// eight bytes after the `ReG#` marker, so anything shorter or longer
    /// would silently read back as a different serial than was typed. The
    /// default, `00000000`, is patently not a real board's key -- a
    /// synthetic serial means the module reads as unregistered, and that is
    /// the honest outcome for a run that did not name a real one.
    #[arg(long, value_name = "DIGITS", default_value = "00000000", value_parser = parse_bturno_arg)]
    bturno: String,

    /// Load a resident (TSR) program before `program`, so DOS calls the main
    /// program makes reach the TSR's own handler first -- e.g. a real vendor
    /// Btrieve engine answering `int 7Bh` instead of this host's Rust one.
    ///
    /// The value may carry a command tail after the first whitespace, e.g.
    /// `--tsr "BTRIEVE.EXE /P:2048"`. DOS 8.3 names never contain spaces, so
    /// splitting on the first whitespace is unambiguous.
    ///
    /// A TSR that means to own a vector this host also stubs needs
    /// [`Cli::unhook`] as well. This comment used to claim no stand-down step
    /// was needed, on the reasoning that `AH=25h` writes the IVT directly so
    /// the TSR's hook would simply replace ours. Running it disproved that:
    /// the real Btrieve 5.00c manager reads vector `0x7B` back first
    /// (`AH=35h`), sees our stub's `0x33` -- the very offset we copy from it
    /// to satisfy `DFAAPI`'s probe -- concludes it is already resident,
    /// prints "Program already loaded" and exits 1. It never reaches its own
    /// `AH=25h` at all. A stub faithful enough to answer a probe is faithful
    /// enough to fool the program it imitates.
    #[arg(long, value_name = "PROGRAM")]
    tsr: Option<String>,

    /// Leave this interrupt vector unhooked, so a `--tsr` program can claim
    /// it and be *called* rather than merely resident.
    ///
    /// `hook_all` stubs all 256 vectors, so without this every vector reads
    /// back as taken and any TSR that probes before installing will decline.
    /// Repeatable; hex (`0x7b`) or decimal.
    #[arg(long, value_name = "VECTOR", value_parser = parse_vector)]
    unhook: Vec<u8>,

    /// Command tail handed to the program, exactly as DOS would.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "TAIL")]
    tail: Vec<String>,
}

/// Which runtime a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    RealMode,
    Pe32,
    /// An LE/LX linear executable -- a DOS/4GW-era 32-bit protected-mode
    /// program, run natively by `dos4g` (runexe is the extender).
    Le,
    Unsupported,
}

/// How many import calls a PE32 program may make before the run is cut short.
///
/// Generous: the point of a run is to find the first thing this host cannot
/// answer, and a program that gets further than this has already told us far
/// more than the budget would. Raised from the original 100,000 once
/// `wccmmutl.exe -recover` measured what "generous" has to mean for a batch
/// maintenance utility walking real board data: `re/wg33src/SRC/api/gcommlib/
/// DFAAPI.C`'s own `btvu` issues one `BTRCALL` per record, and this board's
/// larger files (`WCCITEM2.DAT` alone is 2.7 MB) hold many thousands of
/// them -- 100,000 calls was enough to prove marshalling and dispatch work,
/// not enough to reach a real stopping point.
const PE_CALL_BUDGET: usize = 20_000_000;

/// How long an **unattended** guest may run without crossing into the host
/// -- no DOS/BIOS trap, no import call -- before it is presumed spinning and
/// stopped. Attended runs have no timer at all: the person is the watchdog
/// (see [`install_stop_signals`]).
///
/// This bounds a gap, never a run: the real-mode loop feeds the KVM spin
/// timer on every guest exit and the Win32 loop re-arms the machine's budget
/// on every import, so a program that is working, however slowly, is never
/// cut off. The number is still a judgement -- `-recover` was measured
/// walking `WCCKNMS2.DAT` (895 KB) for five seconds with no crossing at all,
/// so it has to be well clear of that -- but a wrong judgement here only
/// costs an unattended probe a slower report, not a real run its work.
const SPIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The Win32 machine's stop handle, once a PE32 image is loaded.
static INTERRUPTER: OnceLock<mbbs_machine::m32::Interrupter> = OnceLock::new();

/// The thread blocked in `KVM_RUN`, once the real-mode helpers exist and
/// their no-op `SIGUSR1` handler is in place -- zero until then, and a
/// signal that lands before that is not forwarded.
static MAIN_TID: AtomicI32 = AtomicI32::new(0);

/// `SIGINT`/`SIGTERM`: stop the guest wherever it is and let the run report.
///
/// Both guests run natively -- 32-bit code on this thread, real-mode code on
/// a vCPU -- so a guest spinning with no crossing cannot be reached by the
/// drivers, which are only consulted at crossings. This is the one way in:
/// the Win32 machine's [`mbbs_machine::m32::Interrupter`] makes its budget
/// expire now, and a `SIGUSR1` at the `KVM_RUN` thread gives `EINTR` (the
/// same nudge the spin timer uses; a process-directed signal may land on a
/// helper thread, so it is forwarded rather than relied on). A signal that
/// arrives while the host is servicing a crossing is caught at the next
/// resume, or at the top of the real-mode loop.
///
/// The interactive terminal is raw with `ISIG` off, so from *that* keyboard
/// Ctrl-C is a keystroke for the guest and Ctrl-] the driver's own stop,
/// honoured at crossings; a spinning attended guest is stopped with
/// `kill -INT` from elsewhere, and still gets its report and its terminal
/// back.
extern "C" fn on_stop_signal(_: libc::c_int) {
    // Recorded where the blocking terminal driver can see it, so a run
    // parked in a `read` ends too -- see `dos_runtime::driver::stop`.
    dos_runtime::driver::stop::request();
    if let Some(interrupter) = INTERRUPTER.get() {
        interrupter.fire();
    }
    let tid = MAIN_TID.load(Ordering::Relaxed);
    if tid != 0 {
        // SAFETY: signalling a thread of our own process; `tgkill` and
        // `getpid` are async-signal-safe.
        unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGUSR1) };
    }
}

fn install_stop_signals() {
    for signo in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: installing a handler with no SA_RESTART, so a blocked
        // `ioctl(KVM_RUN)` reports EINTR instead of being resumed.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_stop_signal as *const () as usize;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(signo, &sa, std::ptr::null_mut());
        }
    }
}

/// The operator (or the harness) asked for the stop, so a
/// `Stop::Interrupted`/`Outcome::Timeout` that follows is theirs, not the
/// spin timer's.
fn interrupted() -> bool {
    dos_runtime::driver::stop::requested()
}

/// Which runtime `file` belongs to.
///
/// Reads the two bytes at `e_lfanew` rather than trusting the offset itself.
/// `NE` is `Unsupported` rather than routed: `MAJORBBS.EXE` is NE plus a Phar
/// Lap 286 extender and neither host can run it, so refusing it names the
/// problem instead of faulting somewhere inside a loader.
pub fn format_of(file: &[u8]) -> Format {
    if file.len() < 0x40 || &file[0..2] != b"MZ" {
        return Format::Unsupported;
    }
    let lfanew = u32::from_le_bytes([file[0x3c], file[0x3d], file[0x3e], file[0x3f]]) as usize;
    // A real-mode MZ has no extended header at all, and `e_lfanew` is then
    // whatever happened to sit at 0x3c -- all fifteen extracted DOS
    // WCCMMUTL builds carry 0x10000 there, pointing at ordinary code. So an
    // offset that is out of range, or that does not carry a signature we
    // know, means real mode rather than "malformed".
    let Some(sig) = file.get(lfanew..lfanew + 4) else {
        return Format::RealMode;
    };
    match &sig[0..2] {
        b"PE" if sig[2] == 0 && sig[3] == 0 => Format::Pe32,
        b"LE" | b"LX" => Format::Le,
        b"NE" => Format::Unsupported,
        _ => Format::RealMode,
    }
}

/// Run a PE32 console program on the Win32 host.
///
/// Reports where it stopped rather than pretending to have finished: the
/// measured frontier is at `cw3220mt.DLL!_time` (see
/// `docs/2026-08-17-win32-import-trace.md`), so an ordinary run of this program
/// today ends by naming the next symbol to implement. That is the useful
/// output, and printing it is the whole reason this front door exists before
/// the program can complete.
fn run_pe32(
    path: &str,
    data: &[u8],
    tail: &str,
    root_dir: &str,
    keys: &str,
    script_path: Option<&str>,
    interactive: bool,
) -> io::Result<()> {
    let mut loaded = win32::load::load(data)?;
    // A person watching gets no timer; an unattended run gets the spin
    // detector, which `win32::process::run` re-arms at every import it
    // answers (`Machine::rearm_watchdog`) -- see `SPIN_TIMEOUT`. Either way
    // a stop signal reaches the machine through `INTERRUPTER`.
    if interactive {
        loaded.machine.unwatch();
    } else {
        loaded.machine.set_budget(SPIN_TIMEOUT);
    }
    let _ = INTERRUPTER.set(loaded.machine.interrupter());
    println!(
        "{path}: PE32 image, {} imports, entry {:#010x}",
        loaded.imports.len(),
        loaded.entry
    );

    // The same `C:\NAME.EXE` shape the real-mode path builds, and for the same
    // reason: a program reads its own path back and finds its home directory
    // by stripping the filename off the end.
    let program = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("PROGRAM.EXE")
        .to_ascii_uppercase();
    let argv0 = format!("C:\\{program}");
    let args: Vec<&str> = tail.split_whitespace().collect();
    let mut process = win32::process::Process::new(&argv0, &args);

    // The same sandbox the real-mode guest gets, built the same way: one
    // directory descriptor, and `openat2(RESOLVE_BENEATH)` beneath it. The PE32
    // host resolves every `fopen` and `access` through this, so neither runtime
    // can reach a byte the other could not.
    std::fs::create_dir_all(root_dir)?;
    let root = std::fs::File::open(root_dir)?;
    println!("root: {root_dir}");
    process.streams = win32::stream::Streams::new(Some(Files::new(
        root.into(),
        std::path::PathBuf::from(root_dir),
    )));

    // The same two switches the real-mode guest is driven by, behind the same
    // `Driver` trait. A PE32 program has no BIOS keystroke buffer, so `--keys`
    // reaches it as a `Keys` driver rather than through `Keyboard` -- one input
    // path on this side, which is what `_getch` reads. A script wins over
    // literal keys, as it does for the DOS path, because a script is the more
    // specific instruction.
    process.keys = if interactive {
        // The terminal takes the screen from here, exactly as it does for the
        // real-mode guest: it paints the console it is handed on every read
        // and every due poll, so wiring it as the driver *is* the live
        // console. Nothing may be printed until it is dropped -- see the
        // report below.
        println!("interactive: Ctrl-] gives control back");
        Some(Box::new(Terminal::new()?) as Box<dyn dos_runtime::driver::Driver>)
    } else {
        match script_path {
            Some(path) => {
                let text = std::fs::read_to_string(path)?;
                Some(Box::new(Script::parse(&text).map_err(io::Error::other)?)
                    as Box<dyn dos_runtime::driver::Driver>)
            }
            None if !keys.is_empty() => Some(Box::new(dos_runtime::driver::Keys::new(keys))),
            None => None,
        }
    };

    let outcome = win32::process::run(&mut loaded, &mut process, PE_CALL_BUDGET)?;

    // Drop the terminal before printing anything. While it lives it owns the
    // alternate screen, and a report written into that lands in the middle of
    // the program's own output and is then wiped when the screen is restored.
    // The real-mode path defers its report for the same reason.
    let ending = process.keys.as_ref().map(|d| d.ending());
    process.keys = None;

    match outcome {
        win32::process::Outcome::Timeout { eip } if interrupted() => {
            println!("--- interrupted by a signal at {eip:#010x} ---");
        }
        win32::process::Outcome::Timeout { eip } => {
            println!(
                "--- spin: no import call for {}s, at {eip:#010x} ---",
                SPIN_TIMEOUT.as_secs()
            );
        }
        ref other => println!("--- {other:?} ---"),
    }
    show_console(&process);
    report_diagnostics(&process);
    if let Some(ending) = ending {
        println!("driver: {ending}");
    }
    Ok(())
}

/// Print what the program drew.
///
/// **Shaped like the real-mode path's own post-run dump, not like `Terminal`.**
/// `Terminal` enters raw mode and repaints incrementally, which is right for
/// driving an interactive guest and wrong for a batch run that has already
/// finished -- it would take over the operator's terminal to show one final
/// frame. The DOS side has exactly this distinction already: it drives through
/// `Terminal` while running and then dumps `B800:0000` as plain text at the
/// end. This is that same ending, for a console the host owns rather than one
/// it samples out of guest memory.
///
/// Nothing is printed when the program drew nothing, so a run that fails before
/// reaching the console does not emit an empty grid and imply it painted one.
fn show_console(process: &win32::process::Process) {
    let grid = process.console.cells();
    if !anything_drawn(grid) {
        return;
    }

    // The same ruler the real-mode dump prints, for the same reason: a column
    // number is what makes a misplaced write obvious.
    println!("--- console ({}x{}) ---", grid.cols, grid.rows);
    let tens: String = (0..grid.cols).map(|c| char::from(b'0' + ((c / 10) % 10) as u8)).collect();
    let ones: String = (0..grid.cols).map(|c| char::from(b'0' + (c % 10) as u8)).collect();
    println!("    {tens}");
    println!("    {ones}");
    for row in 0..grid.rows {
        let line = grid.line(row);
        // Trailing spaces are trimmed for width, but the row number is kept
        // even for a blank line: a gap in the numbering would read as a row
        // that does not exist rather than one that is empty.
        println!("{row:3} {}", line.trim_end());
    }
    let (col, cursor_row) = process.console.cursor();
    let (size, visible) = process.console.cursor_info();
    println!(
        "cursor: row {cursor_row} col {col}, {} ({size}%)",
        if visible { "visible" } else { "hidden" }
    );
}

/// Whether the program put anything on screen.
///
/// A run that fails before reaching the console must not print an empty grid,
/// because an 80x25 block of blanks with a ruler over it reads as "it painted
/// this" rather than "it painted nothing".
fn anything_drawn(grid: &dos_runtime::screen::Cells) -> bool {
    (0..grid.rows).any(|r| !grid.line(r).trim().is_empty())
}

/// Print what the program *said* -- the diagnostics this host captured because
/// there is nowhere on Linux to deliver them.
///
/// `ReportEventA` would reach the NT event log and `MessageBoxA` a desktop;
/// neither exists here, and on the failure paths this family of utilities takes,
/// the program's own words are the most informative thing it produces. Throwing
/// them away to keep the output tidy would be discarding the answer.
fn report_diagnostics(process: &win32::process::Process) {
    for event in &process.events {
        // `EVENTLOG_ERROR_TYPE` is 1, `WARNING` 2, `INFORMATION` 4. The raw
        // value is printed alongside because this program passes values outside
        // that set.
        println!("event[{:#x}] {}", event.id, event.strings.join(" | "));
    }
    for (caption, text) in &process.messages {
        println!("messagebox[{caption}] {text}");
    }
    if process.slept_calls > 0 {
        println!("slept: {} calls (not actually waited)", process.slept_calls);
    }
}

/// A `Dos` kernel shared with the run loop through interior mutability.
///
/// `Services` only exposes what it composes through `&dyn Service<G>`
/// (`claiming`) and `&dyn Any` (`as_any`) -- both immutable -- so once a
/// service is composed in, nothing outside `Services` can reach back into
/// it. `--tsr` needs exactly that: when a resident program hands room back
/// for the main program (the `StayResident` arm below), the loop has to
/// update the *same* `Dos` the composed services are already dispatching
/// through (`state.psp_seg`, `state.mem`), not a copy nothing reads.
/// Wrapping it in `Rc<RefCell<_>>` and keeping a clone of the handle outside
/// `services` is what makes that possible without adding a mutable-access API
/// to the `dos` crate.
struct SharedDos(Rc<RefCell<dos_runtime::dos::Dos>>);

impl Service<VmGuest> for SharedDos {
    fn claims(&self) -> &[u8] {
        &[0x21]
    }

    fn service(&mut self, vector: u8, g: &mut VmGuest) -> Serviced {
        self.0.borrow_mut().service(vector, g)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn main() -> io::Result<()> {
    let started = std::time::Instant::now();
    let cli = Cli::parse();

    let path = cli.program;
    let root_dir = cli.root;
    let tail = cli.tail.join(" ");
    let keys = cli.keys;
    let script_path = cli.script;
    let trace = cli.trace;
    // SAFETY: `isatty` only inspects the descriptor; it mutates nothing.
    let trace_to_screen = unsafe { libc::isatty(libc::STDERR_FILENO) } == 1;
    let strict = cli.strict;
    let max_calls = cli.max_calls;
    let interactive = cli.interactive;
    install_stop_signals();
    let door = cli.door;
    let baud: Option<u32> = cli.baud;
    let dropfile = cli.dropfile;
    let watch = cli.watch;
    let watch_steps = cli.watch_steps;
    // Counted down as hits are ignored, so this one is genuinely mutable.
    let mut watch_skip = cli.watch_skip;
    let scan: Vec<u16> = cli.scan_u16;
    let family = cli.family;
    let bturno = cli.bturno;
    let tsr = cli.tsr;

    // Somebody is on the other end. The call cap and the spin timer exist to
    // rescue an *unattended* probe from a guest that will not stop, and both
    // have fired on a real session -- so neither applies when attended; the
    // person is the watchdog (`install_stop_signals`). One name for the
    // condition, used everywhere, is the fix.
    let attended = interactive || door;

    // The BBS already knows the line rate, so ask it rather than making the
    // sysop repeat it: DOOR.SYS carries the connect rate on line 2 and the DTE
    // rate on line 5. An explicit --baud still wins, and 0 means no pacing.
    let baud = baud.or_else(|| dropfile.as_deref().and_then(dropfile_baud));

    let data = std::fs::read(&path)?;

    // One front door, two runtimes. Everything below this point is the
    // real-mode path and is unchanged; a PE32 leaves here instead.
    match format_of(&data) {
        Format::Pe32 => {
            if tsr.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--tsr requires the real-mode guest; the memory map and \
                     loader it relies on (PSP_SEG, mz::load, the Arena) have \
                     no PE32 counterpart, and the program here is PE32",
                ));
            }
            return run_pe32(
                &path,
                &data,
                &tail,
                &root_dir,
                &keys,
                script_path.as_deref(),
                interactive,
            );
        }
        Format::Le => {
            if tsr.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--tsr requires the real-mode guest; an LE/LX program runs \
                     natively with no real-mode memory map to load a TSR into",
                ));
            }
            let stdout = io::stdout();
            let mut out = stdout.lock();
            let code = dos_runtime::dos4g::run_le(&data, &mut out)?;
            std::process::exit(code);
        }
        Format::Unsupported => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{path}: not a program either runtime can run. NE is refused \
                     outright: it covers both Windows 3.x programs and MAJORBBS.EXE, \
                     which is additionally a Phar Lap 286 extender. The real-mode \
                     guest runs MZ, the Win32 host runs PE32, and the DOS/4GW host \
                     runs LE/LX"
                ),
            ));
        }
        Format::RealMode => {}
    }

    let img = MzImage::parse(&data)?;
    diag!(
        door,
        "{path}: {} byte image, {} relocations, entry {:#06x}:{:#06x}, \
         stack {:#06x}:{:#06x}, needs {} paragraphs",
        img.bytes.len(),
        img.relocs.len(),
        img.cs,
        img.ip,
        img.ss,
        img.sp,
        img.paragraphs(),
    );

    let mut vm = VmGuest::new(MEM)?;
    vm.hook_all(STUB_SEG)?;
    // Hand a vector back to the guest. `hook_all` stubs all 256, which is
    // what makes every one of them trap out to us -- and also what makes
    // every one of them read back as already claimed. A TSR that probes
    // before installing (Btrieve does, via `AH=35h`) then declines to load,
    // so the only way for it to own a vector is for us not to own it first.
    // Zeroed rather than pointed at an IRET: the guest is about to write its
    // own handler here, and a vector nobody has claimed pointing nowhere is
    // the honest intermediate state.
    unhook_vectors(&mut vm, &cli.unhook)?;

    // The program's own path, which a DOS program reads back as ParamStr(0)
    // and routinely uses to find its home directory. Hardcoding a name here
    // silently misdirects that: LORD strips its own filename off the end, so a
    // stale "C:\LORDCFG.EXE" had it hunting for C:\LOR\NODE0.DAT.
    let program = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("PROGRAM.EXE")
        .to_ascii_uppercase();
    let env = mz::environment(
        &["PATH=C:\\", "COMSPEC=C:\\COMMAND.COM"],
        &format!("C:\\{program}"),
    );
    // The compile-time assertions above `HEAP_SEG`/`INDOS_SEG` only check the
    // *fixed* ends of the gap they live in; the environment block's own
    // length depends on the program's own filename, which is runtime data.
    // This is the check that closes the loop: it is what would actually
    // catch a program whose name is long enough to run the environment
    // block into the InDOS flag or the heap behind it, rather than leaving
    // that to be discovered as silent corruption the way the old `ENV_SEG`
    // bug was. Checked against `INDOS_SEG` rather than `HEAP_SEG` because
    // `INDOS_SEG` is the *closer* boundary -- see its own doc comment --
    // and a bound against the nearer edge of the gap is automatically a
    // bound against the farther one too.
    //
    // Compared as widened sums, never as a subtraction of the two segments.
    // `INDOS_SEG - ENV_SEG` on plain `u16`s would be correct only as long as
    // `INDOS_SEG > ENV_SEG` holds -- which the compile-time assert above this
    // function does pin today, but this expression has no way to *know*
    // that, and this workspace's `Cargo.toml` sets no `overflow-checks`
    // override, so a release build of a subtraction that went negative would
    // wrap to a huge `u16` and this `assert!` would silently always pass --
    // exactly the failure this check exists to catch. Addition cannot
    // underflow the same way, so there is nothing here for a future change
    // to silently get wrong.
    assert!(
        u32::from(ENV_SEG) * 16 + env.len() as u32 <= u32::from(INDOS_SEG) * 16,
        "the DOS environment block ({} bytes) would run into the InDOS flag at {INDOS_SEG:#06x}",
        env.len()
    );
    vm.load(ENV_SEG as usize * 16, &env)?;

    // The InDOS flag byte itself, written once, before the guest ever runs.
    // See [`write_indos_flag`] for why it stays zero for the rest of the
    // run, and the condition under which that would stop being true.
    let indos_at = write_indos_flag(&mut vm)?;

    // `--tsr` swaps which program boots first: a resident program, not the
    // one actually named on the command line. `boot_img`/`boot_tail` are
    // whichever one loads and runs now; `main_program`, when `Some`, is the
    // real target -- parsed already, but not loaded until the resident
    // program hands back room for it (the `StayResident` arm in the loop
    // below).
    let (boot_img, boot_tail, tsr_name, mut main_program): (
        MzImage,
        String,
        Option<String>,
        Option<(MzImage, String)>,
    ) = if let Some(spec) = &tsr {
        let (tsr_prog, tsr_tail) = split_tsr_arg(spec);
        let tsr_data = std::fs::read(&tsr_prog)?;
        let tsr_img = MzImage::parse(&tsr_data)?;
        diag!(
            door,
            "{tsr_prog}: {} byte image, {} relocations, entry {:#06x}:{:#06x}, \
             stack {:#06x}:{:#06x}, needs {} paragraphs (resident)",
            tsr_img.bytes.len(),
            tsr_img.relocs.len(),
            tsr_img.cs,
            tsr_img.ip,
            tsr_img.ss,
            tsr_img.sp,
            tsr_img.paragraphs(),
        );
        (tsr_img, tsr_tail, Some(tsr_prog), Some((img, tail.clone())))
    } else {
        (img, tail.clone(), None, None)
    };

    let at = mz::load(&mut vm, &boot_img, PSP_SEG, ENV_SEG, boot_tail.as_bytes())?;
    diag!(
        door,
        "loaded: psp {:#06x}, image {:#06x}, entering {:#06x}:{:#06x} sp {:#06x}:{:#06x}",
        at.psp_seg, at.image_seg, at.cs, at.ip, at.ss, at.sp
    );
    vm.enter(at.cs, at.ip, at.ss, at.sp, at.psp_seg, at.psp_seg)?;
    if let Some(addr) = watch {
        // Run at full speed and stop on the one access that matters. Stepping
        // from the start would take about a hundred minutes for a two-second
        // program (re/spikes/kvm_singlestep.c).
        vm.debug(Some(addr), false)?;
        diag!(door, "watching {addr:#07x} for a data access");
    }
    // A human takes as long as they take: no spin timer when attended. See
    // `SPIN_TIMEOUT` for what the unattended one measures.
    let helpers = vm.helpers((!attended).then_some(SPIN_TIMEOUT));
    // SAFETY: a plain query about the calling thread -- the one `KVM_RUN`
    // will block in, which is where a stop signal has to land.
    MAIN_TID.store(unsafe { libc::syscall(libc::SYS_gettid) as i32 }, Ordering::Relaxed);

    // The sandbox. Everything the guest opens resolves beneath this one
    // descriptor, enforced by openat2(RESOLVE_BENEATH), not by path munging.
    std::fs::create_dir_all(&root_dir)?;
    let root = std::fs::File::open(&root_dir)?;
    diag!(door, "root: {root_dir}");

    // In door mode the guest talks to a caller rather than to our screen, and
    // which way it does that is the door's own configuration -- LORDCFG's
    // "Fossil / Internal" switch. `Internal` programs the chip directly,
    // served by the port handlers below; `Regular Fossil` calls int 14h,
    // served by the composed `Fossil`. Both have to be the *same* `Uart`:
    // this is the one the host pump below reads stdin into and drains to
    // stdout, and a `Fossil` given a private copy transmits into a queue
    // nobody ever empties -- see `Fossil`'s own doc comment, which is where a
    // live door test actually hung on that before this was shared.
    let serial = door.then(|| Rc::new(RefCell::new(Uart::new(baud))));
    let mut pic = Pic::default();
    let mut pit = Pit::default();
    let _raw = door.then(RawStdin::enter).transpose()?;
    if door {
        eprintln!("door mode: COM1 at {COM1_BASE:#06x}, IRQ4, baud {baud:?}");
    }

    let mut kernel = dos_runtime::dos::Dos::default();
    let mut guest_files = Files::new(root.into(), std::path::PathBuf::from(&root_dir));
    // GALGSBL.DLL is a host library, never board data, so it never exists
    // under --root. Synthesise it and provide it the same way any other
    // filesystem answer arrives -- a real GALGSBL.DLL on disk still wins,
    // exactly as `Files::provide`'s own contract says.
    let galgsbl = dos_runtime::host_library::galgsbl(family.as_deref(), &bturno)
        .map_err(io::Error::other)?;
    guest_files.provide("GALGSBL.DLL", galgsbl);
    kernel.state.files = Some(guest_files);
    // The real segment the loader built this program's PSP at, so AH=62h
    // answers with the program's own PSP rather than failing outright.
    kernel.state.psp_seg = Some(at.psp_seg);
    // `boot_img.paragraphs()` already totals PSP + image + the header's
    // declared `min_alloc` -- the same figure DOS itself would use to size
    // the block it hands this process before any AH=4Ah shrinks it.
    // Everything above that, up to conventional memory's own ceiling, starts
    // out free; see `dos::kernel::Arena::new` for why this exact number is
    // the boundary. `boot_img` is the *loaded* program -- the TSR when
    // `--tsr` named one, or the main program otherwise -- never the pending
    // `main_program` still waiting for room.
    let first_free = at.psp_seg + boot_img.paragraphs() as u16;
    kernel.state.mem = Some(dos_runtime::dos::Arena::new(at.psp_seg, first_free));
    // The pointer `write_indos_flag` already zeroed above, before this
    // program (or the TSR ahead of it) ever ran. Unlike `psp_seg`/`mem`,
    // this is not re-set when `--tsr` hands room to the main program below:
    // it is one fixed paragraph outside the region either program owns, so
    // it stays valid across that handoff.
    kernel.state.indos = Some(indos_at);
    // Shared with the run loop through interior mutability: once `kernel` is
    // composed into `services` below, nothing outside it can reach `state`
    // any more -- see `SharedDos`'s own doc comment. `--tsr`'s `StayResident`
    // arm needs to update `state.psp_seg`/`state.mem` for the main program
    // after the resident program hands back room for it, so this clone is
    // kept outside `services` for exactly that.
    let kernel = Rc::new(RefCell::new(kernel));
    let mut keyboard = Keyboard::default();
    keyboard.feed(&keys);
    let mut driver: Option<Box<dyn Driver>> = if interactive {
        // The terminal takes the screen from here; anything printed while it
        // holds the alternate screen would land in the middle of the guest's
        // output, so the report waits until it is dropped.
        println!("interactive: Ctrl-] gives control back");
        Some(Box::new(Terminal::new()?))
    } else {
        match &script_path {
            Some(path) => {
                let text = std::fs::read_to_string(path)?;
                Some(Box::new(Script::parse(&text).map_err(io::Error::other)?))
            }
            None => None,
        }
    };
    // Shared, not owned outright by `Bios`: a text-mode program moves the
    // cursor by writing CRTC ports directly far more often than it calls
    // `int 10h AH=02`, and that port handling is not a `Service` -- it lives
    // in this loop, below. Both have to mutate the one `Video` a settle's
    // `Screen::snapshot` and the exit report's cursor-move log read, or half
    // of every session's cursor moves would land in a copy nothing ever
    // prints. See `Bios`'s own doc comment for the detail.
    let video = Rc::new(RefCell::new(Video::default()));
    video.borrow().install_bda(&mut vm);

    // The Btrieve heap: a fresh `DosHeap` over the fixed, pre-checked window
    // `HEAP_SEG`/`HEAP_CAPACITY` name above. `DosHeap::new` only fails when
    // its window would run past the end of its own segment, which the
    // compile-time assertions on `HEAP_SEG`/`HEAP_CAPACITY` already rule
    // out, so this `expect` is reporting a broken invariant, not a runtime
    // condition this file expects to see fire.
    let btrieve_heap = dos_runtime::btrieve::DosHeap::new(Ptr::new(HEAP_SEG, 0), HEAP_CAPACITY)
        .expect("HEAP_SEG/HEAP_CAPACITY are checked at compile time to fit their segment");
    let mut services: Services<VmGuest> = Services::new()
        .with(Counting::new(SharedDos(Rc::clone(&kernel))))
        .with(Counting::new(Bios { video: Rc::clone(&video) }))
        .with(Counting::new(dos_runtime::btrieve::Btrieve::new(
            btrieve_heap,
            std::path::PathBuf::from(&root_dir),
        )));
    if let Some(uart) = &serial {
        services = services.with(Counting::new(Fossil::new(Rc::clone(uart))));
    }

    // `int 16h` and a vector nothing claims are the two trap kinds that are
    // deliberately not services (R17, R21) -- the composed decorators' own
    // `calls()` cannot see either, so this is summed with them at report
    // time rather than read from `Counting` alone.
    let mut calls_outside_services = 0u32;
    // Every trap handled, composed or not -- the cap check below needs this
    // running total every iteration, which is cheap here and would not be if
    // it meant re-summing every decorator's `calls()` on each of up to
    // `max_calls` iterations. The exit report's own `{calls}` line is instead
    // reconstructed once, after the loop, from the composed decorators plus
    // `calls_outside_services` (R21) -- the two are expected to agree, but
    // this one exists only to gate the loop, never to be printed.
    let mut calls_seen = 0u32;
    // BIOS-and-other-interrupt entries a service cannot record itself:
    // `int 16h` (not a service, R17) and any vector nothing claims (recorded
    // here, not swallowed, so a gap like `int 2Fh` still shows in the report
    // the way it did before routing went through `Services`).
    let mut bios_extra: BTreeMap<(u8, u8), u32> = BTreeMap::new();
    let mut vectors: Vec<String> = Vec::new();
    let mut settles = 0u32;
    // Set once the watchpoint has fired and we are stepping a bounded window.
    let mut stepping = 0u32;
    let mut window: Vec<String> = Vec::new();
    // A `rep movsb` single-steps once per byte copied. Counting raw steps
    // spends a whole window inside one instruction, so collapse runs at the
    // same address and count distinct instructions instead.
    let mut last_addr = usize::MAX;
    let mut repeats = 0u32;
    // Calls a real machine services and we do not, named at the moment they
    // happen rather than inferred later from a screen that looks wrong.
    let mut gaps: BTreeMap<String, u32> = BTreeMap::new();
    // Where the wall clock goes. "Is the pause the program working, or us?" is
    // not answerable from a total; it needs the split.
    let mut in_guest = std::time::Duration::ZERO;
    let mut slept = std::time::Duration::ZERO;
    let mut longest = (std::time::Duration::ZERO, String::new());
    // Blocked on a person. Lumping this in with our own work makes the harness
    // look like the slow part when it is simply waiting to be typed at.
    let mut waiting = std::time::Duration::ZERO;
    // The busiest stretch between two moments the guest asked for input --
    // which is exactly one user-visible action, so this characterises the
    // pause rather than averaging it away over a whole session.
    let mut since_settle = (0u32, std::time::Duration::ZERO, std::time::Instant::now());
    let mut busiest = (0u32, std::time::Duration::ZERO, std::time::Duration::ZERO);

    let ending = loop {
        // The cap rescues an unattended probe from a program looping on a call
        // we keep refusing. A person playing a game is not that, and LORD idles
        // by polling -- it burns thousands of calls just waiting for a turn.
        // A door serves a person, same as an interactive session: the cap is
        // for unattended probes only.
        if !attended && calls_seen >= max_calls {
            break format!("stopped after {max_calls} calls");
        }
        if let Some(uart) = &serial {
            let mut uart = uart.borrow_mut();
            // Host -> guest: anything the far end has typed.
            let mut buf = [0u8; 256];
            let mut fds = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: polling and reading our own stdin.
            let ready = unsafe { libc::poll(std::ptr::from_mut(&mut fds), 1, 0) };
            if ready > 0 && fds.revents & libc::POLLIN != 0 {
                // SAFETY: `buf` is a live buffer of the stated length.
                let n = unsafe {
                    libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len())
                };
                if n > 0 {
                    for b in &buf[..n as usize] {
                        uart.receive(*b);
                    }
                } else if n == 0 {
                    // The far end hung up. Telling the guest is what lets it
                    // save and exit instead of playing to nobody.
                    uart.set_carrier(false);
                }
            }
            // Guest -> host: whatever the transmitter has clocked out.
            if !uart.tx.is_empty() {
                let out = std::mem::take(&mut uart.tx);
                // SAFETY: writing a live buffer to our own stdout.
                unsafe { libc::write(libc::STDOUT_FILENO, out.as_ptr().cast(), out.len()) };
            }
            let want = uart.interrupting() && pic.may_deliver_irq4();
            vm.set_interrupt_window(want);
            if want && vm.ready_for_interrupt() {
                pic.begin_irq4();
                vm.inject(IRQ4_VECTOR)?;
            }
        }

        if interrupted() {
            let (cs, ip) = vm.cs_ip();
            break format!("interrupted by a signal at {cs:#06x}:{ip:#06x}");
        }
        let ran = std::time::Instant::now();
        let stop = vm.run()?;
        // Every exit is progress as far as the spin timer is concerned.
        helpers.feed();
        let took = ran.elapsed();
        in_guest += took;
        since_settle.0 += 1;
        since_settle.1 += took;
        if took > longest.0 {
            longest = (took, format!("{stop:?}"));
        }
        match stop {
            // Not composed (R17, and Task 6's design note): its `bool` drives
            // a settle protocol -- screen snapshot, driver script, `settles`/
            // `busiest` statistics, run termination -- that a `Service` has no
            // way to express. Kept ahead of the general arm, verbatim.
            Stop::Trap(0x16) => {
                let ah = vm.regs().ah();
                *bios_extra.entry((0x16, ah)).or_insert(0) += 1;
                calls_seen += 1;
                calls_outside_services += 1;
                if !int16_implemented(ah)
                    && let Some(what) = missing(0x16, ah)
                {
                    *gaps.entry(format!("int 16h AH={ah:02X}  {what}")).or_insert(0) += 1;
                    if strict {
                        break format!("unimplemented: int 16h AH={ah:02X} ({what})");
                    }
                }
                if ah == 0x01 || ah == 0x11 {
                    // "Is a key ready?" with none queued is the other way a
                    // program idles. Offer the driver a chance without making
                    // the guest wait for an answer it asked not to wait for.
                    if keyboard.is_empty()
                        && let Some(script) = driver.as_mut()
                        && script.poll_due()
                    {
                        let v = video.borrow();
                        let screen = Screen::snapshot(
                            &vm,
                            v.columns as usize,
                            v.rows as usize,
                            (v.cursor_row, v.cursor_col),
                            v.cursor_visible,
                        );
                        drop(v);
                        match script.poll_key(&screen) {
                            Some(key) => keyboard.push_key(key),
                            // A driver with nothing left to say ends the run,
                            // exactly as it does at a blocking read -- otherwise
                            // an exhausted script leaves the guest polling for a
                            // key that will never come.
                            // "No key right now" is not "nothing left to say":
                            // a `wait` step deliberately answers nothing while
                            // the guest gets on with something.
                            None if !interactive && script.finished() => break script.ending(),
                            None => {}
                        }
                    }
                    int16(&mut vm, &mut keyboard);
                } else if !int16(&mut vm, &mut keyboard) {
                    // The guest has drained its input and finished painting.
                    // This is the settle point: hand the screen to the driver.
                    let Some(script) = driver.as_mut() else {
                        break "waiting for a keystroke, none queued".to_string();
                    };
                    let v = video.borrow();
                    let screen = Screen::snapshot(
                        &vm,
                        v.columns as usize,
                        v.rows as usize,
                        (v.cursor_row, v.cursor_col),
                        v.cursor_visible,
                    );
                    drop(v);
                    if since_settle.0 > busiest.0 {
                        busiest = (since_settle.0, since_settle.1, since_settle.2.elapsed());
                    }
                    since_settle = (0, std::time::Duration::ZERO, std::time::Instant::now());
                    settles += 1;
                    if trace && !interactive {
                        println!(
                            "  [settle {settles}] selected={:?} cursor={:?}",
                            screen.selected(),
                            screen.cursor
                        );
                    }
                    let idle = std::time::Instant::now();
                    // A driver with nothing to say *yet* is not finished. The
                    // guest is blocked, so the only correct answer is to wait
                    // for it rather than to end the run.
                    let mut answer = script.next_key(&screen);
                    while answer.is_none() && !script.finished() {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        answer = script.next_key(&screen);
                    }
                    waiting += idle.elapsed();
                    match answer {
                        Some(key) => {
                            if trace && !interactive {
                                println!("  [settle {settles}] send {key:?}");
                            }
                            keyboard.push_key(key);
                            int16(&mut vm, &mut keyboard);
                        }
                        None => break script.ending(),
                    }
                }
            }
            Stop::Trap(vector) => {
                // The per-call trace `--trace` promises. Like the vector
                // report just below it, this has to read the registers
                // *before* the call is routed: a service's registers on the
                // way out are its answer, not the request.
                if trace && !(interactive && trace_to_screen) {
                    let r = vm.regs();
                    eprintln!(
                        "[int {vector:02x}h] ah={:02x} al={:02x} bx={:04x} cx={:04x} dx={:04x} si={:04x} di={:04x} ds={:04x} es={:04x}",
                        r.ah(), r.al(), r.bx, r.cx, r.dx, r.si, r.di, r.ds, r.es
                    );
                }
                // A report, not dispatch: which vectors the program hooks or
                // saves via AH=25h/35h. Must run before the call is routed,
                // since a service's registers on the way out are not the
                // request any more.
                if vector == 0x21 {
                    let regs = vm.regs();
                    let ah = regs.ah();
                    if ah == 0x25 || ah == 0x35 {
                        let verb = if ah == 0x25 { "hooks" } else { "saves" };
                        vectors.push(format!("{verb} int {:02X}h", regs.al()));
                    }
                }
                // Every trap that reaches this arm is one DOS/BIOS call,
                // whether or not anything claims its vector -- matching the
                // old code's per-arm `calls += 1`, kept as one counter here
                // since the branch it lands in no longer determines that.
                calls_seen += 1;
                match services.service(vector, &mut vm) {
                    Some(Serviced::Continue) => {}
                    Some(Serviced::Yield(d)) => {
                        let before = std::time::Instant::now();
                        std::thread::sleep(d);
                        slept += before.elapsed();
                    }
                    Some(Serviced::Terminate(code)) => {
                        break format!("exited with code {code}");
                    }
                    // `AH=31h`: the program just run asked to go resident
                    // instead of exiting. No stand-down step is needed for
                    // whatever vector it hooked -- `AH=25h` writes the IVT
                    // directly, so its handler already sits in the vector
                    // table by the time this arm runs.
                    Some(Serviced::StayResident { code, paragraphs }) => {
                        let tsr_psp = kernel
                            .borrow()
                            .state
                            .psp_seg
                            .expect("a program that just answered AH=31h was loaded with a PSP segment");
                        match main_program.take() {
                            Some((main_img, main_tail)) => {
                                let main_psp = match checked_seg_add(
                                    tsr_psp,
                                    u32::from(paragraphs),
                                    "the resident block",
                                ) {
                                    Ok(seg) => seg,
                                    Err(msg) => break msg,
                                };
                                let main_at = match mz::load(
                                    &mut vm,
                                    &main_img,
                                    main_psp,
                                    ENV_SEG,
                                    main_tail.as_bytes(),
                                ) {
                                    Ok(at) => at,
                                    Err(e) => {
                                        break format!(
                                            "loading {path} on top of the resident block failed: {e}"
                                        );
                                    }
                                };
                                if let Err(e) = vm.enter(
                                    main_at.cs,
                                    main_at.ip,
                                    main_at.ss,
                                    main_at.sp,
                                    main_at.psp_seg,
                                    main_at.psp_seg,
                                ) {
                                    break format!(
                                        "entering {path} after the resident program failed: {e}"
                                    );
                                }
                                let main_first_free = match checked_seg_add(
                                    main_psp,
                                    main_img.paragraphs() as u32,
                                    "the main program's own image",
                                ) {
                                    Ok(seg) => seg,
                                    Err(msg) => break msg,
                                };
                                {
                                    let mut d = kernel.borrow_mut();
                                    d.state.psp_seg = Some(main_psp);
                                    d.state.mem = Some(dos_runtime::dos::Arena::new(
                                        main_psp,
                                        main_first_free,
                                    ));
                                }
                                println!(
                                    "resident: {} stayed resident (code {code}, {paragraphs} \
                                     paragraphs); loading {path} at {main_psp:#06x}",
                                    tsr_name.as_deref().unwrap_or("the program")
                                );
                                continue;
                            }
                            None => {
                                break format!(
                                    "{} went resident (code {code}, kept {paragraphs} \
                                     paragraphs) with no main program queued behind it",
                                    tsr_name.as_deref().unwrap_or(&path)
                                );
                            }
                        }
                    }
                    Some(Serviced::Fault(f)) => {
                        break match vector {
                            0x14 => format!("bad guest pointer in int 14h: {f:?}"),
                            _ => format!("bad guest pointer: {f:?}"),
                        };
                    }
                    // The service reports the *fact* that it does not model
                    // this call; whether that is REPORTED is the runtime's
                    // policy, and it differs per vector (Task 6's table):
                    Some(Serviced::Unclaimed { vector, ah }) => {
                        // int 21h does NOT go into `gaps`: `Counting::unclaimed()`
                        // already records this same event, and the report
                        // reconstructs it into `missing_dos` (R20), printed
                        // under "still to implement". Adding it to `gaps` too
                        // would print one unimplemented call under both that
                        // section AND "CALLS A REAL MACHINE SERVICES AND WE
                        // DO NOT" -- the brief's own prose keeps those two
                        // maps and sections separate; only its Step 2
                        // pseudocode contradicted that by routing 0x21
                        // through here as well. `--strict` still breaks,
                        // matching the pre-refactor message exactly.
                        if vector == 0x21 {
                            if strict {
                                break format!("unimplemented: int 21h AH={ah:02X}");
                            }
                        } else {
                            let note = match vector {
                                // int 14h (FOSSIL): always reported, once a
                                // FOSSIL driver is composed at all (door mode).
                                0x14 => Some(format!("int 14h AH={ah:02X}  FOSSIL function")),
                                // int 10h/16h: reported only when `missing()`
                                // knows the function's name.
                                0x10 | 0x16 => missing(vector, ah)
                                    .map(|what| format!("int {vector:02X}h AH={ah:02X}  {what}")),
                                // Everything else: never reported here.
                                // Nothing claims these vectors as a `Service`
                                // either, so in practice this arm is
                                // unreachable -- a claimed vector's
                                // `Unclaimed` always names 0x14, 0x10 or
                                // 0x16 here (0x21 is handled above). Kept for
                                // the same reason the `None` arm below is:
                                // silence, not a panic, is the right answer
                                // to a policy question no vector this router
                                // can compose actually asks.
                                _ => None,
                            };
                            if let Some(note) = note {
                                *gaps.entry(note.clone()).or_insert(0) += 1;
                                if strict {
                                    break format!("unimplemented: {note}");
                                }
                            }
                        }
                    }
                    // Nothing claims this vector -- the same case the old
                    // catch-all handled for anything that was not 0x10, 0x14,
                    // 0x15, 0x16 or 0x21. Record it and let the stub's `iret`
                    // return, which is wrong but keeps the program moving so
                    // the next gap shows.
                    None => {
                        let ah = vm.regs().ah();
                        *bios_extra.entry((vector, ah)).or_insert(0) += 1;
                        calls_outside_services += 1;
                        if vector == 0x2f && vm.regs().ax == 0x1680 {
                            let before = std::time::Instant::now();
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            slept += before.elapsed();
                        }
                        // int 14h with no serial port: nothing claims 0x14
                        // unless `--door` composed `Fossil`, so reaching this
                        // arm for 0x14 means a local run configured for a
                        // FOSSIL driver has nothing behind it. Say so, with
                        // the pre-refactor diagnostic and `--strict` message
                        // verbatim (`f9253cb`) -- falling through to
                        // `missing()` prints "serial port services", which is
                        // indistinguishable from a genuinely missing BIOS
                        // function and drops the actionable "use --door" hint.
                        if vector == 0x14 && serial.is_none() {
                            *gaps
                                .entry(
                                    "int 14h  FOSSIL, but this run has no serial port"
                                        .to_string(),
                                )
                                .or_insert(0) += 1;
                            if strict {
                                break "int 14h with no serial port: use --door".to_string();
                            }
                        } else if let Some(what) = missing(vector, ah) {
                            *gaps
                                .entry(format!("int {vector:02X}h AH={ah:02X}  {what}"))
                                .or_insert(0) += 1;
                            if strict {
                                break format!("unimplemented: int {vector:02X}h AH={ah:02X} ({what})");
                            }
                        }
                    }
                }
            }
            Stop::PortWrite { port, value } => match (&serial, port) {
                (Some(uart), p) if (COM1_BASE..COM1_BASE + 8).contains(&p) => {
                    uart.borrow_mut().write(p, value);
                }
                (_, 0x20 | 0x21) => pic.write(port, value),
                (_, 0x40..=0x43) => pit.write(port, value),
                _ => video.borrow_mut().port_out(port, value),
            },
            Stop::PortRead { port } => {
                let value = match (&serial, port) {
                    (Some(uart), p) if (COM1_BASE..COM1_BASE + 8).contains(&p) => {
                        uart.borrow_mut().read(p)
                    }
                    (_, 0x20 | 0x21) => pic.read(port),
                    (_, 0x40..=0x43) => pit.read(port),
                    _ => video.borrow_mut().port_in(port),
                };
                vm.complete_port_read(value);
            }
            Stop::Debug => {
                if stepping > 0 {
                    let here = vm.code_addr();
                    if here == last_addr {
                        repeats += 1;
                    } else {
                        if repeats > 0 {
                            if let Some(prev) = window.last_mut() {
                                prev.push_str(&format!("   (x{})", repeats + 1));
                            }
                            repeats = 0;
                        }
                        window.push(vm.trace_line());
                        last_addr = here;
                        stepping -= 1;
                        if stepping == 0 {
                            vm.debug(None, false)?;
                            break "trace window complete".to_string();
                        }
                    }
                } else if watch_skip > 0 {
                    watch_skip -= 1;
                    println!("  (skipping watchpoint hit at {})", vm.trace_line());
                } else {
                    // The access happened; a data breakpoint is trap-type, so
                    // the instruction named is the one *after* it.
                    println!("\n*** watchpoint hit ***\n  {}", vm.trace_line());
                    window.push(vm.trace_line());
                    if watch_steps > 0 {
                        stepping = watch_steps;
                        vm.debug(watch, true)?;
                    } else {
                        vm.debug(None, false)?;
                        break "watchpoint hit".to_string();
                    }
                }
            }
            Stop::IrqWindow => {}
            // With a UART present, `hlt` is not the end -- it is the guest
            // saying it has nothing to do until an interrupt arrives, which is
            // the whole point of having one.
            Stop::Halted if serial.is_some() => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Stop::Halted => break "halted".to_string(),
            Stop::Interrupted if interrupted() => {
                let (cs, ip) = vm.cs_ip();
                break format!("interrupted by a signal at {cs:#06x}:{ip:#06x}");
            }
            Stop::Interrupted => {
                let (cs, ip) = vm.cs_ip();
                break format!(
                    "spin: no exit from the guest for {}s, at {cs:#06x}:{ip:#06x}",
                    SPIN_TIMEOUT.as_secs()
                );
            }
            Stop::Unexpected(reason) => break format!("unexpected KVM exit {reason}"),
        }
    };

    drop(driver);

    // A door served a live game over stdin/stdout; the DOS-probe report that
    // follows -- a B800 screen dump, a DOS-call histogram, a file ledger -- is
    // for an analysis run (`runexe <prog>` without `--door`), not a player's
    // connection, where it would spray the caller's terminal on exit and bloat
    // the BBS's node log on every game. The guest's exit code is not carried
    // out of the real-mode path anyway (`main` returns `Ok(())`), so ending
    // here changes only the output.
    if door {
        return Ok(());
    }

    // From here on the report reads state back out of the composed services,
    // which own it now that they have been composed (Step 4). `counters()` is
    // enough for anything `Counting` tracks generically; `DosState`'s own
    // fields (`files`, `out`) are not counting state, so reading them back
    // needs the concrete type -- which, since `--tsr` needed the kernel
    // shared through `Rc<RefCell<_>>` (see `SharedDos`), is a borrow of that
    // same handle rather than a downcast through `services`.
    let kernel_dos = kernel.borrow();

    // The program painted straight into the text buffer, which is just guest
    // memory -- so the screen can be read back out without the guest's help.
    // A ruler, and lines marked at their true end. Trimming trailing spaces
    // makes a correctly placed cursor look like it overshoots: the space it
    // sits past is invisible, so "one past the content" reads as "two past the
    // text". A dump that silently drops content is a dump that lies.
    let screen_cursor = (video.borrow().cursor_row, video.borrow().cursor_col);
    println!("--- screen at B800:0000 ---");
    let ruler: String = (0..80).map(|c| char::from(b'0' + (c / 10) % 10)).collect();
    println!("    {ruler}");
    let ruler: String = (0..80).map(|c| char::from(b'0' + c % 10)).collect();
    println!("    {ruler}");
    for row in 0..25u16 {
        let at = Ptr::new(0xb800, row * 160);
        let line: String = match vm.read(at, 160) {
            Ok(cells) => cells
                .chunks(2)
                .map(|c| match c[0] {
                    0x00 | 0xff => ' ',
                    b if b.is_ascii_graphic() || b == b' ' => b as char,
                    _ => '.',
                })
                .collect(),
            Err(_) => continue,
        };
        let end = line.trim_end().len();
        let (crow, ccol) = screen_cursor;
        // Marking the cursor is what makes a trailing space visible: the text
        // stops at one column and the cursor sits past it, and the gap between
        // the two numbers is the content a trimmed dump silently dropped.
        let note = if u16::from(crow) == row {
            format!(" text ends col {end}, cursor at col {ccol}")
        } else {
            format!(" text ends col {end}")
        };
        println!("{row:2} |{}|{note}", &line[..end]);
    }

    if !vectors.is_empty() {
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for v in &vectors {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
        println!("--- interrupt vectors the program touched ---");
        for (what, n) in &counts {
            println!("  {what}  x{n}");
        }
    }

    if !video.borrow().moves.is_empty() {
        println!("--- last cursor moves ---");
        for m in &video.borrow().moves {
            println!("  {m}");
        }
    }

    if let Some(files) = kernel_dos.state.files.as_ref() {
        if !files.ambiguous.is_empty() {
            println!("--- names the host cannot uniquely resolve ---");
            for note in &files.ambiguous {
                println!("  {note}");
            }
        }
        if !files.attempts.is_empty() {
            println!("--- every file the guest asked for ---");
            for (name, how, okd) in &files.attempts {
                println!("  {how:<7} {name:<16} {}", if *okd { "ok" } else { "FAILED" });
            }
        }
        if files.touched.is_empty() {
            println!("--- no files were created or written ---");
        } else {
            println!("--- files the guest created or wrote ---");
            for name in &files.touched {
                let host = std::path::Path::new(&root_dir).join(name);
                let size = std::fs::metadata(&host).map(|m| m.len());
                match size {
                    Ok(n) => println!("  {name}  ({n} bytes at {})", host.display()),
                    Err(_) => println!("  {name}  (not present on the host)"),
                }
            }
        }
    }

    let dos_out = kernel_dos.state.out.as_slice();
    if !dos_out.is_empty() {
        println!("--- program output ---");
        println!("{}", String::from_utf8_lossy(dos_out));
    }

    // The counters a composed `Counting` decorator tracks (Step 4): `seen`,
    // `order` and `unclaimed` are all keyed `(vector, ah)`, so the int 21h
    // views the report used to get for free from a dedicated map are
    // reconstructed here by filtering to `vector == 0x21` and re-keying by
    // `ah` alone (R20) -- filtering that is a no-op in practice, since `Dos`
    // only ever claims 0x21 and nothing else can route a call to it, but
    // doing it explicitly is what keeps this report-building code honest
    // about a decorator that is deliberately generic.
    let kernel_counters = services.claiming(0x21).and_then(|s| s.counters());
    let mut seen: BTreeMap<u8, u32> = BTreeMap::new();
    let mut missing_dos: BTreeMap<u8, u32> = BTreeMap::new();
    let mut order: Vec<u8> = Vec::new();
    if let Some(c) = kernel_counters {
        for (&(vector, ah), &n) in c.seen() {
            if vector == 0x21 {
                *seen.entry(ah).or_insert(0) += n;
            }
        }
        for (&(vector, ah), &n) in c.unclaimed() {
            if vector == 0x21 {
                *missing_dos.entry(ah).or_insert(0) += n;
            }
        }
        order = c
            .order()
            .iter()
            .filter(|&&(vector, _)| vector == 0x21)
            .map(|&(_, ah)| ah)
            .collect();
    }

    // The BIOS-and-other-interrupts table: `bios_extra` (int 16h, and any
    // vector nothing claims -- neither is a `Service`, R17/R21) merged with
    // what the composed `Bios`/`Fossil` decorators recorded for the vectors
    // they do claim. `Bios` claims both 0x10 and 0x15 through one instance,
    // so `claiming(0x10)`'s `seen()` already carries both -- no separate
    // lookup for 0x15 is needed.
    let mut bios = bios_extra;
    let bios_counters = services.claiming(0x10).and_then(|s| s.counters());
    let fossil_counters = services.claiming(0x14).and_then(|s| s.counters());
    for counters in [bios_counters, fossil_counters].into_iter().flatten() {
        for (&key, &n) in counters.seen() {
            *bios.entry(key).or_insert(0) += n;
        }
    }

    // `calls` sums the composed decorators' own counts with
    // `calls_outside_services` (int 16h, plus any vector nothing claims) --
    // never `Counting::calls()` alone, which would silently undercount by
    // exactly those two trap kinds (R21).
    let calls = calls_outside_services
        + kernel_counters.map_or(0, Counters::calls)
        + bios_counters.map_or(0, Counters::calls)
        + fossil_counters.map_or(0, Counters::calls);

    println!("--- {calls} DOS calls, {ending} ---");
    for value in &scan {
        let hits = vm.scan_u16(*value, 12);
        let shown: Vec<String> = hits.iter().map(|a| format!("{a:#07x}")).collect();
        println!("scan {value:5} ({:#06x}): {}", value,
                 if shown.is_empty() { "not in memory".into() } else { shown.join(" ") });
    }

    if !window.is_empty() {
        println!("\n--- trace from the watchpoint ({} instructions) ---", window.len());
        for line in &window {
            println!("  {line}");
        }
    }
    println!("{}", cpu_report(started, calls));
    let wall = started.elapsed();
    let other = wall
        .saturating_sub(in_guest)
        .saturating_sub(slept)
        .saturating_sub(waiting);
    println!(
        "wall: {:.1}s total = {:.1}s in the guest + {:.1}s asleep on its yields \
         + {:.1}s waiting for you + {:.1}s ours",
        wall.as_secs_f64(),
        in_guest.as_secs_f64(),
        slept.as_secs_f64(),
        waiting.as_secs_f64(),
        other.as_secs_f64()
    );
    let ticks = helpers.ticks.load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "bios clock: {ticks} ticks over {:.1}s = {:.2} Hz (should be 18.20)",
        started.elapsed().as_secs_f64(),
        f64::from(ticks) / started.elapsed().as_secs_f64()
    );
    println!(
        "busiest single action: {} calls, {:.0} ms in the guest, {:.0} ms wall",
        busiest.0,
        busiest.1.as_secs_f64() * 1000.0,
        busiest.2.as_secs_f64() * 1000.0
    );
    println!(
        "longest single guest run: {:.0} ms, ended in {}",
        longest.0.as_secs_f64() * 1000.0,
        longest.1
    );
    let shown: Vec<String> = order.iter().map(|a| format!("{a:02X}")).collect();
    println!("first calls: {}", shown.join(" "));

    println!("\n{:>4}  {:>6}  {}", "AH", "calls", "status");
    for (ah, n) in &seen {
        let status = if is_implemented(*ah) {
            "implemented"
        } else {
            "MISSING"
        };
        println!("  {ah:02X}  {n:6}  {status}");
    }
    if !missing_dos.is_empty() {
        let list: Vec<String> = missing_dos.keys().map(|a| format!("{a:02X}")).collect();
        println!("\nstill to implement: {}", list.join(" "));
    }

    if !gaps.is_empty() {
        println!("\n*** CALLS A REAL MACHINE SERVICES AND WE DO NOT ***");
        for (what, n) in &gaps {
            println!("  {what}   x{n}");
        }
    }

    if !bios.is_empty() {
        println!("\nBIOS and other interrupts called (int 10h serviced, rest ignored):");
        for ((vector, ah), n) in &bios {
            println!("  int {vector:02X}h  AH={ah:02X}  {n:6} calls");
        }
    }

    if !vm.port_log.is_empty() {
        println!("\nhardware ports touched:");
        for (port, n) in &vm.port_log {
            let modelled = door && ((COM1_BASE..COM1_BASE + 8).contains(port) || matches!(port, 0x20 | 0x21))
                || matches!(port, 0x3d4 | 0x3d5 | 0x3b4 | 0x3b5 | 0x3da | 0x3ba | 0x40..=0x43);
            let how = if modelled { "modelled" } else { "absent device" };
            println!("  {port:#06x}  {n:6}  {:<48} {how}", port_name(*port));
        }
    }
    Ok(())
}

/// The line rate a DOOR.SYS describes, if it describes one.
///
/// Line 2 is the connect rate and line 5 the DTE rate. A telnet door often
/// reports 0 on line 2, meaning "no modem involved", which is exactly the case
/// where pacing should be off rather than defaulted to something invented.
fn dropfile_baud(path: &str) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines().map(|l| l.trim().parse::<u32>().ok());
    let connect = lines.nth(1).flatten();
    let dte = lines.nth(2).flatten();
    match (connect, dte) {
        (Some(0), Some(d)) if d > 0 => Some(d),
        (Some(c), _) => Some(c),
        (None, Some(d)) => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    /// A blank console prints nothing. An 80x25 block of spaces under a ruler
    /// reads as "the program drew this", which is the opposite of the truth.
    #[test]
    fn a_console_nothing_was_drawn_on_is_not_printed() {
        use dos_runtime::screen::Cells;
        assert!(!super::anything_drawn(&Cells::blank(80, 25)));

        let mut grid = Cells::blank(80, 25);
        grid.cells[3 * 80 + 10].ch = b'X';
        assert!(super::anything_drawn(&grid), "one character counts");

        // Spaces are not content, however many there are.
        let mut spaces = Cells::blank(80, 25);
        for c in &mut spaces.cells {
            c.ch = b' ';
        }
        assert!(!super::anything_drawn(&spaces));
    }

    use super::{Cli, Format, checked_seg_add, dropfile_baud, format_of, split_tsr_arg};
    use clap::Parser;

    /// The ordinary case: a program name and a tail, separated by the first
    /// run of whitespace, as `--tsr "BTRIEVE.EXE /P:2048"` documents.
    #[test]
    fn tsr_arg_splits_the_program_from_its_tail() {
        let (prog, tail) = split_tsr_arg("BTRIEVE.EXE /P:2048");
        assert_eq!(prog, "BTRIEVE.EXE");
        assert_eq!(tail, "/P:2048");
    }

    /// No whitespace at all -- a bare program name -- must not lose its last
    /// character to a `split_once` that found nothing and mishandled it, and
    /// must come back with an empty tail rather than `None`.
    #[test]
    fn tsr_arg_with_no_tail_has_an_empty_tail() {
        let (prog, tail) = split_tsr_arg("BTRIEVE.EXE");
        assert_eq!(prog, "BTRIEVE.EXE");
        assert_eq!(tail, "");
    }

    /// Extra whitespace between the program and its tail is not part of the
    /// tail DOS would see -- the same trimming a hand-typed door invocation
    /// already gets from `--keys`/positional args elsewhere in this file.
    #[test]
    fn tsr_arg_extra_leading_whitespace_before_the_tail_is_trimmed() {
        let (prog, tail) = split_tsr_arg("BTRIEVE.EXE   /P:2048");
        assert_eq!(prog, "BTRIEVE.EXE");
        assert_eq!(tail, "/P:2048");
    }

    /// A block that fits comfortably under the ceiling is accepted, and the
    /// answer is the true sum, not merely "did not error".
    #[test]
    fn resident_block_end_is_accepted_when_it_fits_under_conventional_memory() {
        assert_eq!(checked_seg_add(0x1000, 0x10, "resident block").unwrap(), 0x1010);
    }

    /// The exact boundary: ending precisely at the ceiling is still valid
    /// memory (an `Arena` seeded there just starts with no free space above
    /// it), so this must not be refused off by one.
    #[test]
    fn resident_block_end_exactly_at_the_ceiling_is_accepted() {
        assert_eq!(
            checked_seg_add(0x9ff0, 0x10, "resident block").unwrap(),
            super::CONV_TOP
        );
    }

    /// The case this function exists for: `0xfff0 + 0x0020` overflows a bare
    /// `u16` add and wraps to `0x0010`, which reads as a tiny, obviously
    /// in-bounds segment instead of the nonsense request it actually is.
    /// Checked, widened arithmetic must refuse this rather than wrap.
    #[test]
    fn resident_block_end_refuses_rather_than_wrapping_past_conventional_memory() {
        let err = checked_seg_add(0xfff0, 0x0020, "resident block")
            .expect_err("0xfff0 + 0x0020 must not silently wrap to 0x0010");
        assert!(err.contains("resident block"), "the message must name what overflowed: {err}");
    }

    /// One paragraph past the ceiling is refused too -- the boundary test
    /// above proves the edge is inclusive; this proves the very next value
    /// is not.
    #[test]
    fn resident_block_end_one_paragraph_past_the_ceiling_is_refused() {
        assert!(checked_seg_add(0x9ff0, 0x11, "resident block").is_err());
    }

    /// The format sniff must read the signature bytes, not merely validate
    /// `e_lfanew`. All fifteen extracted DOS `WCCMMUTL.EXE` builds carry
    /// `e_lfanew == 0x10000`, a plausible-looking offset pointing at ordinary
    /// code -- "is `e_lfanew` sane" would route every one of them to the Win32
    /// host.
    #[test]
    fn the_format_sniff_reads_the_signature_not_the_offset() {
        let mut mz = vec![0u8; 0x40];
        mz[0..2].copy_from_slice(b"MZ");
        mz[0x3c..0x40].copy_from_slice(&0x10000u32.to_le_bytes());
        assert_eq!(format_of(&mz), Format::RealMode, "a nonsense e_lfanew is still MZ");

        let mut pe = vec![0u8; 0x100];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(format_of(&pe), Format::Pe32);

        let mut ne = vec![0u8; 0x100];
        ne[0..2].copy_from_slice(b"MZ");
        ne[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        ne[0x80..0x82].copy_from_slice(b"NE");
        assert_eq!(format_of(&ne), Format::Unsupported, "NE is refused, not routed");

        for sig in [b"LE", b"LX"] {
            let mut le = vec![0u8; 0x100];
            le[0..2].copy_from_slice(b"MZ");
            le[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            le[0x80..0x82].copy_from_slice(sig);
            assert_eq!(format_of(&le), Format::Le, "LE/LX routes to the DOS/4GW host");
        }
    }

    /// `PE\0\0` is checked in full. A real-mode image whose code happens to
    /// begin with the two letters `PE` must not be routed to the Win32 host on
    /// the strength of them.
    #[test]
    fn a_two_byte_pe_without_its_nulls_is_not_a_pe() {
        let mut almost = vec![0u8; 0x100];
        almost[0..2].copy_from_slice(b"MZ");
        almost[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        almost[0x80..0x84].copy_from_slice(b"PEEK");
        assert_eq!(format_of(&almost), Format::RealMode);
    }

    /// The live door's invocation, verbatim from
    /// `/sbbs/xtrn/lord/lord-dospoc.sh`: program first, then flags, then a bare
    /// command tail. This is the shape that must never stop parsing.
    #[test]
    fn the_live_door_invocation_still_parses() {
        let cli = Cli::try_parse_from([
            "runexe",
            "/sbbs/xtrn/lord/LORD.EXE",
            "--root",
            "/sbbs/xtrn/lord",
            "--door",
            "--dropfile",
            "/sbbs/xtrn/lord/NODE1/DOOR.SYS",
            "1",
            "/DREW",
        ])
        .expect("the door's own command line must parse");

        assert_eq!(cli.program, "/sbbs/xtrn/lord/LORD.EXE");
        assert_eq!(cli.root, "/sbbs/xtrn/lord");
        assert!(cli.door);
        assert_eq!(cli.tail.join(" "), "1 /DREW", "the command tail is what LORD reads its node from");
    }

    /// The ordering trap that cost a real session two failed runs: with the old
    /// hand-rolled parser `--root` was taken as the program name, and the error
    /// was a bare ENOENT that named nothing.
    #[test]
    fn flags_may_precede_the_program_now() {
        let cli = Cli::try_parse_from(["runexe", "--root", "/tmp/x", "SETUP.EXE"])
            .expect("flags before the positional must be accepted");
        assert_eq!(cli.program, "SETUP.EXE");
        assert_eq!(cli.root, "/tmp/x");
    }

    /// The whole point of this change: no root, no run. The old default was
    /// `tmp/lordroot` behind a `create_dir_all`, so a forgotten root silently
    /// built one game's directory wherever the operator happened to be.
    #[test]
    fn a_missing_root_refuses_rather_than_guessing() {
        let err = Cli::try_parse_from(["runexe", "SETUP.EXE"])
            .expect_err("running without --root must be an error");
        let text = err.to_string();
        assert!(text.contains("--root"), "the error must name --root: {text}");
    }

    #[test]
    fn watch_takes_hex_with_or_without_the_prefix() {
        let with = Cli::try_parse_from(["runexe", "--root", ".", "--watch", "0x1eb0", "A.EXE"])
            .expect("0x-prefixed address");
        let without = Cli::try_parse_from(["runexe", "--root", ".", "--watch", "1eb0", "A.EXE"])
            .expect("bare hex address");
        assert_eq!(with.watch, Some(0x1eb0));
        assert_eq!(without.watch, Some(0x1eb0), "bare values were hex before clap and still are");
    }

    #[test]
    fn scan_u16_splits_on_commas() {
        let cli = Cli::try_parse_from(["runexe", "--root", ".", "--scan-u16", "1,22,333", "A.EXE"])
            .expect("comma separated list");
        assert_eq!(cli.scan_u16, vec![1, 22, 333]);
    }

    /// No `--tsr` at all -- the overwhelming majority of invocations -- must
    /// still parse, with the flag reading `None` rather than an empty string.
    #[test]
    fn no_tsr_flag_is_none() {
        let cli = Cli::try_parse_from(["runexe", "--root", ".", "A.EXE"])
            .expect("--tsr is optional");
        assert_eq!(cli.tsr, None);
    }

    fn drop_with(connect: &str, dte: &str) -> String {
        let mut lines: Vec<String> = (0..52).map(|i| format!("field{i}")).collect();
        lines[0] = "COM1:".into();
        lines[1] = connect.into(); // line 2
        lines[4] = dte.into(); // line 5
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/dos-poc-tests")
            .join(format!("drop{connect}_{dte}.sys"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, lines.join("\r\n")).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn the_connect_rate_is_line_two_and_the_dte_rate_is_line_five() {
        // Off by one either way silently picks a neighbouring field, which is
        // a plausible-looking number rather than an error.
        assert_eq!(dropfile_baud(&drop_with("14400", "38400")), Some(14400));
    }

    #[test]
    fn a_telnet_door_reporting_no_modem_falls_back_to_the_dte_rate() {
        assert_eq!(dropfile_baud(&drop_with("0", "38400")), Some(38400));
    }

    #[test]
    fn zero_on_both_means_no_pacing_rather_than_a_made_up_default() {
        assert_eq!(dropfile_baud(&drop_with("0", "0")), Some(0));
    }

    #[test]
    fn a_dropfile_that_is_not_there_yields_nothing() {
        assert_eq!(dropfile_baud("/nonexistent/DOOR.SYS"), None);
    }

    /// What `main` actually does, in order: `hook_all`, then load the
    /// environment block at `ENV_SEG`. A review caught that the old
    /// `ENV_SEG` (`0x00a0`) was sized against a false "256 vectors * 4
    /// bytes = 0x400" invariant -- `hook_all`'s real high-water mark is
    /// `dos_runtime::kvm::STUB_TABLE_BYTES` (`0x403`), 3 bytes more, because
    /// vector `0x7B`'s stub sits at a non-stride-aligned offset. The old
    /// `ENV_SEG` load silently overwrote 3 of vector `0xFF`'s 4 stub bytes
    /// -- the `TRAP_PORT` operand, the `iret`, and the padding -- on every
    /// run. This is the test that would have caught it: it reads vector
    /// `0xFF`'s actual stub bytes back out of guest memory, not just the
    /// segment arithmetic.
    #[test]
    fn loading_the_real_environment_leaves_the_last_stub_intact() {
        use dos_runtime::guest::{Guest, Ptr};
        use dos_runtime::kvm::{STUB_TABLE_BYTES, TRAP_PORT, VmGuest};

        let mut vm = VmGuest::new(super::MEM).expect("open /dev/kvm and map guest memory");
        vm.hook_all(super::STUB_SEG).expect("hook every vector");

        let env = dos_runtime::mz::environment(
            &["PATH=C:\\", "COMSPEC=C:\\COMMAND.COM"],
            "C:\\PROGRAM.EXE",
        );
        vm.load(super::ENV_SEG as usize * 16, &env)
            .expect("load the environment block");

        // Vector 0xFF is the last stub hook_all places, so its offset is
        // STUB_TABLE_BYTES minus one stub's width.
        let last_stub_off = STUB_TABLE_BYTES - 4;
        let bytes = vm
            .read(Ptr::new(super::STUB_SEG, last_stub_off), 3)
            .expect("read vector 0xFF's stub");
        assert_eq!(
            bytes,
            [0xe6, TRAP_PORT as u8, 0xcf],
            "out TRAP_PORT,al ; iret -- vector 0xFF's stub must survive the environment load"
        );
    }

    /// The failure the test above would have caught, reproduced directly:
    /// loading the environment at the *old* `ENV_SEG` (`0x00a0`) does
    /// corrupt vector `0xFF`'s stub. Kept as an executable mutation rather
    /// than a one-off hand-edit of `super::ENV_SEG`, because that constant
    /// is now behind a `const _: () = assert!(...)` -- setting it back to
    /// `0x00a0` fails the *build*, not this test, which is a stronger
    /// guarantee but means the historical failure mode needs its own
    /// reproduction to stay checked by `cargo test` rather than only by
    /// memory of a manual edit. (Confirmed separately, by hand: restoring
    /// `const ENV_SEG: u16 = 0x00a0;` does not compile --
    /// `error[E0080]: evaluation panicked: ENV_SEG must start at or after
    /// A vector is named as hex or decimal, and anything past 255 is refused
    /// rather than truncated -- a truncated vector names a real but different
    /// interrupt, so the mistake would surface as a TSR that mysteriously
    /// never gets called rather than as an error.
    #[test]
    fn a_vector_is_hex_or_decimal_and_never_truncates() {
        assert_eq!(super::parse_vector("0x7b"), Ok(0x7b));
        assert_eq!(super::parse_vector("0X7B"), Ok(0x7b));
        assert_eq!(super::parse_vector("123"), Ok(123));
        assert_eq!(super::parse_vector(" 0x7b "), Ok(0x7b));
        assert!(super::parse_vector("0x100").is_err(), "256 is not a vector");
        assert!(super::parse_vector("300").is_err(), "300 is not a vector");
        assert!(super::parse_vector("").is_err());
        assert!(super::parse_vector("nonsense").is_err());
    }

    /// `--unhook` hands one vector back and leaves every other stub alone.
    ///
    /// Both halves matter. Without the first, a TSR that probes before
    /// installing declines -- measured: real Btrieve 5.00c reads vector
    /// `0x7B`, sees our stub, prints "Program already loaded" and exits 1.
    /// Without the second, unhooking one vector could quietly disarm the
    /// host's whole trap table and every DOS call would stop being serviced.
    #[test]
    fn unhooking_a_vector_clears_only_that_ones_ivt_entry() {
        use dos_runtime::guest::{Guest, Ptr};
        use dos_runtime::kvm::VmGuest;

        let mut vm = VmGuest::new(super::MEM).expect("open /dev/kvm and map guest memory");
        vm.hook_all(super::STUB_SEG).expect("hook every vector");
        let before_21 = vm.read(Ptr::new(0, 0x21 * 4), 4).expect("read int 21h vector").to_vec();
        assert_ne!(before_21, [0u8; 4], "int 21h must be hooked before the test means anything");

        super::unhook_vectors(&mut vm, &[0x7b]).expect("unhook");

        assert_eq!(
            vm.read(Ptr::new(0, 0x7b * 4), 4).expect("read int 7Bh vector"),
            &[0u8; 4],
            "the unhooked vector must be handed back to the guest"
        );
        assert_eq!(
            vm.read(Ptr::new(0, 0x21 * 4), 4).expect("read int 21h vector"),
            &before_21[..],
            "no other vector may be disturbed"
        );
    }

    /// the stub table hook_all fills`.)
    #[test]
    fn the_old_env_seg_would_have_clobbered_the_last_stub() {
        use dos_runtime::guest::{Guest, Ptr};
        use dos_runtime::kvm::{STUB_TABLE_BYTES, TRAP_PORT, VmGuest};

        const OLD_ENV_SEG: u16 = 0x00a0;
        let intact = [0xe6u8, TRAP_PORT as u8, 0xcf];
        let last_stub_off = STUB_TABLE_BYTES - 4;

        let mut vm = VmGuest::new(super::MEM).expect("open /dev/kvm and map guest memory");
        vm.hook_all(super::STUB_SEG).expect("hook every vector");
        let before = vm
            .read(Ptr::new(super::STUB_SEG, last_stub_off), 3)
            .expect("read vector 0xFF's stub")
            .to_vec();
        assert_eq!(before, intact, "hook_all must place an intact stub before any load");

        let env = dos_runtime::mz::environment(
            &["PATH=C:\\", "COMSPEC=C:\\COMMAND.COM"],
            "C:\\PROGRAM.EXE",
        );
        vm.load(OLD_ENV_SEG as usize * 16, &env)
            .expect("load the environment block at the old segment");

        let after = vm
            .read(Ptr::new(super::STUB_SEG, last_stub_off), 3)
            .expect("read vector 0xFF's stub");
        assert_ne!(
            after, intact,
            "the old ENV_SEG no longer reproduces the corruption -- if STUB_TABLE_BYTES or \
             the packing changed, this test and the const assert above ENV_SEG need to move \
             together"
        );
    }

    /// `AH=34h`'s whole contract in one run: [`write_indos_flag`] zeroes
    /// `INDOS_SEG` before the guest ever executes, and that same pointer is
    /// handed to `DosState::indos`, so a program asking `AH=34h` gets back an
    /// address whose byte reads zero. This drives the same `Dos` service
    /// through a real KVM vCPU, the way `main`'s own loop does, and checks
    /// the byte through guest memory rather than trusting that a correct
    /// pointer implies a correct byte -- `kernel.rs`'s own dispatch code
    /// cannot get this byte wrong (it never touches it), but this binary's
    /// wiring can: a `write_indos_flag` that wrote the wrong byte, or a
    /// `main` that never called it or never assigned `kernel.state.indos`,
    /// would all leave the byte unspecified while `AH=34h` still answers
    /// *some* address. Calls [`write_indos_flag`] itself, not a copy of what
    /// it does -- see that function's own doc comment for why.
    #[test]
    fn the_indos_byte_this_binary_writes_reads_back_zero_through_ah_34h() {
        use dos::service::{Serviced, Services};
        use dos_runtime::guest::{Guest, Ptr};
        use dos_runtime::kvm::{Stop, VmGuest};

        const STUB: u16 = 0x0060;
        const CODE_SEG: u16 = 0x2000;
        const CODE_OFF: u16 = 0x0100;

        let mut vm = VmGuest::new(super::MEM).expect("open /dev/kvm and map guest memory");
        vm.hook(0x21, STUB).expect("hook int 21h");

        // mov ah, 0x34 ; int 21h ; mov ax, 0x4C00 ; int 21h
        let program: [u8; 9] = [0xb4, 0x34, 0xcd, 0x21, 0xb8, 0x00, 0x4c, 0xcd, 0x21];
        vm.load(CODE_SEG as usize * 16 + CODE_OFF as usize, &program)
            .expect("load the program");
        vm.start(CODE_SEG, CODE_OFF, CODE_SEG, 0xfffe).expect("enter real mode");

        // `main`'s own call, not a copy of what it does -- see
        // `write_indos_flag`'s own doc comment for why that distinction is
        // the whole point of this test.
        let indos_at = super::write_indos_flag(&mut vm).expect("zero the InDOS flag");

        let mut kernel = dos_runtime::dos::Dos::default();
        kernel.state.indos = Some(indos_at);
        let mut services: Services<VmGuest> = Services::new().with(kernel);

        let mut answered_at = None;
        loop {
            match vm.run().expect("KVM run") {
                Stop::Trap(vector) => match services.service(vector, &mut vm) {
                    Some(Serviced::Continue) => {
                        if answered_at.is_none() {
                            let r = vm.regs();
                            answered_at = Some(Ptr::new(r.es, r.bx));
                        }
                    }
                    Some(Serviced::Terminate(_)) => break,
                    other => panic!("unexpected: {other:?}"),
                },
                other => panic!("unexpected guest stop: {other:?}"),
            }
        }

        let at = answered_at.expect("AH=34h must answer before the program terminates");
        assert_eq!(at, indos_at, "AH=34h must answer with the same pointer write_indos_flag returned");
        let byte = vm.read(at, 1).expect("the InDOS address must be mapped memory")[0];
        assert_eq!(byte, 0, "the InDOS flag byte must read back zero");
    }
}

/// Name the ports a DOS-era runtime is likely to reach for, so the log reads
/// as a finding rather than a list of numbers.
fn port_name(port: u16) -> &'static str {
    match port {
        0x20 | 0x21 => "8259 interrupt controller",
        0x40..=0x43 => "8253 timer (Turbo Pascal calibrates its delay loop here)",
        0x60 | 0x64 => "keyboard controller",
        0x70 | 0x71 => "CMOS / real-time clock",
        0x3b0..=0x3bf => "MDA video",
        0x3c0..=0x3cf => "VGA",
        0x3d0..=0x3df => "CGA/EGA video",
        0x3f8..=0x3ff => "COM1 serial",
        0x2f8..=0x2ff => "COM2 serial",
        _ => "",
    }
}
