//! The `mbbs-server` binary: parse arguments, boot the host thread, listen.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mbbs::Terms;
use mbbs::abi::{Wg16, Wg32, Wg32Cpu};
use mbbs_server::conn::{self, Listener, Machine, default_keys};
use mbbs_server::host::Boot;
use mbbs_server::pool::MachineId;
use mbbs_server::termcompat::Stack;

const DEFAULT_MODULE: &str = "re/WCCMMUD.DLL";
const DEFAULT_LISTEN: &str = "127.0.0.1:2323";
const DEFAULT_TERMS: u16 = 2;

/// [`select_machine`]'s label for the always-present `Wg16` machine.
///
/// [`select_machine`]: mbbs_server::conn
const WG16_LABEL: &str = "MajorMUD";

/// [`select_machine`]'s label for the optional `Wg32` machine, `--module32`.
///
/// [`select_machine`]: mbbs_server::conn
const WG32_LABEL: &str = "LunatiX";

/// The arena [`Wg32Cpu::new`]'s placeholder `Memory` reserves for
/// `--module32`'s host-allocated regions (`ModuleMem::alloc_region`, design
/// doc Part 3) -- everything a `Wg32` module asks the host to allocate at
/// runtime, on top of its own loaded image.
///
/// **Provisional, the same way `DEFAULT_POLLS_PER_WAKE` is provisional.** No
/// real 32-bit module has ever run against this host long enough to measure
/// what it actually needs (`crates/mbbs/tests/wg32_round_trip.rs`'s own
/// fixture gets by on `0x0002_0000`, but that is a synthetic one-import
/// module built to prove the border works, not LunatiX). 16 MiB is a
/// generous guess, not a measurement: undershoot fails loudly
/// (`Memory::alloc`'s `OutOfMemory`, not silent corruption -- `flatptr.rs`
/// bounds-checks every access against the arena's real mapped range), so the
/// honest failure mode of guessing too small is a board that refuses to
/// serve rather than one that corrupts state, and overshoot only costs
/// address space `MAP_32BIT` has to spare, not RSS (anonymous pages are not
/// resident until touched). Retune from a real session's high-water mark,
/// not from this comment.
const DEFAULT_WG32_ARENA_BYTES: usize = 0x0100_0000;

/// Poll dispatches granted per driver wake -- `--polls-per-wake`'s default.
///
/// **This number is the board's whole idle CPU cost, and very nearly its
/// poll rate in hertz.** Measured with two players standing in the Realm:
/// wakes are kick-driven at one a second, a polling channel spends the whole
/// budget every wake, and the host thread's clock reads came back as
/// `budget + 1` -- 33, 129 and 513 at budgets of 32, 128 and 512.
///
/// It cannot be calibrated from inside the host. `Ended::Waiting`'s
/// `polls_cut` is `true` at every budget (see its doc), because `dopoll`
/// re-arms until the budget runs out and the chain has no way to say "done".
/// Whether the number is big enough is a question about the module's own
/// amortised work -- for MajorMUD, whether monsters act at the rate they
/// should -- and answering it needs someone to play the game.
///
/// 512 is provisional, and chosen for the asymmetry rather than from a
/// measurement of the game: MajorMUD's polling routine advances ONE monster
/// per call, gated on every other call, so a budget of 32 buys about sixteen
/// monster updates a second and a table of any size would starve. Overshoot
/// is nearly free -- once a round drains, every further dispatch falls
/// through one branch -- while undershoot makes the world visibly slow. 513
/// clock reads a second is a rounding error of CPU; sixteen monster updates
/// a second may not be a playable game.
const DEFAULT_POLLS_PER_WAKE: usize = 512;

/// Passes made per `Host::cycle` call -- `--passes`'s default.
///
/// `Host::cycle`'s `max` bounds dispatch *attempts*, not dispatches
/// themselves: the call returns the instant its queue is empty, so `passes`
/// only matters as a ceiling against a queue that keeps refilling. That
/// queue is bounded per wake by `--polls-per-wake` re-arms of the polling
/// status, plus up to one already-queued-but-not-rearmed `POLSTS` per
/// channel once the budget runs out (`Host::dopoll`'s budget comment), plus
/// whatever `In` messages this wake drained (one status each). With the
/// defaults above, `DEFAULT_POLLS_PER_WAKE` plus `DEFAULT_TERMS` must stay
/// under it, so this is the poll budget plus room for a burst of
/// connects and input rather than a number chosen on its own for a burst of connects or input
/// on top of a full poll budget without ever being the thing that cuts a
/// wake short.
const DEFAULT_PASSES: usize = 1024;

// Every rejection (an unknown flag, a missing required one, a number that
// does not parse) is a clear message to stderr and a non-zero exit, never a
// fallback to a default the operator did not ask for -- that would be
// exactly the undefined-behaviour-shaped surprise this codebase prefers a
// compile error or a clean refusal over. `--terms 0` gets the same
// treatment even though it is not a parse failure: `Terms::new` panics on
// it, and a panic is a worse answer than a message and a non-zero exit, so
// `parse_terms` range-checks before `main` ever calls `Terms::new`.
#[derive(Parser, Debug)]
#[command(name = "mbbs-server", about = "a tokio edge in front of one WCCMMUD.DLL host")]
struct Cli {
    /// The board directory (holds the module's own data files)
    #[arg(long)]
    root: PathBuf,

    /// The module to load
    #[arg(long, default_value = DEFAULT_MODULE)]
    module: PathBuf,

    /// Address to bind for a modern client: CP437 transcoded to UTF-8, and
    /// the ANSI.SYS divergences patched. Repeatable, to listen on more than
    /// one address.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: Vec<String>,

    /// Address to bind for a period client -- SyncTERM, MegaMUD, or anything
    /// else that already speaks the host's own CP437/ANSI.SYS on the wire.
    /// The host's bytes go out essentially untouched (telnet's IAC still
    /// gets doubled -- that is framing, not rendering). Repeatable; no
    /// default, since a board with no period clients need not open this
    /// port at all.
    #[arg(long)]
    listen_raw: Vec<String>,

    /// Fixed channel count, must be at least 1
    #[arg(long, default_value_t = DEFAULT_TERMS, value_parser = parse_terms)]
    terms: u16,

    /// Poll dispatches granted per driver wake
    #[arg(long, default_value_t = DEFAULT_POLLS_PER_WAKE)]
    polls_per_wake: usize,

    /// Passes made per Host::cycle call
    #[arg(long, default_value_t = DEFAULT_PASSES)]
    passes: usize,

    /// Connection keys handed to a new player [default: DEMO,NORMAL,USER]
    #[arg(long, value_delimiter = ',', value_parser = parse_key)]
    keys: Vec<String>,

    /// DIAGNOSTIC ONLY -- DO NOT USE ON A BOARD ANYONE PLAYS ON. Enumerate
    /// every unimplemented symbol this session reaches by writing to PATH,
    /// instead of stopping the module the first time one is hit. This makes
    /// the module produce WRONG BEHAVIOUR from that point on: every
    /// unimplemented call gets a fabricated zero/null return instead of a
    /// real answer, and the module cannot tell the difference. Use this only
    /// for a throwaway session whose sole purpose is to build the list of
    /// gaps at PATH; never leave it on for real play.
    #[arg(long, value_name = "PATH")]
    survey_unimplemented_and_corrupt_the_session: Option<PathBuf>,

    /// A second, 32-bit module to boot alongside the primary `Wg16` one
    /// (LunatiX, design doc §4a). When given, a connect-time selector
    /// appears -- see `mbbs_server::conn`'s module doc, "The connect-time
    /// selector" -- naming this machine `LunatiX` and the always-present one
    /// `MajorMUD`. When absent, this binary behaves exactly as it did before
    /// this flag existed: no prompt, one machine. Requires `--root32`, since
    /// this machine's own data files must not share a directory with the
    /// primary machine's.
    #[arg(long, requires = "root32", value_name = "PATH")]
    module32: Option<PathBuf>,

    /// The 32-bit module's own board directory -- only meaningful together
    /// with `--module32`. Deliberately has no default and is not allowed to
    /// fall back to `--root`: two machines writing into the same root would
    /// silently share (and corrupt) one module's Btrieve files with the
    /// other's -- see `mbbs_server::pool`'s module doc on why two machines'
    /// state must never collide.
    #[arg(long, value_name = "PATH")]
    root32: Option<PathBuf>,

    /// This board's Galacticomm registration number -- the `bturno` global,
    /// `BRKTHU.H:108`, eight digits.
    ///
    /// Absent, `bturno` stays as `Host::new` placed it: nine zero bytes, a
    /// board with no serial. That was this binary's only behaviour until
    /// now, and it is not neutral -- `bturno` is a `GALGSBL` datum modules
    /// read directly, and MajorBBS-family modules key their own licensing on
    /// it, so a blank one makes every board look identical and unregistered
    /// to anything that checks.
    #[arg(long, value_name = "DIGITS")]
    bturno: Option<String>,

    /// `--bturno` for the 32-bit machine, when the two boards do not share a
    /// serial. Falls back to `--bturno` when absent.
    ///
    /// Two machines on one server are two boards; nothing says one
    /// registration covers both, and a module on the second machine reading
    /// the first machine's serial would be a quiet lie rather than a
    /// convenience.
    #[arg(long, value_name = "DIGITS")]
    bturno32: Option<String>,
}

/// Range-check `--terms` before it ever reaches `Terms::new`, which panics
/// on 0 or on a count above `i16::MAX`.
fn parse_terms(s: &str) -> Result<u16, String> {
    let n: u16 = s.parse().map_err(|e| format!("'{s}' is not a valid number: {e}"))?;
    if n == 0 {
        return Err(
            "must be at least 1 (a host with no channels cannot serve anyone)".to_string(),
        );
    }
    if n > i16::MAX as u16 {
        return Err(format!(
            "{n} is too large; the module addresses a channel as a 16-bit signed int, so the \
             limit is {}",
            i16::MAX
        ));
    }
    Ok(n)
}

/// One `--keys` segment. An empty segment (a stray comma, or an empty flag
/// value) is rejected rather than silently handing a new connection a blank
/// key.
fn parse_key(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err(
            "must not contain an empty key (check for a stray or trailing comma)".to_string(),
        );
    }
    Ok(s.to_string())
}

/// Turn the parsed flags into the listener list `conn::serve` binds:
/// `--listen` addresses take [`Stack::modern`], `--listen-raw` addresses take
/// [`Stack::raw`], modern ones first, each group in the order given.
///
/// This is the **only** place a command-line flag becomes a transport choice,
/// and it is a free function rather than three lines inside `main` for one
/// reason: `main` is unreachable from a test. Left inline, swapping the two
/// constructors here inverted the entire feature — every modern client served
/// raw CP437 and every period client served UTF-8 — and *nothing in the
/// workspace failed*, not the CLI tests (which only inspect the parsed
/// `Cli`), not `conn`'s per-port byte tests (which call `serve` with a list
/// they build themselves), and not the live-socket integration tests (which
/// compare ASCII substrings through `from_utf8_lossy` and cannot see an
/// encoding at all). Measured, not supposed. Extracting it costs nothing and
/// makes the mapping assertable; see `flags_map_to_their_own_stacks`.
fn listeners(cli: &Cli) -> Vec<Listener<'_>> {
    cli.listen
        .iter()
        .map(|addr| (addr.as_str(), Stack::modern as fn() -> Stack))
        .chain(
            cli.listen_raw
                .iter()
                .map(|addr| (addr.as_str(), Stack::raw as fn() -> Stack)),
        )
        .collect()
}

/// Build [`Boot::build`]'s closure for a `Wg32` machine: read `module_path`'s
/// bytes, parse them as a PE, and build a placeholder [`Wg32Cpu`] -- a
/// [`mbbs_machine::m32::Machine`] plus a [`mbbs_machine::m32::Memory`]
/// wrapping this same file's own [`mbbs_machine::m32::Image`], exactly the
/// shape `crates/mbbs/tests/wg32_round_trip.rs`'s `machine_and_placeholder`
/// builds from a synthetic fixture -- this one is real. `host::life` (in
/// `mbbs-server/src/host.rs`) reads `boot.module` (the same path) again
/// immediately after this runs and calls `host.load`, whose `Wg32::load`
/// replaces this placeholder image wholesale via
/// [`mbbs_machine::m32::Memory::replace_image`] while leaving the arena this
/// closure reserved untouched -- see that method's own doc comment, and
/// `wg32_round_trip.rs`'s module doc, "The load-order hazard this file first
/// exposed, now fixed". Building the placeholder from the module's own
/// bytes, rather than a throwaway skeleton, means a file that cannot even be
/// read or parsed as a PE fails here, on `Boot::build`, with the same error
/// `host.load` would otherwise report one line later.
///
/// `Fn`, not `FnOnce`: [`host::run`]'s restart loop calls [`Boot::build`]
/// once per life (see its own doc comment, "Surviving a module stop"), so
/// this closure re-reads and re-parses the file every restart rather than
/// only once at process start.
fn build_wg32_cpu(module_path: PathBuf) -> impl Fn() -> io::Result<Wg32Cpu> + Send {
    move || {
        let file = std::fs::read(&module_path)?;
        let pe = mbbs_machine::m32::PeImage::parse(&file).map_err(io::Error::other)?;
        let image = mbbs_machine::m32::Image::load(&file, &pe)?;
        let mem = mbbs_machine::m32::Memory::new(image, DEFAULT_WG32_ARENA_BYTES)?;
        let machine = mbbs_machine::m32::Machine::new()?;
        Ok(Wg32Cpu::new(machine, mem))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // The listener list borrows `cli`'s address strings, so it is built
    // before `Boot` takes ownership of anything; the clones below are two
    // paths and a short key list, once, at startup.
    let listeners = listeners(&cli);

    let terms = Terms::new(cli.terms);
    let keys = if cli.keys.is_empty() {
        default_keys()
    } else {
        cli.keys.clone()
    };

    if let Some(path) = &cli.survey_unimplemented_and_corrupt_the_session {
        eprintln!(
            "mbbs-server: SURVEY MODE IS ON, writing to {}. This board will now \
             fabricate a return for every unimplemented symbol it reaches instead \
             of stopping -- that is WRONG BEHAVIOUR, tolerable only for a \
             throwaway diagnostic session. Do not use this on a board anyone is \
             actually playing on.",
            path.display()
        );
    }

    // This CLI always boots `Wg16` -- `re/WCCMMUD.DLL`'s own ABI -- and
    // optionally a second, `Wg32` machine when `--module32` is given
    // (LunatiX, design doc §4a). `conn::spawn_machine` is generic over
    // `A: Abi` since Task 20 of
    // `docs/plans/2026-08-12-abi-border-implementation.md`; each call spawns
    // its own dedicated thread that builds its own `A::Cpu` *on* that thread
    // (`Boot::build`, called from `host::life` -- never here, since `A::Cpu`
    // is `!Send` and can never cross into this `async fn`). Every machine's
    // sender is wrapped in a `conn::Machine` and handed to one `serve_on`
    // call, which is what wires the connect-time selector between them --
    // see `conn.rs`'s own module doc, "The connect-time selector".
    //
    // `MachineId(0)` for `Wg16` and `MachineId(1)` for `Wg32` are not
    // placeholders: every `Chan` a machine's `Pool` hands out is tagged with
    // its own id (`pool.rs`), and that tag is what keeps the two boards'
    // channel zeros distinguishable process-wide. See `mbbs_server::pool`'s
    // module doc.
    let boot: Boot<Wg16> = Boot {
        machine: MachineId(0),
        build: Box::new(mbbs_machine::m16::Machine::new),
        root: cli.root.clone(),
        module: cli.module.clone(),
        terms,
        bturno: cli.bturno.clone(),
        polls_per_wake: cli.polls_per_wake,
        passes: cli.passes,
        clock_reads: None,
        wake_age_ms: None,
        dispatched_total: None,
        calls_total: None,
        survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
    };

    let mut machines = vec![Machine {
        id: MachineId(0),
        label: WG16_LABEL.to_string(),
        tx: conn::spawn_machine(boot),
    }];

    if let (Some(module32), Some(root32)) = (cli.module32.clone(), cli.root32.clone()) {
        let boot32: Boot<Wg32> = Boot {
            machine: MachineId(1),
            build: Box::new(build_wg32_cpu(module32.clone())),
            root: root32,
            module: module32,
            terms,
            bturno: cli.bturno32.clone().or_else(|| cli.bturno.clone()),
            polls_per_wake: cli.polls_per_wake,
            passes: cli.passes,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
        };
        machines.push(Machine {
            id: MachineId(1),
            label: WG32_LABEL.to_string(),
            tx: conn::spawn_machine(boot32),
        });
    }

    let addrs = match conn::serve_on(machines, keys, &listeners).await {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("mbbs-server: failed to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    for addr in &addrs {
        println!("mbbs-server: listening on {addr}");
    }

    // The accept loop and the host thread are both spawned already; this
    // task's only remaining job is to keep the process alive for them.
    std::future::pending::<()>().await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, DEFAULT_PASSES, DEFAULT_POLLS_PER_WAKE, listeners};

    fn args<'a>(v: &[&'a str]) -> Vec<&'a str> {
        let mut a = vec!["mbbs-server"];
        a.extend_from_slice(v);
        a
    }

    /// `--listen` addresses get the modern stack and `--listen-raw` addresses
    /// get the period one -- the mapping, not merely the parse.
    ///
    /// Asserted by *behaviour* rather than by comparing the `fn() -> Stack`
    /// pointers: Rust and LLVM may merge functions with identical bodies, so
    /// pointer equality is not a dependable statement about which constructor
    /// a listener carries. Feeding each stack a byte the two treat
    /// differently is. `0xDB` is CP437's full block: the modern stack
    /// transcodes it to U+2588 (three UTF-8 bytes), the period stack leaves
    /// the single byte alone.
    ///
    /// Swapping the two constructors in [`listeners`] fails this test and,
    /// before it existed, failed nothing at all.
    #[test]
    fn flags_map_to_their_own_stacks() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--listen",
            "127.0.0.1:2323",
            "--listen-raw",
            "127.0.0.1:2324",
        ]))
        .expect("parses");

        let got = listeners(&cli);
        assert_eq!(
            got.iter().map(|(addr, _)| *addr).collect::<Vec<_>>(),
            ["127.0.0.1:2323", "127.0.0.1:2324"],
            "modern addresses first, then raw, each in the order given"
        );

        assert_eq!(
            got[0].1().outbound(&[0xDB]),
            "\u{2588}".as_bytes(),
            "--listen is the modern stack: CP437 0xDB transcodes to a full block"
        );
        assert_eq!(
            got[1].1().outbound(&[0xDB]),
            &[0xDB],
            "--listen-raw is the period stack: the byte reaches the client as CP437"
        );
    }

    /// The only required flag is `--root`; everything else takes the
    /// documented default.
    #[test]
    fn defaults_are_applied_when_only_root_is_given() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert_eq!(cli.root, std::path::PathBuf::from("tmp"));
        assert_eq!(cli.module, std::path::PathBuf::from("re/WCCMMUD.DLL"));
        assert_eq!(cli.listen, vec!["127.0.0.1:2323".to_string()]);
        assert!(cli.listen_raw.is_empty(), "no default period port -- opt in with --listen-raw");
        assert_eq!(cli.terms, 2);
        assert_eq!(cli.polls_per_wake, DEFAULT_POLLS_PER_WAKE);
        assert_eq!(cli.passes, DEFAULT_PASSES);
        assert!(cli.keys.is_empty(), "no --keys given, so main falls back to default_keys()");
    }

    /// `--listen` repeated binds more than one modern-stack address, in the
    /// order given.
    #[test]
    fn listen_is_repeatable() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--listen",
            "127.0.0.1:2323",
            "--listen",
            "127.0.0.1:2324",
        ]))
        .expect("parses");
        assert_eq!(cli.listen, vec!["127.0.0.1:2323".to_string(), "127.0.0.1:2324".to_string()]);
    }

    /// `--listen-raw` is repeatable too, independent of `--listen`.
    #[test]
    fn listen_raw_is_repeatable() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--listen-raw",
            "127.0.0.1:2325",
            "--listen-raw",
            "127.0.0.1:2326",
        ]))
        .expect("parses");
        assert_eq!(
            cli.listen_raw,
            vec!["127.0.0.1:2325".to_string(), "127.0.0.1:2326".to_string()]
        );
        assert_eq!(
            cli.listen,
            vec!["127.0.0.1:2323".to_string()],
            "--listen keeps its own default even when only --listen-raw is given"
        );
    }

    /// `--listen-raw` alone, with no `--listen` on the command line at all,
    /// still gets `--listen`'s documented default -- `--listen-raw` adds a
    /// port, it does not replace the modern one.
    #[test]
    fn listen_raw_alone_still_defaults_listen() {
        let cli =
            Cli::try_parse_from(args(&["--root", "tmp", "--listen-raw", "127.0.0.1:2325"]))
                .expect("parses");
        assert_eq!(cli.listen, vec!["127.0.0.1:2323".to_string()]);
        assert_eq!(cli.listen_raw, vec!["127.0.0.1:2325".to_string()]);
    }

    /// `--help` short-circuits, even with other flags present -- a caller
    /// asking for help should get it, not an error about a flag they were
    /// only passing out of habit.
    #[test]
    fn help_short_circuits() {
        let err = Cli::try_parse_from(args(&["--help", "--terms", "not-a-number"])).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// No `--root` at all is a clear error, not a silent default.
    #[test]
    fn missing_root_is_an_error() {
        let err = Cli::try_parse_from(args(&["--terms", "2"])).unwrap_err();
        assert!(err.to_string().contains("--root"), "error should name the missing flag: {err}");
    }

    /// `--module32` without `--root32` is refused by clap's own `requires`
    /// enforcement, not left to `main` to notice at boot -- two machines
    /// sharing one root would silently corrupt one module's Btrieve files
    /// with the other's (see `--root32`'s own doc comment).
    #[test]
    fn module32_without_root32_is_an_error() {
        let err = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("root32"),
            "error should name the flag that is missing: {err}"
        );
    }

    /// `--module32` together with `--root32` parses cleanly, and without
    /// either flag both are simply absent -- a board with no second module
    /// need not mention either one.
    #[test]
    fn module32_and_root32_parse_together_and_default_to_absent() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert!(cli.module32.is_none());
        assert!(cli.root32.is_none());

        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        assert_eq!(cli.module32, Some(std::path::PathBuf::from("LUNATIX.EXE")));
        assert_eq!(cli.root32, Some(std::path::PathBuf::from("tmp32")));
    }

    /// A flag this binary does not know about is refused, not ignored.
    #[test]
    fn unknown_argument_is_an_error() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--bogus", "x"])).unwrap_err();
        assert!(err.to_string().contains("--bogus"), "error should name the bad flag: {err}");
    }

    /// A flag with nothing after it is refused, not silently left at its
    /// default.
    #[test]
    fn a_dangling_flag_is_an_error() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--terms"])).unwrap_err();
        assert!(
            err.to_string().contains("--terms"),
            "error should name the flag missing its value: {err}"
        );
    }

    /// `Terms::new(0)` panics; this must catch it first and report cleanly.
    #[test]
    fn terms_zero_is_rejected_before_it_reaches_terms_new() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--terms", "0"])).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("--terms") && msg.contains("at least 1"),
            "error should explain why 0 is refused: {err}"
        );
    }

    /// A count the module cannot address as a 16-bit signed channel number
    /// is refused the same way `Terms::new` would panic on it.
    #[test]
    fn terms_above_i16_max_is_rejected() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--terms", "40000"])).unwrap_err();
        assert!(err.to_string().contains("--terms"), "error should name the flag: {err}");
    }

    /// A value that does not parse as the expected number names both the
    /// flag and the bad value, not just "invalid input".
    #[test]
    fn an_unparseable_number_is_a_clear_error() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--terms", "banana"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--terms"), "error should name the flag: {msg}");
        assert!(msg.contains("banana"), "error should echo the bad value: {msg}");
    }

    /// `--keys` splits on commas.
    #[test]
    fn keys_split_on_commas() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--keys", "A,B,C"])).expect("parses");
        assert_eq!(cli.keys, vec!["A", "B", "C"]);
    }

    /// A stray comma produces an empty key, which is refused rather than
    /// silently handed to a new connection.
    #[test]
    fn an_empty_key_segment_is_rejected() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--keys", "A,,C"])).unwrap_err();
        assert!(err.to_string().contains("--keys"), "error should name the flag: {err}");
    }
}
