//! The `mbbs-server` binary: parse arguments, boot the host thread, listen.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mbbs::Terms;
use mbbs::abi::{Wg16, Wg32, Wg32Cpu};
use mbbs_machine::Format;
use mbbs_server::conn::{self, Listener, default_keys};
use mbbs_server::host::{Boot, ExtensionBuilder};
use mbbs_server::msg::In;
use mbbs_server::termcompat::Stack;

const DEFAULT_LISTEN: &str = "127.0.0.1:2323";
const DEFAULT_TERMS: u16 = 2;

/// The arena [`Wg32Cpu::new`]'s placeholder `Memory` reserves for a `Wg32`
/// module's host-allocated regions (`ModuleMem::alloc_region`, design doc
/// Part 3) -- everything a `Wg32` module asks the host to allocate at
/// runtime, on top of its own loaded images.
///
/// **Provisional, the same way `DEFAULT_POLLS_PER_SECOND` is provisional.** No
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

/// Poll firings granted per elapsed second -- `--polls-per-second`'s default.
///
/// **512 preserves today's behaviour and is not a derived number.** The old
/// `--polls-per-wake` granted 512 per driver wake, and an armed board wakes
/// about once a second off `_BACKGROUND_FAST`'s heartbeat, so 512/second is
/// what the board was already getting. Keeping it makes this change a
/// cadence fix rather than a retuning.
///
/// The floor that would make it *meaningful* is a property of the module's
/// own config -- for MajorMUD, `MONSBUF` (option 24, 300 on the board this
/// was measured against), the monster-table bound its firings walk one entry
/// at a time. Below that the world runs at `grant / MONSBUF` of intended
/// speed, silently. This host does not read another program's config and
/// pretend to understand it; see the design doc's "the budget, and what the
/// host may not pretend to know".
const DEFAULT_POLLS_PER_SECOND: usize = 512;

/// The `syscyc` vector fires once per elapsed second by default -- the edge a
/// gate-shaped handler needs, and the cadence every board ran at before
/// `--syscyc` existed. See [`mbbs::Host::set_syscyc_hz`].
const DEFAULT_SYSCYC_HZ: u32 = 1;

// Every rejection (an unknown flag, a missing required one, a number that
// does not parse) is a clear message to stderr and a non-zero exit, never a
// fallback to a default the operator did not ask for -- that would be
// exactly the undefined-behaviour-shaped surprise this codebase prefers a
// compile error or a clean refusal over. `--terms 0` gets the same
// treatment even though it is not a parse failure: `Terms::new` panics on
// it, and a panic is a worse answer than a message and a non-zero exit, so
// `parse_terms` range-checks before `main` ever calls `Terms::new`.
#[derive(Parser, Debug)]
#[command(name = "mbbs-server", about = "a tokio edge in front of one MajorBBS-family machine")]
struct Cli {
    /// The board directory: where the module's own data files live (its
    /// `.MSG`, `.DAT`, `.VIR` and whatever else it opens by bare name) and
    /// where it writes. The host changes into it before the module runs, so
    /// every relative path the module opens resolves here. Always required.
    #[arg(long)]
    root: Option<PathBuf>,

    /// The module(s) to load, in dependency order -- `mbbs_server::host::Boot`'s
    /// own doc, "Booting N modules", is the full contract. The first one
    /// given is the one every connecting channel enters (`Host::connect`'s
    /// `first_module()`); anything after it is an addon, loaded and
    /// initialised so its own exports are reachable and its own imports can
    /// resolve against the module before it, but never dispatched a channel
    /// directly.
    ///
    /// Which machine boots is decided by the module files' own header, not a
    /// flag: [`plan`] sniffs every given path with
    /// [`mbbs_machine::Format::sniff`] and boots a `Wg16` machine for NE
    /// files, or a `Wg32` machine for PE files -- both repeatable, in the
    /// order given; mixing formats is a named `Err`.
    ///
    /// At least one is required: this host ships no module of its own and
    /// has no default to fall back on.
    #[arg(long, required = true)]
    module: Vec<PathBuf>,

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

    /// Path of a Unix-domain socket for BBS door sessions (`mbbs-door`
    /// connects here on a caller's behalf). No default: a board with two
    /// games has two servers and two sockets, and a shared default would
    /// let one steal the other's.
    #[arg(long)]
    listen_door: Option<PathBuf>,

    /// Channel count: how many callers can be connected at once. Fixed for
    /// the life of the process, because the module's own per-channel tables
    /// are sized from it at init. At least 1, at most 32767.
    #[arg(long, default_value_t = DEFAULT_TERMS, value_parser = parse_terms)]
    terms: u16,

    /// How many times per second the host fires the module's background
    /// poll routine while idle. That routine is where a module advances its
    /// world between keystrokes; too low and the world runs slow, too high
    /// and the process spins. 512 is what a period board delivered.
    #[arg(long, default_value_t = DEFAULT_POLLS_PER_SECOND)]
    polls_per_second: usize,

    /// Times per second to fire the `syscyc` vector while idle. The default 1
    /// suits a module whose `syscyc` is an idempotent gate (MajorMUD). Set it
    /// higher for a module that steps a per-call queue every fire (RCIROSE,
    /// `--syscyc 100`), whose world otherwise advances at 1 Hz.
    #[arg(long, default_value_t = DEFAULT_SYSCYC_HZ)]
    syscyc: u32,

    /// The keys every caller holds. A key is MajorBBS's unit of
    /// entitlement: a module asks `haskey` before it lets a caller into a
    /// game, a menu or a sysop command, and the sysop of a period board
    /// granted keys per account. This host has no accounts, so one set is
    /// handed to every connection. Comma-separated; a key may not be empty.
    /// [default: DEMO,NORMAL,USER]
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

    /// A directory of `*.lua` scripts (`mbbs-lua`'s `LuaExtension`) to load
    /// above the module at startup, for QoL commands the module itself
    /// never had -- `mbbs-lua`'s own crate doc has the full seam.
    ///
    /// Loads on whichever machine this board boots -- `Wg16` or `Wg32` --
    /// getting its own `LuaExtension` instance. **Caution:** the
    /// shipped scripts (`summon`, `cash`, `setexp`) were written and measured
    /// against the 16-bit MajorMUD build -- their export names and record
    /// offsets are not known to hold for a 32-bit module. See
    /// `mbbs-lua`'s own crate doc and `crates/mbbs/src/extension.rs`'s module
    /// doc for the specifics.
    ///
    /// A directory that fails to load is a startup error, not a warning: a
    /// board that silently came up without its scripts is exactly the
    /// failure mode this refuses to be. `None` (the default) leaves this
    /// binary running exactly as it did before this flag existed.
    #[arg(long, value_name = "DIR")]
    scripts: Option<PathBuf>,
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

/// Which machine this command line boots, and with what -- the pure decision
/// `main` turns into a `Boot`. Never touches a filesystem: the formats come
/// in from `main` (`sniff_all`), so the decision stays unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Wg16 { modules: Vec<PathBuf>, root: PathBuf },
    Wg32 { modules: Vec<PathBuf>, root: PathBuf },
}

/// Read every requested module's header. A file that cannot be read or
/// sniffed is a startup error naming the file.
fn sniff_all(modules: &[PathBuf]) -> Result<Vec<Format>, String> {
    modules
        .iter()
        .map(|path| {
            let file = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            Format::sniff(&file).map_err(|e| format!("{}: {e}", path.display()))
        })
        .collect()
}

/// Decide the machine from the requested modules and their formats
/// (`formats[i]` is `cli.module[i]`'s). Every rejection is a
/// named `Err`, never a panic and never a silent fallback.
fn plan(cli: &Cli, formats: &[Format]) -> Result<Plan, String> {
    let modules = cli.module.clone();
    if modules.is_empty() {
        return Err("--module is required".to_string());
    }
    if formats.len() != modules.len() {
        return Err(format!("{} modules but {} formats", modules.len(), formats.len()));
    }
    let root = cli.root.clone().ok_or_else(|| "--root is required".to_string())?;

    let first = formats[0];
    if let Some((path, other)) = modules.iter().zip(formats).find(|(_, f)| **f != first) {
        return Err(format!(
            "{} is a {} file but {} is {}; every --module must be the same format",
            path.display(),
            format_name(*other),
            modules[0].display(),
            format_name(first),
        ));
    }
    match first {
        Format::Ne => Ok(Plan::Wg16 { modules, root }),
        Format::Pe => Ok(Plan::Wg32 { modules, root }),
    }
}

/// The name [`plan`]'s error messages use for a [`Format`] -- `NE`/`PE`,
/// matching how the file formats are known outside this codebase, rather
/// than `Format`'s own `Ne`/`Pe` `Debug` spelling.
fn format_name(format: Format) -> &'static str {
    match format {
        Format::Ne => "NE",
        Format::Pe => "PE",
    }
}

/// Build [`Boot::build`]'s closure for a `Wg32` machine: an empty
/// [`mbbs_machine::m32::Memory`] with the host arena, and a fresh
/// [`mbbs_machine::m32::Machine`]. Every module's image arrives through
/// `Host::load` (`host::life`'s per-module loop), in `--module` order.
fn build_wg32_cpu() -> impl Fn() -> io::Result<Wg32Cpu> + Send {
    || {
        let mem = mbbs_machine::m32::Memory::new(DEFAULT_WG32_ARENA_BYTES)?;
        let machine = mbbs_machine::m32::Machine::new()?;
        Ok(Wg32Cpu::new(machine, mem))
    }
}

/// Build [`Boot::extension`]'s closure for `--scripts`: load `dir` as an
/// `mbbs_lua::LuaExtension`, boxed as the ABI-erased `Extension<A>` the field
/// expects. Generic over `A: Abi` -- `mbbs_lua::LuaExtension` implements
/// `Extension<A>` for any ABI (its struct carries nothing ABI-specific; see
/// its own crate doc), so this builder can hand one to whichever machine
/// (`Wg16` or `Wg32`) this board's [`Plan`] boots -- see the call site in
/// `main` below.
///
/// A directory that fails to load names both the directory and the
/// underlying reason -- see [`Boot::extension`]'s own doc comment for why
/// this must be a startup error, never a silent, unscripted board. `host::life`
/// calls this AFTER every module has loaded and initialised (see
/// `ExtensionBuilder`'s own doc comment), so `modules` is never empty on a
/// board that boots at all -- `load_with_modules` resolves a script's bare
/// namespace against exactly these.
///
/// Any per-script soft-skip note `LuaExtension::load_with_modules` produced
/// is printed here, before the concrete `LuaExtension` is boxed away as
/// `Box<dyn Extension<A>>` -- that erasure is the last point anything
/// outside `mbbs-lua` can still call `LuaExtension::notes()` at all.
///
/// `Fn`, not `FnOnce`, the same way [`build_wg32_cpu`] is: [`host::run`]'s
/// restart loop calls this once per life, so a restarted machine gets its
/// scripts freshly loaded rather than losing them after the first restart.
fn build_lua_extension<A: mbbs::abi::Abi + 'static>(dir: PathBuf) -> ExtensionBuilder<A> {
    Box::new(move |modules: &[(String, A::Module)]| {
        let named: Vec<(&str, &A::Module)> = modules.iter().map(|(name, module)| (name.as_str(), module)).collect();
        let ext = mbbs_lua::LuaExtension::load_with_modules::<A>(&dir, &named)
            .map_err(|e| io::Error::other(format!("loading scripts from {}: {e}", dir.display())))?;
        for note in ext.notes() {
            eprintln!("mbbs-server: {note}");
        }
        Ok(Box::new(ext) as Box<dyn mbbs::extension::Extension<A>>)
    })
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

    let modules = cli.module.clone();
    let formats = match sniff_all(&modules) {
        Ok(formats) => formats,
        Err(msg) => {
            eprintln!("mbbs-server: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match plan(&cli, &formats) {
        Ok(plan) => plan,
        Err(msg) => {
            eprintln!("mbbs-server: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // The accept paths' shared "is the board taking callers" flag. `life`
    // sets it true once a life has booted, `tear_down` clears it at the
    // start of maintenance. See `host::Serving`'s own doc.
    let serving: mbbs_server::host::Serving =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));

    // One machine per process. Its host thread builds its own `A::Cpu`
    // (`Boot::build`, called from `host::life`) -- `A::Cpu` is `!Send` and
    // never crosses into this `async fn`.
    let tx = match plan {
        Plan::Wg16 { modules, root } => conn::spawn_machine(Boot::<Wg16> {
            build: Box::new(mbbs_machine::m16::Machine::new),
            root,
            modules,
            terms,
            bturno: cli.bturno.clone(),
            polls_per_second: cli.polls_per_second,
            syscyc_hz: cli.syscyc,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
            extension: cli.scripts.clone().map(build_lua_extension),
            maintenance_interval: mbbs_server::host::MAINTENANCE_INTERVAL,
            serving: serving.clone(),
        }),
        Plan::Wg32 { modules, root } => conn::spawn_machine(Boot::<Wg32> {
            build: Box::new(build_wg32_cpu()),
            root,
            modules,
            terms,
            bturno: cli.bturno.clone(),
            polls_per_second: cli.polls_per_second,
            syscyc_hz: cli.syscyc,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
            extension: cli.scripts.clone().map(build_lua_extension),
            maintenance_interval: mbbs_server::host::MAINTENANCE_INTERVAL,
            serving: serving.clone(),
        }),
    };
    let shutdown = tx.clone();
    let door_tx = tx.clone();

    let addrs = match conn::serve_on(tx, keys, &listeners, serving.clone()).await {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("mbbs-server: failed to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    for addr in &addrs {
        println!("mbbs-server: listening on {addr}");
    }

    if let Some(path) = &cli.listen_door {
        if let Err(e) = mbbs_server::door::serve(path.clone(), door_tx, serving.clone()).await {
            eprintln!("mbbs-server: failed to bind the door socket {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("mbbs-server: door socket at {}", path.display());
    }

    // The accept loop and the host thread are already spawned; this task's
    // only remaining job is to keep the process alive for it, and to shut it
    // down in an orderly way when told to.
    let signal = wait_for_signal().await;
    eprintln!("mbbs-server: {signal} -- shutting the module down");
    shut_down(&shutdown, SHUTDOWN_GRACE).await;
    if let Some(path) = &cli.listen_door {
        let _ = std::fs::remove_file(path);
    }
    ExitCode::SUCCESS
}

/// How long the module gets, in total, to finish shutting down.
///
/// A module's `finrou` is real work, not a formality: MajorMUD's writes every
/// dirty buffer back through Btrieve, and on this host that goes through a
/// reindex whose cost grows with the file (`BUGS.md`). Thirty seconds is
/// generous for that and still short enough that a wedged module cannot hold
/// a terminal open indefinitely -- and the alternative to a bound is not a
/// slower exit, it is an exit that never happens.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Resolve when the process is asked to stop, naming what asked.
///
/// Both signals, because they arrive from different places and mean the same
/// thing here: SIGINT is the operator at a terminal, SIGTERM is `systemd`,
/// `docker stop`, or a plain `kill`. Handling only the first would mean every
/// service-managed shutdown skipped `finrou` -- which is the case that matters
/// most, since it is the one that happens unattended.
///
/// SIGKILL is deliberately absent: it cannot be caught, which is the whole
/// reason the module's own recovery marker exists and why `WCCMMUTL -recover`
/// ships with MajorMUD. A host cannot promise a clean shutdown, only take one
/// when it is offered.
async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(e) => {
            // Losing SIGTERM is not worth refusing to run over, but it is
            // worth saying: an operator whose `systemctl stop` silently skips
            // shutdown would otherwise find out from the next boot's recovery
            // mode instead of from here.
            eprintln!("mbbs-server: cannot listen for SIGTERM ({e}); SIGINT only");
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
    }
}

/// Ask the host thread to shut its module down, and wait up to `grace` for
/// its `finrou` sweep to finish.
async fn shut_down(tx: &std::sync::mpsc::Sender<In>, grace: Duration) {
    let (done, wait) = tokio::sync::oneshot::channel();
    if tx.send(In::Shutdown { done }).is_err() {
        return;
    }
    if tokio::time::timeout(grace, wait).await.is_err() {
        eprintln!(
            "mbbs-server: the module did not finish shutting down within {grace:?} -- \
             exiting anyway; it may leave a recovery marker behind"
        );
    } else {
        eprintln!("mbbs-server: shut down");
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use mbbs::abi::Wg32;
    use mbbs_machine::Format;
    use std::path::PathBuf;

    use super::{
        Cli, DEFAULT_POLLS_PER_SECOND, Plan,
        build_lua_extension, listeners, plan,
    };

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
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", 
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

    #[test]
    fn listen_door_is_optional_and_takes_a_path() {
        let cli = Cli::try_parse_from(["mbbs-server", "--module", "W.DLL", "--listen-door", "/run/user/1000/mbbs-mmud.sock"])
            .expect("parses");
        assert_eq!(cli.listen_door.as_deref(), Some(std::path::Path::new("/run/user/1000/mbbs-mmud.sock")));
        assert!(Cli::try_parse_from(["mbbs-server", "--module", "W.DLL"]).expect("parses").listen_door.is_none());
    }

    /// `--module` and `--root` alone parse cleanly and everything else takes
    /// its documented default.
    #[test]
    fn defaults_are_applied_when_only_module_and_root_are_given() {
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp"])).expect("parses");
        assert_eq!(cli.root, Some(std::path::PathBuf::from("tmp")));
        assert_eq!(cli.module, vec![std::path::PathBuf::from("W.DLL")]);
        assert_eq!(cli.listen, vec!["127.0.0.1:2323".to_string()]);
        assert!(cli.listen_raw.is_empty(), "no default period port -- opt in with --listen-raw");
        assert_eq!(cli.terms, 2);
        assert_eq!(cli.polls_per_second, DEFAULT_POLLS_PER_SECOND);
        assert!(cli.keys.is_empty(), "no --keys given, so main falls back to default_keys()");
    }

    /// `--listen` repeated binds more than one modern-stack address, in the
    /// order given.
    #[test]
    fn listen_is_repeatable() {
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", 
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
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", 
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
            Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--listen-raw", "127.0.0.1:2325"]))
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

    /// `--root` is not a clap-level required flag -- parsing succeeds with
    /// it absent. `plan` requires it always; clap does not, so the check has
    /// one testable home.
    #[test]
    fn root_is_optional_at_the_parse_layer() {
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", "--terms", "2"])).expect("parses");
        assert_eq!(cli.root, None);
    }

    /// `build_lua_extension` is what `main` actually maps `--scripts` through
    /// for a `Wg32` machine's own `Boot::extension` field -- `a_pe_module_plans_a_wg32_board`
    /// only proves such a board is accepted, not that it would actually carry
    /// a working extension. This proves the generic builder produces a real
    /// `LuaExtension`, boxed as `Extension<Wg32>`, from the same shipped
    /// `scripts/` directory `mbbs-lua`'s own tests load against `Wg16`.
    #[test]
    fn build_lua_extension_produces_a_wg32_extension_from_the_shipped_scripts() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
        let builder = build_lua_extension::<Wg32>(dir);
        // No modules given: all three shipped scripts bind `wccmmud` (see
        // `scripts/lib/wccmmud.lua`), so with an empty module list every one
        // of them soft-skips -- `wccmmud` is not loaded on this machine, so
        // `namespace::install`'s `__index` handler refuses the bind and
        // `exec_scripts` catches it as a note, not a load failure. The
        // extension still builds, just with zero registered commands: this
        // test's own job is proving that all-skip-still-installs property
        // and that the generic builder produces a real `Extension<Wg32>`,
        // not exercising namespace resolution against a real module.
        builder(&[]).expect("the shipped scripts/ directory loads against Wg32 just as it does against Wg16");
    }

    /// `--scripts` together with a `Wg16` machine (the default, plain
    /// `--root` case) parses and plans cleanly.
    #[test]
    fn scripts_with_wg16_present_plans_cleanly() {
        let cli = Cli::try_parse_from(args(&[
            "--root", "tmp", "--scripts", "scripts", "--module", "A",
        ]))
        .expect("parses");
        assert_eq!(
            plan(&cli, &[Format::Ne]),
            Ok(Plan::Wg16 { modules: vec![PathBuf::from("A")], root: PathBuf::from("tmp") })
        );
    }

    /// Every NE module given, in order, plans a `Wg16` board.
    #[test]
    fn ne_modules_plan_a_wg16_board_with_every_module_in_order() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module", "A", "--module", "B"])).expect("parses");
        assert_eq!(
            plan(&cli, &[Format::Ne, Format::Ne]),
            Ok(Plan::Wg16 { modules: vec![PathBuf::from("A"), PathBuf::from("B")], root: PathBuf::from("tmp") })
        );
    }

    /// A single PE module plans a `Wg32` board.
    #[test]
    fn a_pe_module_plans_a_wg32_board() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module", "W.DLL"])).expect("parses");
        assert_eq!(
            plan(&cli, &[Format::Pe]),
            Ok(Plan::Wg32 { modules: vec![PathBuf::from("W.DLL")], root: PathBuf::from("tmp") })
        );
    }

    /// No `--module` at all is refused by the parser, naming the flag. There
    /// is no built-in module to fall back on.
    #[test]
    fn no_module_flag_is_refused_by_name() {
        let err = Cli::try_parse_from(args(&["--root", "tmp"])).expect_err("--module is required");
        assert!(err.to_string().contains("--module"), "the error names the flag: {err}");
    }

    /// A mix of NE and PE modules is refused by name -- the offending file,
    /// its own format, and the format the first module set.
    #[test]
    fn mixed_formats_are_refused_by_name() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module", "A", "--module", "B.DLL"])).expect("parses");
        let err = plan(&cli, &[Format::Ne, Format::Pe]).expect_err("mixed");
        assert!(err.contains("B.DLL") && err.contains("PE") && err.contains("NE"), "{err}");
    }

    /// Every PE module given, in order, plans a `Wg32` board -- the same
    /// N-module contract `ne_modules_plan_a_wg16_board_with_every_module_in_order`
    /// proves for `Wg16`.
    #[test]
    fn two_pe_modules_plan_a_wg32_board_in_order() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module", "A.DLL", "--module", "B.DLL"])).expect("parses");
        assert_eq!(
            plan(&cli, &[Format::Pe, Format::Pe]),
            Ok(Plan::Wg32 { modules: vec![PathBuf::from("A.DLL"), PathBuf::from("B.DLL")], root: PathBuf::from("tmp") })
        );
    }

    /// `--root` absent is a named `Err` from `plan`, not a panic and not a
    /// boot with an empty root path.
    #[test]
    fn missing_root_is_a_named_plan_error() {
        let cli = Cli::try_parse_from(args(&["--module", "A"])).expect("parses");
        let err = plan(&cli, &[Format::Ne]).expect_err("no root");
        assert!(err.contains("--root"), "{err}");
    }

    /// The same case as `missing_root_is_a_named_plan_error`, reached with
    /// a 16-bit module: `--root` is optional at the clap layer and required
    /// by `plan`.
    #[test]
    fn wg16_boot_without_root_is_a_named_plan_error() {
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL"])).expect("parses; --root is optional at the clap layer");
        let err = plan(&cli, &[Format::Ne]).expect_err("a Wg16 boot needs --root");
        assert!(err.contains("--root"), "error should name the missing flag: {err}");
    }

    /// A format count that does not match the requested modules is refused
    /// rather than indexing out of bounds or silently ignoring the mismatch.
    #[test]
    fn a_format_count_that_does_not_match_the_modules_is_refused() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module", "A"])).expect("parses");
        assert!(plan(&cli, &[]).is_err());
    }

    /// `--module32`/`--root32`/`--bturno32` no longer exist -- two boards
    /// are two processes now.
    #[test]
    fn module32_is_gone() {
        assert!(Cli::try_parse_from(args(&["--root", "tmp", "--module32", "X"])).is_err());
        assert!(Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--root32", "X"])).is_err());
        assert!(Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--bturno32", "1"])).is_err());
    }

    /// A flag this binary does not know about is refused, not ignored.
    #[test]
    fn unknown_argument_is_an_error() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--bogus", "x"])).unwrap_err();
        assert!(err.to_string().contains("--bogus"), "error should name the bad flag: {err}");
    }

    /// A flag with nothing after it is refused, not silently left at its
    /// default.
    #[test]
    fn a_dangling_flag_is_an_error() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--terms"])).unwrap_err();
        assert!(
            err.to_string().contains("--terms"),
            "error should name the flag missing its value: {err}"
        );
    }

    /// `--scripts` with nothing after it is refused with a named error, the
    /// same way `--terms` is above -- not silently left at `None`, and not
    /// merely reported as "unrecognised argument" (which would pass even if
    /// `--scripts` had never been wired up as a real flag at all).
    #[test]
    fn scripts_without_a_directory_is_an_error() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--scripts"])).unwrap_err();
        assert!(
            err.to_string().contains("--scripts"),
            "error should name the flag missing its value: {err}"
        );
        assert!(
            !err.to_string().to_lowercase().contains("unrecognized")
                && !err.to_string().to_lowercase().contains("unexpected"),
            "this must fail because --scripts needs a value, not because clap does not \
             know the flag: {err}"
        );
    }

    /// `Terms::new(0)` panics; this must catch it first and report cleanly.
    #[test]
    fn terms_zero_is_rejected_before_it_reaches_terms_new() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--terms", "0"])).unwrap_err();
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
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--terms", "40000"])).unwrap_err();
        assert!(err.to_string().contains("--terms"), "error should name the flag: {err}");
    }

    /// A value that does not parse as the expected number names both the
    /// flag and the bad value, not just "invalid input".
    #[test]
    fn an_unparseable_number_is_a_clear_error() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--terms", "banana"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--terms"), "error should name the flag: {msg}");
        assert!(msg.contains("banana"), "error should echo the bad value: {msg}");
    }

    /// `--keys` splits on commas.
    #[test]
    fn keys_split_on_commas() {
        let cli = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--keys", "A,B,C"])).expect("parses");
        assert_eq!(cli.keys, vec!["A", "B", "C"]);
    }

    /// A stray comma produces an empty key, which is refused rather than
    /// silently handed to a new connection.
    #[test]
    fn an_empty_key_segment_is_rejected() {
        let err = Cli::try_parse_from(args(&["--module", "W.DLL", "--root", "tmp", "--keys", "A,,C"])).unwrap_err();
        assert!(err.to_string().contains("--keys"), "error should name the flag: {err}");
    }
}
