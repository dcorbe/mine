//! The `mbbs-server` binary: parse arguments, boot the host thread, listen.

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mbbs::Terms;
use mbbs::abi::{Wg16, Wg32, Wg32Cpu};
use mbbs_server::conn::{self, Listener, Machine, default_keys};
use mbbs_server::host::{Boot, ExtensionBuilder};
use mbbs_server::msg::In;
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

// Every rejection (an unknown flag, a missing required one, a number that
// does not parse) is a clear message to stderr and a non-zero exit, never a
// fallback to a default the operator did not ask for -- that would be
// exactly the undefined-behaviour-shaped surprise this codebase prefers a
// compile error or a clean refusal over. `--terms 0` gets the same
// treatment even though it is not a parse failure: `Terms::new` panics on
// it, and a panic is a worse answer than a message and a non-zero exit, so
// `parse_terms` range-checks before `main` ever calls `Terms::new`.
#[derive(Parser, Debug)]
#[command(name = "mbbs-server", about = "a tokio edge in front of one or more MajorBBS-family modules")]
struct Cli {
    /// The board directory (holds the module's own data files).
    ///
    /// Required only when a `Wg16` machine actually boots -- that is,
    /// whenever `--module` is non-empty, or both `--module` and `--module32`
    /// are empty (the default-module fallback, see `--module`'s own doc
    /// comment). A `--module32`-only board, with no `Wg16` machine at all,
    /// need not give this. [`plan`] is what checks this, not clap: whether
    /// `--root` is required depends on what *else* was given, which clap's
    /// own `required`/`requires` cannot express.
    #[arg(long)]
    root: Option<PathBuf>,

    /// The module(s) to load onto a `Wg16` machine. Repeatable: give it more
    /// than once to boot more than one module, in dependency order --
    /// `mbbs_server::host::Boot`'s own doc, "Booting N modules", is the full
    /// contract. The first one given is the one every connecting channel
    /// enters (`Host::connect`'s `first_module()`); anything after it is an
    /// addon, loaded and initialised so its own exports are reachable and its
    /// own imports can resolve against the module before it, but never
    /// dispatched a channel directly.
    ///
    /// Left empty, [`plan`] decides what happens from `--module32`: given,
    /// this board boots `Wg32` *only* -- no `Wg16` machine exists at all, so
    /// there is nothing for `--module`'s default to name. Absent too, `plan`
    /// falls back to `DEFAULT_MODULE`, exactly this binary's original
    /// single-module behaviour -- deliberate backward compatibility, so
    /// `mbbs-server --root tmp` keeps booting MajorMUD unchanged.
    #[arg(long)]
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

    /// Fixed channel count, must be at least 1
    #[arg(long, default_value_t = DEFAULT_TERMS, value_parser = parse_terms)]
    terms: u16,

    /// Poll firings granted per elapsed second
    #[arg(long, default_value_t = DEFAULT_POLLS_PER_SECOND)]
    polls_per_second: usize,

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

    /// A second, 32-bit machine to boot -- alongside a primary `Wg16` one
    /// when `--module` is also given (or falls back to its default), or
    /// *alone*, with no `Wg16` machine at all, when `--module` is empty
    /// (LunatiX, design doc §4a). When two machines boot, a connect-time
    /// selector appears -- see `mbbs_server::conn`'s module doc, "The
    /// connect-time selector" -- naming this machine `LunatiX` and the other
    /// `MajorMUD`. When absent entirely, this binary behaves exactly as it
    /// did before this flag existed: no prompt, one `Wg16` machine.
    ///
    /// Requires `--root32`, since this machine's own data files must not
    /// share a directory with the primary machine's -- but that is [`plan`]'s
    /// check, not clap's: giving `--module32` without `--root32` is a named,
    /// explicit `Err` from `plan`, not a `requires`-attribute parse failure,
    /// so the decision stays in the one place all of it is testable.
    ///
    /// Repeatable in the same shape `--module` is, for CLI uniformity --
    /// `mbbs::Host<Wg32>` has no architectural objection to more than one
    /// registered module. **`main` refuses more than one value here today**,
    /// with a named error, rather than accepting it and silently corrupting
    /// the machine: `Wg32::load` reaches
    /// [`mbbs_machine::m32::Memory::replace_image`], which -- true to its
    /// name -- replaces the *whole* placeholder image wholesale on every
    /// call, so a second `host.load` for a second `Wg32` module would discard
    /// the first module's own loaded image, not add to it. No second Wg32
    /// module (LunatiX has no known addon) exists to prove multi-module Wg32
    /// boot against, and extending `Memory::replace_image` to append rather
    /// than replace is `mbbs-machine`'s call to make, not this binary's.
    #[arg(long, value_name = "PATH")]
    module32: Vec<PathBuf>,

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

    /// A directory of `*.lua` scripts (`mbbs-lua`'s `LuaExtension`) to load
    /// above the module at startup, for QoL commands the module itself
    /// never had -- `mbbs-lua`'s own crate doc has the full seam.
    ///
    /// Loads on whichever machine(s) this board boots -- `Wg16`, `Wg32`, or
    /// both, each getting its own `LuaExtension` instance. **Caution:** the
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

/// `--module32` given more than once is refused, not silently truncated to
/// its first value or accepted and left to corrupt the machine at boot --
/// see `--module32`'s own doc comment for why the underlying loader cannot
/// honour a second one. `Ok(())` for zero or one value.
///
/// A free function for the same reason [`listeners`] is: `main` is
/// unreachable from a test, so the one thing worth unit-testing about this
/// check -- that it names the count and fires only past one -- lives here
/// instead.
fn check_module32_count(cli: &Cli) -> Result<(), String> {
    if cli.module32.len() > 1 {
        return Err(format!(
            "--module32 was given {} times, but the Wg32 loader can only host one module today \
             (Memory::replace_image replaces the whole image on every load, so a second one \
             would silently discard the first) -- see --module32's own doc comment",
            cli.module32.len()
        ));
    }
    Ok(())
}

/// A `Wg16` machine's own boot parameters, as decided by [`plan`].
#[derive(Debug, PartialEq, Eq)]
struct Wg16Plan {
    /// Always `MachineId(0)` -- see [`Plan`]'s own doc comment on why this is
    /// fixed rather than computed from which machines happen to be present.
    machine: MachineId,
    modules: Vec<PathBuf>,
    root: PathBuf,
}

/// A `Wg32` machine's own boot parameters, as decided by [`plan`].
#[derive(Debug, PartialEq, Eq)]
struct Wg32Plan {
    /// Always `MachineId(1)`, even when no `Wg16` machine boots alongside it
    /// -- see [`Plan`]'s own doc comment.
    machine: MachineId,
    module: PathBuf,
    root: PathBuf,
}

/// Which machines a given command line asks for -- the pure decision `main`
/// turns into `Boot<Wg16>`/`Boot<Wg32>` values and spawns from. Building this
/// never touches a filesystem or spawns a thread; that is deliberate, so the
/// boot decision itself is unit-testable, which is how the bug this replaced
/// (`--module32` without `--root32` silently booting a `Wg16`-only board, no
/// warning) went unnoticed: the decision used to live inline in `main`,
/// which no test can reach.
///
/// Each present machine carries its own fixed `MachineId` (`Wg16Plan`'s and
/// `Wg32Plan`'s own doc comments) -- `MachineId(1)` for `Wg32` even when
/// `wg16` is `None`, never renumbered down to close the gap.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    wg16: Option<Wg16Plan>,
    wg32: Option<Wg32Plan>,
}

/// Decide which machines a command line boots, and with what. Three rules
/// for which machines boot, plus one flag-compatibility check:
///
/// 1. `--module` given (one or more) -- boot `Wg16` with those. Requires
///    `--root`.
/// 2. `--module` empty **and** `--module32` given -- no `Wg16` machine at
///    all. `Wg32` only.
/// 3. Both empty -- boot `Wg16` with [`DEFAULT_MODULE`], exactly as this
///    binary has always done. Requires `--root`. This is deliberate backward
///    compatibility: `mbbs-server --root tmp` must keep booting MajorMUD
///    unchanged, so the default cannot simply be removed.
///
/// `--scripts` has no rule of its own here: it reaches whichever machine(s)
/// end up booting (see its own doc comment), so a `--module32`-only board
/// with `--scripts` plans exactly as cleanly as any other -- there used to be
/// a fourth rule refusing that combination, back when `--scripts` could only
/// ever reach a `Wg16` machine; it no longer applies now that `LuaExtension`
/// implements `Extension<A>` for any ABI.
///
/// Every rejection is a plain, named `Err(String)` -- never a panic, and
/// never a silent no-op the way the `if let (Some(a), Some(b))` pattern this
/// replaced was: `--module32` without `--root32` used to fall through that
/// `if let` and boot a `Wg16`-only board with no message at all, despite
/// `--root32`'s own doc comment calling itself required.
///
/// `MachineId(0)` for `Wg16` and `MachineId(1)` for `Wg32` are assigned here,
/// fixed, never computed from presence: `pool.rs`'s module doc explains that
/// a `Chan`'s id tag is what keeps two boards' channel zeros distinguishable
/// process-wide, so a `Wg32`-only board must keep `MachineId(1)` rather than
/// being renumbered down to `0` just because no `Wg16` machine sits at that
/// slot this time.
fn plan(cli: &Cli) -> Result<Plan, String> {
    check_module32_count(cli)?;

    let wg32 = match (cli.module32.first().cloned(), cli.root32.clone()) {
        (Some(module), Some(root)) => Some(Wg32Plan { machine: MachineId(1), module, root }),
        (Some(_), None) => {
            return Err(
                "--module32 was given but --root32 was not -- a Wg32 machine's own board \
                 directory must never share a directory with another machine's (see \
                 --root32's own doc comment)"
                    .to_string(),
            );
        }
        (None, _) => None,
    };

    let modules = if !cli.module.is_empty() {
        Some(cli.module.clone())
    } else if wg32.is_none() {
        // Rule 3: both empty, fall back to the default -- but only when no
        // Wg32 machine is picking up the board instead (rule 2).
        Some(vec![PathBuf::from(DEFAULT_MODULE)])
    } else {
        None
    };

    let wg16 = match modules {
        Some(modules) => {
            let root = cli.root.clone().ok_or_else(|| {
                "--root is required to boot a Wg16 machine (give --module32 alone, with no \
                 --module, to boot a Wg32-only board instead)"
                    .to_string()
            })?;
            Some(Wg16Plan { machine: MachineId(0), modules, root })
        }
        None => None,
    };

    if wg16.is_none() && wg32.is_none() {
        // Defensive: rule 3's fallback should make this unreachable, since
        // it only yields `None` when `wg32` is `Some`.
        return Err("no machines to boot".to_string());
    }

    Ok(Plan { wg16, wg32 })
}

/// Build [`Boot::build`]'s closure for a `Wg32` machine: read `module_path`'s
/// bytes, parse them as a PE, and build a placeholder [`Wg32Cpu`] -- a
/// [`mbbs_machine::m32::Machine`] plus a [`mbbs_machine::m32::Memory`]
/// wrapping this same file's own [`mbbs_machine::m32::Image`], exactly the
/// shape `crates/mbbs/tests/wg32_round_trip.rs`'s `machine_and_placeholder`
/// builds from a synthetic fixture -- this one is real. `host::life` (in
/// `mbbs-server/src/host.rs`) reads `boot.modules[0]` (the same path, and
/// today the *only* path -- see `--module32`'s own doc comment on why this
/// binary refuses more than one) again immediately after this runs and calls
/// `host.load`, whose `Wg32::load`
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

/// Build [`Boot::extension`]'s closure for `--scripts`: load `dir` as an
/// `mbbs_lua::LuaExtension`, boxed as the ABI-erased `Extension<A>` the field
/// expects. Generic over `A: Abi` -- `mbbs_lua::LuaExtension` implements
/// `Extension<A>` for any ABI (its struct carries nothing ABI-specific; see
/// its own crate doc), so this builder can hand one to a `Wg16` machine, a
/// `Wg32` machine, or both, each getting its own freshly-loaded `LuaExtension`
/// -- see the call sites in `main` below and their own comments on why a
/// dual-machine board never shares one VM between machines.
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

    // `plan` is the one place that decides which machines this command line
    // boots -- see its own doc comment for the three rules. Everything past
    // this point just builds from the result; the decision itself never
    // spawns a thread or touches a filesystem, which is what makes it
    // testable at all.
    let plan = match plan(&cli) {
        Ok(plan) => plan,
        Err(msg) => {
            eprintln!("mbbs-server: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // `conn::spawn_machine` is generic over `A: Abi` since Task 20 of
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
    // module doc. The ids stay fixed per ABI even when `Wg16` is absent --
    // `MachineId(1)` for a `Wg32`-only board, never renumbered down to `0` --
    // so a board's channels stay distinguishable in logs and artifacts
    // regardless of which machines happen to be present.
    let mut machines = Vec::new();

    if let Some(wg16) = plan.wg16 {
        let boot: Boot<Wg16> = Boot {
            machine: wg16.machine,
            build: Box::new(mbbs_machine::m16::Machine::new),
            root: wg16.root,
            modules: wg16.modules,
            terms,
            bturno: cli.bturno.clone(),
            polls_per_second: cli.polls_per_second,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
            extension: cli.scripts.clone().map(build_lua_extension),
        };
        machines.push(Machine {
            id: wg16.machine,
            label: WG16_LABEL.to_string(),
            tx: conn::spawn_machine(boot),
        });
    }

    if let Some(wg32) = plan.wg32 {
        let boot32: Boot<Wg32> = Boot {
            machine: wg32.machine,
            build: Box::new(build_wg32_cpu(wg32.module.clone())),
            root: wg32.root,
            modules: vec![wg32.module],
            terms,
            bturno: cli.bturno32.clone().or_else(|| cli.bturno.clone()),
            polls_per_second: cli.polls_per_second,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: cli.survey_unimplemented_and_corrupt_the_session.clone(),
            // Its own `LuaExtension`, built by its own closure call -- see
            // `build_lua_extension`'s own doc comment on why a dual-machine
            // board never shares one Lua VM between machines. What the
            // shipped scripts (`summon`/`cash`/`setexp`) actually do against
            // a `Wg32` module is unverified -- see `--scripts`'s own doc
            // comment.
            extension: cli.scripts.clone().map(build_lua_extension),
        };
        machines.push(Machine {
            id: wg32.machine,
            label: WG32_LABEL.to_string(),
            tx: conn::spawn_machine(boot32),
        });
    }

    // Cloned before `serve_on` takes ownership: these are how the signal
    // handler below reaches each host thread, and `Sender<In>` is the only
    // way in -- the `Machine` itself is gone once the listeners have it.
    let shutdown: Vec<(String, std::sync::mpsc::Sender<In>)> = machines
        .iter()
        .map(|m| (m.label.clone(), m.tx.clone()))
        .collect();

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

    // The accept loop and the host threads are all spawned already; this
    // task's only remaining job is to keep the process alive for them, and to
    // shut them down in an orderly way when told to.
    let signal = wait_for_signal().await;
    eprintln!("mbbs-server: {signal} -- shutting the modules down");
    shut_down_machines(&shutdown, SHUTDOWN_GRACE).await;
    ExitCode::SUCCESS
}

/// How long every module gets, in total, to finish shutting down.
///
/// A module's `finrou` is real work, not a formality: MajorMUD's writes every
/// dirty buffer back through Btrieve, and on this host that goes through a
/// reindex whose cost grows with the file (`BUGS.md`). Thirty seconds is
/// generous for that and still short enough that a wedged module cannot hold
/// a terminal open indefinitely -- and the alternative to a bound is not a
/// slower exit, it is an exit that never happens.
///
/// The budget is for the whole sweep rather than per machine, because what an
/// operator is waiting on is the process, not any one of its threads.
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

/// Ask every machine to shut down and wait for all of them, up to `grace`.
///
/// The requests all go out before any of them is waited on, so the machines
/// finalise concurrently and the budget is the slowest one rather than the
/// sum. A machine whose thread has already died fails to `send` or drops its
/// half of the channel; both read as "nothing more to wait for", which is
/// correct -- there is no module left to finalise either way.
async fn shut_down_machines(machines: &[(String, std::sync::mpsc::Sender<In>)], grace: Duration) {
    let mut waiting = Vec::new();
    for (label, tx) in machines {
        let (done, wait) = tokio::sync::oneshot::channel();
        if tx.send(In::Shutdown { done }).is_ok() {
            waiting.push((label.clone(), wait));
        }
    }

    let deadline = tokio::time::Instant::now() + grace;
    for (label, wait) in waiting {
        match tokio::time::timeout_at(deadline, wait).await {
            Ok(_) => eprintln!("mbbs-server: {label} shut down"),
            Err(_) => {
                eprintln!(
                    "mbbs-server: {label} did not finish shutting down within {grace:?} -- \
                     exiting anyway; its module may leave a recovery marker behind"
                );
                // No point waiting on the rest: they shared one deadline and
                // it has passed.
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use mbbs::abi::Wg32;

    use super::{
        Cli, DEFAULT_MODULE, DEFAULT_POLLS_PER_SECOND, MachineId,
        build_lua_extension, check_module32_count, listeners, plan,
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

    /// `--root` alone parses cleanly and everything else takes its documented
    /// default; `--module` no longer carries a clap-level default (that
    /// fallback moved into `plan`, see `no_module_flags_falls_back_to_the_default_module`
    /// below), so it parses as empty here.
    #[test]
    fn defaults_are_applied_when_only_root_is_given() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert_eq!(cli.root, Some(std::path::PathBuf::from("tmp")));
        assert!(cli.module.is_empty(), "--module's default now lives in plan(), not clap");
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

    /// `--root` is no longer a clap-level required flag -- parsing succeeds
    /// with it absent, since whether it is actually needed depends on
    /// whether a `Wg16` machine ends up booting at all, which only `plan`
    /// knows.
    #[test]
    fn root_is_optional_at_the_parse_layer() {
        let cli = Cli::try_parse_from(args(&["--terms", "2"])).expect("parses");
        assert_eq!(cli.root, None);
    }

    /// `--module32` without `--root32` still parses cleanly at the clap
    /// layer -- the `requires` attribute was removed in favour of `plan`'s
    /// own check, below, which is what `main` actually consults, and which
    /// is where a mutation to this rule would need to be caught.
    #[test]
    fn module32_without_root32_parses_but_plan_refuses_it() {
        let cli =
            Cli::try_parse_from(args(&["--root", "tmp", "--module32", "LUNATIX.EXE"]))
                .expect("parses; --root32's absence is plan's problem, not clap's");
        let err = plan(&cli).expect_err("plan must refuse --module32 without --root32");
        assert!(
            err.contains("--root32"),
            "error should name the flag that is missing: {err}"
        );
    }

    /// `--scripts` together with a `--module32`-only command line (no
    /// `--module`, so no `Wg16` machine boots at all) now plans cleanly:
    /// `LuaExtension` implements `Extension<A>` for any ABI, so `--scripts`
    /// reaches a `Wg32`-only board exactly as it reaches a `Wg16` one. This
    /// used to be a refusal (`--scripts` was `Wg16`-only); that guard was
    /// removed once the Lua seam stopped being pinned to one ABI.
    #[test]
    fn scripts_without_wg16_plans_cleanly_on_a_wg32_only_board() {
        let cli = Cli::try_parse_from(args(&[
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
            "--scripts",
            "scripts",
        ]))
        .expect("parses");
        let plan = plan(&cli).expect("--scripts with a Wg32-only board is now a valid plan");
        assert!(plan.wg16.is_none(), "no --module and no default fallback: no Wg16 machine");
        assert!(plan.wg32.is_some(), "--module32 + --root32 were given");
    }

    /// `build_lua_extension` is what `main` actually maps `--scripts` through
    /// for a `Wg32` machine's own `Boot::extension` field -- `plan` alone
    /// (the test above) only proves a `--module32`-only board is accepted,
    /// not that it would actually carry a working extension. This proves the
    /// generic builder produces a real `LuaExtension`, boxed as
    /// `Extension<Wg32>`, from the same shipped `scripts/` directory
    /// `mbbs-lua`'s own tests load against `Wg16`.
    #[test]
    fn build_lua_extension_produces_a_wg32_extension_from_the_shipped_scripts() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
        let builder = build_lua_extension::<Wg32>(dir);
        // No modules given: none of the shipped scripts bind a bare
        // namespace today, so an empty list still loads cleanly -- this
        // test's own job is proving the generic builder itself produces a
        // real `Extension<Wg32>`, not exercising namespace resolution.
        builder(&[]).expect("the shipped scripts/ directory loads against Wg32 just as it does against Wg16");
    }

    /// `--scripts` together with a `Wg16` machine (the default, plain
    /// `--root` case) parses and plans cleanly.
    #[test]
    fn scripts_with_wg16_present_plans_cleanly() {
        let cli =
            Cli::try_parse_from(args(&["--root", "tmp", "--scripts", "scripts"])).expect("parses");
        let plan = plan(&cli).expect("--scripts with a Wg16 machine present is a valid plan");
        assert!(plan.wg16.is_some(), "the default rule still boots a Wg16 machine");
    }

    /// `--module32` together with `--root32` parses cleanly, and without
    /// either flag both are simply absent -- a board with no second module
    /// need not mention either one.
    #[test]
    fn module32_and_root32_parse_together_and_default_to_absent() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert!(cli.module32.is_empty());
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
        assert_eq!(cli.module32, vec![std::path::PathBuf::from("LUNATIX.EXE")]);
        assert_eq!(cli.root32, Some(std::path::PathBuf::from("tmp32")));
    }

    /// Rule 2: `--module32`/`--root32` given, `--module` empty -- `plan`
    /// boots `Wg32` only. No `Wg16` machine at all, and no `--root` needed
    /// for one that never boots.
    #[test]
    fn module32_alone_boots_wg32_only() {
        let cli = Cli::try_parse_from(args(&[
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
        ]))
        .expect("parses; --root is not required when no Wg16 machine boots");
        let plan = plan(&cli).expect("a Wg32-only board is a valid plan");

        assert!(plan.wg16.is_none(), "no --module and no default fallback: no Wg16 machine");
        let wg32 = plan.wg32.expect("--module32 + --root32 were given");
        assert_eq!(wg32.machine, MachineId(1));
        assert_eq!(wg32.module, std::path::PathBuf::from("LUNATIX.EXE"));
        assert_eq!(wg32.root, std::path::PathBuf::from("tmp32"));
    }

    /// Rule 3: no module flags at all -- `plan` falls back to
    /// `DEFAULT_MODULE`, the same single-module behaviour this binary has
    /// always had. This is the backward-compatibility case: `mbbs-server
    /// --root tmp` must keep booting MajorMUD unchanged.
    #[test]
    fn no_module_flags_falls_back_to_the_default_module() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        let plan = plan(&cli).expect("the default module fills in when both are empty");

        let wg16 = plan.wg16.expect("the default-module fallback boots a Wg16 machine");
        assert_eq!(wg16.machine, MachineId(0));
        assert_eq!(wg16.modules, vec![std::path::PathBuf::from(DEFAULT_MODULE)]);
        assert_eq!(wg16.root, std::path::PathBuf::from("tmp"));
        assert!(plan.wg32.is_none(), "no --module32 was given");
    }

    /// Rule 1: `--module` given -- `plan` boots `Wg16` with exactly those
    /// modules, and no `Wg32` machine, since `--module32` was not given.
    #[test]
    fn explicit_module_boots_wg16_with_no_wg32() {
        let cli = Cli::try_parse_from(args(&["--module", "A", "--root", "R"])).expect("parses");
        let plan = plan(&cli).expect("an explicit module with --root is a valid plan");

        let wg16 = plan.wg16.expect("--module was given");
        assert_eq!(wg16.machine, MachineId(0));
        assert_eq!(wg16.modules, vec![std::path::PathBuf::from("A")]);
        assert_eq!(wg16.root, std::path::PathBuf::from("R"));
        assert!(plan.wg32.is_none(), "no --module32 was given");
    }

    /// `--module32` without `--root32` is a named `Err` from `plan`, not a
    /// silent skip -- the bug the old `if let (Some(a), Some(b))` pattern in
    /// `main` had, where a Wg32 machine that could not be built simply
    /// vanished with no message.
    #[test]
    fn module32_without_root32_is_a_named_plan_error() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp", "--module32", "LUNATIX.EXE"]))
            .expect("parses at the clap layer; plan is what refuses it");
        let err = plan(&cli).expect_err("--module32 without --root32 must be refused");
        assert!(err.contains("--root32"), "error should name the missing flag: {err}");
    }

    /// `plan` defers to `check_module32_count` rather than duplicating its
    /// own count check -- two `--module32` values must still be refused when
    /// reached through `plan`, not just when `check_module32_count` is
    /// called directly.
    #[test]
    fn plan_refuses_more_than_one_module32_via_check_module32_count() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
            "--module32",
            "SECOND.DLL",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        let err = plan(&cli).expect_err("two --module32 values must be refused");
        assert!(err.contains("--module32"), "error should name the flag: {err}");
    }

    /// A `Wg16` machine that would boot (the default-module fallback, here)
    /// with `--root` absent is a named `Err` from `plan`, not a panic and not
    /// a boot with an empty root path.
    #[test]
    fn wg16_boot_without_root_is_a_named_plan_error() {
        let cli = Cli::try_parse_from(args(&[])).expect("parses; --root is optional at the clap layer");
        let err = plan(&cli).expect_err("the default module wants to boot Wg16, which needs --root");
        assert!(err.contains("--root"), "error should name the missing flag: {err}");
    }

    /// `MachineId`s stay fixed per ABI: `Wg32` is always `MachineId(1)`, even
    /// on a board with no `Wg16` machine at all -- `pool.rs`'s module doc
    /// explains why renumbering by presence would make a `Wg32`-only board's
    /// channels indistinguishable, in logs and artifacts, from a paired
    /// board's `Wg16` channels.
    #[test]
    fn machine_ids_stay_fixed_per_abi_even_when_wg16_is_absent() {
        let paired = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module",
            "A",
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        let paired_plan = plan(&paired).expect("both an explicit module and --module32 is valid");
        assert_eq!(paired_plan.wg16.expect("--module was given").machine, MachineId(0));
        assert_eq!(paired_plan.wg32.expect("--module32 was given").machine, MachineId(1));

        let wg32_only = Cli::try_parse_from(args(&[
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        let wg32_only_plan = plan(&wg32_only).expect("a Wg32-only board is a valid plan");
        assert!(wg32_only_plan.wg16.is_none());
        assert_eq!(
            wg32_only_plan.wg32.expect("--module32 was given").machine,
            MachineId(1),
            "Wg32 keeps MachineId(1) even with no Wg16 machine to share the id space with"
        );
    }

    /// `--module` is repeatable, and in the order given -- load order is the
    /// whole channel-entry contract (`mbbs_server::host::Boot::modules`'s own
    /// doc), so the parse must preserve it rather than merely collecting the
    /// values.
    #[test]
    fn module_is_repeatable_and_keeps_order() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module",
            "re/WCCMMUD.DLL",
            "--module",
            "WCCMMPLS.DLL",
        ]))
        .expect("parses");
        assert_eq!(
            cli.module,
            vec![
                std::path::PathBuf::from("re/WCCMMUD.DLL"),
                std::path::PathBuf::from("WCCMMPLS.DLL"),
            ]
        );
    }

    /// `--module32` is repeatable too, in the same shape as `--module` --
    /// this is what `check_module32_count`'s own tests, below, have
    /// something to refuse.
    #[test]
    fn module32_is_repeatable_at_the_parse_layer() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
            "--module32",
            "SECOND.DLL",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        assert_eq!(
            cli.module32,
            vec![std::path::PathBuf::from("LUNATIX.EXE"), std::path::PathBuf::from("SECOND.DLL")]
        );
    }

    /// Zero or one `--module32` value is fine -- `check_module32_count` must
    /// not fire on the ordinary cases.
    #[test]
    fn check_module32_count_accepts_zero_or_one() {
        let none = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert_eq!(check_module32_count(&none), Ok(()));

        let one = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        assert_eq!(check_module32_count(&one), Ok(()));
    }

    /// Two or more `--module32` values are refused, with the count in the
    /// message -- `Wg32::load`'s `replace_image` would otherwise silently
    /// discard every module but the last.
    #[test]
    fn check_module32_count_refuses_more_than_one() {
        let cli = Cli::try_parse_from(args(&[
            "--root",
            "tmp",
            "--module32",
            "LUNATIX.EXE",
            "--module32",
            "SECOND.DLL",
            "--root32",
            "tmp32",
        ]))
        .expect("parses");
        let err = check_module32_count(&cli).expect_err("two values must be refused");
        assert!(err.contains("--module32"), "error should name the flag: {err}");
        assert!(err.contains('2'), "error should say how many were given: {err}");
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

    /// `--scripts` with nothing after it is refused with a named error, the
    /// same way `--terms` is above -- not silently left at `None`, and not
    /// merely reported as "unrecognised argument" (which would pass even if
    /// `--scripts` had never been wired up as a real flag at all).
    #[test]
    fn scripts_without_a_directory_is_an_error() {
        let err = Cli::try_parse_from(args(&["--root", "tmp", "--scripts"])).unwrap_err();
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
