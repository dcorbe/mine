//! The `mbbs-server` binary: parse arguments, boot the host thread, listen.
//!
//! Argument parsing is hand-rolled against `std::env::args` rather than
//! pulling in a dependency for seven flags -- this workspace has none, and
//! the plan does not call for one. Every rejection (an unknown flag, a
//! missing required one, a number that does not parse) prints a clear
//! message to stderr and exits non-zero rather than falling back to a
//! default the operator did not ask for: silently defaulting a bad value
//! would be exactly the undefined-behaviour-shaped surprise this codebase
//! prefers a compile error or a clean refusal over. `--terms 0` gets the
//! same treatment even though it is not a parse failure -- `Terms::new`
//! panics on it, and a panic is a worse answer than a message and a
//! non-zero exit.

use std::path::PathBuf;
use std::process::ExitCode;

use mbbs::Terms;
use mbbs_server::conn::{self, default_keys};
use mbbs_server::host::Boot;

const DEFAULT_MODULE: &str = "re/WCCMMUD.DLL";
const DEFAULT_LISTEN: &str = "127.0.0.1:2323";
const DEFAULT_TERMS: u16 = 2;

/// Poll dispatches granted per driver wake -- `--polls-per-wake`'s default.
///
/// The module advances exactly one monster per poll dispatch
/// (`_SLOW_UPDATE_NEXT_MONSTER` and its fast/medium siblings, see
/// `docs/plans/2026-08-08-tokio-transport-design.md`), off a global cursor
/// every polling channel shares, gated on a pending-round counter that a
/// background `rtkick` arms and a fully-drained sweep clears. So the floor
/// for this number is "enough dispatches to sweep the live-monster table
/// once per wake"; short of that floor a round survives to the next wake
/// instead of draining -- `polls_cut` on `Ended::Waiting` is how a driver
/// finds out that happened.
///
/// This repository has not measured the table's real size against a live
/// board -- that is Task 13's job, watching `polls_cut` on real traffic and
/// raising this until it stops being set on every wake. 32 is a starting
/// hypothesis, not a tuned number: generous for the handful of live
/// monsters a `--terms 2` development board is likely to have nearby, and
/// cheap to overshoot -- once a round drains, the module's own pending-round
/// counter is zero and every further dispatch this wake falls through as one
/// branch, not a monster update. Undershooting is graceful (a round survives
/// to the next wake and monsters act slowly), so getting this starting value
/// wrong by a factor of a few costs smoothness, not correctness.
const DEFAULT_POLLS_PER_WAKE: usize = 32;

/// Passes made per `Host::cycle` call -- `--passes`'s default.
///
/// `Host::cycle`'s `max` bounds dispatch *attempts*, not dispatches
/// themselves: the call returns the instant its queue is empty, so `passes`
/// only matters as a ceiling against a queue that keeps refilling. That
/// queue is bounded per wake by `--polls-per-wake` re-arms of the polling
/// status, plus up to one already-queued-but-not-rearmed `POLSTS` per
/// channel once the budget runs out (`Host::dopoll`'s budget comment), plus
/// whatever `In` messages this wake drained (one status each). With the
/// defaults above, `DEFAULT_POLLS_PER_WAKE` (32) plus `DEFAULT_TERMS` (2) is
/// comfortably under 64, so 64 leaves slack for a burst of connects or input
/// on top of a full poll budget without ever being the thing that cuts a
/// wake short.
const DEFAULT_PASSES: usize = 64;

const USAGE: &str = "\
mbbs-server -- a tokio edge in front of one WCCMMUD.DLL host

USAGE:
    mbbs-server --root <dir> [OPTIONS]

REQUIRED:
    --root <dir>              The board directory (holds the module's own data files)

OPTIONS:
    --module <path>           The module to load [default: re/WCCMMUD.DLL]
    --listen <addr>           Address to bind [default: 127.0.0.1:2323]
    --terms <n>                Fixed channel count, must be at least 1 [default: 2]
    --polls-per-wake <n>       Poll dispatches granted per driver wake [default: 32]
    --passes <n>                Passes made per Host::cycle call [default: 64]
    --keys <comma,separated>   Connection keys handed to a new player [default: DEMO,NORMAL,USER]
    --help                     Print this message and exit
";

/// A parsed command line, before `--terms` becomes a `Terms` (which can
/// panic on a bad value, so that conversion happens under our own check, not
/// inside the library).
#[derive(Debug)]
struct Config {
    root: PathBuf,
    module: PathBuf,
    listen: String,
    terms: Terms,
    polls_per_wake: usize,
    passes: usize,
    keys: Vec<String>,
}

/// What parsing the command line produced.
#[derive(Debug)]
enum ParseResult {
    /// `--help` was given. Print [`USAGE`] and stop; nothing else parsed
    /// matters once this is seen.
    Help,
    Config(Config),
}

/// Parse `argv[1..]`. Every failure is a `String` meant for a human, printed
/// to stderr by the caller.
fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<ParseResult, String> {
    let mut root: Option<PathBuf> = None;
    let mut module = PathBuf::from(DEFAULT_MODULE);
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut terms_count: u16 = DEFAULT_TERMS;
    let mut polls_per_wake = DEFAULT_POLLS_PER_WAKE;
    let mut passes = DEFAULT_PASSES;
    let mut keys = default_keys();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" => return Ok(ParseResult::Help),
            "--root" => root = Some(PathBuf::from(next_value(&mut iter, "--root")?)),
            "--module" => module = PathBuf::from(next_value(&mut iter, "--module")?),
            "--listen" => listen = next_value(&mut iter, "--listen")?,
            "--terms" => {
                terms_count = parse_number(&next_value(&mut iter, "--terms")?, "--terms")?;
            }
            "--polls-per-wake" => {
                polls_per_wake =
                    parse_number(&next_value(&mut iter, "--polls-per-wake")?, "--polls-per-wake")?;
            }
            "--passes" => {
                passes = parse_number(&next_value(&mut iter, "--passes")?, "--passes")?;
            }
            "--keys" => keys = parse_keys(&next_value(&mut iter, "--keys")?)?,
            other => return Err(format!("unknown argument '{other}' (see --help)")),
        }
    }

    let root = root.ok_or_else(|| "--root is required (see --help)".to_string())?;

    // `Terms::new` panics on 0 or on a count above `i16::MAX` -- a compile
    // error would be better still, but a clean refusal here is the next best
    // thing, and strictly better than letting a bad flag reach a panic.
    if terms_count == 0 {
        return Err(
            "--terms must be at least 1 (a host with no channels cannot serve anyone)"
                .to_string(),
        );
    }
    if terms_count > i16::MAX as u16 {
        return Err(format!(
            "--terms: {terms_count} is too large; the module addresses a channel as a 16-bit \
             signed int, so the limit is {}",
            i16::MAX
        ));
    }
    let terms = Terms::new(terms_count);

    Ok(ParseResult::Config(Config {
        root,
        module,
        listen,
        terms,
        polls_per_wake,
        passes,
        keys,
    }))
}

/// The value that must follow a flag, or a clear error naming the flag that
/// was left dangling.
fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next().ok_or_else(|| format!("{flag} requires a value"))
}

/// Parse a flag's value as a number, or explain which flag and value failed.
fn parse_number<T>(value: &str, flag: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| format!("{flag}: '{value}' is not a valid number: {e}"))
}

/// Split `--keys`' value on commas. An empty segment (a stray comma, or an
/// empty flag value) is rejected rather than silently handing the new
/// connection a blank key -- see the module doc on not defaulting a value
/// the operator got wrong.
fn parse_keys(value: &str) -> Result<Vec<String>, String> {
    let keys: Vec<String> = value.split(',').map(str::to_string).collect();
    if keys.iter().any(String::is_empty) {
        return Err(format!(
            "--keys: '{value}' contains an empty key (check for a stray or trailing comma)"
        ));
    }
    Ok(keys)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = std::env::args().skip(1);
    let config = match parse_args(args) {
        Ok(ParseResult::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(ParseResult::Config(config)) => config,
        Err(e) => {
            eprintln!("mbbs-server: {e}");
            return ExitCode::FAILURE;
        }
    };

    let boot = Boot {
        root: config.root,
        module: config.module,
        terms: config.terms,
        polls_per_wake: config.polls_per_wake,
        passes: config.passes,
        clock_reads: None,
    };

    let addr = match conn::serve(boot, config.keys, &config.listen).await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("mbbs-server: failed to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("mbbs-server: listening on {addr}");

    // The accept loop and the host thread are both spawned already; this
    // task's only remaining job is to keep the process alive for them.
    std::future::pending::<()>().await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{ParseResult, parse_args};

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The only required flag is `--root`; everything else takes the
    /// documented default.
    #[test]
    fn defaults_are_applied_when_only_root_is_given() {
        match parse_args(args(&["--root", "tmp"])).expect("parses") {
            ParseResult::Help => panic!("no --help was given"),
            ParseResult::Config(c) => {
                assert_eq!(c.root, std::path::PathBuf::from("tmp"));
                assert_eq!(c.module, std::path::PathBuf::from("re/WCCMMUD.DLL"));
                assert_eq!(c.listen, "127.0.0.1:2323");
                assert_eq!(c.terms.count(), 2);
                assert_eq!(c.polls_per_wake, 32);
                assert_eq!(c.passes, 64);
                assert_eq!(c.keys, super::default_keys());
            }
        }
    }

    /// `--help` short-circuits, even with other flags present -- a caller
    /// asking for help should get it, not an error about a flag they were
    /// only passing out of habit.
    #[test]
    fn help_short_circuits() {
        assert!(matches!(
            parse_args(args(&["--help", "--terms", "not-a-number"])),
            Ok(ParseResult::Help)
        ));
    }

    /// No `--root` at all is a clear error, not a silent default.
    #[test]
    fn missing_root_is_an_error() {
        let err = parse_args(args(&["--terms", "2"])).unwrap_err();
        assert!(err.contains("--root"), "error should name the missing flag: {err}");
    }

    /// A flag this binary does not know about is refused, not ignored.
    #[test]
    fn unknown_argument_is_an_error() {
        let err = parse_args(args(&["--root", "tmp", "--bogus", "x"])).unwrap_err();
        assert!(err.contains("--bogus"), "error should name the bad flag: {err}");
    }

    /// A flag with nothing after it is refused, not silently left at its
    /// default.
    #[test]
    fn a_dangling_flag_is_an_error() {
        let err = parse_args(args(&["--root", "tmp", "--terms"])).unwrap_err();
        assert!(err.contains("--terms"), "error should name the flag missing its value: {err}");
    }

    /// `Terms::new(0)` panics; this must catch it first and report cleanly.
    #[test]
    fn terms_zero_is_rejected_before_it_reaches_terms_new() {
        let err = parse_args(args(&["--root", "tmp", "--terms", "0"])).unwrap_err();
        assert!(
            err.contains("--terms") && err.to_lowercase().contains("at least 1"),
            "error should explain why 0 is refused: {err}"
        );
    }

    /// A count the module cannot address as a 16-bit signed channel number
    /// is refused the same way `Terms::new` would panic on it.
    #[test]
    fn terms_above_i16_max_is_rejected() {
        let err = parse_args(args(&["--root", "tmp", "--terms", "40000"])).unwrap_err();
        assert!(err.contains("--terms"), "error should name the flag: {err}");
    }

    /// A value that does not parse as the expected number names both the
    /// flag and the bad value, not just "invalid input".
    #[test]
    fn an_unparseable_number_is_a_clear_error() {
        let err = parse_args(args(&["--root", "tmp", "--terms", "banana"])).unwrap_err();
        assert!(err.contains("--terms"), "error should name the flag: {err}");
        assert!(err.contains("banana"), "error should echo the bad value: {err}");
    }

    /// `--keys` splits on commas.
    #[test]
    fn keys_split_on_commas() {
        match parse_args(args(&["--root", "tmp", "--keys", "A,B,C"])).expect("parses") {
            ParseResult::Config(c) => assert_eq!(c.keys, vec!["A", "B", "C"]),
            ParseResult::Help => panic!("no --help was given"),
        }
    }

    /// A stray comma produces an empty key, which is refused rather than
    /// silently handed to a new connection.
    #[test]
    fn an_empty_key_segment_is_rejected() {
        let err = parse_args(args(&["--root", "tmp", "--keys", "A,,C"])).unwrap_err();
        assert!(err.contains("--keys"), "error should name the flag: {err}");
    }
}
