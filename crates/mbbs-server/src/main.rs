//! The `mbbs-server` binary: parse arguments, boot the host thread, listen.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mbbs::Terms;
use mbbs_server::conn::{self, default_keys};
use mbbs_server::host::Boot;

const DEFAULT_MODULE: &str = "re/WCCMMUD.DLL";
const DEFAULT_LISTEN: &str = "127.0.0.1:2323";
const DEFAULT_TERMS: u16 = 2;

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

    /// Address to bind
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: String,

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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let terms = Terms::new(cli.terms);
    let keys = if cli.keys.is_empty() { default_keys() } else { cli.keys };

    let boot = Boot {
        root: cli.root,
        module: cli.module,
        terms,
        polls_per_wake: cli.polls_per_wake,
        passes: cli.passes,
        clock_reads: None,
    };

    let addr = match conn::serve(boot, keys, &cli.listen).await {
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
    use clap::Parser;

    use super::{Cli, DEFAULT_PASSES, DEFAULT_POLLS_PER_WAKE};

    fn args<'a>(v: &[&'a str]) -> Vec<&'a str> {
        let mut a = vec!["mbbs-server"];
        a.extend_from_slice(v);
        a
    }

    /// The only required flag is `--root`; everything else takes the
    /// documented default.
    #[test]
    fn defaults_are_applied_when_only_root_is_given() {
        let cli = Cli::try_parse_from(args(&["--root", "tmp"])).expect("parses");
        assert_eq!(cli.root, std::path::PathBuf::from("tmp"));
        assert_eq!(cli.module, std::path::PathBuf::from("re/WCCMMUD.DLL"));
        assert_eq!(cli.listen, "127.0.0.1:2323");
        assert_eq!(cli.terms, 2);
        assert_eq!(cli.polls_per_wake, DEFAULT_POLLS_PER_WAKE);
        assert_eq!(cli.passes, DEFAULT_PASSES);
        assert!(cli.keys.is_empty(), "no --keys given, so main falls back to default_keys()");
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
