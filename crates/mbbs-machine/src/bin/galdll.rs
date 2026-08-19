//! Write a synthesised NE host-library image to a file: the durable
//! counterpart to [`mbbs_machine::m16::emit`], for a consumer that lives
//! outside this process and outside `runexe`'s in-memory `Files`.
//!
//! Usage: `galdll <library> [--board <dir>] [--family <name>] [--bturno <8 digits>] -o <path>`
//!
//! `<library>` is a canonical or aliased name from [`mbbs_machine::library`]
//! (`GALGSBL`, `MAJORBBS`, ...). `--bturno` defaults to `00000000`, exactly as
//! `runexe`'s own flag does -- a synthetic serial means the module reads as
//! unregistered, which is the honest outcome for an artifact nobody typed a
//! real key into.
//!
//! # Why this refuses where `runexe` does not
//!
//! The emitted export table is a **superset** of any demand: `wg101` and
//! `wg2` agree on all 16 ordinals `WCCMMUD.DLL` actually imports and still
//! differ at `@102` (`cdixfn`, `wg2` only -- see
//! `tests/galgsbl_layouts.rs`'s `layout_a_is_additive_and_moves_no_ordinal`).
//! `runexe`'s image is ephemeral and nothing parses its export table back, so
//! taking the anchor there costs nothing. A file written here outlives the
//! run, and another consumer may read exactly the ordinal the two candidates
//! disagree on -- so [`choose`] refuses instead of guessing whenever more
//! than one candidate remains and `--family` did not settle it.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mbbs_machine::library;
use mbbs_machine::m16::{self, NeImage, Symbol, Target};

/// Settle on one profile name among `candidates`.
///
/// - An explicit `family` wins only if it is among `candidates` -- an
///   override outside the candidate list is refused, not honoured, because
///   honouring it would write an image for a generation the evidence (or the
///   caller's own `--board`-less default) never named.
/// - With no `family` and exactly one candidate, that candidate is the
///   answer.
/// - With no `family` and several, this refuses and names them, because a
///   guess here would be baked into a file that outlives the run. See the
///   module doc comment for why that is a different call than `runexe`'s.
pub fn choose(candidates: &[&str], family: Option<&str>) -> Result<String, String> {
    if let Some(family) = family {
        return if candidates.contains(&family) {
            Ok(family.to_owned())
        } else {
            Err(format!(
                "--family {family} is not among the candidates this board supports: {}",
                candidates.join(", ")
            ))
        };
    }
    match candidates {
        [] => Err("no candidate generation at all -- this is a bug in the caller".to_owned()),
        [one] => Ok((*one).to_owned()),
        many => Err(format!(
            "ambiguous: {} all agree on every ordinal this board demands, so which one \
             wrote this file cannot be recovered from the file itself -- pass --family to \
             choose one",
            many.join(", ")
        )),
    }
}

/// Every ordinal a board's modules ask of any library, read from their own
/// `Target::Import` relocations.
///
/// Not a second NE import parser: [`NeImage::parse`], [`Target`] and
/// [`Symbol`] are already public on `mbbs_machine::m16` (Task 1's fence only
/// stops `library.rs` from naming `m16`, not a consumer outside it), so this
/// is the same handful of lines `crates/mbbs`'s own `imported_symbols` walks,
/// narrowed to the ordinal imports [`library::Demand`] can use. Files that do
/// not parse as NE (Btrieve data, `.MSG`, `.MCV`, ...) are silently skipped
/// rather than treated as an error: a board directory holds plenty of those,
/// and none of them can name an ordinal.
fn board_demand(board: &Path) -> Result<library::Demand, String> {
    let mut demand = library::Demand::new();
    let entries =
        fs::read_dir(board).map_err(|e| format!("reading --board {}: {e}", board.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading --board {}: {e}", board.display()))?;
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(image) = NeImage::parse(&bytes) else {
            continue;
        };
        for segment in &image.segments {
            for reloc in &segment.relocations {
                let Target::Import { module, symbol: Symbol::Ordinal(ordinal) } = &reloc.target
                else {
                    continue;
                };
                if let Ok(from) = image.module_name(*module) {
                    demand.add(from, *ordinal);
                }
            }
        }
    }
    Ok(demand)
}

/// The candidate generation names for this run: the anchor alone when there
/// is no board to read imports from (or the board named no NE module at
/// all), otherwise whatever [`library::detect`] admits against the board's
/// accumulated [`library::Demand`].
fn candidates_for(board: Option<&Path>) -> Result<Vec<&'static str>, String> {
    let Some(board) = board else {
        return Ok(vec![library::ANCHOR]);
    };
    let demand = board_demand(board)?;
    if demand.libraries().next().is_none() {
        // No NE module in the directory named anything: there is no demand
        // to detect from, which is the same state as not passing --board.
        return Ok(vec![library::ANCHOR]);
    }
    match library::detect(&demand) {
        library::Outcome::Unique(p) => Ok(vec![p.name]),
        library::Outcome::Unobservable { agreeing, .. } => Ok(agreeing),
        library::Outcome::Ambiguous { discriminating } => Err(format!(
            "the board's own modules disagree on {} ordinal(s) across generations \
             ({}) -- pass --family",
            discriminating.len(),
            discriminating
                .iter()
                .map(|d| format!("{}.{}", d.library, d.ordinal))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        library::Outcome::NoneAdmissible { excluded, unevidenced } => Err(format!(
            "no generation is admissible for this board's own demand \
             (excluded: {excluded:?}, unevidenced: {unevidenced:?})"
        )),
    }
}

/// Eight ASCII digits, exactly -- `GETRNO` reads exactly eight bytes after
/// the `ReG#` marker, so a short or long value would silently mean a
/// different serial than what was typed.
fn parse_bturno(s: &str) -> Result<&str, String> {
    if s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(s)
    } else {
        Err(format!("--bturno must be exactly eight digits, got {s:?}"))
    }
}

struct Cli {
    library: String,
    board: Option<PathBuf>,
    family: Option<String>,
    bturno: String,
    out: PathBuf,
}

fn usage() -> ! {
    eprintln!(
        "usage: galdll <library> [--board <dir>] [--family <name>] [--bturno <8 digits>] -o <path>"
    );
    std::process::exit(2);
}

fn parse_args(args: &[String]) -> Cli {
    let mut library = None;
    let mut board = None;
    let mut family = None;
    let mut bturno = "00000000".to_owned();
    let mut out = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--board" => {
                i += 1;
                board = Some(PathBuf::from(args.get(i).unwrap_or_else(|| usage())));
            }
            "--family" => {
                i += 1;
                family = Some(args.get(i).unwrap_or_else(|| usage()).clone());
            }
            "--bturno" => {
                i += 1;
                bturno = args.get(i).unwrap_or_else(|| usage()).clone();
            }
            "-o" => {
                i += 1;
                out = Some(PathBuf::from(args.get(i).unwrap_or_else(|| usage())));
            }
            other if library.is_none() && !other.starts_with('-') => {
                library = Some(other.to_owned());
            }
            other => {
                eprintln!("unrecognised argument: {other}");
                usage();
            }
        }
        i += 1;
    }

    Cli {
        library: library.unwrap_or_else(|| usage()),
        board,
        family,
        bturno,
        out: out.unwrap_or_else(|| usage()),
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let canonical = library::library(&cli.library)
        .ok_or_else(|| format!("no library named {:?} in the registry", cli.library))?
        .name;

    let bturno = parse_bturno(&cli.bturno)?;

    let candidates = candidates_for(cli.board.as_deref())?;
    let chosen = choose(&candidates, cli.family.as_deref())?;
    let profile = library::profile(&chosen)
        .unwrap_or_else(|| panic!("chosen profile {chosen} is not in library::PROFILES"));
    let table = profile
        .table(canonical)
        .ok_or_else(|| format!("profile {chosen} has no table for {canonical}"))?;

    let names: HashMap<u16, Box<str>> = table.names();
    let mut exports: Vec<(u16, String)> =
        names.into_iter().map(|(ordinal, name)| (ordinal, name.to_string())).collect();
    exports.sort_by_key(|&(ordinal, _)| ordinal);
    let export_refs: Vec<(u16, &str)> =
        exports.iter().map(|(ordinal, name)| (*ordinal, name.as_str())).collect();

    let payload = format!("ReG#{bturno}\0").into_bytes();
    let bytes = m16::emit(canonical, &export_refs, &payload);

    fs::write(&cli.out, &bytes).map_err(|e| format!("writing {}: {e}", cli.out.display()))?;
    eprintln!(
        "wrote {} bytes to {} -- {} exports, profile {chosen}",
        bytes.len(),
        cli.out.display(),
        export_refs.len()
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_args(&args);
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
