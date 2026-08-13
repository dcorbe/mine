//! Parse every PE32 file named on stdin and report how the parser did.
//!
//! One path per line. For each, the file is read and handed to
//! [`PeImage::parse`], then dropped before the next line is read -- the corpus
//! this is meant to run against is real archive binaries, not fixtures, and
//! nothing here holds more than one file's bytes in memory at a time.
//!
//! Prints a running total and, at the end, a histogram of failure kinds with
//! one example path per kind -- enough to go find the actual bytes behind each
//! distinct way a real file defeated this parser, which is the point: a
//! failure here can be the file's fault or the parser's, and telling those
//! apart needs a path to look at, not just a count.
//!
//! Modelled on the sibling `mbbs16` corpus sweep described in
//! `docs/plans/2026-08-08-mbbs32-design.md` ("The corpus"): 1,541 NE files
//! there, parsed 1,537 and mapped 1,532, with the four failures worth reading
//! individually rather than dismissing as noise.
//!
//! ```text
//! python3 build_the_list.py | cargo run -q -p mbbs32 --release --example parse_sweep
//! ```

use std::collections::BTreeMap;
use std::io::BufRead;

use mbbs_machine::m32::PeImage;

/// The variant name of a [`mbbs_machine::m32::PeError`], e.g. `"UnmappedRva"`.
///
/// `PeError` has no `strum`-style discriminant name accessor, and hand-listing
/// its dozen-plus variants here would drift the moment a new one is added
/// (exactly the kind of second copy this parser's own doc comments warn
/// against). `{:?}` always starts with the variant's bare name, followed by
/// either nothing, a space and a `{ .. }` struct body, or a space and a
/// tuple body -- so the first whitespace-or-brace boundary is the name.
fn kind_of(debug: &str) -> &str {
    let end = debug.find([' ', '(', '{']).unwrap_or(debug.len());
    &debug[..end]
}

fn main() {
    let stdin = std::io::stdin();

    let mut total = 0usize;
    let mut parsed = 0usize;
    let mut io_errors: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut parse_failures: BTreeMap<String, (usize, String)> = BTreeMap::new();

    for line in stdin.lock().lines() {
        let path = line.expect("stdin is readable");
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        total += 1;

        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                let entry = io_errors
                    .entry(format!("{:?}", e.kind()))
                    .or_insert_with(|| (0, path.to_string()));
                entry.0 += 1;
                continue;
            }
        };

        match PeImage::parse(&bytes) {
            Ok(_) => parsed += 1,
            Err(e) => {
                let debug = format!("{e:?}");
                let kind = kind_of(&debug).to_string();
                let entry = parse_failures
                    .entry(kind)
                    .or_insert_with(|| (0, path.to_string()));
                entry.0 += 1;
            }
        }
    }

    let failed = total - parsed;
    println!("total: {total}   parsed: {parsed}   failed: {failed}");

    if !io_errors.is_empty() {
        println!("\nunreadable (not a parser failure, the file could not be opened):");
        for (kind, (count, example)) in &io_errors {
            println!("  {kind}: {count} (e.g. {example})");
        }
    }

    if !parse_failures.is_empty() {
        println!("\nparse failure kinds:");
        for (kind, (count, example)) in &parse_failures {
            println!("  {kind}: {count} (e.g. {example})");
        }
    }
}
