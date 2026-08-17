//! Compile a MajorBBS/Worldgroup `.MSG` file into the `.MCV` the host reads.
//!
//! Galacticomm shipped this as a separate step, not something the host does at
//! boot: the Worldgroup tool is `WGSMSX.EXE`, whose own window title calls it
//! "Message File Indexing" (`re/wg33src/VCPROJ/WGSMSX/wgsmsx.cpp`), and
//! `re/wg33src/infwl/putmsg.bat` runs it and *then* copies the `.MSG` into the
//! server directory. The DOS equivalent was `MSGCOMP`, which does not survive in
//! the recovered archive. Nothing in the recovered host source writes a `.MCV`
//! at all -- `MCVEND` appears only in the reader.
//!
//! Which is why this exists. A DOS utility run outside the host needs the
//! compiled form and cannot make it: `WCCMMUTL.EXE` refuses to start without
//! `WCCMMUD.MCV`, and the MajorMUD distro ships only `WCCMMUD.MSG`. See
//! `docs/2026-08-17-wccmmutl-incomplete-install.md`.
//!
//! ```text
//! msgcomp WCCMMUD.MSG                 # writes WCCMMUD.MCV beside it
//! msgcomp WCCMMUD.MSG -o out/FOO.MCV  # writes where you say
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mbbs::mcv;
use mbbs::msg::MsgFile;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "-o" | "--output" => match args.next() {
                Some(path) => output = Some(PathBuf::from(path)),
                None => {
                    eprintln!("msgcomp: -o needs a path");
                    return ExitCode::FAILURE;
                }
            },
            "-h" | "--help" => {
                println!("usage: msgcomp <FILE.MSG> [-o <FILE.MCV>]");
                return ExitCode::SUCCESS;
            }
            _ if input.is_none() => input = Some(PathBuf::from(arg)),
            other => {
                eprintln!("msgcomp: unexpected argument {other:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    let Some(input) = input else {
        eprintln!("usage: msgcomp <FILE.MSG> [-o <FILE.MCV>]");
        return ExitCode::FAILURE;
    };

    // `.MCV` beside the input by default, matching what the host expects to find
    // next to a module's own files.
    let output = output.unwrap_or_else(|| input.with_extension("MCV"));

    let bytes = match std::fs::read(&input) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("msgcomp: {}: {e}", input.display());
            return ExitCode::FAILURE;
        }
    };

    let name = Path::new(&input)
        .file_name()
        .map_or_else(|| String::from("<input>"), |n| n.to_string_lossy().into());

    let parsed = match MsgFile::parse(&name, &bytes) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("msgcomp: {}: {e:?}", input.display());
            return ExitCode::FAILURE;
        }
    };

    // A file with no `LANGUAGE` line is ordinary -- MajorMUD's three have none --
    // and every `.MCV` in the archive records `English/ANSI` regardless.
    let language = parsed.language().unwrap_or(mcv::DEFAULT_LANGUAGE);
    let compiled = mcv::compile(parsed.messages(), language);

    if let Err(e) = std::fs::write(&output, &compiled) {
        eprintln!("msgcomp: {}: {e}", output.display());
        return ExitCode::FAILURE;
    }

    println!(
        "{} -> {}: {} messages, {} bytes, language {}",
        input.display(),
        output.display(),
        parsed.len(),
        compiled.len(),
        String::from_utf8_lossy(language)
    );
    ExitCode::SUCCESS
}
