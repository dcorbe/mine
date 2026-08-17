//! The `.MSG` reader, against files the real host compiled.
//!
//! [`mbbs::msg`] reads `.MSG` directly and never writes a `.MCV`, because a
//! module cannot tell the difference: `opnmsg` returns a handle it only passes
//! back to `setmbk` and `clsmsg`. But that leaves the reader with nothing to be
//! wrong against -- and being wrong is quiet here, because `stgopt(N)` indexes
//! by position and a miscount shifts every message after it with no error
//! anywhere.
//!
//! Galacticomm's `MSGRDR.C` does not survive. What does survive is ten modules
//! that shipped **both** their `.MSG` and the `.MCV` the real host compiled from
//! it, and a `.MCV` holds every message in order. That is the ground truth, and
//! this is the test that uses it.
//!
//! The files are third-party module distributions under `archive/`, which is
//! gitignored precisely because none of it is ours to redistribute. So these
//! skip when it is absent, the same as `wccmmud.rs`.
//!
//! ```text
//! cargo test -p mbbs --test msgfile -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};

use mbbs::msg::MsgFile;

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

/// A compiled `.MCV`, decoded far enough to read its messages back.
///
/// `struct msgblk` in `MSGUTL.H` names the trailing sixteen bytes and says they
/// are "always last": `lnglist`, `lenlist` and `loclist` as `long`s, then
/// `lngcnt` and `msgcnt` as `int`s. `loclist` points at an array of `msgcnt`
/// file offsets, each naming a NUL-terminated message.
///
/// **Test-only, and deliberately.** The host implements no `.MCV` support --
/// see `mbbs::msg` for why one format beats two -- and this exists to check the
/// one that ships, not to become a second reader with its own bugs.
struct McvFile {
    messages: Vec<Vec<u8>>,
}

impl McvFile {
    fn parse(bytes: &[u8]) -> Self {
        let trailer = &bytes[bytes.len() - 16..];
        let word = |at: usize| i32::from_le_bytes(trailer[at..at + 4].try_into().unwrap());
        let short = |at: usize| i16::from_le_bytes(trailer[at..at + 2].try_into().unwrap());

        let loclist = word(8) as usize;
        let msgcnt = short(14) as usize;

        let messages = (0..msgcnt)
            .map(|n| {
                let at = loclist + n * 4;
                let offset =
                    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
                let end = bytes[offset..]
                    .iter()
                    .position(|b| *b == 0)
                    .expect("a message is NUL-terminated");
                bytes[offset..offset + end].to_vec()
            })
            .collect();

        Self { messages }
    }
}

/// Every recovered module that shipped a `.MSG` and the `.MCV` built from it.
///
/// Paths rather than a directory walk: which files are the evidence is part of
/// the test, and a walk that quietly found none would pass.
const PAIRS: &[&str] = &[
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Infinetwork Brawl v2.0a/COPY/INFGFMSG",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     BSW Anonymous Teleconference v1.0/COPY/BSWANON",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Gateway Major Monitor v1.0/COPY/FE_MM",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARN-C",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARN-D",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARN-M",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARN-T",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARNDD",
    "archive/modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
     Tele-arena 5.6c & 5.6d GOLD/56DGOLD/TSGARNDT",
];

/// Every message our reader produces equals the one the real host compiled.
///
/// Text and not merely count. A count agreeing while the text does not is the
/// exact shape of an off-by-one that has cancelled out somewhere, and it is
/// what this test is for.
#[test]
#[ignore = "needs the module archive"]
fn the_reader_agrees_with_the_host_that_compiled_these() {
    let mut checked = 0usize;
    let mut messages = 0usize;

    for stem in PAIRS {
        let (Ok(msg), Ok(mcv)) = (
            std::fs::read(repo(&format!("{stem}.MSG"))),
            std::fs::read(repo(&format!("{stem}.MCV"))),
        ) else {
            continue;
        };

        let name = Path::new(stem).file_name().unwrap().to_string_lossy();
        let ours = MsgFile::parse(&name, &msg).expect("the archive's files parse");
        let theirs = McvFile::parse(&mcv);

        assert_eq!(
            ours.len(),
            theirs.messages.len(),
            "{name}: {} messages read, {} compiled",
            ours.len(),
            theirs.messages.len()
        );

        for (n, (a, b)) in ours.messages().iter().zip(&theirs.messages).enumerate() {
            assert_eq!(
                a,
                b,
                "{name} message {n}:\n  read     {:?}\n  compiled {:?}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            );
        }

        eprintln!("{name}: {} messages, all identical", ours.len());
        checked += 1;
        messages += ours.len();
    }

    if checked == 0 {
        eprintln!("skipped: the module archive is not present in this checkout");
        return;
    }
    eprintln!("{checked} modules, {messages} messages, byte for byte");
    assert!(checked >= 9, "only {checked} of {} pairs found", PAIRS.len());
}

/// MajorMUD's own three files, which have no `.MCV` to check against.
///
/// So this checks what can be checked without one: that they parse at all, and
/// that their message counts are what they were when this was written. A reader
/// change that shifts one is then a failing test rather than a wrong string
/// somewhere in the game a fortnight later.
#[test]
#[ignore = "needs tmp/*.MSG"]
fn majormuds_message_files_are_the_size_they_were() {
    // Measured 2026-08-04 against MajorMUD 1.11p's shipped files.
    let expected = [
        ("WCCMMUD.MSG", 81),
        ("WCCMMHLP.MSG", 264),
        ("WCCTEXT.MSG", 10),
    ];

    for (name, count) in expected {
        let Ok(bytes) = std::fs::read(repo(&format!("tmp/{name}"))) else {
            eprintln!("skipped: tmp/{name} is not present in this checkout");
            continue;
        };
        let file = MsgFile::parse(name, &bytes).expect("parses");
        eprintln!("{name}: {} messages", file.len());
        assert_eq!(file.len(), count, "{name}");
    }
}

/// **The compiler's oracle.** Every pair in [`PAIRS`] shipped a `.MSG` and the
/// `.MCV` the real host's indexer built from it, so compiling ours and comparing
/// bytes is a total check on the format -- layout, offsets, terminators and
/// trailer at once. Nothing here trusts our own reader to validate our own
/// writer.
#[test]
fn compiling_a_msg_reproduces_the_mcv_that_shipped_with_it() {
    let mut checked = 0usize;
    let mut bytes = 0usize;

    for stem in PAIRS {
        let (Ok(msg), Ok(mcv)) = (
            std::fs::read(repo(&format!("{stem}.MSG"))),
            std::fs::read(repo(&format!("{stem}.MCV"))),
        ) else {
            continue;
        };

        let name = Path::new(stem).file_name().unwrap().to_string_lossy();
        let ours = MsgFile::parse(&name, &msg).expect("the archive's files parse");
        let language = ours.language().unwrap_or(mbbs::mcv::DEFAULT_LANGUAGE);
        let built = mbbs::mcv::compile(ours.messages(), language);

        assert_eq!(
            built.len(),
            mcv.len(),
            "{name}: compiled {} bytes, shipped {} bytes",
            built.len(),
            mcv.len()
        );
        if built != mcv {
            let at = built
                .iter()
                .zip(&mcv)
                .position(|(a, b)| a != b)
                .expect("lengths match so a byte must differ");
            panic!(
                "{name}: first difference at byte {at}: compiled {:#04x}, shipped {:#04x}",
                built[at], mcv[at]
            );
        }

        eprintln!("{name}: {} bytes, byte for byte", built.len());
        checked += 1;
        bytes += built.len();
    }

    if checked == 0 {
        eprintln!("skipped: the module archive is not present in this checkout");
        return;
    }
    eprintln!("{checked} files compiled, {bytes} bytes, all identical");
    assert!(checked >= 9, "only {checked} of {} pairs found", PAIRS.len());
}
