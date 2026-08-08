//! Forge a corpus of Btrieve files **this host wrote**, for the real engine to
//! read back.
//!
//! `tools/btrieve-oracle/` can drive genuine Pervasive Btrieve 6.15 over any
//! file, and has been run over the thirty-two MajorMUD ships. That establishes
//! the oracle works; it establishes nothing about this crate, because none of
//! those files came out of it. This produces the ones that did.
//!
//! Three variants per file, in rising order of how much of the write path each
//! one exercises:
//!
//! | variant   | what it does                              | what it puts under the engine |
//! |-----------|-------------------------------------------|-------------------------------|
//! | `reindex` | load the records, rebuild every key's tree | `pages::build_index` at the file's real depth |
//! | `update`  | rewrite one record in place, then close   | the same, plus `write_record` over an existing slot |
//! | `grown`   | append records until the tree must deepen, then close | slot allocation, page appends, and a tree this host built from a shape the shipped file never had |
//!
//! The output is a directory of whole, openable Btrieve files -- not the bare
//! index pages `tests/btrieve.rs` walks on a scratch file, which no engine can
//! open. `tools/btrieve-oracle/sweep.sh <dir>` is what reads them.
//!
//! ```text
//! cargo test -p mbbs --test forge -- --ignored --nocapture
//! tools/btrieve-oracle/sweep.sh target/btrieve-corpus
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use mbbs::btrieve::keys::Kind;
use mbbs::btrieve::{Btrieve, Geometry};
use mbbs::{Config, Heap};
use mbbs16::Machine;

/// Every file MajorMUD ships that actually holds records, and how many.
///
/// The count is here so the forge fails loudly if it opens a file whose shape
/// has changed under it, rather than silently forging a corpus of empty files
/// the engine would then bless.
const HOLDS_RECORDS: &[(&str, u32)] = &[
    ("WCCACTS.VIR", 64),
    ("WCCCLASS.VIR", 15),
    ("WCCITEMS.VIR", 1950),
    ("WCCKNMSR.VIR", 1101),
    ("WCCMP001.VIR", 26720),
    ("WCCMSG.VIR", 3867),
    ("WCCRACE.VIR", 13),
    ("WCCSHOPS.VIR", 178),
    ("WCCSPELS.VIR", 1379),
    ("WCCTEXT.VIR", 3467),
    ("WCCUPDAT.DAT", 38754),
];

fn data() -> Option<PathBuf> {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp");
    if at.join("WCCITEMS.VIR").is_file() {
        return Some(at);
    }
    eprintln!("skipped: no MajorMUD data files in tmp/");
    None
}

/// Where the corpus lands. Under `target/` because it is build output: it is
/// regenerated from `tmp/` every run and nothing should ever be edited in it.
fn corpus() -> PathBuf {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/btrieve-corpus");
    std::fs::create_dir_all(&at).expect("a corpus directory");
    at
}

/// A host just complete enough to open a Btrieve file: the 16-bit machine the
/// block's four allocations live in, a heap to cut them from, and the open-file
/// table itself.
struct Forge {
    machine: Machine,
    heap: Heap,
    btrieve: Btrieve,
}

impl Forge {
    fn new() -> Self {
        Self {
            machine: Machine::new().expect("a 16-bit machine"),
            heap: Heap::new(Config::default()),
            btrieve: Btrieve::default(),
        }
    }

    /// Copy `name` out of `from` into `<corpus>/<variant>/`, open it, hand it to
    /// `work`, then close it -- which is where a dirty block is reindexed, the
    /// same flush point `clsbtv` is.
    ///
    /// The copy is the point: `tmp/` holds the only copies of the shipped data
    /// this repo has, and every variant here writes.
    fn forge(
        &mut self,
        from: &Path,
        name: &str,
        variant: &str,
        work: impl FnOnce(&mut mbbs::btrieve::Block) -> Result<(), String>,
    ) -> Result<PathBuf, String> {
        let dir = corpus().join(variant);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(name);
        std::fs::copy(from.join(name), &path).map_err(|e| e.to_string())?;

        let geometry = Geometry::read(name, &path).map_err(|e| e.to_string())?;
        // `maxlen` is the module's own idea of the record length, and a module
        // that opened these would pass its `struct`'s size. The file's own
        // `reclen` is the only value here that cannot be wrong.
        let at = self
            .btrieve
            .open(&mut self.machine, &mut self.heap, name, &path, geometry, geometry.reclen)?;

        let result = work(self.btrieve.block_mut(at)?);

        // Closed even when `work` failed, so one file's refusal does not leak a
        // block into the next file's open table.
        let closed = self
            .btrieve
            .close(&mut self.machine, &mut self.heap, at)
            .map_err(|e| e.to_string());

        // And the copy is REMOVED when `work` failed. The copy is made before
        // the work, so a refusal otherwise leaves a byte-identical copy of the
        // shipped file sitting in the corpus under a variant's name -- and the
        // sweep then reports a clean descend for a file nothing wrote, which
        // reads as coverage and is not. Measured: `update` and `grown` each
        // held a WCCTEXT.VIR this host had refused to touch, and the engine
        // blessed all eleven files in a ten-file corpus.
        if result.is_err() || closed.is_err() {
            let _ = std::fs::remove_file(&path);
        }
        result?;
        closed?;
        Ok(path)
    }
}

fn read_le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |n, b| (n << 8) | u64::from(*b))
}

fn write_le(into: &mut [u8], mut value: u64) {
    for byte in into.iter_mut() {
        *byte = value as u8;
        value >>= 8;
    }
}

/// The `n`th key value to append to a file whose single key is `segment`.
///
/// An integer key counts on from `highest`, which is the largest already in the
/// file. A text key gets `~~` and a number: `0x7e` is the last printable ASCII
/// byte and sorts after every name, id and message tag in these files. Neither
/// is *assumed* unused -- the caller checks each against the set of key values
/// the file already holds, because a duplicate on a key that forbids them would
/// make the forge produce a file that is wrong in a way the engine would then
/// blame on the index.
fn next_key(segment: &mbbs::btrieve::keys::Segment, highest: u64, n: u64) -> Vec<u8> {
    let length = usize::from(segment.length);
    match segment.kind {
        Kind::Signed | Kind::Unsigned => {
            let mut out = vec![0u8; length];
            write_le(&mut out, highest + 1 + n);
            out
        }
        Kind::Text => {
            let mut out = format!("~~{n}").into_bytes();
            out.resize(length, 0);
            out
        }
    }
}

/// The whole corpus, in one pass over `tmp/`.
///
/// Deliberately one test rather than three: the three variants of a file share
/// the open/copy machinery, and a partial corpus is worse than none -- the
/// sweep would report on whatever happened to be on disk from a previous run.
#[test]
#[ignore = "needs MajorMUD's data files in tmp/"]
fn forge_a_corpus_the_real_engine_can_read() {
    let Some(data) = data() else { return };
    let root = corpus();
    let _ = std::fs::remove_dir_all(&root);

    let mut forge = Forge::new();
    let mut made = 0usize;
    let mut skipped: Vec<String> = Vec::new();

    for (name, expected) in HOLDS_RECORDS {
        // C1: rebuild every key's tree over records nothing changed. The
        // narrowest variant, and the one whose output should hold exactly the
        // entries the shipped index holds.
        let path = forge
            .forge(&data, name, "reindex", |block| {
                let count = block.records().map_err(|e| e.to_string())?.len();
                if count as u32 != *expected {
                    return Err(format!("{count} records, not {expected}"));
                }
                block.reindex().map_err(|e| e.to_string())
            })
            .unwrap_or_else(|e| panic!("{name}: reindex: {e}"));
        eprintln!("reindex  {}", path.display());
        made += 1;

        // C2: one record rewritten in place. The byte chosen is the LAST byte
        // of the record, which is outside every key segment in every file here
        // -- a key that reached the final byte would make this an insert of a
        // different key rather than an update, and the assert is what keeps
        // that from happening silently.
        let path = forge.forge(&data, name, "update", |block| {
            let keys = block.keys().to_vec();
            let reclen = usize::from(block.geometry().reclen);
            let (position, mut bytes) = {
                let records = block.records().map_err(|e| e.to_string())?;
                let record = records.ordered(0, 0).ok_or("no first record")?;
                (record.position, record.bytes.clone())
            };
            if bytes.len() != reclen {
                // A variable-length file: `update` refuses these, and rightly.
                return Err(format!(
                    "record is {} bytes and reclen is {reclen}",
                    bytes.len()
                ));
            }
            for key in &keys {
                for segment in &key.segments {
                    let end = usize::from(segment.offset) + usize::from(segment.length);
                    assert!(
                        end < reclen,
                        "{name}: key {} reaches the last byte; pick another one to flip",
                        key.number
                    );
                }
            }
            let last = reclen - 1;
            bytes[last] ^= 0xff;
            block.update(position, &bytes).map_err(|e| e.to_string())
        });
        match path {
            Ok(path) => {
                eprintln!("update   {}", path.display());
                made += 1;
            }
            Err(why) => skipped.push(format!("{name} update: {why}")),
        }

        // C3: append until the tree has to deepen. Small files get enough
        // records to turn a single leaf into a multi-level tree, which is the
        // shape no shipped file could have supplied for them; the two large
        // ones get a token number, because every insert re-derives the file's
        // occupied slots and doing that 26,720 times over is quadratic for no
        // extra coverage -- their `reindex` variant already puts a depth-3 tree
        // under the engine.
        let grow = if *expected < 2_000 { 1_500 } else { 50 };
        let path = forge.forge(&data, name, "grown", |block| {
            let keys = block.keys().to_vec();
            let [key] = keys.as_slice() else {
                return Err(format!("{} keys, and this only handles one", keys.len()));
            };
            let [segment] = key.segments.as_slice() else {
                return Err(format!(
                    "{} segments, and this only handles one",
                    key.segments.len()
                ));
            };
            let offset = usize::from(segment.offset);
            let length = usize::from(segment.length);

            let (highest, template, mut taken) = {
                let records = block.records().map_err(|e| e.to_string())?;
                let len = records.ordered_len(0).ok_or("no key 0")?;
                let last = records.ordered(0, len - 1).ok_or("no last record")?;
                let taken: HashSet<Vec<u8>> = (0..len)
                    .map(|n| key.extract(&records.ordered(0, n).expect("in range").bytes))
                    .collect();
                (
                    read_le(&key.extract(&last.bytes)),
                    last.bytes.clone(),
                    taken,
                )
            };

            for n in 0..grow {
                let value = next_key(segment, highest, n);
                if !taken.insert(value.clone()) {
                    return Err(format!("key {value:02x?} is already in the file"));
                }
                let mut record = template.clone();
                record[offset..offset + length].copy_from_slice(&value);
                block.insert(&record).map_err(|e| e.to_string())?;
            }
            Ok(())
        });
        match path {
            Ok(path) => {
                eprintln!("grown    {} (+{grow})", path.display());
                made += 1;
            }
            Err(why) => skipped.push(format!("{name} grown: {why}")),
        }
    }

    for why in &skipped {
        eprintln!("skipped  {why}");
    }
    eprintln!("{made} files forged into {}", root.display());

    // Eleven reindexes, and ten each of the two writing variants. The one file
    // that refuses both is WCCTEXT, the only variable-length file of the
    // eighteen: `insert` has always refused those, and `update` refuses them
    // now -- it did not when this forge was first run, and genuine Btrieve
    // rejected the whole file it produced. See
    // `docs/plans/2026-08-08-oracle-wash.md`.
    assert_eq!(made, 31, "expected 11 + 10 + 10 forged files");
    assert_eq!(
        skipped.len(),
        2,
        "only WCCTEXT should refuse to be written: {skipped:?}"
    );
    for why in &skipped {
        assert!(
            why.starts_with("WCCTEXT.VIR ") && why.contains("variable-length"),
            "unexpected refusal: {why}"
        );
    }
}
