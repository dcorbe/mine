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
//! Plus a fourth, `duplicates`, over a single file rather than every one of
//! them: `WCCUSERS` ships with zero records, but is the one file whose keys
//! include a duplicate-permitting one (key 2, MajorMUD's own experience
//! field), and `HOLDS_RECORDS` below is a table of files that already hold
//! records, which this one does not. `forge_a_duplicate_key_the_real_engine_can_read`
//! inserts a populated corpus of characters -- colliding groups on key 2,
//! distinct values on keys 0 and 1 -- so `pages::chain_pair`'s
//! `[prev][next]` links get written and can be walked, not merely built and
//! left unread. Both halves of the pair get one: `.VIR`'s own key 2
//! descriptor names a chain offset (2034) past its physical record length
//! (2006), which `pages::write_chain` used to refuse outright, until
//! `docs/plans/2026-08-09-btrieve-duplicate-writes.md` established that
//! offset fits the page's actual usable end when nothing else shares the
//! page -- exactly `.VIR`'s shape, one record per page. `.DAT` reads
//! `physical - 8` there instead and is inserted into as an independent
//! check. See the test's own doc comment,
//! `docs/plans/2026-08-07-btrieve-interior-pages-design.md` and
//! `tools/btrieve-oracle/fixtures/DUPKEY30.txt` for the shape this is
//! measured against.
//!
//! The output is a directory of whole, openable Btrieve files -- not the bare
//! index pages `tests/btrieve.rs` walks on a scratch file, which no engine can
//! open. `tools/btrieve-oracle/sweep.sh <dir>` is what reads them.
//!
//! ```text
//! cargo test -p mbbs --test forge -- --ignored --nocapture
//! tools/btrieve-oracle/sweep.sh target/btrieve-corpus
//! tools/btrieve-oracle/sweep.sh target/btrieve-corpus-duplicates
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use mbbs::abi::Wg16;
use mbbs::btrieve::keys::Kind;
use mbbs::btrieve::AbiMem;
use mbbs::btrieve::{Btrieve, Geometry};
use mbbs::{Config, Heap};
use mbbs_machine::m16::Machine;

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
/// **One root per test, and that is not tidiness.** Each corpus test wipes its
/// whole root on the way in, so a previous run's files cannot be swept as this
/// run's coverage. Tests in a binary run in parallel, so two of them sharing a
/// root means that wipe can land between another test's `create_dir_all` and
/// its `copy` -- which is not a flake that shows up as a wrong answer but as
/// `No such file or directory` on the *destination*, and which happened on the
/// first clean run after the duplicate variant was added.
fn corpus(root: &str) -> PathBuf {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(root);
    std::fs::create_dir_all(&at).expect("a corpus directory");
    at
}

/// A host just complete enough to open a Btrieve file: the 16-bit machine the
/// block's four allocations live in, a heap to cut them from, and the open-file
/// table itself.
struct Forge {
    machine: Machine,
    heap: Heap<Wg16>,
    btrieve: Btrieve<AbiMem<Wg16>>,
    /// This forge's own corpus root, wiped on the way in. See [`corpus`].
    root: PathBuf,
}

impl Forge {
    fn new(root: &str) -> Self {
        let root = corpus(root);
        let _ = std::fs::remove_dir_all(&root);
        Self {
            machine: Machine::new().expect("a 16-bit machine"),
            heap: Heap::new(Config::default()),
            btrieve: Btrieve::default(),
            root,
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
        work: impl FnOnce(&mut mbbs::btrieve::Block<AbiMem<Wg16>>) -> Result<(), String>,
    ) -> Result<PathBuf, String> {
        let dir = self.root.join(variant);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(name);
        std::fs::copy(from.join(name), &path).map_err(|e| e.to_string())?;

        let geometry = Geometry::read(name, &path).map_err(|e| e.to_string())?;
        // `maxlen` is the module's own idea of the record length, and a module
        // that opened these would pass its `struct`'s size. The file's own
        // `reclen` is the only value here that cannot be wrong.
        let at = self.btrieve.open(
            self.machine.mem_mut(),
            &mut self.heap,
            name,
            &path,
            geometry,
            geometry.reclen,
        )?;

        let result = work(self.btrieve.block_mut(at)?);

        // Closed even when `work` failed, so one file's refusal does not leak a
        // block into the next file's open table.
        let closed = self
            .btrieve
            .close(self.machine.mem_mut(), &mut self.heap, at)
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
    let mut forge = Forge::new("btrieve-corpus");
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
            // No length pre-check: whether this buffer may be written back is
            // `Block::update`'s judgement, not the forge's, and letting the
            // forge decide would hide the answer it is here to collect. A
            // variable-length file's record comes back longer than `reclen`
            // (the fixed part plus its fragments) and `update` refuses it.
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
    eprintln!("{made} files forged into {}", forge.root.display());

    // Eleven reindexes and eleven updates -- `update` now succeeds for
    // WCCTEXT too. `docs/plans/2026-08-11-survivability-and-the-reachable-
    // surface.md` Task 5 Track A gave `Block::update` one shape-checked hole
    // in its variable-length refusal: an equal-length, single-fragment,
    // non-continued in-place rewrite, which is exactly the record this forge
    // exercises -- flipping the last byte of the *fixed* part (see the
    // `update` closure above) leaves the fragment's own bytes unchanged, so
    // the new body is the same length as the one already on the page and the
    // shape matches. `grown` still refuses for WCCTEXT: it is an *insert*,
    // and `Block::insert` on a variable-length file is unconditional and
    // untouched by Track A -- multi-fragment splitting and a fragment-page
    // allocator are a later track's work, not this one's.
    //
    // This forge used to record two refusals here, both WCCTEXT, when
    // `update` also refused unconditionally; genuine Btrieve then rejected
    // the whole file that had been produced under that older code, with
    // status 54. See `docs/plans/2026-08-08-oracle-wash.md`.
    assert_eq!(made, 32, "expected 11 + 11 + 10 forged files");
    assert_eq!(
        skipped.len(),
        1,
        "only WCCTEXT's grown (insert) should refuse to be written: {skipped:?}"
    );
    for why in &skipped {
        assert!(
            why.starts_with("WCCTEXT.VIR grown:") && why.contains("variable-length"),
            "unexpected refusal: {why}"
        );
    }
}

/// Group sizes for one "cycle" of [`insert_duplicate_users`]: five that
/// collide (7, 5, 4, 3, 2 records apiece) and four singletons -- a value
/// carried by exactly one record, the very first thing a real board's second
/// character produces if nobody else already saved at that experience.
const DUPLICATE_GROUP_SIZES: [u32; 9] = [7, 5, 4, 3, 2, 1, 1, 1, 1];

/// How many times [`DUPLICATE_GROUP_SIZES`] repeats, each time with a fresh,
/// non-overlapping base value so only the *intended* records collide.
const DUPLICATE_REPEATS: u32 = 6;

/// Insert a populated, duplicate-colliding corpus of characters into an empty
/// `WCCUSERS`-shaped block, then reindex it.
///
/// Every newly rolled MajorMUD character has zero experience, so a real
/// board's key 2 (experience) collides from the first save onward -- and
/// nothing MajorMUD ships holds records at all, so nothing shipped can put
/// that under the engine. This inserts them instead: distinct values on keys
/// 0 and 1 (name, owner -- both forbid duplicates, so a collision there is a
/// bug in this fixture, not a fact about the host) and colliding groups on
/// key 2, sized by [`DUPLICATE_GROUP_SIZES`] x [`DUPLICATE_REPEATS`] --
/// `9 * 6 = 54` distinct key-2 values, `(7+5+4+3+2+1+1+1+1) * 6 = 150`
/// records total.
///
/// 150 also blows key 0's single-page capacity on purpose: its entries are
/// `30 + 8 = 38` bytes (unique key, [`pages::Shape::entry_size`]), so
/// `(2048 - 12) / 38 = 53` fit one page and 150 needs three -- key 0's tree
/// is a real multi-level tree, not a single leaf, when the engine descends
/// it.
///
/// # Errors
///
/// If the block does not already hold zero records and the three
/// single-segment keys (30-byte name, some-width owner, 4-byte
/// duplicate-permitting experience) this assumes, or if a record cannot be
/// inserted or the block cannot be reindexed.
fn insert_duplicate_users(block: &mut mbbs::btrieve::Block<AbiMem<Wg16>>) -> Result<(), String> {
    let count = block.records().map_err(|e| e.to_string())?.len();
    if count != 0 {
        return Err(format!(
            "{count} records, not the 0 this variant assumes it is starting from"
        ));
    }

    let keys = block.keys().to_vec();
    let [key0, key1, key2] = keys.as_slice() else {
        return Err(format!("{} keys, not the 3 this variant assumes", keys.len()));
    };

    let name_seg = match key0.segments.as_slice() {
        [only] => *only,
        other => return Err(format!("key 0 has {} segments, not 1", other.len())),
    };
    let owner_seg = match key1.segments.as_slice() {
        [only] => *only,
        other => return Err(format!("key 1 has {} segments, not 1", other.len())),
    };
    let exp_seg = match key2.segments.as_slice() {
        [only] => *only,
        other => return Err(format!("key 2 has {} segments, not 1", other.len())),
    };
    if !key2.duplicates {
        return Err("key 2 does not permit duplicates".to_owned());
    }

    let reclen = usize::from(block.geometry().reclen);
    if reclen != 1998 {
        return Err(format!("reclen {reclen}, not the 1998 this variant assumes"));
    }

    let mut index = 0usize;
    for repeat in 0..DUPLICATE_REPEATS {
        let base = repeat * 100;
        for (group, size) in DUPLICATE_GROUP_SIZES.iter().enumerate() {
            let value = base + group as u32;
            for _ in 0..*size {
                let mut record = vec![0u8; reclen];

                let name = format!("Forge{index:04}").into_bytes();
                let name_at = usize::from(name_seg.offset);
                record[name_at..name_at + name.len()].copy_from_slice(&name);

                let owner = format!("Owner{index:04}").into_bytes();
                let owner_at = usize::from(owner_seg.offset);
                record[owner_at..owner_at + owner.len()].copy_from_slice(&owner);

                let exp_at = usize::from(exp_seg.offset);
                let exp_len = usize::from(exp_seg.length);
                record[exp_at..exp_at + exp_len]
                    .copy_from_slice(&value.to_le_bytes()[..exp_len]);

                block.insert(&record).map_err(|e| e.to_string())?;
                index += 1;
            }
        }
    }

    eprintln!(
        "duplicates  inserted {index} records over {} distinct key-2 values \
         ({} colliding groups, {} singletons, per cycle x {DUPLICATE_REPEATS} cycles)",
        DUPLICATE_GROUP_SIZES.len() * DUPLICATE_REPEATS as usize,
        DUPLICATE_GROUP_SIZES.iter().filter(|n| **n > 1).count(),
        DUPLICATE_GROUP_SIZES.iter().filter(|n| **n == 1).count(),
    );

    block.reindex().map_err(|e| e.to_string())
}

/// The fourth variant: a duplicate-permitting key, populated and chained.
///
/// **This host used to refuse to write a chain into `WCCUSERS.VIR`.** Its
/// key 2 (experience) descriptor names a chain offset of 2034, past the
/// file's own physical record length of 2006 bytes -- `2034 + 8 = 2042` does
/// not fit `physical`, and `pages::write_chain` refused on exactly that
/// check. But `2042` is `page (2048) - HEADER (6)`, the page's own usable
/// end, and `WCCUSERS.VIR` holds one record per page -- nothing shares that
/// page, so the 36 bytes past `physical` belong to no other record.
/// **Measured, not assumed, by `crates/btrieve-oracle/tests/engine.rs`'s
/// `wccusers_vir_chain_offset_measurement`** (Task 5 of
/// `docs/plans/2026-08-09-btrieve-engine-in-the-loop.md`): three records
/// inserted into a fresh copy of the `.VIR` over the real engine, all
/// colliding on key 2, all returned status 0, and the raw file afterward
/// carried an 8-byte chain node at the declared offset 2034 in every
/// physical slot. `pages::write_chain`'s bound is now per-slot rather than a
/// flat `physical`: a page's last slot -- the only one with no neighbour to
/// spill into -- may use up to `page - HEADER`, and every other slot still
/// stops at `physical`
/// (`docs/plans/2026-08-09-btrieve-duplicate-writes.md`, "What is still
/// owed"). So the `.VIR` is now inserted into directly.
///
/// `WCCUSERS.DAT` -- same 2048-byte page, same `1998` reclen, same `2006`
/// physical, same three single-segment keys -- reads `1998` at that offset,
/// which is `physical - 8`, the rule already measured against
/// `DUPKEY30.DAT` (see `at::CHAIN`'s doc comment), so it is inserted into as
/// well, as an independent check that the fix did not disturb the ordinary
/// case.
///
/// The `.VIR`'s key 1 is 11 bytes where the `.DAT`'s is 30, and that 11 is
/// *internally coherent* -- entry size 19 is `11 + 8` and max entries 107 is
/// `(2048 - 12) / 19`, both computed by the engine from 11 -- so the file was
/// created that way on purpose, not damaged. Genuine Btrieve opens it
/// without complaint and reports `key 1 len=11`. The two files came from
/// different builds; which one remains unmeasured, and nothing here depends
/// on that answer: a running board writes characters to the `.DAT`, and the
/// `.VIR` is the virgin template an install copies from.
#[test]
#[ignore = "needs MajorMUD's data files in tmp/"]
fn forge_a_duplicate_key_the_real_engine_can_read() {
    let Some(data) = data() else { return };
    let mut forge = Forge::new("btrieve-corpus-duplicates");

    let vir = forge
        .forge(&data, "WCCUSERS.VIR", "duplicates", insert_duplicate_users)
        .unwrap_or_else(|e| panic!("WCCUSERS.VIR duplicates: {e}"));
    eprintln!("duplicates {}", vir.display());

    let dat = forge
        .forge(&data, "WCCUSERS.DAT", "duplicates", insert_duplicate_users)
        .unwrap_or_else(|e| panic!("WCCUSERS.DAT duplicates: {e}"));
    eprintln!("duplicates {}", dat.display());
}
