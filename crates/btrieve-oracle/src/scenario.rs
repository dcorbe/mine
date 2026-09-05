//! Recorded conversations with genuine Pervasive Btrieve 6.15, committed as
//! data so the everyday test suite never has to run Wine.
//!
//! A [`Scenario`] is a seed (either a `B_CREATE` [`Request`] or a committed
//! file's raw bytes) plus the [`Request`]s to make against the file it
//! produces. A [`Transcript`] is what the genuine engine answered: one
//! [`Response`] per call, plus the resulting file's bytes once every call
//! landed and the file was closed. [`Fixture`] pairs the two and is what
//! actually gets written to `fixtures/`.
//!
//! # Why generation and replay are different programs
//!
//! Wine is an oracle, never a shipped dependency: `crates/btrieve-oracle`'s
//! own `tests/engine.rs` already establishes the house pattern of `#[ignore]`
//! plus a loud skip when `wine` is not on `PATH`. This module's generator
//! (`#[cfg(test)] mod generate`, function `record_fixtures_from_the_genuine_engine`,
//! `#[ignore]`) follows the same rule and is never run by a bare `cargo
//! test`. The replay half (Task 12, `crates/btrieve/tests/differential.rs`)
//! reads only the committed `fixtures/*.fixture` files this generator wrote
//! and never touches Wine at all.
//!
//! # `posblk` is not scenario data
//!
//! Every [`Request`] this module stores carries a placeholder `posblk`
//! (`[0u8; 128]`) -- it is never read. Both `generate::drive` here and
//! whatever harness Task 12 builds thread ONE `posblk` buffer through a
//! scenario's calls by hand, starting at zero (a fresh `B_CREATE` does not
//! leave the file open -- see `generate::drive`'s own doc comment) and
//! carrying each response's `posblk` into the next request,
//! exactly the way `crates/btrieve/src/btrcall.rs`'s own tests and
//! `crates/mbbs/tests/btrieve.rs`'s oracle scenarios already do. Genuine
//! Btrieve's position block is 128 bytes of engine-private cursor state;
//! this host's is a handle into host-side state (see `Call::posblk`'s doc
//! comment in `btrcall.rs`). Neither shape is scenario data, and comparing
//! them is deliberately out of scope for Task 12's diff.
//!
//! # Regenerating the fixtures
//!
//! ```sh
//! export WINEPREFIX=${BTRIEVE_WINEPREFIX:-$HOME/.btrieve-wine}
//! sh tools/btrieve-oracle/build.sh
//! CARGO_BUILD_JOBS=2 cargo test -p btrieve-oracle --lib -j 2 -- \
//!     --ignored record_fixtures_from_the_genuine_engine --nocapture
//! ```
//!
//! `build.sh` compiles `btrvprobe.exe` from the current
//! `tools/btrieve-oracle/btrvprobe.c` and installs it, with the genuine
//! `WBTRV32.DLL`/`W32MKDE.EXE` engine, into the Wine prefix. The test then
//! spawns one `wine btrvprobe.exe serve <port>` (via [`Engine::spawn`]) and
//! drives every scenario over it, each against its own uniquely-named file
//! under `$WINEPREFIX/drive_c/btrieve/` -- never reusing a path, because the
//! Microkernel caches pages by path across processes and will serve a stale
//! file's pages for a new one under the same name (measured the hard way in
//! `tools/btrieve-oracle/sweep.sh` and `docs/2026-08-16-v6-update-delete-oracle.md`).
//! Produced fixtures on 2026-08-17: wine-11.14, `btrvprobe.exe` built the
//! same day from the source this file cites by line number.
//!
//! # The `B_CREATE` wire layout, for whoever writes the replay
//!
//! Every seed here but the three `v5_variable_*` fixtures' -- those carry a
//! whole file, [`Seed::File`] -- is a `B_CREATE` request whose
//! `databuf` is one `FileSpec` (16 bytes) followed by one `KeySpec` (16
//! bytes), `tools/btrieve-oracle/btrvprobe.c:76-104`, both `#pragma
//! pack(push, 1)`:
//!
//! ```text
//! FileSpec   u16 reclen | u16 pagesize | u16 indexes_raw | u32 records
//!            | u16 flags | u8 dup_pointers | u8 unused | u16 allocations
//! KeySpec    u16 position (1-based) | u16 length | u16 flags
//!            | u32 approx_count | u8 ext_type | u8 null_value
//!            | u8[2] reserved | u8 number | u8 acs_number
//! ```
//!
//! `KeySpec.flags` bits, `tools/btrieve-oracle/crtprobe.c:51`: `DUP=0x01`
//! (duplicates permitted) `MODIFY=0x02` (the key may change on update)
//! `MANUAL=0x08` `SEGMENT=0x10` (continues into the next `KeySpec`)
//! `DESCENDING=0x40` `EXTTYPE=0x100` (use `ext_type` rather than the classic
//! string collation) `NULLKEY=0x200`. Every fixture here declares exactly
//! one key, an unsigned-binary (`ext_type = 0x0e`) 4-byte value at record
//! offset 0 (wire `position = 1`) -- the same shape
//! `crates/btrieve/src/btrcall.rs`'s own `scratch_file` test helper builds
//! through the Rust `FileSpec`/`KeySpec`/`SegmentSpec` types (`offset: 0,
//! length: 4, kind: 0x0e`), so a scenario seeded from a decoded `B_CREATE`
//! and a file `crate::create` builds describe the same geometry.
//!
//! # A disagreement the first recording already surfaced
//!
//! Genuine Btrieve answers **status 4** ("key value not found") for a
//! `B_GET_EQUAL` that finds nothing, and reserves **status 9** ("end of
//! file") for a sequential `Get Next`/`Get Previous`/`Get First`/`Get Last`
//! (or Step) that has run off the end -- measured directly in
//! `update_and_delete.fixture` (a `Get Equal` for a just-deleted key answers
//! 4) and `status_ten_refusal_and_same_value_rewrite.fixture` (a `Get Equal`
//! for a key that was never written answers 4). `crates/btrieve/src/
//! btrcall.rs`'s `get` dispatch arm currently answers `Status(9)` for every
//! `Op` variant's miss, `Get Equal` included -- this is not a status this
//! module invented an opinion about, it is what the genuine engine actually
//! sent back on the wire, recorded here for Task 12 to compare against.

use crate::{Request, Response};

/// What a [`Scenario`] starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seed {
    /// A `B_CREATE` [`Request`] (see this module's doc comment for the
    /// `FileSpec`/`KeySpec` wire layout carried in `databuf`, and the
    /// filename, NUL-terminated, carried in `keybuf`) that builds the file
    /// from nothing.
    Create(Request),
    /// A pre-built file's raw bytes, written into place before the first
    /// call. What the three `v5_variable_*` fixtures are seeded with: a
    /// version 5, variable-length file `btrieve::create` wrote, a shape a
    /// `B_CREATE` over this wire cannot ask the genuine engine for.
    ///
    /// The file's name comes from the scenario's first call, which must be
    /// the `B_OPEN` that opens it (`generate::record_fixtures_from_the_
    /// genuine_engine`); nothing else in a file-seeded scenario says what
    /// to call it.
    File(Vec<u8>),
}

/// A seed plus the calls to make against the file it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// A short, filesystem-safe name. Used as the fixture's file stem and
    /// as the DOS filename the seed's file is given inside the Wine prefix,
    /// so it must be unique among every `Scenario` a single generator run
    /// produces.
    pub name: String,
    pub seed: Seed,
    /// The requests to make, in order, once the seed's file exists. Each
    /// `Request`'s `posblk` is a placeholder -- see this module's doc
    /// comment on why `posblk` threading is the harness's job, not data
    /// carried here.
    pub calls: Vec<Request>,
}

/// What the genuine engine answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// One [`Response`] per [`Scenario::calls`] entry, same order.
    pub responses: Vec<Response>,
    /// The seed's file, read back after every call landed. Real Btrieve
    /// buffers writes; a scenario's `calls` must end in a `B_CLOSE` (op 1)
    /// for this to reflect what was actually written -- every scenario this
    /// crate generates does.
    pub file: Vec<u8>,
}

/// A [`Scenario`] paired with the [`Transcript`] it produced against the
/// genuine engine -- the unit this module reads and writes as one fixture
/// file, so a scenario and its transcript can never be mismatched by a
/// rename or a partial commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    pub scenario: Scenario,
    pub transcript: Transcript,
}

// ---------------------------------------------------------------------
// Encoding. Deliberately hand-rolled rather than pulling in serde: this
// crate has zero dependencies today (`Cargo.toml`), and `Request`/
// `Response` already establish the house convention -- a `u32` length
// prefix around everything, little-endian throughout. This module's own
// framing reuses `Request::encode`/`Response::encode` verbatim for the
// pieces that are already self-delimiting (each starts with its own
// `frame_len`) rather than inventing a second way to serialise the same
// two types.
// ---------------------------------------------------------------------

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A cursor over encoded fixture bytes. Mirrors `lib.rs`'s private `Reader`
/// in spirit -- fails loudly on truncation rather than panicking -- but is
/// its own small type: `Reader` is private to `lib.rs` and this module has
/// no reason to widen that just to read four more shapes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| {
                format!(
                    "fixture truncated: wanted {n} bytes at offset {}, have {}",
                    self.pos,
                    self.buf.len()
                )
            })?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        Ok(self.take(n)?.to_vec())
    }

    /// Reads one `u32 frame_len | body` unit -- the shape both
    /// `Request::encode` and `Response::encode` produce -- and returns the
    /// whole thing (frame_len included), so the caller can hand it straight
    /// to `Request::decode`/`Response::decode`, which both expect the body
    /// alone (frame_len already stripped).
    fn take_framed(&mut self) -> Result<Vec<u8>, String> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    fn string(&mut self) -> Result<String, String> {
        let len = self.u32()? as usize;
        let bytes = self.bytes(len)?;
        String::from_utf8(bytes).map_err(|e| format!("fixture name is not UTF-8: {e}"))
    }

    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

impl Seed {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Seed::Create(req) => {
                out.push(0);
                out.extend_from_slice(&req.encode());
            }
            Seed::File(bytes) => {
                out.push(1);
                push_u32(out, bytes.len() as u32);
                out.extend_from_slice(bytes);
            }
        }
    }

    fn decode(c: &mut Cursor<'_>) -> Result<Self, String> {
        match c.u8()? {
            0 => {
                let framed = c.take_framed()?;
                Ok(Seed::Create(Request::decode(&framed)?))
            }
            1 => {
                let len = c.u32()? as usize;
                Ok(Seed::File(c.bytes(len)?))
            }
            other => Err(format!("unknown seed tag {other}")),
        }
    }
}

impl Scenario {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_u32(&mut out, self.name.len() as u32);
        out.extend_from_slice(self.name.as_bytes());
        self.seed.encode(&mut out);
        push_u32(&mut out, self.calls.len() as u32);
        for call in &self.calls {
            out.extend_from_slice(&call.encode());
        }
        out
    }

    fn decode(c: &mut Cursor<'_>) -> Result<Self, String> {
        let name = c.string()?;
        let seed = Seed::decode(c)?;
        let n = c.u32()? as usize;
        let mut calls = Vec::with_capacity(n);
        for _ in 0..n {
            let framed = c.take_framed()?;
            calls.push(Request::decode(&framed)?);
        }
        Ok(Scenario { name, seed, calls })
    }
}

impl Transcript {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_u32(&mut out, self.responses.len() as u32);
        for resp in &self.responses {
            out.extend_from_slice(&resp.encode());
        }
        push_u32(&mut out, self.file.len() as u32);
        out.extend_from_slice(&self.file);
        out
    }

    fn decode(c: &mut Cursor<'_>) -> Result<Self, String> {
        let n = c.u32()? as usize;
        let mut responses = Vec::with_capacity(n);
        for _ in 0..n {
            let framed = c.take_framed()?;
            responses.push(Response::decode(&framed)?);
        }
        let file_len = c.u32()? as usize;
        let file = c.bytes(file_len)?;
        Ok(Transcript { responses, file })
    }
}

impl Fixture {
    /// Encodes this fixture as bytes: the scenario, then its transcript,
    /// back to back. Both halves are internally length-prefixed, so this
    /// needs no outer framing of its own.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.scenario.encode();
        out.extend_from_slice(&self.transcript.encode());
        out
    }

    /// Decodes a fixture written by [`Fixture::encode`].
    ///
    /// # Errors
    ///
    /// If the bytes are truncated, carry an unknown seed tag, or leave
    /// trailing bytes unconsumed.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(bytes);
        let scenario = Scenario::decode(&mut c)?;
        let transcript = Transcript::decode(&mut c)?;
        if !c.finished() {
            return Err(format!(
                "fixture has {} trailing byte(s) after a complete scenario and transcript",
                c.buf.len() - c.pos
            ));
        }
        Ok(Fixture { scenario, transcript })
    }

    /// Writes this fixture to `<dir>/<scenario.name>.fixture`, returning the
    /// path written.
    ///
    /// # Errors
    ///
    /// If creating `dir` or writing the file fails.
    pub fn write(&self, dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let path = dir.join(format!("{}.fixture", self.scenario.name));
        std::fs::write(&path, self.encode())
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        Ok(path)
    }
}

/// `crates/btrieve-oracle/fixtures/`, resolved from this crate's own
/// manifest directory so it means the same thing no matter which crate's
/// test binary calls it.
#[must_use]
pub fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Loads every `*.fixture` file in [`fixtures_dir`], sorted by name for a
/// deterministic order.
///
/// # Errors
///
/// If the directory can't be read, or any file in it fails to decode.
pub fn load_all() -> Result<Vec<Fixture>, String> {
    let dir = fixtures_dir();
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "fixture"))
        .collect();
    entries.sort();

    entries
        .into_iter()
        .map(|path| {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            Fixture::decode(&bytes).map_err(|e| format!("decoding {}: {e}", path.display()))
        })
        .collect()
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    fn sample_request(op: u16) -> Request {
        Request {
            op,
            posblk: [0u8; 128],
            datalen: 4,
            databuf: vec![1, 2, 3, 4],
            keylen: 255,
            keynum: 0,
            keybuf: vec![9, 9, 9, 9],
        }
    }

    fn sample_response(status: i16) -> Response {
        Response {
            status,
            posblk: [7u8; 128],
            datalen: 4,
            databuf: vec![5, 6, 7, 8],
            keybuf: vec![],
        }
    }

    #[test]
    fn a_fixture_with_a_create_seed_survives_the_round_trip() {
        let fixture = Fixture {
            scenario: Scenario {
                name: "roundtrip".to_owned(),
                seed: Seed::Create(sample_request(14)),
                calls: vec![sample_request(0), sample_request(5)],
            },
            transcript: Transcript {
                responses: vec![sample_response(0), sample_response(9)],
                file: vec![0xaa; 16],
            },
        };

        let bytes = fixture.encode();
        let decoded = Fixture::decode(&bytes).expect("decodes");
        assert_eq!(decoded, fixture);
    }

    #[test]
    fn a_fixture_with_a_file_seed_survives_the_round_trip() {
        let fixture = Fixture {
            scenario: Scenario {
                name: "file-seeded".to_owned(),
                seed: Seed::File(vec![1, 2, 3, 4, 5]),
                calls: vec![sample_request(1)],
            },
            transcript: Transcript {
                responses: vec![sample_response(0)],
                file: vec![1, 2, 3, 4, 5],
            },
        };

        let bytes = fixture.encode();
        let decoded = Fixture::decode(&bytes).expect("decodes");
        assert_eq!(decoded, fixture);
    }

    #[test]
    fn trailing_bytes_after_a_complete_fixture_are_an_error() {
        let fixture = Fixture {
            scenario: Scenario {
                name: "short".to_owned(),
                seed: Seed::File(vec![]),
                calls: vec![],
            },
            transcript: Transcript {
                responses: vec![],
                file: vec![],
            },
        };
        let mut bytes = fixture.encode();
        bytes.push(0xff);
        assert!(Fixture::decode(&bytes).is_err());
    }

    #[test]
    fn a_truncated_fixture_is_an_error_not_a_panic() {
        let fixture = Fixture {
            scenario: Scenario {
                name: "truncated".to_owned(),
                seed: Seed::Create(sample_request(14)),
                calls: vec![sample_request(0)],
            },
            transcript: Transcript {
                responses: vec![sample_response(0)],
                file: vec![1, 2, 3],
            },
        };
        let bytes = fixture.encode();
        assert!(Fixture::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}

// =========================================================================
// The generator. Behind #[ignore] and nowhere else: this is the ONLY place
// in this crate (indeed, in the whole differential-testing story this task
// is Phase 4 of) that is allowed to build the actual `Scenario`s. Everyday
// runs -- Task 12's replay included -- read only the committed
// `fixtures/*.fixture` files this produces. The one exception is the nested
// `gate` module, which reads one of those committed fixtures and spawns no
// engine at all.
// =========================================================================

#[cfg(test)]
mod generate {
    use super::*;
    use std::process::{Command, Stdio};

    const B_OPEN: u16 = 0;
    const B_CLOSE: u16 = 1;
    const B_INSERT: u16 = 2;
    const B_UPDATE: u16 = 3;
    const B_DELETE: u16 = 4;
    const B_GET_EQUAL: u16 = 5;
    const B_GET_NEXT: u16 = 6;
    const B_GET_PREVIOUS: u16 = 7;
    const B_GET_GREATER: u16 = 8;
    const B_GET_AT_MOST: u16 = 11;
    const B_GET_FIRST: u16 = 12;
    const B_GET_LAST: u16 = 13;
    const B_CREATE: u16 = 14;
    const B_STAT: u16 = 15;
    const B_STEP_NEXT: u16 = 24;
    const B_STEP_FIRST: u16 = 33;

    const MODE_NORMAL: i8 = 0;

    const KFLAG_MODIFY: u16 = 0x02;
    const KFLAG_EXTTYPE: u16 = 0x100;
    const KT_UNSIGNED_BINARY: u8 = 0x0e;

    fn wine_on_path() -> bool {
        Command::new("wine")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    fn btrieve_work_dir() -> std::path::PathBuf {
        let prefix = std::env::var("BTRIEVE_WINEPREFIX")
            .unwrap_or_else(|_| format!("{}/.btrieve-wine", std::env::var("HOME").unwrap()));
        std::path::Path::new(&prefix).join("drive_c/btrieve")
    }

    /// `C:\btrieve\<name>`, NUL-terminated -- what `B_OPEN`/`B_CREATE` want
    /// in their key buffer, `tools/btrieve-oracle/btrvprobe.c`'s
    /// `open_file`.
    fn dos_path(name: &str) -> Vec<u8> {
        let mut p = format!(r"C:\btrieve\{name}").into_bytes();
        p.push(0);
        p
    }

    /// The `C:\btrieve\<name>` a request carries in its key buffer, read
    /// back out: everything up to the NUL terminator, as text.
    fn name_in(keybuf: &[u8]) -> String {
        let end = keybuf.iter().position(|b| *b == 0).unwrap_or(keybuf.len());
        String::from_utf8_lossy(&keybuf[..end]).into_owned()
    }

    /// A `B_CREATE` request for a file with exactly one key: an
    /// unsigned-binary 4-byte value at record offset 0. See this module's
    /// top-level doc comment for the full `FileSpec`/`KeySpec` wire layout.
    /// `key_modifiable` sets `KFLAG_MODIFY` -- every fixture but the
    /// status-10 pair leaves it off, matching
    /// `crates/btrieve/src/btrcall.rs`'s `scratch_file` helper
    /// (`modifiable: false`).
    fn create_request(name: &str, record_len: u16, key_modifiable: bool) -> Request {
        let mut data = Vec::with_capacity(32);
        // FileSpec, 16 bytes.
        data.extend_from_slice(&record_len.to_le_bytes()); // reclen
        data.extend_from_slice(&512u16.to_le_bytes()); // pagesize
        data.extend_from_slice(&1u16.to_le_bytes()); // indexes_raw
        data.extend_from_slice(&0u32.to_le_bytes()); // records
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.push(0); // dup_pointers
        data.push(0); // unused
        data.extend_from_slice(&0u16.to_le_bytes()); // allocations
        // KeySpec, 16 bytes.
        data.extend_from_slice(&1u16.to_le_bytes()); // position (1-based)
        data.extend_from_slice(&4u16.to_le_bytes()); // length
        let mut flags = KFLAG_EXTTYPE;
        if key_modifiable {
            flags |= KFLAG_MODIFY;
        }
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // approx_count
        data.push(KT_UNSIGNED_BINARY); // ext_type
        data.push(0); // null_value
        data.extend_from_slice(&[0, 0]); // reserved
        data.push(0); // number
        data.push(0); // acs_number

        let keybuf = dos_path(name);
        Request {
            op: B_CREATE,
            posblk: [0u8; 128],
            datalen: data.len() as u32,
            databuf: data,
            keylen: keybuf.len() as u8,
            // Fail if the file already exists -- see this module's own doc
            // comment on never reusing a path.
            keynum: 0,
            keybuf,
        }
    }

    fn open_request(name: &str) -> Request {
        let keybuf = dos_path(name);
        Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: keybuf.len() as u8,
            keynum: MODE_NORMAL,
            keybuf,
        }
    }

    fn close_request() -> Request {
        Request {
            op: B_CLOSE,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: 0,
            keynum: 0,
            keybuf: Vec::new(),
        }
    }

    /// One 8-byte record: a 4-byte little-endian key, then a 4-byte payload
    /// tag repeated across all four bytes so a databuf dump is easy to read
    /// by eye.
    fn record(key: u32, tag: u8) -> Vec<u8> {
        let mut r = vec![0u8; 8];
        r[0..4].copy_from_slice(&key.to_le_bytes());
        r[4..8].copy_from_slice(&[tag; 4]);
        r
    }

    fn insert_request(key: u32, tag: u8) -> Request {
        let data = record(key, tag);
        Request {
            op: B_INSERT,
            posblk: [0u8; 128],
            datalen: data.len() as u32,
            databuf: data,
            keylen: 255,
            keynum: 0,
            keybuf: vec![0u8; 255],
        }
    }

    /// A keyed read (the Get family): the search value goes in `keybuf`,
    /// `keynum` names key 0 (this file's only key), and `datalen` offers a
    /// buffer generously larger than the 8-byte record -- `databuf` itself
    /// is left empty, since only `datalen` governs the real engine's buffer
    /// capacity on this wire (`tools/btrieve-oracle/btrvprobe.c`'s
    /// `serve_one`: `dlen = datalen_in` is what `BTRCALL` actually receives
    /// as the capacity, `databuf_len_in` only pre-fills content). Mirrors
    /// `crates/mbbs/tests/btrieve.rs`'s own `get` helper.
    fn get_request(op: u16, key: u32) -> Request {
        Request {
            op,
            posblk: [0u8; 128],
            datalen: 64,
            databuf: Vec::new(),
            keylen: 255,
            keynum: 0,
            keybuf: key.to_le_bytes().to_vec(),
        }
    }

    /// Get Next/Previous/First/Last: no search value, but still a keyed
    /// read (`keynum` still names key 0), so the reply's key order is the
    /// one this test checks.
    fn get_no_value(op: u16) -> Request {
        Request {
            op,
            posblk: [0u8; 128],
            datalen: 64,
            databuf: Vec::new(),
            keylen: 255,
            keynum: 0,
            keybuf: Vec::new(),
        }
    }

    fn step_request(op: u16) -> Request {
        Request {
            op,
            posblk: [0u8; 128],
            datalen: 64,
            databuf: Vec::new(),
            keylen: 0,
            keynum: 0,
            keybuf: Vec::new(),
        }
    }

    fn stat_request() -> Request {
        Request {
            op: B_STAT,
            posblk: [0u8; 128],
            datalen: 1024,
            databuf: Vec::new(),
            keylen: 255,
            keynum: -1,
            keybuf: vec![0u8; 255],
        }
    }

    /// Update: rewrites the currently-positioned record.
    /// `tools/btrieve-oracle/updprobe.c:275`, `delprobe.c:1028` -- both pass
    /// the new record as `databuf`, a 4-byte `keybuf` (unused by a plain
    /// key-unchanged update; carried anyway to match the measured calling
    /// convention), `keylen: 4`, `keynum: 0`.
    fn update_request(key: u32, tag: u8) -> Request {
        let data = record(key, tag);
        Request {
            op: B_UPDATE,
            posblk: [0u8; 128],
            datalen: data.len() as u32,
            databuf: data,
            keylen: 4,
            keynum: 0,
            keybuf: vec![0u8; 4],
        }
    }

    /// Delete: no databuf, no keybuf -- `tools/btrieve-oracle/delprobe.c:359`,
    /// `btrcall(B_DELETE, posblk, NULL, &dlen, NULL, 0, 0)`.
    fn delete_request() -> Request {
        Request {
            op: B_DELETE,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: 0,
            keynum: 0,
            keybuf: Vec::new(),
        }
    }

    // -----------------------------------------------------------------
    // The v5 variable-length key file. Everything above builds a
    // fixed-length file through the wire's own B_CREATE; the three
    // scenarios below start from a file `crates/btrieve`'s own
    // `create` wrote instead (`Seed::File`), because a B_CREATE over this
    // wire cannot ask for the shape they need: version 5, variable-length
    // records, and a key collating through an ALLCAPS alternate collating
    // sequence. Whether genuine Btrieve 6.15 will keep such a file at
    // version 5 rather than rebuilding it as v6 is exactly what
    // `gate::the_genuine_engine_left_the_file_v5_and_folded_sysop_through_the_acs`
    // measures.
    // -----------------------------------------------------------------

    /// The variable tail's buffer size, `RINGSZ` in MajorBBS's own key
    /// file. What a Get offers the engine as its data-buffer capacity.
    const RINGSZ: u32 = 1024;

    /// The key file the auth work needs: 31-byte fixed portion, one key --
    /// a 30-byte string at offset 0 collating through an ALLCAPS ACS --
    /// and a variable tail. Byte-for-byte the spec
    /// `crates/btrieve/src/create.rs`'s own `keyrec_spec` test helper
    /// builds; that helper is private to its module's test mod, so the
    /// literal is repeated here rather than reached for.
    fn keyrec_spec() -> btrieve::FileSpec {
        btrieve::FileSpec {
            record_length: 31,
            page_size: 1024,
            keys: vec![btrieve::KeySpec {
                segments: vec![btrieve::SegmentSpec {
                    offset: 0,
                    length: 30,
                    kind: 0x0b,
                    descending: false,
                }],
                duplicates: false,
                modifiable: false,
                acs: true,
            }],
            acs: Some(btrieve::acs::allcaps()),
            variable: true,
        }
    }

    /// Builds one empty [`keyrec_spec`] file with `btrieve::create` and
    /// returns its bytes, for a [`Seed::File`] scenario to write into the
    /// Wine prefix.
    ///
    /// The scratch file lives under this crate's own `target/` (gitignored)
    /// and is never committed -- the committed copy of these bytes is the
    /// one inside each fixture, which is also the only copy the replay
    /// harness ever reads.
    fn seed_keyrec_file() -> Vec<u8> {
        let path = fixtures_dir().join("../target/seed_keyrec.dat");
        let dir = path.parent().expect("the path has a parent");
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
        // `btrieve::create` never overwrites, and this runs once per
        // scenario that wants the seed.
        if path.exists() {
            std::fs::remove_file(&path)
                .unwrap_or_else(|e| panic!("removing {}: {e}", path.display()));
        }
        btrieve::create(&path, &keyrec_spec())
            .unwrap_or_else(|e| panic!("creating the seed file: {e}"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    /// One key record: the 30-byte key (a userid, NUL-padded to the key's
    /// full length) followed by the variable tail (a ring of key names,
    /// NUL-terminated). The fixed portion is 31 bytes, so the tail's first
    /// byte still falls inside it -- that is this file's geometry, not an
    /// off-by-one.
    fn keyrec(userid: &str, ring: &str) -> Vec<u8> {
        assert!(
            userid.len() <= 30,
            "userid {userid:?} does not fit this file's 30-byte key"
        );
        let mut rec = vec![0u8; 30];
        rec[..userid.len()].copy_from_slice(userid.as_bytes());
        rec.extend_from_slice(ring.as_bytes());
        rec.push(0);
        rec
    }

    /// Insert one [`keyrec`]. `keylen`/`keybuf` mirror [`insert_request`]:
    /// an Insert takes its key from the record, not from the key buffer,
    /// but the buffer is still handed over at the size the measured calling
    /// convention uses.
    fn insert_keyrec_request(userid: &str, ring: &str) -> Request {
        let data = keyrec(userid, ring);
        Request {
            op: B_INSERT,
            posblk: [0u8; 128],
            datalen: data.len() as u32,
            databuf: data,
            keylen: 255,
            keynum: 0,
            keybuf: vec![0u8; 255],
        }
    }

    /// A keyed read against the key file: the search value is a 30-byte
    /// NUL-padded userid (the key's full declared length), and the engine
    /// is offered a [`RINGSZ`]-byte data buffer so a record with its whole
    /// variable tail fits. `databuf` itself stays empty for the same reason
    /// [`get_request`]'s does -- only `datalen` governs the real engine's
    /// buffer capacity on this wire.
    ///
    /// Pass `""` for the userid on Get First/Next, which take no search
    /// value.
    fn get_keyrec_request(op: u16, userid: &str) -> Request {
        assert!(
            userid.len() <= 30,
            "userid {userid:?} does not fit this file's 30-byte key"
        );
        let mut keybuf = vec![0u8; 30];
        keybuf[..userid.len()].copy_from_slice(userid.as_bytes());
        Request {
            op,
            posblk: [0u8; 128],
            datalen: RINGSZ,
            databuf: Vec::new(),
            keylen: 255,
            keynum: 0,
            keybuf,
        }
    }

    /// Every scenario this crate commits fixtures for, covering Open,
    /// Close, Insert, Update, Delete, the Get family, Step and Stat -- the
    /// opcodes `crates/btrieve/src/btrcall.rs`'s dispatch table implements
    /// (`describe`, `:150-174`).
    fn all_scenarios() -> Vec<Scenario> {
        vec![
            open_close_scenario(),
            insert_get_step_stat_scenario(),
            update_and_delete_scenario(),
            status_ten_scenario(),
            v5_variable_insert_scenario(),
            v5_variable_delete_scenario(),
            v5_variable_grow_scenario(),
            v5_variable_release_empty_scenario(),
            v5_variable_release_reinsert_scenario(),
        ]
    }

    /// Open, Close -- the smallest possible scenario, and a baseline: if
    /// this one disagrees, nothing else can be trusted either.
    fn open_close_scenario() -> Scenario {
        let name = "OPENCLOSE.DAT".to_owned();
        Scenario {
            seed: Seed::Create(create_request(&name, 8, false)),
            calls: vec![open_request(&name), close_request()],
            name: "open_close".to_owned(),
        }
    }

    /// Insert three records out of key order, then read them back every way
    /// this file's Get family and Step family can: Equal, Next, Previous,
    /// Greater, At Most, First, Last, Step First/Next -- plus Stat. Keys
    /// 100, 200, 50 inserted in that physical order make key order (50,
    /// 100, 200) and physical/insertion order (100, 200, 50) diverge, so a
    /// Get that silently answered in physical order instead of key order
    /// would be caught.
    fn insert_get_step_stat_scenario() -> Scenario {
        let name = "GETSTEPSTAT.DAT".to_owned();
        Scenario {
            seed: Seed::Create(create_request(&name, 8, false)),
            calls: vec![
                open_request(&name),
                insert_request(100, 1),
                insert_request(200, 2),
                insert_request(50, 3),
                get_no_value(B_GET_FIRST),    // key order: 50
                get_no_value(B_GET_NEXT),     // 100
                get_no_value(B_GET_NEXT),     // 200
                get_no_value(B_GET_NEXT),     // status 9: end of file
                get_request(B_GET_EQUAL, 100),
                get_no_value(B_GET_PREVIOUS), // 50
                get_no_value(B_GET_LAST),     // 200
                get_request(B_GET_GREATER, 100),  // 200
                get_request(B_GET_AT_MOST, 150),  // 100
                step_request(B_STEP_FIRST),   // physical order: 100
                step_request(B_STEP_NEXT),    // 200
                step_request(B_STEP_NEXT),    // 50
                step_request(B_STEP_NEXT),    // status 9: end of file
                stat_request(),
                close_request(),
            ],
            name: "insert_get_step_stat".to_owned(),
        }
    }

    /// Insert, Update (payload only, key unchanged), Delete -- each
    /// verified with a Get Equal immediately after.
    fn update_and_delete_scenario() -> Scenario {
        let name = "UPDDEL.DAT".to_owned();
        Scenario {
            seed: Seed::Create(create_request(&name, 8, false)),
            calls: vec![
                open_request(&name),
                insert_request(42, 1),
                get_request(B_GET_EQUAL, 42), // establishes currency
                update_request(42, 9),
                get_request(B_GET_EQUAL, 42), // payload changed
                delete_request(),             // deletes the record Get just positioned on
                get_request(B_GET_EQUAL, 42), // status 4: gone
                close_request(),
            ],
            name: "update_and_delete".to_owned(),
        }
    }

    /// The scenario that matters most: a key declared NOT modifiable
    /// refuses an update that would change its value (status 10, nothing
    /// written), and the identical bytes rewritten with the SAME key value
    /// succeed (status 0). `docs/2026-08-16-v6-update-delete-oracle.md`
    /// measured both halves through the raw C probes
    /// (`delprobe.exe modsame`); this fixture pins the same two answers
    /// through the wire this crate's Rust client actually uses, so Task 12
    /// can replay them against `btrcall` rather than resting on a probe
    /// transcript alone.
    fn status_ten_scenario() -> Scenario {
        let name = "MODKEY.DAT".to_owned();
        Scenario {
            seed: Seed::Create(create_request(&name, 8, false)), // key NOT modifiable
            calls: vec![
                open_request(&name),
                insert_request(42, 1),
                get_request(B_GET_EQUAL, 42), // currency
                // Refused: changes the key's value.
                update_request(99, 1),
                get_request(B_GET_EQUAL, 42), // still there, untouched
                get_request(B_GET_EQUAL, 99), // status 4: nothing written under the new key
                get_request(B_GET_EQUAL, 42), // re-establish currency
                // Allowed: the key is rewritten with the value it already
                // has, only the payload changes.
                update_request(42, 9),
                get_request(B_GET_EQUAL, 42), // payload changed, key unchanged
                close_request(),
            ],
            name: "status_ten_refusal_and_same_value_rewrite".to_owned(),
        }
    }

    /// Insert two key records into a v5 variable-length file our own
    /// `create` wrote, then read them back -- including a Get Equal for
    /// `sysop` in lower case against a record inserted as `Sysop`, which
    /// only finds anything if the ALLCAPS alternate collating sequence is
    /// really in force.
    ///
    /// Each of the three scenarios below uses its own DOS filename: the
    /// Microkernel caches pages by path across processes, so two scenarios
    /// in one run must never share one (this module's own doc comment).
    fn v5_variable_insert_scenario() -> Scenario {
        let name = "KEYSINS.DAT";
        Scenario {
            name: "v5_variable_insert".to_owned(),
            seed: Seed::File(seed_keyrec_file()),
            calls: vec![
                open_request(name),
                insert_keyrec_request("Sysop", "DEMO NORMAL SYSOP"),
                insert_keyrec_request("&USER", "DEMO NORMAL"),
                get_keyrec_request(B_GET_EQUAL, "sysop"), // ACS: lower case finds it
                get_keyrec_request(B_GET_FIRST, ""),
                get_keyrec_request(B_GET_NEXT, ""),
                get_keyrec_request(B_GET_NEXT, ""), // status 9: end of file
                close_request(),
            ],
        }
    }

    /// Delete a record from a v5 variable-length file, confirm it is gone,
    /// then insert a longer record -- does the engine reuse the freed
    /// fragment, and what does the file look like afterwards.
    fn v5_variable_delete_scenario() -> Scenario {
        let name = "KEYSDEL.DAT";
        Scenario {
            name: "v5_variable_delete".to_owned(),
            seed: Seed::File(seed_keyrec_file()),
            calls: vec![
                open_request(name),
                insert_keyrec_request("Sysop", "DEMO NORMAL SYSOP"),
                insert_keyrec_request("Test", "DEMO"),
                get_keyrec_request(B_GET_EQUAL, "Sysop"), // establishes currency
                delete_request(),
                get_keyrec_request(B_GET_EQUAL, "Sysop"), // status 4: gone
                insert_keyrec_request("Testy", "DEMO NORMAL MODERATE MASS_MAIL"),
                close_request(),
            ],
        }
    }

    /// The only fragment on a page is deleted and nothing follows: what
    /// genuine does to an emptied variable page (free chain? PAGES?
    /// VARIABLE_HIGHEST?).
    fn v5_variable_release_empty_scenario() -> Scenario {
        let name = "KEYSREL.DAT";
        Scenario {
            name: "v5_variable_release_empty".to_owned(),
            seed: Seed::File(seed_keyrec_file()),
            calls: vec![
                open_request(name),
                insert_keyrec_request("Only", "DEMO"),
                get_keyrec_request(B_GET_EQUAL, "Only"),
                delete_request(),
                get_keyrec_request(B_GET_EQUAL, "Only"), // status 4
                close_request(),
            ],
        }
    }

    /// The only fragment on a page is deleted and another record follows:
    /// whether the emptied page is reused for the new fragment.
    fn v5_variable_release_reinsert_scenario() -> Scenario {
        let name = "KEYSREI.DAT";
        Scenario {
            name: "v5_variable_release_reinsert".to_owned(),
            seed: Seed::File(seed_keyrec_file()),
            calls: vec![
                open_request(name),
                insert_keyrec_request("Only", "DEMO"),
                get_keyrec_request(B_GET_EQUAL, "Only"),
                delete_request(),
                insert_keyrec_request("Next", "DEMO NORMAL"),
                get_keyrec_request(B_GET_EQUAL, "next"), // ACS: found
                close_request(),
            ],
        }
    }

    /// Enough records to need a second variable page: 1024-byte pages, so
    /// 60 records of about 50 bytes force the engine off the file's one
    /// pre-allocated data page and into fresh physical pages.
    fn v5_variable_grow_scenario() -> Scenario {
        let name = "KEYSGRW.DAT";
        let mut calls = vec![open_request(name)];
        for n in 0..60u32 {
            calls.push(insert_keyrec_request(
                &format!("User{n:02}"),
                "DEMO NORMAL MODERATE",
            ));
        }
        calls.push(get_keyrec_request(B_GET_EQUAL, "User59"));
        calls.push(close_request());
        Scenario {
            name: "v5_variable_grow".to_owned(),
            seed: Seed::File(seed_keyrec_file()),
            calls,
        }
    }

    /// The one thing in this module that runs in an ordinary `cargo test`:
    /// it reads the committed `v5_variable_insert.fixture` and never goes
    /// near Wine. It lives here rather than beside `encoding_tests`
    /// because it reads the same opcode constants the scenarios are built
    /// from.
    mod gate {
        use super::*;

        fn insert_fixture() -> Fixture {
            let path = fixtures_dir().join("v5_variable_insert.fixture");
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            Fixture::decode(&bytes)
                .unwrap_or_else(|e| panic!("decoding {}: {e}", path.display()))
        }

        /// Two questions this branch could not answer without a recording,
        /// asked of the same transcript.
        ///
        /// **Did the file stay v5?** Genuine Btrieve 6.15 is a v6 engine,
        /// and nothing promised it would leave a v5 file alone rather than
        /// rebuilding it in its own format on the first write. If it had,
        /// every v5 measurement taken from these fixtures would be about a
        /// file the engine no longer had, and this branch's plan would have
        /// stopped here. A v5 control record opens with four zero bytes and
        /// carries its version in byte 7 (`crate::version`, and
        /// `btrieve::create`'s `fcr::VERSION_BYTE`); a v6 one opens `"FC"`.
        ///
        /// **Did the ALLCAPS collating sequence work?** The scenario
        /// inserts `Sysop` and then asks for `sysop`. Under raw byte
        /// ordering that finds nothing (status 4). Status 0, with the
        /// `Sysop` record and its whole variable tail in the reply, is the
        /// genuine engine reading -- from a file this project's own
        /// `create` wrote -- the ACS block and the key's collating flag
        /// that Tasks 1 and 2 put there.
        #[test]
        fn the_genuine_engine_left_the_file_v5_and_folded_sysop_through_the_acs() {
            let fixture = insert_fixture();
            let file = &fixture.transcript.file;

            assert_ne!(
                &file[..2],
                b"FC",
                "the engine rebuilt the file as v6; first 0x40 bytes: {:02x?}",
                &file[..0x40]
            );
            assert_eq!(
                &file[..4],
                &[0, 0, 0, 0],
                "not a v5 file control record; first 0x40 bytes: {:02x?}",
                &file[..0x40]
            );
            assert_eq!(
                file[0x07],
                4,
                "v5 version byte; first 0x40 bytes: {:02x?}",
                &file[..0x40]
            );

            let calls = fixture.scenario.calls.iter();
            let pairs: Vec<_> = calls.zip(&fixture.transcript.responses).collect();
            for (call, resp) in &pairs {
                if call.op == B_INSERT {
                    assert_eq!(
                        resp.status, 0,
                        "the engine refused an insert into the v5 variable-length file"
                    );
                }
            }

            let (_, resp) = pairs
                .iter()
                .find(|(call, _)| call.op == B_GET_EQUAL && call.keybuf.starts_with(b"sysop"))
                .expect("the scenario asks for `sysop` in lower case");
            assert_eq!(
                resp.status, 0,
                "lower-case `sysop` did not find the `Sysop` record: the ACS did not collate"
            );
            assert_eq!(
                &resp.databuf[..5],
                b"Sysop",
                "the record found under `sysop` is not the one inserted as `Sysop`"
            );
        }
    }

    /// Drives one `Scenario` over an already-spawned `Engine`: performs the
    /// seed, then every call in order, threading `posblk` by hand (see this
    /// module's top-level doc comment), and reads the resulting file's
    /// bytes back off disk once every call has landed.
    fn drive(
        scenario: &Scenario,
        engine: &mut crate::Engine,
        file_path: &std::path::Path,
    ) -> Result<Transcript, String> {
        match &scenario.seed {
            Seed::Create(req) => {
                // Measured here: genuine Btrieve's B_CREATE does NOT leave
                // the file open the way B_OPEN does -- the posblk it hands
                // back is untouched (still all zero), and a B_CLOSE against
                // it answers status 3, "file not open".
                // `tools/btrieve-oracle/btrvprobe.c`'s own `cmd_create`
                // fires a B_CLOSE right after anyway, but never checks its
                // status, which is how this went unnoticed there. So Create
                // just creates; the scenario's own first call (a B_OPEN)
                // does the actual opening.
                let resp = engine.call(req.clone())?;
                if resp.status != 0 {
                    return Err(format!(
                        "{}: seed B_CREATE failed with status {}",
                        scenario.name, resp.status
                    ));
                }
            }
            Seed::File(bytes) => {
                std::fs::write(file_path, bytes)
                    .map_err(|e| format!("{}: writing seed file: {e}", scenario.name))?;
            }
        }

        let mut posblk = [0u8; 128];
        let mut responses = Vec::with_capacity(scenario.calls.len());
        for call in &scenario.calls {
            let mut req = call.clone();
            req.posblk = posblk;
            let resp = engine.call(req)?;
            posblk = resp.posblk;
            responses.push(resp);
        }

        let file = std::fs::read(file_path)
            .map_err(|e| format!("{}: reading the resulting file: {e}", scenario.name))?;
        Ok(Transcript { responses, file })
    }

    /// Generates and commits `fixtures/*.fixture`, one per [`all_scenarios`]
    /// entry, from genuine Pervasive Btrieve 6.15 under Wine. See this
    /// module's top-level doc comment for the exact invocation. Never run
    /// by a bare `cargo test`.
    #[test]
    #[ignore = "drives genuine Btrieve under Wine; see this module's doc comment"]
    fn record_fixtures_from_the_genuine_engine() {
        if !wine_on_path() {
            eprintln!("skipped: wine is not on PATH");
            return;
        }

        let mut engine = crate::Engine::spawn().expect("spawning btrvprobe serve");
        let pid = std::process::id();
        let work_dir = btrieve_work_dir();

        for scenario in all_scenarios() {
            // A recorded fixture is data, and the process id below is baked
            // into it, so re-recording rewrites a committed file for no
            // reason. Only a deliberate RERECORD=1 does that.
            if fixtures_dir().join(format!("{}.fixture", scenario.name)).exists()
                && std::env::var("RERECORD").as_deref() != Ok("1")
            {
                eprintln!("skipped (exists): {}", scenario.name);
                continue;
            }

            // Every scenario's own filename, per its `create_request`/seed,
            // is prefixed with this process's id so two runs -- or two
            // scenarios that happened to pick the same base name -- never
            // collide on a path the Microkernel might have cached.
            let dos_name = match &scenario.seed {
                Seed::Create(req) => name_in(&req.keybuf),
                // A pre-built file carries no filename of its own, so the
                // scenario's first call -- which must be the B_OPEN that
                // opens it -- is what says where the file goes.
                Seed::File(_) => match scenario.calls.first() {
                    Some(req) if req.op == B_OPEN => name_in(&req.keybuf),
                    _ => panic!(
                        "{}: a Seed::File scenario must open its file with a B_OPEN first call; \
                         nothing else says what to call the file",
                        scenario.name
                    ),
                },
            };
            // dos_name is `C:\btrieve\<base>`; re-derive the base and give
            // it this process's id, then rebuild every request that
            // referenced the un-prefixed name.
            let base = dos_name.rsplit('\\').next().expect("has a backslash");
            let unique = format!("{pid}{base}");
            let scenario = reprefix(scenario, base, &unique);

            let file_path = work_dir.join(&unique);
            let transcript = drive(&scenario, &mut engine, &file_path)
                .unwrap_or_else(|e| panic!("recording {}: {e}", scenario.name));

            eprintln!(
                "{}: {} call(s), {} status(es): {:?}",
                scenario.name,
                scenario.calls.len(),
                transcript.responses.len(),
                transcript.responses.iter().map(|r| r.status).collect::<Vec<_>>()
            );

            let fixture = Fixture { scenario, transcript };
            let path = fixture.write(&fixtures_dir()).expect("writing the fixture");
            eprintln!("  wrote {}", path.display());

            let _ = std::fs::remove_file(&file_path);
        }
    }

    /// Rewrites every `Request` in `scenario` that names `old` (the
    /// un-prefixed DOS filename) in its `keybuf`, replacing it with `new`.
    /// Only the seed's `B_CREATE` and the first call's `B_OPEN` ever carry a
    /// filename on this wire, but this walks every call rather than
    /// special-casing which ones, so a future scenario that reopens the
    /// file mid-sequence is not a silent trap.
    fn reprefix(scenario: Scenario, old: &str, new: &str) -> Scenario {
        let rewrite = |mut req: Request| -> Request {
            if let Some(pos) = find_subsequence(&req.keybuf, old.as_bytes()) {
                let mut keybuf = req.keybuf[..pos].to_vec();
                keybuf.extend_from_slice(new.as_bytes());
                keybuf.extend_from_slice(&req.keybuf[pos + old.len()..]);
                req.keylen = keybuf.len() as u8;
                req.keybuf = keybuf;
            }
            req
        };

        let seed = match scenario.seed {
            Seed::Create(req) => Seed::Create(rewrite(req)),
            other @ Seed::File(_) => other,
        };
        let calls = scenario.calls.into_iter().map(rewrite).collect();
        Scenario { name: scenario.name, seed, calls }
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}
