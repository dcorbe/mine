//! Btrieve operation 15, STAT: report a file's shape and key definitions in
//! Btrieve's own reply format.
//!
//! `dfaCountRec` and `dfaRecLen` (`re/wg33src/SRC/api/gcommlib/DFAAPI.C:778,
//! 790`) need none of this -- both issue a full `B_STAT` and then read
//! exactly one field back out of it (`fs.numofr`, `fs.reclen`), and this
//! host already has both on [`super::Geometry`] without a wire reply to
//! build. What is missing, and what this module builds, is the reply
//! `dfaStat` and `dfaStatus` (`DFAAPI.C:810,820`) hand a module verbatim:
//! Btrieve's own byte layout, not this crate's own [`super::Geometry`]/
//! [`super::keys::Key`] shapes.
//!
//! # The vendor header describes the request; the wire was measured
//!
//! `re/wg33src/SRC/api/gcommlib/DFAAPI.C:31-57` (`struct filspc`/`struct
//! keyspc`) and `re/wg33src/INC/DFAAPI.H:147-165` (`struct
//! dfaStatFileSpec`/`struct dfaStatKeySpec`, the create-side sibling
//! `create.rs` already reads) between them give the field WIDTHS right --
//! every offset below matches both headers' byte counts -- but neither says
//! what the engine actually WRITES: whether the 265-byte `altcol` tail
//! `struct statbf` reserves is ever filled, whether a short buffer gets a
//! truncated prefix or something else, or what `keyno` changes. Those are
//! measured here, against genuine Pervasive Btrieve 6.15 under Wine, with
//! `tools/btrieve-oracle/statprobe.c` (`dump`/`trunc`/`keyno` commands) --
//! not inferred from the struct declarations. Every number below with no
//! citation of its own is that program's `dump` output, hex-checked against
//! this crate's own [`super::Geometry`]/[`super::keys::parse`] on the same
//! file.
//!
//! ## The reply has no 265-byte tail, and one entry per SEGMENT
//!
//! `struct statbf` reserves `ACSSIZ` (265) bytes of alternate-collating-
//! sequence space after the key specs. **Measured: it is never sent.** A
//! full `B_STAT` on `WCCUSERS.DAT` (three keys, reclen 1998) returns exactly
//! 64 bytes -- 16 (file spec) + 3*16 (one key spec each) -- with `outlen`
//! reported back through the in/out length pointer, whatever buffer was
//! offered. `WCCBANKS.DAT` (one key, two segments) returns 48 bytes for one
//! reported "index": the reply carries one `KeySpec` **per segment**, not
//! per key, confirmed by its second entry's `ANOSEG` bit (`0x10`) being
//! clear only on the last segment -- exactly the split
//! [`super::keys::Key::number`] and [`super::keys::Key::definition`] already
//! draw on the read side, and the same distinction `tools/btrieve-oracle/
//! btrvprobe.c`'s own `key_extent()` comment names for the read-only `stat`
//! command this module's `statprobe.c` grew out of.
//!
//! ## `approx_count` is a stored field, not a live count
//!
//! Every key spec carries a `DWORD` `approx_count`. Two shipped files with
//! non-zero records and a *unique* key (`WCCTEXT.DAT`: reclen 22, key length
//! 18, 3,467 records; `WCCITEMS.DAT`: reclen 1061, 1,950 records) read it
//! back exactly equal to the file's own record count -- unsurprising for a
//! unique key, but it independently pins where the number comes from: byte-
//! for-byte, both files hold that exact number, high-word-first
//! ([`super::pages::long`]), at [`super::pages::fcr::KEY_RECORDS`] of the
//! key's *own first definition* -- the same field [`super::Btrieve::reindex`]
//! already maintains on every write this crate performs. Confirmed
//! distinctly from "unique key coincidence" with a throwaway file this
//! session's own oracle built and populated (`tools/btrieve-oracle/
//! crtprobe.c create`/`insert`, one duplicate-permitting key): three records
//! sharing one key value read `approx_count = 1`; a fourth record under a
//! *second* value read `approx_count = 2` -- the **distinct index-entry
//! count**, not the record count (which read 3 and 4 respectively, in the
//! file spec's own `records` field, at the same two points). So this module
//! never recomputes anything from loaded records: it reads
//! [`super::pages::fcr::KEY_RECORDS`] straight off the file control record,
//! exactly the field this crate's own write path already keeps correct.
//!
//! A multi-segment key's *continuation* definitions carry no such field --
//! `create.rs`'s own `build_fcr` only writes `KEY_RECORDS`/`KEY_ROOT` etc.
//! when `sn == 0` -- so every segment of a key repeats the **first**
//! definition's `approx_count`, the same way every segment of `WCCBANKS`'s
//! one key repeats `number = 0` in the measurement above (`WCCITOWN.DAT`'s
//! second key, two segments, both read `number = 1`). Read from disk once
//! per key, not once per definition.
//!
//! ## A v6 file's `position` is measured from the record, not the slot
//!
//! `NEWMP001.VIR` -- the one v6 file MajorMUD ships -- caught a genuine bug
//! in an early version of this module: its one key reads `offset = 2` at
//! [`at::OFFSET`], so `position = offset + 1` gave `3`, and genuine Btrieve
//! answered `1`. `records.rs`'s own `key_shift` already names why: a v6
//! record's physical slot opens with a two-byte marker the module never
//! sees (`Records::read`'s `key_shift = 2` for [`Version::V6`], `0`
//! otherwise), so [`at::OFFSET`] -- which is measured from the *slot*, the
//! same reference point [`super::keys::Segment::offset`] uses before
//! `records.rs`'s own `keyed()` pads it back out -- reads two bytes ahead of
//! where the module's own record starts. **`position` is measured from the
//! record**, not the slot, so this module subtracts `key_shift` before
//! adding the wire's `+1`: `1` on `NEWMP001.VIR`, confirmed against genuine
//! Btrieve. No v5 file is affected -- `key_shift` is `0` for all seventeen.
//!
//! ## `keyno`, and version
//!
//! `dfaStatus` passes an explicit key number (`DFAAPI.C:820`); `dfaStat`,
//! `dfaCountRec` and `dfaRecLen` all pass `0` (`:784,800,815`) --
//! `btrvprobe.c`'s own `stat_file()` helper instead defaults to `-1`, which
//! is what first surfaced this: **the reply's key specs never change with
//! `keyno`**, at any value, in range or out (`WCCUSERS.DAT`, three keys,
//! keyno 0, 2, 5 and -2 all returned the identical 48 trailing bytes). The
//! *only* thing `keyno` changes is the top byte of the file spec's
//! `indexes` word: it reads `0x40` when `keyno == -1` and `0x00` for every
//! other value tried, on every v5 file measured -- confirming
//! `tools/btrieve-oracle/btrvprobe.c`'s own `fs_indexes()` comment ("a flag
//! bit the Programmer's Reference does not put in this field") without
//! explaining it, until `NEWMP001.VIR` -- the one v6 file MajorMUD ships --
//! read `0x60` at `keyno == -1` and `0x00` at `keyno == 0`, the identical
//! pattern a fresh v6 file this session's own `crtprobe.c` built and
//! populated also showed. **The high byte is `0x40 | (version==6 ? 0x20 :
//! 0) ` when `keyno == -1`, and `0x00` otherwise** -- a version marker folded
//! into the same word as the "no key requested" flag, visible only when a
//! caller asks for one.
//!
//! ## Truncation: whole 16-byte units only, and a floor under 16 bytes this
//! module refuses to guess at
//!
//! `tools/btrieve-oracle/statprobe.c trunc` swept buffer lengths against
//! `WCCUSERS.DAT` (64-byte full reply). Status 22 ("data buffer too short")
//! for anything under 64, exactly as `docs/plans/2026-08-12-btrieve-finish.md`
//! Task 7 already established for record GETs ("truncate and continue, not
//! failed") -- but the *content* written is not a byte-exact prefix cut at
//! the offered length. It is cut at the next lower multiple of 16: offering
//! 17-31 bytes still returns only the first 16 (the file spec alone, no key
//! spec at all); offering 60-63 returns 48 (two whole key specs, the third
//! dropped entire); offering 64 returns all 64 with status 0. **Below one
//! whole unit (under 16 bytes), the reply is measured NOT to be a prefix of
//! the real bytes at all** -- offering 4 bytes returned `ff ff ff ff`,
//! reproducibly across repeated calls, not the real header's `ce 07 00 08`.
//! No real caller in `DFAAPI.C` ever offers a STAT buffer under 16 bytes
//! (`dfaCountRec`/`dfaRecLen` always pass `sizeof(struct statbf)`, `dfaStat`/
//! `dfaStatus` take a caller's `len`, which for any of MajorMUD's own
//! `struct`s is far larger than one file spec), so [`deliver`] does not
//! attempt to reproduce that byte pattern -- it returns nothing for a buffer
//! that short, which is honest about "not a real prefix" without inventing
//! a shape nothing on hand explains.

use std::path::Path;

use crate::mem::Mem;

use super::keys::Key;
use super::{pages, BtvError, Geometry, Version};

/// Bytes of the file-spec header -- `struct filspc`/`struct dfaStatFileSpec`,
/// confirmed by this module's own measurement (see the module doc comment)
/// to be exactly what the reply opens with, never padded to
/// `sizeof(struct statbf)`.
const FILE_SPEC_WIDTH: usize = 16;

/// Bytes of one key spec -- `struct keyspc`/`struct dfaStatKeySpec`, one per
/// **segment**, not per key. Same width as [`FILE_SPEC_WIDTH`]; both were
/// measured as the unit truncation rounds down to, see [`deliver`].
const KEY_SPEC_WIDTH: usize = 16;

/// Where the fields this module writes live in the file control record.
/// Restated locally rather than imported -- the same convention `create.rs`'s
/// own `at` module explains: a self-contained table beats importing from
/// three modules for a handful of offsets. [`KEYS_BASE`]/[`KEY_WIDTH`] match
/// [`super::keys`]'s private `BASE`/`WIDTH` and [`super::pages::fcr::KEYS`]/
/// [`super::pages::fcr::KEY_WIDTH`]; [`KEY_RECORDS`] matches
/// [`super::pages::fcr::KEY_RECORDS`]. `ATTRIBUTES`/`OFFSET`/`LENGTH`/
/// `EXTENDED` match [`super::keys`]'s private `at` module and `create.rs`'s
/// own `at` module of the same names.
mod at {
    /// Where key definitions start in the file control record.
    pub const KEYS_BASE: usize = 0x110;
    /// Bytes of one key definition.
    pub const KEY_WIDTH: usize = 0x1e;
    /// How many records this key indexes -- a [`super::super::pages::long`],
    /// meaningful only on a key's *first* definition (see the module doc
    /// comment's "`approx_count` is a stored field" section).
    pub const KEY_RECORDS: usize = 0x04;
    /// Attribute flags -- copied verbatim into the reply's key spec `flags`
    /// word. This crate's own reader ([`super::super::keys::parse`]) decodes
    /// these bits into [`Key`]'s booleans and loses the ones it does not
    /// need (`DFAKF_MODIFYABLE`, in particular -- `create.rs`'s own
    /// `attrs::MODIFIABLE` doc comment: "has no effect on anything this
    /// crate reads"), which is exactly why this module reads the word fresh
    /// from disk instead of reconstructing it from `Key`/`Segment`.
    pub const ATTRIBUTES: usize = 0x08;
    /// Segment offset within the record, 0-based on disk.
    pub const OFFSET: usize = 0x14;
    /// Segment length in bytes.
    pub const LENGTH: usize = 0x16;
    /// The extended data type byte, verbatim. [`super::super::keys::Kind`]
    /// collapses several distinct codes to one ordering (`0x00`/`0x0a`/
    /// `0x0b`/`0x20` all read as [`super::super::keys::Kind::Text`]), so
    /// only a fresh read of this byte can tell them apart for the wire.
    pub const EXTENDED: usize = 0x1c;
}

/// One key's contribution to a STAT reply -- what a module reads back as one
/// `struct keyspc`/`struct dfaStatKeySpec` entry. One of these per **segment**
/// of a key, not one per key -- see this module's doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatKey {
    /// 1-based byte offset of this segment within the **record** -- the
    /// same `+1` `DFAAPI.C:734` applies once when it builds a create request
    /// (`create.rs`'s own [`super::SegmentSpec`] doc comment). On a v5 file
    /// this is [`super::keys::Segment::offset`] plus one; on v6, the raw
    /// on-disk field is measured from the *slot*, two bytes ahead of the
    /// record, and this module subtracts that shift first -- see the module
    /// doc comment's "a v6 file's `position` is measured from the record,
    /// not the slot" section.
    pub position: u16,
    /// This segment's length in bytes.
    pub length: u16,
    /// The raw attribute word, verbatim off disk -- the same bit numbering
    /// [`super::keys::flag`] reads and `create.rs`'s own `attrs` module
    /// writes (`DUPLICATES=1`, `MODIFIABLE=2`, `OLD_BINARY=4`, `ANOSEG=0x10`,
    /// `DESCENDING=0x40`, `EXTENDED=0x100`), including bits neither of those
    /// modules exposes (`MODIFIABLE`).
    pub flags: u16,
    /// Distinct index entries this key holds -- see the module doc comment's
    /// "`approx_count` is a stored field" section. Repeated identically
    /// across every segment of a multi-segment key.
    pub approx_count: u32,
    /// The raw extended type byte, verbatim off disk.
    pub ext_type: u8,
    /// This key's own zero-based ordinal -- [`super::keys::Key::number`].
    /// Repeated identically across every segment of a multi-segment key,
    /// measured on `WCCITOWN.DAT`'s two-segment second key (both segments
    /// read `number = 1`).
    pub number: u8,
}

/// A file's STAT reply, before it is serialised to Btrieve's wire bytes.
/// Plain data -- no `mbbs_machine::m16::Machine`, no
/// `mbbs_machine::m16::FarPtr` -- so both ABIs' `dfaStat`/`dfaStatus`
/// marshalling can build on the same reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub reclen: u16,
    pub pagesize: u16,
    /// How many keys, **not segments** -- the low byte of the wire's
    /// `indexes` word. Always fits `u8`: [`super::keys::SEGMAX`] (24) bounds
    /// the segment count, and a key is at least one segment.
    pub keys: u8,
    pub records: u32,
    /// Bit 0 of the wire's `flags` word -- measured equal to
    /// [`super::Geometry::variable`] on every file checked (`WCCTEXT.DAT`:
    /// `0x0001`; every non-variable file measured: `0x0000`). No file
    /// checked sets any other bit, matching this crate's own
    /// [`super::flag`] doc comment that nothing in `tmp/` sets compression
    /// or blank truncation either -- so only this one bit is reproduced,
    /// and it is the only one this module has ever seen requested.
    pub variable: bool,
    /// One entry per key **segment**, in file order.
    pub key_specs: Vec<StatKey>,
}

impl Stat {
    /// Read `path`'s STAT reply out of its geometry and already-parsed keys.
    ///
    /// `keys` supplies the *shape* -- which definitions belong to which key,
    /// in what order, and each key's own number -- exactly what
    /// [`super::keys::parse`] already computed correctly for
    /// [`super::Block::keys`]. What it does **not** supply is read fresh from
    /// the file control record here: the raw attribute word, the raw
    /// extended-type byte, and the stored distinct-entry count, none of
    /// which [`Key`]/[`super::keys::Segment`] preserve (see this module's
    /// doc comment and [`at::ATTRIBUTES`]'s own doc comment for why).
    ///
    /// No records are loaded -- unlike [`super::Block::records`], this reads
    /// only the file's first page, which is why [`super::Block::stat`] takes
    /// `&self` rather than `&mut self`: real Btrieve does not recompute
    /// `approx_count` at `B_STAT` time either, it reports what the last
    /// write already stored (see the module doc comment).
    ///
    /// # Errors
    ///
    /// If the first page cannot be read, or a key's own definition or its
    /// first definition's record-count field runs past it.
    pub fn read(name: &str, path: &Path, geometry: &Geometry, keys: &[Key]) -> Result<Self, BtvError> {
        let fail = |why: String| BtvError {
            file: name.to_owned(),
            why,
        };

        let fcr = super::read_head(path, usize::from(geometry.page))
            .map_err(|e| fail(format!("{}: {e}", path.display())))?;

        // A v6 record's physical slot opens with a two-byte marker the
        // module never sees -- `records.rs`'s own `key_shift`, and this
        // module's own doc comment's "a v6 file's `position` is measured
        // from the record, not the slot" section, which is where
        // `NEWMP001.VIR` caught this being missing.
        let key_shift: u16 = if geometry.version == super::Version::V6 { 2 } else { 0 };

        let mut key_specs = Vec::new();
        for key in keys {
            let first_at = at::KEYS_BASE + usize::from(key.definition) * at::KEY_WIDTH;
            let records_at = first_at + at::KEY_RECORDS;
            let approx_count = fcr
                .get(records_at..records_at + 4)
                .map(pages::long)
                .ok_or_else(|| {
                    fail(format!(
                        "key {}: its record-count field at {records_at:#x} runs past this \
                         file's {}-byte first page",
                        key.number,
                        fcr.len()
                    ))
                })?;

            for segment in 0..key.segments.len() {
                let def_at = at::KEYS_BASE + (usize::from(key.definition) + segment) * at::KEY_WIDTH;
                let def = fcr.get(def_at..def_at + at::KEY_WIDTH).ok_or_else(|| {
                    fail(format!(
                        "key {} segment {segment}: its definition at {def_at:#x} runs past \
                         this file's {}-byte first page",
                        key.number,
                        fcr.len()
                    ))
                })?;
                let word = |offset: usize| u16::from_le_bytes([def[offset], def[offset + 1]]);
                let slot_offset = word(at::OFFSET);
                let record_offset = slot_offset.checked_sub(key_shift).ok_or_else(|| {
                    fail(format!(
                        "key {} segment {segment}: its offset ({slot_offset}) is inside this \
                         v6 file's {key_shift}-byte slot marker, which should not happen -- a \
                         real key segment is always inside the record, past the marker",
                        key.number
                    ))
                })?;
                key_specs.push(StatKey {
                    position: record_offset + 1,
                    length: word(at::LENGTH),
                    flags: word(at::ATTRIBUTES),
                    approx_count,
                    ext_type: def[at::EXTENDED],
                    number: key.number as u8,
                });
            }
        }

        let nkeys = u8::try_from(keys.len())
            .map_err(|_| fail(format!("{} keys, more than a byte can hold", keys.len())))?;

        Ok(Self {
            reclen: geometry.reclen,
            pagesize: geometry.page,
            keys: nkeys,
            records: geometry.records,
            variable: geometry.variable,
            key_specs,
        })
    }

    /// Serialise this into Btrieve's `B_STAT` reply bytes -- the full,
    /// untruncated reply; see [`deliver`] for what a caller's own buffer
    /// length actually receives.
    ///
    /// `keyno` is the value `dfaStatus` passes explicitly (`dfaStat`,
    /// `dfaCountRec` and `dfaRecLen` all pass `0`) -- see the module doc
    /// comment's "`keyno`, and version" section for what it changes.
    pub fn wire(&self, version: Version, keyno: i8) -> Vec<u8> {
        let mut out = Vec::with_capacity(FILE_SPEC_WIDTH + self.key_specs.len() * KEY_SPEC_WIDTH);

        let high: u16 = if keyno == -1 {
            0x40 | if version == Version::V6 { 0x20 } else { 0 }
        } else {
            0
        };
        let indexes_raw = u16::from(self.keys) | (high << 8);

        out.extend_from_slice(&self.reclen.to_le_bytes());
        out.extend_from_slice(&self.pagesize.to_le_bytes());
        out.extend_from_slice(&indexes_raw.to_le_bytes());
        out.extend_from_slice(&self.records.to_le_bytes());
        let flags: u16 = if self.variable { 1 } else { 0 };
        out.extend_from_slice(&flags.to_le_bytes());
        out.push(0); // dup_pointers -- measured zero on every file, see StatKey's doc comment
        out.push(0); // unused -- measured zero on every file
        out.extend_from_slice(&0u16.to_le_bytes()); // allocations -- measured zero on every file

        for key in &self.key_specs {
            out.extend_from_slice(&key.position.to_le_bytes());
            out.extend_from_slice(&key.length.to_le_bytes());
            out.extend_from_slice(&key.flags.to_le_bytes());
            out.extend_from_slice(&key.approx_count.to_le_bytes());
            out.push(key.ext_type);
            out.push(0); // null_value -- keys::parse already refuses NULL_ALL/NULL_ANY, so
                         // no key this reaches can carry a null value
            out.extend_from_slice(&[0, 0]); // reserved -- measured zero on every file
            out.push(key.number);
            out.push(0); // acs_number -- keys::parse already refuses a numbered ACS
        }

        debug_assert_eq!(out.len(), FILE_SPEC_WIDTH + self.key_specs.len() * KEY_SPEC_WIDTH);
        out
    }
}

/// What a `buffer_len`-byte caller buffer actually receives of `full` (a
/// [`Stat::wire`] reply), and whether that is short of the whole thing.
///
/// Measured (`tools/btrieve-oracle/statprobe.c trunc`, this module's doc
/// comment): real Btrieve writes only whole [`FILE_SPEC_WIDTH`]/
/// [`KEY_SPEC_WIDTH`]-byte units that fit entirely inside `buffer_len`, in
/// order, and reports "too short" whenever any unit had to be dropped --
/// even one byte short of the next unit still gets nothing more. Below one
/// whole unit, this returns nothing (see the module doc comment for why the
/// measured 0xFF-filled bytes are not reproduced): no real caller ever
/// offers a STAT buffer that short, so there is no real shape to match.
pub fn deliver(full: &[u8], buffer_len: usize) -> (&[u8], bool) {
    let usable = if buffer_len < FILE_SPEC_WIDTH {
        0
    } else {
        FILE_SPEC_WIDTH + ((buffer_len - FILE_SPEC_WIDTH) / KEY_SPEC_WIDTH) * KEY_SPEC_WIDTH
    };
    let usable = usable.min(full.len());
    (&full[..usable], usable < full.len())
}

impl<M: Mem> super::Block<M> {
    /// This file's `B_STAT` reply, as [`Stat::read`] measures it -- see that
    /// function's doc comment for why `&self` is enough (no record load).
    ///
    /// # Errors
    ///
    /// See [`Stat::read`].
    pub fn stat(&self) -> Result<Stat, BtvError> {
        Stat::read(&self.name, &self.path, &self.geometry, &self.keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Segment;
    use crate::keys::Kind;

    /// A minimal file control record holding one 30-byte key at record
    /// offset 0, no duplicates, unsigned extended type -- enough bytes for
    /// [`Stat::read`] to walk without a real file.
    fn single_key_fcr(page: u16, approx_count: u32, ext_type: u8, extra_flags: u16) -> Vec<u8> {
        let mut fcr = vec![0u8; usize::from(page)];
        let def = at::KEYS_BASE;
        fcr[def + at::KEY_RECORDS..def + at::KEY_RECORDS + 4]
            .copy_from_slice(&pages::to_long(approx_count));
        let attrs: u16 = 0x0100 | extra_flags; // EXTENDED, plus whatever the caller wants
        fcr[def + at::ATTRIBUTES..def + at::ATTRIBUTES + 2].copy_from_slice(&attrs.to_le_bytes());
        fcr[def + at::OFFSET..def + at::OFFSET + 2].copy_from_slice(&0u16.to_le_bytes());
        fcr[def + at::LENGTH..def + at::LENGTH + 2].copy_from_slice(&30u16.to_le_bytes());
        fcr[def + at::EXTENDED] = ext_type;
        fcr
    }

    /// `name` is both the scratch directory and the file within it -- a
    /// distinct directory per caller, the same convention `create.rs`'s own
    /// `scratch` helper explains: two tests running in parallel must never
    /// share one directory, since [`crate::testing::scratch`] clears it on
    /// every call.
    fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = crate::testing::scratch(name).join("file.dat");
        std::fs::write(&path, bytes).expect("write fixture");
        path
    }

    fn one_key(number: u16) -> Key {
        Key {
            number,
            definition: 0,
            segments: vec![Segment {
                offset: 0,
                length: 30,
                kind: Kind::Unsigned,
                descending: false,
            }],
            duplicates: false,
            modifiable: true,
            chain: None,
                    acs: None,
                    null: None,
}
    }

    /// The measured shape: 16 bytes of file spec, 16 of key spec, nothing
    /// past it -- no 265-byte `altcol` tail, one entry for a one-segment
    /// key. See this module's doc comment.
    #[test]
    fn a_single_key_reply_is_exactly_thirty_two_bytes() {
        let fcr = single_key_fcr(512, 5, 0x0e, 0);
        let path = scratch("single.dat", &fcr);
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 1,
            reclen: 100,
            physical: 100,
            records: 5,
            pages: 1,
            variable: false,
        };
        let stat = Stat::read("single.dat", &path, &geometry, &[one_key(0)]).expect("reads");
        let wire = stat.wire(Version::V5, 0);
        assert_eq!(wire.len(), 32, "no 265-byte altcol tail");
        assert_eq!(&wire[0..2], &100u16.to_le_bytes(), "reclen");
        assert_eq!(&wire[2..4], &512u16.to_le_bytes(), "pagesize");
        assert_eq!(wire[4], 1, "one key, keyno != -1 so no high-byte flag");
        assert_eq!(wire[5], 0);
        assert_eq!(&wire[6..10], &5u32.to_le_bytes(), "records");
        assert_eq!(&wire[16..18], &1u16.to_le_bytes(), "position, 1-based");
        assert_eq!(&wire[18..20], &30u16.to_le_bytes(), "length");
        assert_eq!(&wire[22..26], &5u32.to_le_bytes(), "approx_count from disk, not recomputed");
        assert_eq!(wire[26], 0x0e, "ext_type verbatim");
        assert_eq!(wire[28], 0, "key number");
    }

    /// `keyno == -1` sets the measured `0x40` high bit; anything else
    /// clears it, whatever value -- measured across 0, 2, 5 and -2 on a real
    /// file, see this module's doc comment.
    #[test]
    fn keyno_minus_one_sets_the_measured_flag_bit_and_nothing_else_does() {
        let fcr = single_key_fcr(512, 0, 0x0e, 0);
        let path = scratch("keyno.dat", &fcr);
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 1,
            reclen: 100,
            physical: 100,
            records: 0,
            pages: 1,
            variable: false,
        };
        let stat = Stat::read("keyno.dat", &path, &geometry, &[one_key(0)]).expect("reads");

        assert_eq!(stat.wire(Version::V5, -1)[5], 0x40);
        assert_eq!(stat.wire(Version::V5, 0)[5], 0x00);
        assert_eq!(stat.wire(Version::V5, 2)[5], 0x00);
        assert_eq!(stat.wire(Version::V5, -2)[5], 0x00, "only exactly -1, not any negative");
    }

    /// A v6 file adds `0x20` to the same byte, only when `keyno == -1` --
    /// measured on `NEWMP001.VIR` and on a v6 file this session's own
    /// oracle created and populated.
    #[test]
    fn a_v6_file_adds_the_measured_extra_bit_only_when_keyno_is_minus_one() {
        // Offset 2, not 0: a v6 key's on-disk offset is always at least
        // `key_shift` (2), since it is measured from the slot -- see
        // `a_v6_files_offset_is_measured_from_the_record_not_the_slot`
        // below. Zero would trip `Stat::read`'s own underflow guard.
        let mut fcr = single_key_fcr(512, 0, 0x0e, 0);
        let def = at::KEYS_BASE;
        fcr[def + at::OFFSET..def + at::OFFSET + 2].copy_from_slice(&2u16.to_le_bytes());
        let path = scratch("v6.dat", &fcr);
        let geometry = Geometry {
            version: Version::V6,
            page: 512,
            keys: 1,
            reclen: 100,
            physical: 100,
            records: 0,
            pages: 1,
            variable: false,
        };
        let stat = Stat::read("v6.dat", &path, &geometry, &[one_key(0)]).expect("reads");
        assert_eq!(stat.wire(Version::V6, -1)[5], 0x60, "0x40 | 0x20");
        assert_eq!(stat.wire(Version::V6, 0)[5], 0x00);
    }

    /// The bug `NEWMP001.VIR` caught: a v6 key's raw on-disk offset (2, for
    /// a key that starts at the record's own byte 0) is measured from the
    /// physical slot, two bytes ahead of the record -- so `position` must
    /// read `1`, not `3`. See the module doc comment's "a v6 file's
    /// `position` is measured from the record, not the slot" section.
    #[test]
    fn a_v6_files_offset_is_measured_from_the_record_not_the_slot() {
        let mut fcr = single_key_fcr(512, 0, 0x0e, 0);
        let def = at::KEYS_BASE;
        fcr[def + at::OFFSET..def + at::OFFSET + 2].copy_from_slice(&2u16.to_le_bytes());
        let path = scratch("v6-offset.dat", &fcr);
        let geometry = Geometry {
            version: Version::V6,
            page: 512,
            keys: 1,
            reclen: 100,
            physical: 100,
            records: 0,
            pages: 1,
            variable: false,
        };
        let stat = Stat::read("v6-offset.dat", &path, &geometry, &[one_key(0)]).expect("reads");
        assert_eq!(
            stat.key_specs[0].position, 1,
            "record byte 0 is position 1, not 3 -- the slot marker is not the record"
        );

        // The same file read as v5 (this crate never actually does that --
        // version is a property of the file, not a caller's choice -- but
        // the guard is what proves the subtraction is conditional on
        // `key_shift`, not applied unconditionally) would read 3.
        let v5_geometry = Geometry { version: Version::V5, ..geometry };
        let v5_stat = Stat::read("v6-offset.dat", &path, &v5_geometry, &[one_key(0)]).expect("reads");
        assert_eq!(v5_stat.key_specs[0].position, 3, "no shift applied for v5");
    }

    /// The variable-length bit is the only file flag this module reproduces
    /// -- measured `0x0001` on `WCCTEXT.DAT`, `0x0000` on everything else.
    #[test]
    fn the_variable_flag_is_the_only_file_flag_bit_set() {
        let fcr = single_key_fcr(512, 0, 0x0e, 0);
        let path = scratch("var.dat", &fcr);
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 1,
            reclen: 22,
            physical: 26,
            records: 0,
            pages: 1,
            variable: true,
        };
        let stat = Stat::read("var.dat", &path, &geometry, &[one_key(0)]).expect("reads");
        assert_eq!(&stat.wire(Version::V5, 0)[10..12], &1u16.to_le_bytes());
    }

    /// Every segment of a multi-segment key repeats that key's own number
    /// and its first definition's `approx_count` -- measured on
    /// `WCCITOWN.DAT`'s two-segment key (both segments read `number = 1`)
    /// and reasoned from `create.rs`'s own `build_fcr`, which only writes
    /// `KEY_RECORDS` on a key's first (`sn == 0`) definition.
    #[test]
    fn every_segment_of_a_key_repeats_its_number_and_approx_count() {
        let mut fcr = vec![0u8; 512];
        // Key 0: one segment, at definition 0.
        let def0 = at::KEYS_BASE;
        fcr[def0 + at::KEY_RECORDS..def0 + at::KEY_RECORDS + 4]
            .copy_from_slice(&pages::to_long(7));
        fcr[def0 + at::ATTRIBUTES..def0 + at::ATTRIBUTES + 2]
            .copy_from_slice(&0x0100u16.to_le_bytes());
        fcr[def0 + at::LENGTH..def0 + at::LENGTH + 2].copy_from_slice(&4u16.to_le_bytes());
        fcr[def0 + at::EXTENDED] = 0x0f;

        // Key 1: two segments, at definitions 1 and 2. Only definition 1
        // (the key's first) carries KEY_RECORDS -- definition 2 is left
        // zero, matching create.rs's own build_fcr.
        let def1 = at::KEYS_BASE + at::KEY_WIDTH;
        fcr[def1 + at::KEY_RECORDS..def1 + at::KEY_RECORDS + 4]
            .copy_from_slice(&pages::to_long(3));
        fcr[def1 + at::ATTRIBUTES..def1 + at::ATTRIBUTES + 2]
            .copy_from_slice(&0x0110u16.to_le_bytes()); // EXTENDED | ANOSEG
        fcr[def1 + at::OFFSET..def1 + at::OFFSET + 2].copy_from_slice(&4u16.to_le_bytes());
        fcr[def1 + at::LENGTH..def1 + at::LENGTH + 2].copy_from_slice(&2u16.to_le_bytes());
        fcr[def1 + at::EXTENDED] = 0x0e;

        let def2 = at::KEYS_BASE + 2 * at::KEY_WIDTH;
        // KEY_RECORDS left zero here, deliberately -- a continuation
        // definition's own copy is meaningless.
        fcr[def2 + at::ATTRIBUTES..def2 + at::ATTRIBUTES + 2]
            .copy_from_slice(&0x0100u16.to_le_bytes());
        fcr[def2 + at::OFFSET..def2 + at::OFFSET + 2].copy_from_slice(&6u16.to_le_bytes());
        fcr[def2 + at::LENGTH..def2 + at::LENGTH + 2].copy_from_slice(&1u16.to_le_bytes());
        fcr[def2 + at::EXTENDED] = 0x0b;

        let path = scratch("multi.dat", &fcr);
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 2,
            reclen: 20,
            physical: 20,
            records: 3,
            pages: 1,
            variable: false,
        };
        let keys = vec![
            one_key(0),
            Key {
                number: 1,
                definition: 1,
                segments: vec![
                    Segment { offset: 4, length: 2, kind: Kind::Unsigned, descending: false },
                    Segment { offset: 6, length: 1, kind: Kind::Text, descending: false },
                ],
                duplicates: false,
                modifiable: true,
                chain: None,
                            acs: None,
                            null: None,
},
        ];
        let stat = Stat::read("multi.dat", &path, &geometry, &keys).expect("reads");
        assert_eq!(stat.key_specs.len(), 3, "one per segment: 1 + 2");
        assert_eq!(stat.key_specs[0].number, 0);
        assert_eq!(stat.key_specs[1].number, 1);
        assert_eq!(stat.key_specs[2].number, 1, "key 1's second segment repeats key 1's number");
        assert_eq!(stat.key_specs[1].approx_count, 3, "key 1's first definition");
        assert_eq!(
            stat.key_specs[2].approx_count, 3,
            "key 1's second segment repeats the FIRST definition's approx_count, \
             not its own (zero) KEY_RECORDS field"
        );
        assert_eq!(stat.key_specs[0].approx_count, 7, "key 0's own, unrelated, count");
    }

    /// `deliver` rounds down to whole units, never hands back a partial
    /// key spec, and reports "short" whenever anything was dropped --
    /// measured boundary values from `WCCUSERS.DAT`'s 64-byte reply (see
    /// this module's doc comment): 16..31 all yield 16 bytes, 32..63 all
    /// yield 32 or 48, only 64+ yields the whole thing.
    #[test]
    fn deliver_rounds_down_to_whole_units() {
        let full: Vec<u8> = (0..64u8).collect(); // 64 distinguishable bytes
        assert_eq!(deliver(&full, 0), (&full[..0], true));
        assert_eq!(deliver(&full, 15), (&full[..0], true), "under one whole unit: nothing");
        assert_eq!(deliver(&full, 16), (&full[..16], true));
        assert_eq!(deliver(&full, 17), (&full[..16], true), "16, not 17 -- no partial key spec");
        assert_eq!(deliver(&full, 31), (&full[..16], true));
        assert_eq!(deliver(&full, 32), (&full[..32], true));
        assert_eq!(deliver(&full, 63), (&full[..48], true), "2 whole key specs, not 3");
        assert_eq!(deliver(&full, 64), (&full[..64], false), "the whole reply, not short");
        assert_eq!(deliver(&full, 1000), (&full[..64], false), "never more than the real reply");
    }
}
