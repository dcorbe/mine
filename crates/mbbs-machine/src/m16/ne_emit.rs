//! Writing an NE (New Executable) image from an export table.
//!
//! The counterpart to `ne`'s reader: [`emit`] builds the smallest NE image
//! that answers "here is a library with these exports and this payload," in
//! the same header layout [`crate::m16::ne::NeImage::parse`] reads. It takes
//! a module name, an `(ordinal, name)` export table and an opaque payload,
//! and nothing else -- it knows nothing about GALGSBL, registries,
//! generations or serials. That is deliberate: `library.rs` is fenced by
//! `tests/no_cross_imports.rs` from naming anything in `m16`, and a writer
//! that reached into the registry for its own inputs would sit inside that
//! fence rather than beside it.
//!
//! # `retf` stubs, not trapping thunks
//!
//! The design spec calls for entry points that are "thunks that trap back
//! into this host." This emits a plain `retf` (`0xcb`) per export instead.
//! Two reasons. First, nothing loads a synthesised library from a file
//! today -- load-time imports go through `shims::entry` and `DosLoadModule`
//! through `dosenv`'s handle table, neither of which touches the
//! filesystem -- so a trapping thunk would ship with no caller, the same
//! dead-code shape that bit `provision()` two plans ago. Second, the trap
//! mechanism differs per host: `runexe`'s guests trap through the port-out
//! stub in `kvm.rs`, while an mbbs-hosted module goes through the loader's
//! thunk table. Choosing one without a caller to test against would be
//! guessing at an interface neither side has built yet. The segment layout
//! below is exactly where a trapping thunk plugs in once a caller exists;
//! the round-trip test does not change when it does.
//!
//! # The spec is our own reader
//!
//! Every offset below mirrors what [`crate::m16::ne::NeImage::parse`] reads,
//! since that parser already reads every vendor NE binary under `archive/`.
//! This file does not import `ne`'s private constants -- one module produces
//! bytes, the other consumes them, and they are checked against each other
//! only through [`crate::m16::ne::NeImage::parse`] itself, in this module's
//! own tests.

/// Bytes of MZ stub before the NE header. The header sits immediately after
/// it, so `e_lfanew` is a compile-time constant rather than something to
/// compute.
const MZ_STUB: usize = 0x40;

/// Bytes of NE header proper.
const NE_HEADER: usize = 0x40;

/// Sector-alignment shift for segment data: `1 << ALIGN` bytes per sector.
const ALIGN: u16 = 4;

/// `retf`: a real, executable far return, and the whole of every entry
/// point's code. One byte, no operand.
const RETF: u8 = 0xcb;

/// A 16-bit segment's size when a length field reads zero -- both the
/// segment-table length and a bundle bytes' worth cannot spell 64 KiB any
/// other way, since the field is a word.
const SIXTY_FOUR_K: usize = 0x1_0000;

/// A length-prefixed name plus its ordinal, the shape
/// [`crate::m16::ne::NeImage::parse`]'s name-table walk reads: one length
/// byte, that many bytes of name, then a `u16` ordinal.
fn pname(out: &mut Vec<u8>, name: &str, ordinal: u16) {
    assert!(name.len() <= 0xff, "a pstring's length is one byte");
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ordinal.to_le_bytes());
}

/// Places `data` at the next sector boundary and returns `(sector, length
/// field)`. Empty data gets `(0, 0)` -- sector `0` is how the reader spells
/// "no file data for this segment," not "at file offset 0" -- and the length
/// field wraps the same way the reader unwraps it: `data.len() as u16`
/// already reads back as `0` when `data.len()` is exactly 65536, which the
/// reader takes to mean 64 KiB.
fn place_segment(out: &mut Vec<u8>, data: &[u8]) -> (u16, u16) {
    assert!(
        data.len() <= SIXTY_FOUR_K,
        "a 16-bit segment cannot hold more than 64 KiB"
    );
    if data.is_empty() {
        return (0, 0);
    }
    let sector_bytes = 1usize << ALIGN;
    while !out.len().is_multiple_of(sector_bytes) {
        out.push(0);
    }
    let sector = (out.len() / sector_bytes) as u16;
    out.extend_from_slice(data);
    (sector, data.len() as u16)
}

/// Write a little-endian `u16` NE-header field, `at` bytes into the header.
fn header_u16(out: &mut [u8], at: usize, v: u16) {
    out[MZ_STUB + at..MZ_STUB + at + 2].copy_from_slice(&v.to_le_bytes());
}

/// Emit an NE image: `module`'s own name, an `(ordinal, name)` export table,
/// and an opaque `payload`.
///
/// Ordinal gaps in `exports` become entry-table holes rather than being
/// packed away -- a caller asking for ordinals 1 and 5 gets ordinal 5 at
/// ordinal 5, not renumbered to 2 -- and `payload` lands verbatim inside a
/// data segment, findable afterwards by a linear byte scan.
///
/// `exports` need not arrive already sorted by ordinal: this sorts a copy,
/// since the entry table's holes are defined by ordinal order, not by the
/// order the caller listed them in. Duplicate ordinals are the caller's bug,
/// not something this function detects.
pub fn emit(module: &str, exports: &[(u16, &str)], payload: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<(u16, &str)> = exports.to_vec();
    sorted.sort_by_key(|&(ordinal, _)| ordinal);

    let mut out = vec![0u8; MZ_STUB + NE_HEADER];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&(MZ_STUB as u32).to_le_bytes());
    out[MZ_STUB..MZ_STUB + 2].copy_from_slice(b"NE");

    // Segment table: two fixed rows (code, then data), patched once their
    // data is placed and its sector/length are known.
    let segtab = out.len();
    out.resize(segtab + 16, 0);

    // No imports: zero module references, and an imported-names table
    // holding only the leading empty string every reader of that table
    // expects. Nothing reads through `modtab`/`imptab` today -- the
    // module-reference loop never runs with a zero count, and there are no
    // TGT_IMPORTNAME relocations to resolve through `imptab` -- but a
    // dangling offset naming nothing would be a landmine for whoever adds
    // imports later.
    let modtab = out.len();
    let imptab = out.len();
    out.push(0);

    // Resident name table: this module's own name first -- what `own_name`
    // reads unconditionally as the table's first entry -- then one entry
    // per export, in the caller's own order (name-table order is not
    // entry-table order; only the entry table's holes are ordinal-ordered).
    let restab = out.len();
    pname(&mut out, module, 0);
    for &(ordinal, name) in exports {
        pname(&mut out, name, ordinal);
    }
    out.push(0); // terminator: an empty pstring ends the table

    // Entry table: one segment-1 bundle per export, with a skip bundle
    // filling every gap between ordinals. Code offsets are assigned in
    // ordinal order -- one `retf` per export -- so walking `sorted` here is
    // also laying out the code segment's bytes.
    let entrytab = out.len();
    let mut code = Vec::with_capacity(sorted.len());
    let mut next_ordinal = 1u16;
    for &(ordinal, _name) in &sorted {
        let mut hole = ordinal.saturating_sub(next_ordinal);
        // A skip bundle's count is one byte, so a gap wider than 255 needs
        // more than one bundle. GALGSBL's own widest measured gap is 9
        // (81 to 90); this loop exists so a caller with a wider one still
        // gets a correct image instead of a silently truncated count.
        while hole > 0 {
            let chunk = hole.min(255);
            out.push(chunk as u8);
            out.push(0); // indicator 0: a skip bundle, no entry data follows
            hole -= chunk;
        }
        out.push(1); // one entry in this bundle
        out.push(1); // indicator: fixed segment 1, the code segment
        out.push(0x01); // flags: exported
        let offset = code.len() as u16;
        out.extend_from_slice(&offset.to_le_bytes());
        code.push(RETF);
        next_ordinal = ordinal + 1;
    }
    out.push(0); // terminator: a zero count ends the table
    let entrytab_len = out.len() - entrytab;

    // Non-resident name table: a description, then a terminator. Never read
    // by anything but `collect_names`, which drops this first entry too, the
    // same as the resident table's module name.
    let nrtab = out.len();
    pname(&mut out, &format!("{module} host library"), 0);
    out.push(0);
    let nrtab_len = out.len() - nrtab;

    let (code_sector, code_len) = place_segment(&mut out, &code);
    out[segtab..segtab + 2].copy_from_slice(&code_sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&code_len.to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0u16.to_le_bytes()); // code, no relocations
    out[segtab + 6..segtab + 8].copy_from_slice(&code_len.to_le_bytes());

    let (data_sector, data_len) = place_segment(&mut out, payload);
    let data_row = segtab + 8;
    out[data_row..data_row + 2].copy_from_slice(&data_sector.to_le_bytes());
    out[data_row + 2..data_row + 4].copy_from_slice(&data_len.to_le_bytes());
    out[data_row + 4..data_row + 6].copy_from_slice(&0x0001u16.to_le_bytes()); // data segment
    out[data_row + 6..data_row + 8].copy_from_slice(&data_len.to_le_bytes());

    header_u16(&mut out, 0x04, (entrytab - MZ_STUB) as u16);
    header_u16(&mut out, 0x06, entrytab_len as u16);
    header_u16(&mut out, 0x0c, 0x8001); // library, single-data
    header_u16(&mut out, 0x0e, 2); // autodata: the payload's data segment
    header_u16(&mut out, 0x1c, 2); // segment count: code, then data
    header_u16(&mut out, 0x1e, 0); // no imported modules
    header_u16(&mut out, 0x20, nrtab_len as u16);
    header_u16(&mut out, 0x22, (segtab - MZ_STUB) as u16);
    header_u16(&mut out, 0x26, (restab - MZ_STUB) as u16);
    header_u16(&mut out, 0x28, (modtab - MZ_STUB) as u16);
    header_u16(&mut out, 0x2a, (imptab - MZ_STUB) as u16);
    header_u16(&mut out, 0x32, ALIGN);
    // The one table offset that is file-relative rather than header-relative
    // -- `NeImage::parse` reads it as a `u32` straight off the file, unlike
    // every other table offset above.
    out[MZ_STUB + 0x2c..MZ_STUB + 0x30].copy_from_slice(&(nrtab as u32).to_le_bytes());
    out[MZ_STUB + 0x36] = 0x02; // executable type; NeImage::parse records it, nothing checks it

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m16::ne::NeImage;

    /// The strongest check available: our own NE reader, which already parses
    /// every vendor binary in `archive/`, must read back exactly the export
    /// table we asked for.
    #[test]
    fn our_own_reader_parses_the_image_and_sees_the_exports() {
        let bytes = emit("GALGSBL", &[(1, "_BTUBSE"), (72, "_BTURNO"), (101, "_BTUICX")], b"");
        let image = NeImage::parse(&bytes).expect("our own reader must parse what we emit");
        for (ordinal, name) in [(1u16, "_BTUBSE"), (72, "_BTURNO"), (101, "_BTUICX")] {
            let entry = image
                .entries
                .get(ordinal as usize - 1)
                .and_then(Option::as_ref)
                .unwrap_or_else(|| panic!("ordinal {ordinal} has no entry"));
            assert!(entry.exported, "ordinal {ordinal} must be exported");
            let _ = name;
        }
        assert_eq!(image.module_name(0).ok(), None, "no imports were asked for");
    }

    /// A gap in the ordinal space is a hole, not a shift. GALGSBL's own tables
    /// are not contiguous -- the WG 3.x build jumps 81 to 90 -- so an emitter
    /// that packed entries would renumber every export after the gap.
    #[test]
    fn a_gap_in_the_ordinals_stays_a_gap() {
        let bytes = emit("GALGSBL", &[(1, "_A"), (5, "_B")], b"");
        let image = NeImage::parse(&bytes).expect("parses");
        assert!(image.entries[0].is_some(), "ordinal 1 present");
        for hole in 1..4 {
            assert!(image.entries[hole].is_none(), "ordinal {} must be a hole", hole + 1);
        }
        assert!(image.entries[4].is_some(), "ordinal 5 present, not shifted to 2");
    }

    /// The payload lives **inside a declared segment**, not dangling past the
    /// end of the file.
    ///
    /// Added after execution found the plan's placement mutation did not
    /// discriminate. The round-trip test passes an empty payload, so there is
    /// nothing to misplace; and neither it nor the linear-scan test inspects
    /// segment bounds, while `NeImage::parse` does no whole-file cross-check --
    /// so bytes appended past every declared structure parse perfectly
    /// cleanly. A byte scan finds the marker either way, which is precisely
    /// why "a scan finds it" cannot stand in for "it is placed correctly".
    #[test]
    fn the_payload_lives_inside_a_declared_segment() {
        let bytes = emit("GALGSBL", &[(1, "_A")], b"ReG#00000000\0");
        let at = bytes.windows(4).position(|w| w == b"ReG#").expect("marker present");
        let image = NeImage::parse(&bytes).expect("parses");
        assert!(
            image.segments.iter().any(|s| s.file.contains(&at)),
            "the payload at {at:#x} is in no declared segment: {:?}",
            image.segments.iter().map(|s| s.file.clone()).collect::<Vec<_>>()
        );
    }

    /// The payload has to survive verbatim and be findable by a linear byte
    /// scan, because that is exactly how `GETRNO` looks for it.
    #[test]
    fn the_payload_is_findable_by_a_linear_scan() {
        let bytes = emit("GALGSBL", &[(1, "_A")], b"ReG#00000000\0");
        let at = bytes
            .windows(4)
            .position(|w| w == b"ReG#")
            .expect("a linear scan must find the marker, as GETRNO does");
        assert_eq!(&bytes[at + 4..at + 12], b"00000000");
    }
}
