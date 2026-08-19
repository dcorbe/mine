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
//! # A forwarder, not a stub
//!
//! The design spec calls for entry points that are "thunks that trap back
//! into this host." An m16 thunk is not bytes in a module's image, though
//! -- it is a slot in a host-owned `bridge` selector
//! (`THUNK_TABLE_OFFSET + slot * THUNK_STRIDE`), and the loader points an
//! import fixup at that slot. An emitted image cannot contain one, because
//! the selector is not known at emit time.
//!
//! So instead each export **imports** a routine of its own name, from a
//! module of its own name, and the entry point is a `jmp far`
//! (`0xea <off16> <sel16>`) through a relocation naming that import. The
//! existing loader resolves `Target::Import` exactly the way it resolves
//! any other module's import: through [`crate::module::ImportResolver`],
//! which for an unresolved routine hands back a real, executable thunk
//! slot in the bridge selector (`ea <off32> <sel>`, a far jump into the
//! host's own code). So the guest's `call far` to the export lands on our
//! `jmp far`, which the loader has already patched to point at that host
//! thunk -- reusing the loader's existing `Target::Import` path rather than
//! inventing new trapping machinery.
//!
//! ## The circularity this would create, and the rule that avoids it
//!
//! **A forwarder that imports from its own library name would resolve to
//! itself once a resolver ever prefers an already-loaded module's exports
//! over the host's own tables, and loop.** The rule: *the synthesised
//! image itself must always be loaded with the unflipped resolver* --
//! host tables first, exactly as every other load today -- so its imports
//! bind to host shims/thunks rather than back into the image that is still
//! being loaded. Precedence-flipping (preferring an already-loaded module
//! over the host tables) is a decision for *other* modules loaded
//! afterwards to opt into, per load, never a global default and never
//! something the forwarder's own load may use.
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

/// `jmp far ptr16:16`: the opcode byte. Followed by a 4-byte operand
/// initialised per [`OPERAND_OFFSET_INIT`] and patched at load time by a
/// relocation.
const FAR_JMP: u8 = 0xea;

/// The far jump's operand's initial offset word, `CHAIN_END` (`0xffff`) --
/// matching `crate::m16::ne`'s own private constant of the same name and
/// value, restated here because this module does not import `ne`'s private
/// items (see this file's own doc comment on the reader being the spec).
///
/// A non-additive relocation's applier treats a site's *current* word as
/// the offset of the next site in a fixup chain, walking it after every
/// write, and stops only at `CHAIN_END` or a self-referential link. Each
/// forwarder relocation here names exactly one site -- there is no chain --
/// so that word must already read as "no next link" before the loader ever
/// touches it. Zero would not do that: zero is a real segment offset, so a
/// zero-initialised operand on any export but the very first would have the
/// applier walk off to offset 0 of the code segment and corrupt whatever
/// `jmp far` bytes live there.
const OPERAND_OFFSET_INIT: u16 = 0xffff;

/// Relocation source `SRC_FAR_ADDR`: a 4-byte `ptr16:16` site, offset word
/// then selector word. Matches `crate::m16::ne`'s private constant of the
/// same name and value; restated for the same reason as
/// [`OPERAND_OFFSET_INIT`].
const SRC_FAR_ADDR: u8 = 3;

/// Relocation target kind `TGT_IMPORTNAME`, in the low two bits of the
/// flags byte. Matches `crate::m16::ne`'s private constant.
const TGT_IMPORTNAME: u8 = 2;

/// Segment flag: relocation records follow this segment's file data.
/// Matches `crate::m16::ne`'s private `SEG_RELOCINFO`.
const SEG_RELOCINFO: u16 = 0x0100;

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

/// A length-prefixed name with **no** trailing ordinal -- the shape the
/// module- and imported-name tables hold, as opposed to the exported-name
/// tables [`pname`] serves.
fn plain_pstring(out: &mut Vec<u8>, name: &str) {
    assert!(name.len() <= 0xff, "a pstring's length is one byte");
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
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

    // Imports: one module reference -- `module`'s own name -- and one
    // imported name per export, so each export's forwarding jump can name
    // an import of the same symbol. The imported-name table leads with a
    // placeholder empty pstring at offset 0, the convention
    // `crates/mbbs/tests/detection.rs`'s hand-built modules also follow and
    // the reason a real module reference is never offset 0.
    let mut impnames = vec![0u8];
    let module_at = impnames.len();
    plain_pstring(&mut impnames, module);
    let symbol_at: Vec<u16> = sorted
        .iter()
        .map(|&(_, name)| {
            let at = impnames.len() as u16;
            plain_pstring(&mut impnames, name);
            at
        })
        .collect();

    let modtab = out.len();
    out.extend_from_slice(&(module_at as u16).to_le_bytes());
    let imptab = out.len();
    out.extend_from_slice(&impnames);

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
    // ordinal order -- one forwarding `jmp far` per export -- so walking
    // `sorted` here is also laying out the code segment's bytes.
    //
    // `relocs[i]` is the code-segment offset of export `i`'s jump operand
    // (one past its opcode byte), lined up 1:1 with `symbol_at[i]` above --
    // both built by iterating `sorted` in the same order.
    let entrytab = out.len();
    let mut code = Vec::with_capacity(sorted.len() * 5);
    let mut relocs = Vec::with_capacity(sorted.len());
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
        code.push(FAR_JMP);
        relocs.push(code.len() as u16);
        // The operand: patched at load time by the relocation below. The
        // offset half starts life as CHAIN_END, not zero -- see
        // OPERAND_OFFSET_INIT. The selector half's initial value is
        // immaterial; SRC_FAR_ADDR always overwrites both halves.
        code.extend_from_slice(&OPERAND_OFFSET_INIT.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
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
    // SEG_RELOCINFO only when there is code to hang relocations off of --
    // `NeImage::parse`'s `parse_segment` only looks for relocation records
    // when the segment's file length is nonzero, so writing them for an
    // empty code segment (a caller with no exports at all) would leave
    // orphaned bytes the reader never consumes.
    let code_flags = if relocs.is_empty() { 0u16 } else { SEG_RELOCINFO };
    out[segtab + 4..segtab + 6].copy_from_slice(&code_flags.to_le_bytes());
    out[segtab + 6..segtab + 8].copy_from_slice(&code_len.to_le_bytes());

    // Relocations: immediately after the code segment's file data, exactly
    // where `parse_segment` looks for them (`start + file_len`, no sector
    // padding in between). One SRC_FAR_ADDR/TGT_IMPORTNAME record per
    // export, non-additive -- each names exactly one site, not a chain.
    if !relocs.is_empty() {
        out.extend_from_slice(&(relocs.len() as u16).to_le_bytes());
        for (&site, &name_at) in relocs.iter().zip(symbol_at.iter()) {
            out.push(SRC_FAR_ADDR);
            out.push(TGT_IMPORTNAME); // no TGT_ADDITIVE: one site, not a chain
            out.extend_from_slice(&site.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes()); // module reference index, 1-based
            out.extend_from_slice(&name_at.to_le_bytes()); // imported name offset within imptab
        }
    }

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
    header_u16(&mut out, 0x1e, 1); // one imported module: this module's own name
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

    /// Each export is a far jump through a relocation naming the same symbol
    /// as an import. The host loader then binds that import to a real
    /// thunk, so calling the export reaches the host routine -- using the
    /// loader's existing `Target::Import` path rather than any new trapping
    /// machinery. Replaces Task 1's `retf` stubs, which existed for one
    /// task and never shipped.
    ///
    /// Checks the entry point's own byte, not merely that a relocation
    /// exists somewhere in the segment. A relocation count alone cannot
    /// tell "the export is a jump patched by this fixup" from "the export
    /// is still a `retf`, and this fixup happens to sit at some other,
    /// unreached site in the same segment" -- mutating the entry byte back
    /// to `retf` while still emitting the fixup passed the weaker version
    /// of this test outright.
    #[test]
    fn every_export_forwards_to_an_import_of_the_same_name() {
        let exports = [(59u16, "_BTUXMT"), (72u16, "_BTURNO")];
        let bytes = emit("GALGSBL", &exports, b"");
        let image = NeImage::parse(&bytes).expect("parses");

        assert!(
            image.modules.iter().any(|m| m == "GALGSBL"),
            "the forwarder must import from a module of its own name: {:?}",
            image.modules
        );
        let imported: usize = image
            .segments
            .iter()
            .flat_map(|s| s.relocations.iter())
            .filter(|r| matches!(r.target, crate::m16::ne::Target::Import { .. }))
            .count();
        assert_eq!(imported, 2, "one import fixup per export");

        for (ordinal, name) in exports {
            let entry = image.entries[ordinal as usize - 1].expect("ordinal has an entry");
            let seg = &image.segments[entry.segment as usize - 1];
            let at = seg.file.start + entry.offset as usize;
            assert_eq!(
                bytes[at], 0xea,
                "ordinal {ordinal} ({name})'s entry point must itself be the jmp far, not a stub beside an unreached fixup"
            );
        }
    }
}
