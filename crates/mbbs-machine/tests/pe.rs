//! Parsing, against images built here rather than against a real module.
//!
//! The real-module tests live in `tests/wccmmud.rs`. These exist because a real
//! file exercises exactly one path through each branch, and the error paths need
//! an input built to reach them.

use mbbs_machine::m32::{Export, ExportAddress, Exports, Import, Module, PeError, PeImage, Relocation, Symbol};

/// The smallest thing that parses: an MZ stub, a PE signature, a COFF header
/// saying i386, a PE32 optional header, and no sections.
///
/// **Every optional-header field carries a distinct, non-zero value**, and that
/// is load-bearing rather than tidy. Left at zero -- as this helper originally
/// had them -- a parser reading `entry_point` from `image_base`'s offset returns
/// zero for both and no test can tell. That exact transposition was mutated in
/// and the whole suite stayed green, which is why
/// `every_optional_header_field_comes_from_its_own_offset` exists. The values
/// are also pairwise unequal, so no two fields can be swapped without one of
/// them landing on a number that belongs to the other.
fn minimal() -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    v[0x86..0x88].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

    let opt = 0x98;
    v[opt + 16..opt + 20].copy_from_slice(&ENTRY_POINT.to_le_bytes());
    v[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    v[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    v[opt + 36..opt + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
    v
}

/// The five optional-header values `minimal()` plants. Pairwise distinct, and
/// none of them zero -- see that function's note for why that matters.
const ENTRY_POINT: u32 = 0x0000_1111;
const IMAGE_BASE: u32 = 0x2222_0000;
const SECTION_ALIGNMENT: u32 = 0x0000_3000;
const FILE_ALIGNMENT: u32 = 0x0000_0400;
const SIZE_OF_IMAGE: u32 = 0x0005_5000;

#[test]
fn every_optional_header_field_comes_from_its_own_offset() {
    // The success path, which nothing else in this file reaches: every test
    // here but this one asserts on `unwrap_err()`, so before this existed the
    // parser could read all five of these fields from each other's offsets and
    // the suite stayed green.
    let image = PeImage::parse(&minimal()).unwrap();
    assert_eq!(image.entry_point, ENTRY_POINT, "entry point, opt+16");
    assert_eq!(image.image_base, IMAGE_BASE, "image base, opt+28");
    assert_eq!(
        image.section_alignment, SECTION_ALIGNMENT,
        "section alignment, opt+32"
    );
    assert_eq!(image.file_alignment, FILE_ALIGNMENT, "file alignment, opt+36");
    assert_eq!(image.size_of_image, SIZE_OF_IMAGE, "size of image, opt+56");

    // Characteristics 0x010e clears IMAGE_FILE_RELOCS_STRIPPED.
    assert!(image.rebasable(), "RELOCS_STRIPPED is clear in 0x010e");
}

#[test]
fn an_image_with_relocs_stripped_is_not_rebasable() {
    // The other side of `rebasable()`, which no test reached either. Task 12
    // refuses to load one of these anywhere but its own ImageBase, so this
    // predicate is about to become load-bearing.
    let mut v = minimal();
    let c = u16::from_le_bytes([v[0x96], v[0x97]]) | 0x0001;
    v[0x96..0x98].copy_from_slice(&c.to_le_bytes());
    assert!(!PeImage::parse(&v).unwrap().rebasable());
}

#[test]
fn a_truncated_file_is_an_error_rather_than_a_short_read() {
    let full = minimal();
    for cut in [0, 1, 0x3f, 0x80, 0x90, 0x9a] {
        let err = PeImage::parse(&full[..cut]).unwrap_err();
        assert!(
            matches!(err, PeError::NotPe | PeError::Truncated { .. }),
            "cut at {cut:#x} gave {err:?}"
        );
    }
}

#[test]
fn a_file_that_is_not_pe_is_an_error() {
    assert_eq!(PeImage::parse(b"").unwrap_err(), PeError::NotPe);
    assert_eq!(PeImage::parse(b"ZM\0\0").unwrap_err(), PeError::NotPe);
    let mut v = minimal();
    v[0x80..0x84].copy_from_slice(b"NE\0\0");
    assert_eq!(PeImage::parse(&v).unwrap_err(), PeError::NotPe);
}

#[test]
fn a_64_bit_image_is_refused_rather_than_misread() {
    let mut v = minimal();
    v[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::NotPe32 { magic: 0x020b }
    );
}

#[test]
fn a_non_i386_image_is_refused() {
    let mut v = minimal();
    v[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::NotI386 { machine: 0x8664 }
    );
}

/// `minimal()` plus one section. The section table follows the optional
/// header, at `opt + SizeOfOptionalHeader` -- which is why the value that
/// field carries matters, not just whether it is present.
fn with_one_section() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    let sec = 0x98 + 0xe0; // opt + SizeOfOptionalHeader
    v.resize(sec + 40 + 0x200, 0);
    v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes()); // PointerToRawData
    v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    v
}

/// `with_one_section()`'s CODE section only covers virtual/raw rva
/// `0x1000..0x1100` / `0x1000..0x1080`. Some relocation tests below
/// deliberately target rvas past that -- a second 4 KiB page, or an offset
/// near the 12-bit field's edge -- to prove `page + offset` arithmetic rather
/// than `page | offset`. Task 12 made `PeImage::parse` check every
/// relocation's `rva` against the section table (see `Relocation`'s doc
/// comment in `pe.rs`), so those targets now need to actually be inside a
/// section rather than merely being math the parser used to accept
/// unchecked. This grows the one section's `VirtualSize`/`SizeOfRawData` to
/// `end_rva - 0x1000` and grows the file to match, without touching
/// `with_one_section()` itself -- other tests depend on its exact 0x100/0x80
/// sizes.
fn with_one_section_extended_to(end_rva: u32) -> Vec<u8> {
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    let raw_offset = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap());
    let size = end_rva - 0x1000; // the section's own rva, per with_one_section()
    v[sec + 8..sec + 12].copy_from_slice(&size.to_le_bytes()); // VirtualSize
    v[sec + 16..sec + 20].copy_from_slice(&size.to_le_bytes()); // SizeOfRawData
    let needed = raw_offset as usize + size as usize;
    if v.len() < needed {
        v.resize(needed, 0);
    }
    v
}

#[test]
fn a_section_table_parses() {
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(image.sections.len(), 1);
    let s = &image.sections[0];
    assert_eq!(s.name, "CODE");
    assert_eq!(s.rva, 0x1000);
    assert_eq!(s.virtual_size, 0x100);
    assert_eq!(s.raw_size, 0x80);
}

#[test]
fn every_section_field_comes_from_its_own_offset() {
    // Mirrors `every_optional_header_field_comes_from_its_own_offset`:
    // `with_one_section()` already plants five nonzero, pairwise-distinct
    // values (rva 0x1000, virtual_size 0x100, raw_size 0x80, raw_offset
    // ~0x1a0, characteristics 0x6000_0020), so a parser reading one field
    // from another field's byte offset in the 40-byte section header --
    // e.g. `characteristics` (at+36) from `rva`'s offset (at+12) -- lands on
    // a value that belongs to the wrong field and is caught here. Nothing
    // consumes `characteristics` yet, but Task 11 uses it to choose page
    // protections, so it is about to become load-bearing.
    let image = PeImage::parse(&with_one_section()).unwrap();
    let s = &image.sections[0];
    let sec = 0x98 + 0xe0; // opt + SizeOfOptionalHeader, same as with_one_section()
    assert_eq!(s.rva, 0x1000, "rva, section+12");
    assert_eq!(s.virtual_size, 0x100, "virtual size, section+8");
    assert_eq!(s.raw_size, 0x80, "raw size, section+16");
    assert_eq!(s.raw_offset, (sec + 40) as u32, "raw offset, section+20");
    assert_eq!(s.characteristics, 0x6000_0020, "characteristics, section+36");
}

#[test]
fn an_rva_resolves_to_a_file_offset_only_inside_a_section() {
    let image = PeImage::parse(&with_one_section()).unwrap();
    let base = image.sections[0].raw_offset;
    assert_eq!(image.rva_to_file(0x1000).unwrap(), base as usize);
    assert_eq!(image.rva_to_file(0x1040).unwrap(), base as usize + 0x40);

    // Below every section, and above the only one.
    assert_eq!(
        image.rva_to_file(0x0fff).unwrap_err(),
        PeError::UnmappedRva { rva: 0x0fff }
    );
    assert_eq!(
        image.rva_to_file(0x2000).unwrap_err(),
        PeError::UnmappedRva { rva: 0x2000 }
    );
}

#[test]
fn an_rva_in_the_bss_tail_has_no_file_offset() {
    // VirtualSize 0x100 but SizeOfRawData 0x80: the last 0x80 bytes are BSS and
    // exist only once the image is mapped. Asking for a file offset there is a
    // bug in the caller, not a valid translation.
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(
        image.rva_to_file(0x1080).unwrap_err(),
        PeError::UnmappedRva { rva: 0x1080 }
    );
}

/// Two sections, laid out on disk so that CODE's raw data ends exactly where
/// DATA's raw data begins. This is the shape that makes a `virtual_size`
/// vs. `raw_size` bug in `rva_to_file` observable as *wrong bytes* rather
/// than merely as a wrong boolean: if BSS-tail RVAs were resolved against
/// `virtual_size`, an address in CODE's tail would silently return an offset
/// that lands inside DATA's raw bytes on disk.
fn with_two_sections() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    let sec0 = 0x98 + 0xe0;
    let sec1 = sec0 + 40;
    let raw0 = sec1 + 40;
    let raw1 = raw0 + 0x80;
    v.resize(raw1 + 0x80 + 0x200, 0);

    v[sec0..sec0 + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec0 + 8..sec0 + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    v[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    v[sec0 + 16..sec0 + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec0 + 20..sec0 + 24].copy_from_slice(&(raw0 as u32).to_le_bytes());
    v[sec0 + 36..sec0 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    v[sec1..sec1 + 8].copy_from_slice(b"DATA\0\0\0\0");
    v[sec1 + 8..sec1 + 12].copy_from_slice(&0x80u32.to_le_bytes()); // VirtualSize
    v[sec1 + 12..sec1 + 16].copy_from_slice(&0x1100u32.to_le_bytes()); // VirtualAddress, right after CODE's virtual range
    v[sec1 + 16..sec1 + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec1 + 20..sec1 + 24].copy_from_slice(&(raw1 as u32).to_le_bytes());
    v[sec1 + 36..sec1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    // A marker at the start of DATA's raw bytes: a buggy translation of
    // CODE's BSS tail would land here instead of erroring.
    v[raw1] = 0xaa;
    v
}

#[test]
fn a_second_sections_raw_bytes_are_never_returned_for_the_first_sections_bss_tail() {
    let image = PeImage::parse(&with_two_sections()).unwrap();
    assert_eq!(image.sections.len(), 2);
    assert_eq!(
        image.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["CODE", "DATA"]
    );

    // rva 0x1080 is inside CODE's VirtualSize (0x100) but past its
    // SizeOfRawData (0x80): BSS, not file bytes -- even though DATA's raw
    // bytes happen to sit immediately afterward on disk.
    assert_eq!(
        image.rva_to_file(0x1080).unwrap_err(),
        PeError::UnmappedRva { rva: 0x1080 }
    );

    // DATA's own rva resolves to DATA's own raw offset, independent of CODE.
    let data = &image.sections[1];
    assert_eq!(image.rva_to_file(0x1100).unwrap(), data.raw_offset as usize);
}

#[test]
fn a_too_small_size_of_optional_header_is_refused() {
    // SizeOfOptionalHeader locates the section table (`opt + optional_size`).
    // A value smaller than this parser's own reads reach (opt+56, 4 bytes --
    // i.e. up through opt+60) means "trust this field to place the section
    // table" is trusting a number that cannot even describe the header
    // fields already read out of it. 0x20 is such a value: real headers are
    // 0xe0 (this module) or occasionally smaller for older linkers, but never
    // this small.
    let mut v = minimal();
    v[0x94..0x96].copy_from_slice(&0x20u16.to_le_bytes());
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::BadOptionalHeaderSize { size: 0x20 }
    );
}

/// `IMAGE_REL_BASED_HIGHLOW` (type 3) packed with `offset` the way
/// `IMAGE_BASE_RELOCATION` entries store it: type in the top 4 bits, the
/// 12-bit offset from the block's page in the low bits.
fn highlow(offset: u16) -> u16 {
    0x3000 | (offset & 0x0fff)
}

/// `IMAGE_REL_BASED_ABSOLUTE` (type 0): padding, dropped rather than applied.
fn absolute(offset: u16) -> u16 {
    offset & 0x0fff
}

/// Lays out one or more base-relocation blocks right after `with_one_section`'s
/// CODE section raw data, and points the base-relocation data directory
/// (index 5, at `opt + 96 + 5*8`) at a directory whose declared `size` is
/// exactly the sum of the blocks written -- `dir_size` overrides that, for
/// tests that need the directory to lie about how many bytes of blocks
/// follow it. Each block is `(page_rva, entries)`; entries are pre-packed by
/// `highlow`/`absolute`, and each block's own header always tells the truth
/// about its size (`8 + 2*entries.len()`); a block that lies about *its own*
/// size is written directly with `write_reloc_block_raw` instead.
///
/// The directory RVA is always the section's own RVA (0x1000): the block data
/// is written starting at that section's raw offset, so the directory and the
/// first block always share a file position, independent of what "page" each
/// block's entries target.
///
/// This exists (as opposed to always computing `dir_size` from the blocks,
/// which is what every test but the disagreement tests below wants) because a
/// directory/block-sum mismatch is exactly the bug class this file's
/// out-of-bounds and dangling-block-chain tests exist to catch. Do not remove
/// this parameter to "simplify" the signature back to always-matching: no
/// test built only on top of the always-agreeing helper can ever construct
/// the disagreement.
fn write_relocation_blocks_with_dir_size(v: &mut [u8], blocks: &[(u32, &[u16])], dir_size: u32) {
    let sec = 0x98 + 0xe0;
    let raw = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap()) as usize;
    let mut at = raw;
    for (page, entries) in blocks {
        let size = 8 + entries.len() * 2;
        write_reloc_block_raw(v, at, *page, size as u32, entries);
        at += size;
    }
    let dir = 0x98 + 96 + 5 * 8;
    v[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    v[dir + 4..dir + 8].copy_from_slice(&dir_size.to_le_bytes());
}

/// As `write_relocation_blocks_with_dir_size`, but the directory's declared
/// size is always the exact sum of the blocks written -- the shape every
/// test wants except the ones deliberately probing a disagreement between
/// the two.
fn write_relocation_blocks(v: &mut [u8], blocks: &[(u32, &[u16])]) {
    let total: u32 = blocks.iter().map(|(_, e)| 8 + e.len() as u32 * 2).sum();
    write_relocation_blocks_with_dir_size(v, blocks, total);
}

/// Writes one block's header (`page`, and a `size` that need not match
/// `8 + 2*entries.len()`) plus whatever entries are given, at file offset
/// `at`. Returns `at + size` -- not `at + `(bytes actually written), since a
/// block's declared size is what the parser advances by, independent of how
/// many entry bytes this helper happened to fill in.
///
/// A block that lies about its own size is exactly what
/// `write_relocation_blocks`'s always-truthful blocks cannot express, and is
/// the shape needed to test a size that overruns its directory or that isn't
/// `8 + 2*n`.
fn write_reloc_block_raw(v: &mut [u8], at: usize, page: u32, size: u32, entries: &[u16]) -> usize {
    v[at..at + 4].copy_from_slice(&page.to_le_bytes());
    v[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        v[at + 8 + i * 2..at + 10 + i * 2].copy_from_slice(&e.to_le_bytes());
    }
    at + size as usize
}

#[test]
fn base_relocations_parse_and_padding_is_dropped() {
    // One block covering page rva 0x1000: two HIGHLOW entries and one
    // ABSOLUTE pad. Block header is 8 bytes, each entry 2.
    let mut v = with_one_section();
    write_relocation_blocks(
        &mut v,
        &[(0x1000, &[highlow(0x004), highlow(0x008), absolute(0)])],
    );

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![Relocation { rva: 0x1004 }, Relocation { rva: 0x1008 }],
        "the ABSOLUTE entry is padding and must not survive parsing"
    );
}

#[test]
fn two_relocation_blocks_are_both_read_in_order() {
    // A single block makes `at += size` invisible: a parser that only ever
    // reads the first block, or that forgets to advance `at`, would still
    // pass a one-block test. Two blocks at two different pages catch both:
    // if the second block were skipped, the last two relocations here would
    // be missing; if `at` were miscomputed, the second block's header would
    // be read from the wrong offset and either error out or attribute its
    // entries to the wrong page.
    let mut v = with_one_section_extended_to(0x3000);
    write_relocation_blocks(
        &mut v,
        &[
            (0x1000, &[highlow(0x010)]),
            (0x2000, &[highlow(0x004), highlow(0xffc)]),
        ],
    );

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![
            Relocation { rva: 0x1010 },
            Relocation { rva: 0x2004 },
            Relocation { rva: 0x2ffc },
        ]
    );
}

#[test]
fn relocation_rva_is_page_plus_offset_not_page_or_offset() {
    // A block's `page` field is not guaranteed 4KiB-aligned by anything this
    // parser checks, and `page + offset` and `page | offset` only agree when
    // it is. 0x1800 is deliberately unaligned, and the two entries land in
    // two different 4KiB regions (0x1000..0x2000 and 0x2000..0x3000): a
    // one-block, one-page test cannot distinguish `+` from `|`, because every
    // page RVA in such a test is chosen aligned. This also exercises the
    // block's last entry (offset 0xffe, right at the edge of the 12-bit
    // range) to rule out an off-by-one that drops it.
    let mut v = with_one_section_extended_to(0x3000);
    write_relocation_blocks(&mut v, &[(0x1800, &[highlow(0x000), highlow(0xffe)])]);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![Relocation { rva: 0x1800 }, Relocation { rva: 0x27fe }],
        "page 0x1800 + offset 0xffe is 0x27fe; page 0x1800 | offset 0xffe would be 0x1ffe"
    );
}

#[test]
fn an_unsupported_relocation_type_is_an_error() {
    // Type 3 (HIGHLOW) is the only type this image contains and the only one
    // implemented; anything else must be reported rather than silently
    // applied or silently dropped like ABSOLUTE padding is.
    let mut v = with_one_section();
    write_relocation_blocks(&mut v, &[(0x1000, &[0x1000 | 0x004])]); // type 1: HIGH

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnsupportedRelocation { kind: 1 }
    );
}

#[test]
fn a_reloc_block_larger_than_its_directory_is_refused() {
    // A block declares size 0x100 (room for 0x7c entries) while the
    // directory declares only 10 bytes: header plus one entry. Before the
    // fix, the loop only checked that the next block *header* fit before the
    // directory's end, never the block's own declared `size` -- so `at`
    // advanced by the full 0x100 regardless, and a second, phantom entry
    // planted just past the directory's declared end (offset 0xff, at file
    // offset `raw + 10`) was walked and silently included in
    // `image.relocations`. This is the case the standalone probe that found
    // this defect built.
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    let raw = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap()) as usize;
    write_reloc_block_raw(&mut v, raw, 0x1000, 0x100, &[highlow(0x004), highlow(0x0ff)]);
    let dir = 0x98 + 96 + 5 * 8;
    v[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    v[dir + 4..dir + 8].copy_from_slice(&10u32.to_le_bytes());

    assert!(
        matches!(
            PeImage::parse(&v).unwrap_err(),
            PeError::RelocBlockOutOfBounds { need: 0x100, .. }
        ),
        "a block whose declared size runs past its directory's end must be refused, \
         not walked past the directory boundary"
    );
}

#[test]
fn a_reloc_block_size_that_leaves_a_dangling_byte_is_refused() {
    // Size 9: one byte past the 8-byte header, which is not `8 + 2*n` for any
    // integer `n`. `(size - 8) / 2` floor-divides to 0 entries, so accepting
    // this would silently drop the dangling byte while still advancing `at`
    // by the full declared size -- shifting every later block's parse
    // position by an attacker-chosen offset.
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    let raw = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap()) as usize;
    write_reloc_block_raw(&mut v, raw, 0x1000, 9, &[]);
    let dir = 0x98 + 96 + 5 * 8;
    v[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    v[dir + 4..dir + 8].copy_from_slice(&9u32.to_le_bytes());

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::MalformedRelocBlockSize { at: raw, size: 9 }
    );
}

#[test]
fn a_directory_declaring_more_bytes_than_its_blocks_sum_to_is_refused() {
    // One well-formed block (10 bytes: header + one entry), but the
    // directory declares 12 -- two bytes more than any block actually
    // occupies. Whether to accept this (treat the shortfall as harmless
    // padding) or reject it (require the walk to land exactly on the
    // directory's declared end) is a real design choice: this loader takes
    // the second, because accepting it means the 2 leftover bytes -- and
    // whatever follows them in the file if the shortfall happens to be at
    // least 8 bytes -- would otherwise be reinterpreted as the start of a
    // fresh block, parsing bytes the directory never claimed as relocations
    // that were never declared.
    let mut v = with_one_section();
    write_relocation_blocks_with_dir_size(&mut v, &[(0x1000, &[highlow(0x004)])], 12);

    assert!(
        matches!(
            PeImage::parse(&v).unwrap_err(),
            PeError::RelocBlockOutOfBounds { need: 8, .. }
        ),
        "a directory whose declared size exceeds its block chain's true length \
         must be refused rather than have the shortfall read as a new block"
    );
}

/// Part B (Task 10-13) `mmap`s a `size_of_image`-byte region and, per
/// section, `unsafe`ly copies `raw_size` bytes from `raw_offset` in the file
/// to `rva` in that mapping. Nothing between the file and that copy checks
/// either range against the buffer it actually indexes into, so a malformed
/// section here is an out-of-bounds read or write once Part B exists rather
/// than a parse-time error -- exactly the "malformed file is an error, not a
/// half-built machine" contract this module states for itself. These tests
/// are the parse-time refusal.
#[test]
fn a_sections_raw_data_past_the_end_of_the_file_is_refused() {
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    let raw_offset = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap());
    let file_len = v.len() as u32;
    // One byte more than fits between raw_offset and the end of the file.
    let bad_raw_size = file_len - raw_offset + 1;
    v[sec + 16..sec + 20].copy_from_slice(&bad_raw_size.to_le_bytes());

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::SectionOutOfBounds {
            section: "CODE".to_string(),
            what: "raw data",
            end: u64::from(raw_offset) + u64::from(bad_raw_size),
            limit: u64::from(file_len),
        }
    );
}

#[test]
fn a_sections_virtual_range_past_size_of_image_is_refused() {
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    // rva is 0x1000; push virtual_size one byte past where it would fit
    // inside SIZE_OF_IMAGE (0x0005_5000).
    let bad_virtual_size = SIZE_OF_IMAGE - 0x1000 + 1;
    v[sec + 8..sec + 12].copy_from_slice(&bad_virtual_size.to_le_bytes());

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::SectionOutOfBounds {
            section: "CODE".to_string(),
            what: "virtual range",
            end: u64::from(0x1000u32) + u64::from(bad_virtual_size),
            limit: u64::from(SIZE_OF_IMAGE),
        }
    );
}

#[test]
fn a_sections_raw_size_that_would_overrun_the_image_once_mapped_is_refused() {
    // Small virtual_size, so the "virtual range" check above passes; but
    // raw_size is deliberately large enough that rva + raw_size still runs
    // past size_of_image -- the range Task 11's copy actually writes into.
    // Neither the "raw data" check (raw_offset + raw_size <= file.len()) nor
    // the "virtual range" check (rva + virtual_size <= size_of_image) catches
    // this on its own: raw_size and virtual_size are independent fields, and
    // before this check was added, nothing related them to each other.
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    v[sec + 8..sec + 12].copy_from_slice(&0x10u32.to_le_bytes()); // virtual_size: tiny
    let raw_offset = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap());
    // rva is 0x1000; one byte more than fits between rva and SIZE_OF_IMAGE.
    let bad_raw_size = SIZE_OF_IMAGE - 0x1000 + 1;
    v[sec + 16..sec + 20].copy_from_slice(&bad_raw_size.to_le_bytes());
    // Long enough that the "raw data vs. file length" check passes, so
    // parsing reaches the new check rather than the old one.
    v.resize((raw_offset + bad_raw_size) as usize + 0x10, 0);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::SectionOutOfBounds {
            section: "CODE".to_string(),
            what: "raw data mapped into the image",
            end: u64::from(0x1000u32) + u64::from(bad_raw_size),
            limit: u64::from(SIZE_OF_IMAGE),
        }
    );
}

#[test]
fn a_pure_bss_section_with_zero_raw_size_still_parses() {
    // SizeOfRawData 0 (nothing on disk, the section is entirely BSS) is
    // legal and must not be rejected by the raw-data bounds check: with
    // raw_size 0, raw_offset + raw_size is just raw_offset, which is well
    // inside the file here.
    let mut v = with_one_section();
    let sec = 0x98 + 0xe0;
    v[sec + 16..sec + 20].copy_from_slice(&0u32.to_le_bytes());

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(image.sections[0].raw_size, 0);
}

// --- Imports (Task 5) -------------------------------------------------

fn put_u32(v: &mut [u8], at: usize, val: u32) {
    v[at..at + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_u16(v: &mut [u8], at: usize, val: u16) {
    v[at..at + 2].copy_from_slice(&val.to_le_bytes());
}

fn put_bytes(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A section big enough to lay out a whole synthetic import directory by
/// hand: descriptors, ILT/IAT arrays, hint/name pairs and library-name
/// strings, all addressable within one section's RVA range
/// (`0x1000..0x1400`). No BSS tail -- these tests are about the import walk
/// itself, not the section-bounds tests already covered above.
fn with_one_import_section() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    v.resize(raw + 0x400 + 0x200, 0);
    put_bytes(&mut v, sec, b"IMPORT\0\0");
    put_u32(&mut v, sec + 8, 0x400); // VirtualSize
    put_u32(&mut v, sec + 12, 0x1000); // VirtualAddress
    put_u32(&mut v, sec + 16, 0x400); // SizeOfRawData
    put_u32(&mut v, sec + 20, raw as u32); // PointerToRawData
    put_u32(&mut v, sec + 36, 0x4000_0040);
    v
}

/// Points data directory 1 (import) at `rva`/`size`. `size` is not required
/// to be descriptor-count-accurate -- see the comment in `pe.rs` on why this
/// parser never trusts it as one.
fn set_import_directory(v: &mut [u8], rva: u32, size: u32) {
    let dir = 0x98 + 96 + 8; // opt + 96 + DIR_IMPORT(1) * 8
    put_u32(v, dir, rva);
    put_u32(v, dir + 4, size);
}

#[test]
fn imports_walk_two_libraries_by_name_and_ordinal_with_the_iat_kept_separate_from_the_ilt() {
    // Layout, computed rather than hand-placed at magic offsets so nothing
    // here can silently overlap:
    //   desc0        LIBA.DLL: OriginalFirstThunk != FirstThunk (real ILT
    //                and IAT, at different addresses)
    //   desc1        LIBB.DLL: OriginalFirstThunk == 0 (older-linker
    //                fallback -- ILT and IAT read the very same array)
    //   desc2        the all-zero terminator
    //   desc3        a well-formed-looking THIRD descriptor. If the walk
    //                does not actually stop at desc2, this is parsed too,
    //                and `imports.len() == 4` below catches it.
    //   liba_ilt     LIBA's ILT: name entry, ordinal entry, 0 terminator
    //   liba_iat     LIBA's IAT: a DIFFERENT address from liba_ilt, pre-filled
    //                with a sentinel this loader must never read the value
    //                of (only its address matters) and must never confuse
    //                for the ILT's own address
    //   libb_thunk   LIBB's single thunk array (the fallback case)
    //   hint_funcone / hint_alpha / hint_beta   hint+name pairs
    //   name_liba / name_libb                   library name strings
    let mut v = with_one_import_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let desc0 = raw;
    let desc1 = desc0 + 20;
    let desc2 = desc1 + 20;
    let desc3 = desc2 + 20;
    let liba_ilt = desc3 + 20;
    let liba_iat = liba_ilt + 12; // 3 x u32
    let libb_thunk = liba_iat + 12;
    let hint_funcone = libb_thunk + 12;
    let hint_alpha = hint_funcone + 2 + 8; // 2-byte hint + "FuncOne\0"
    let hint_beta = hint_alpha + 2 + 6; // "Alpha\0"
    let name_liba = hint_beta + 2 + 5; // "Beta\0"
    let name_libb = name_liba + 9; // "LIBA.DLL\0"

    // desc0: LIBA.DLL, a real ILT distinct from its IAT.
    put_u32(&mut v, desc0, to_rva(liba_ilt)); // OriginalFirstThunk
    put_u32(&mut v, desc0 + 4, 0); // TimeDateStamp
    put_u32(&mut v, desc0 + 8, 0); // ForwarderChain
    put_u32(&mut v, desc0 + 12, to_rva(name_liba)); // Name
    put_u32(&mut v, desc0 + 16, to_rva(liba_iat)); // FirstThunk

    // desc1: LIBB.DLL, OriginalFirstThunk == 0 -- falls back to FirstThunk.
    put_u32(&mut v, desc1, 0);
    put_u32(&mut v, desc1 + 4, 0);
    put_u32(&mut v, desc1 + 8, 0);
    put_u32(&mut v, desc1 + 12, to_rva(name_libb));
    put_u32(&mut v, desc1 + 16, to_rva(libb_thunk));

    // desc2: the all-zero terminator.
    put_u32(&mut v, desc2, 0);
    put_u32(&mut v, desc2 + 4, 0);
    put_u32(&mut v, desc2 + 8, 0);
    put_u32(&mut v, desc2 + 12, 0);
    put_u32(&mut v, desc2 + 16, 0);

    // desc3: looks exactly like desc0. Must never be reached.
    put_u32(&mut v, desc3, to_rva(liba_ilt));
    put_u32(&mut v, desc3 + 4, 0);
    put_u32(&mut v, desc3 + 8, 0);
    put_u32(&mut v, desc3 + 12, to_rva(name_liba));
    put_u32(&mut v, desc3 + 16, to_rva(liba_iat));

    // LIBA's ILT: one by-name entry, one by-ordinal entry, 0 terminator.
    put_u32(&mut v, liba_ilt, to_rva(hint_funcone));
    put_u32(&mut v, liba_ilt + 4, 0x8000_0000 | 842);
    put_u32(&mut v, liba_ilt + 8, 0);
    // LIBA's IAT: a different array. Its contents are never read by this
    // loader (a later task binds them); the sentinel is neither zero nor a
    // plausible pointer, so misreading it would be obviously wrong if it
    // were ever inspected.
    put_u32(&mut v, liba_iat, 0xdead_beef);
    put_u32(&mut v, liba_iat + 4, 0xdead_beef);
    put_u32(&mut v, liba_iat + 8, 0xdead_beef);

    // LIBB's single thunk array, read as both ILT and IAT.
    put_u32(&mut v, libb_thunk, to_rva(hint_alpha));
    put_u32(&mut v, libb_thunk + 4, to_rva(hint_beta));
    put_u32(&mut v, libb_thunk + 8, 0);

    put_u16(&mut v, hint_funcone, 0); // hint, never read
    put_bytes(&mut v, hint_funcone + 2, b"FuncOne\0");
    put_u16(&mut v, hint_alpha, 0);
    put_bytes(&mut v, hint_alpha + 2, b"Alpha\0");
    put_u16(&mut v, hint_beta, 0);
    put_bytes(&mut v, hint_beta + 2, b"Beta\0");
    put_bytes(&mut v, name_liba, b"LIBA.DLL\0");
    put_bytes(&mut v, name_libb, b"LIBB.DLL\0");

    // Deliberately not descriptor-count-accurate: 4 descriptors follow (80
    // bytes), the directory claims 40. See the comment in `pe.rs` on why
    // this parser never trusts the directory `Size` field as a bound.
    set_import_directory(&mut v, to_rva(desc0), 40);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.imports,
        vec![
            Import {
                library: "LIBA.DLL".to_string(),
                symbol: Symbol::Name("FuncOne".to_string()),
                iat_rva: to_rva(liba_iat),
            },
            Import {
                library: "LIBA.DLL".to_string(),
                symbol: Symbol::Ordinal(842),
                iat_rva: to_rva(liba_iat) + 4,
            },
            Import {
                library: "LIBB.DLL".to_string(),
                symbol: Symbol::Name("Alpha".to_string()),
                iat_rva: to_rva(libb_thunk),
            },
            Import {
                library: "LIBB.DLL".to_string(),
                symbol: Symbol::Name("Beta".to_string()),
                iat_rva: to_rva(libb_thunk) + 4,
            },
        ],
        "4 imports across 2 libraries; the all-zero descriptor must stop the \
         walk before the well-formed-looking phantom descriptor after it"
    );
}

#[test]
fn an_ordinal_import_is_not_read_as_a_name() {
    // A single descriptor naming "X.DLL" with one by-ordinal thunk (842,
    // i.e. IMPORT_BY_ORDINAL | 0x034a). This is the fixture the mandatory
    // mutation targets: drop the `entry & IMPORT_BY_ORDINAL != 0` check and
    // 0x8000_034a is read as a name RVA instead -- an address nowhere near
    // any section in this fixture -- turning this `unwrap()` into a panic on
    // `UnmappedRva` rather than a silently wrong `Symbol::Name`.
    let mut v = with_one_import_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;

    let ilt_rva = 0x1000u32; // the ILT array itself
    let name_rva = 0x1000u32 + 8; // "X.DLL\0"
    let desc_rva = 0x1000u32 + 0x10;

    put_u32(&mut v, raw, 0x8000_0000 | 842); // ordinal 842
    put_u32(&mut v, raw + 4, 0); // ILT terminator
    put_bytes(&mut v, raw + 8, b"X.DLL\0");

    let desc = raw + 0x10;
    put_u32(&mut v, desc, ilt_rva);
    put_u32(&mut v, desc + 4, 0);
    put_u32(&mut v, desc + 8, 0);
    put_u32(&mut v, desc + 12, name_rva);
    put_u32(&mut v, desc + 16, ilt_rva); // FirstThunk -- contents never read
    put_u32(&mut v, desc + 20, 0); // terminator descriptor
    put_u32(&mut v, desc + 24, 0);
    put_u32(&mut v, desc + 28, 0);
    put_u32(&mut v, desc + 32, 0);
    put_u32(&mut v, desc + 36, 0);

    set_import_directory(&mut v, desc_rva, 20);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.imports,
        vec![Import {
            library: "X.DLL".to_string(),
            symbol: Symbol::Ordinal(842),
            iat_rva: ilt_rva,
        }]
    );
}

#[test]
fn an_import_library_name_rva_outside_any_section_is_refused() {
    let mut v = with_one_import_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let ilt_rva = 0x1000u32;
    let bogus_name_rva = 0x9999_0000u32; // nowhere near this image's sections

    put_u32(&mut v, raw, 0x8000_0000 | 1); // one ordinal ILT entry
    put_u32(&mut v, raw + 4, 0);

    let desc = raw + 0x10;
    put_u32(&mut v, desc, ilt_rva);
    put_u32(&mut v, desc + 4, 0);
    put_u32(&mut v, desc + 8, 0);
    put_u32(&mut v, desc + 12, bogus_name_rva);
    put_u32(&mut v, desc + 16, ilt_rva);

    set_import_directory(&mut v, 0x1000 + 0x10, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnmappedRva { rva: bogus_name_rva }
    );
}

#[test]
fn an_iat_slot_outside_any_section_is_refused() {
    // Unlike the ILT, nothing about walking the import table ever
    // dereferences the IAT cursor -- it is only ever advanced and recorded
    // into `Import::iat_rva`. A `FirstThunk` pointing anywhere a u32 can name
    // would otherwise sail straight through into `Image::bind_imports`
    // (Task 13), which indexes the mapping at exactly that rva.
    let mut v = with_one_import_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let ilt_rva = 0x1000u32; // inside the one section: valid
    let bogus_iat_rva = 0x9999_0000u32; // nowhere near this image's sections
    let name_rva = 0x1000u32 + 0x20; // reuse in-bounds space for "X\0"

    put_u32(&mut v, raw, 0x8000_0000 | 1); // one ordinal ILT entry
    put_u32(&mut v, raw + 4, 0);
    put_bytes(&mut v, raw + 0x20, b"X\0");

    let desc = raw + 0x10;
    put_u32(&mut v, desc, ilt_rva); // OriginalFirstThunk: a real, distinct ILT
    put_u32(&mut v, desc + 4, 0);
    put_u32(&mut v, desc + 8, 0);
    put_u32(&mut v, desc + 12, name_rva);
    put_u32(&mut v, desc + 16, bogus_iat_rva); // FirstThunk

    set_import_directory(&mut v, 0x1000 + 0x10, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnmappedRva {
            rva: bogus_iat_rva
        }
    );
}

#[test]
fn a_library_name_with_no_nul_before_the_end_of_its_section_is_refused() {
    // Two sections: DESC holds the descriptor and its ILT with plenty of
    // room, NAME is exactly 4 bytes and none of them is zero -- no NUL is
    // possible without reading past NAME's own raw data into whatever the
    // file places after it.
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    let sec0 = 0x98 + 0xe0;
    let sec1 = sec0 + 40;
    let raw0 = sec1 + 40;
    let raw1 = raw0 + 0x40;
    v.resize(raw1 + 4 + 0x200, 0);

    put_bytes(&mut v, sec0, b"DESC\0\0\0\0");
    put_u32(&mut v, sec0 + 8, 0x40);
    put_u32(&mut v, sec0 + 12, 0x1000);
    put_u32(&mut v, sec0 + 16, 0x40);
    put_u32(&mut v, sec0 + 20, raw0 as u32);
    put_u32(&mut v, sec0 + 36, 0x4000_0040);

    put_bytes(&mut v, sec1, b"NAME\0\0\0\0");
    put_u32(&mut v, sec1 + 8, 4);
    put_u32(&mut v, sec1 + 12, 0x1040); // right after DESC's virtual range
    put_u32(&mut v, sec1 + 16, 4);
    put_u32(&mut v, sec1 + 20, raw1 as u32);
    put_u32(&mut v, sec1 + 36, 0x4000_0040);

    let ilt_rva = 0x1000u32;
    let name_rva = 0x1040u32;
    put_u32(&mut v, raw0, 0x8000_0000 | 1); // ILT: one ordinal entry
    put_u32(&mut v, raw0 + 4, 0);

    let desc = raw0 + 0x10;
    put_u32(&mut v, desc, ilt_rva);
    put_u32(&mut v, desc + 4, 0);
    put_u32(&mut v, desc + 8, 0);
    put_u32(&mut v, desc + 12, name_rva);
    put_u32(&mut v, desc + 16, ilt_rva);

    put_bytes(&mut v, raw1, b"XYZW"); // NAME's 4 raw bytes: no NUL anywhere

    set_import_directory(&mut v, 0x1000 + 0x10, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnterminatedString {
            what: "import library name",
            at: raw1,
        }
    );
}

#[test]
fn a_symbol_name_rva_in_a_bss_tail_has_no_bytes_to_read() {
    // VirtualSize (0x400) exceeds SizeOfRawData (shrunk to 0x40 here): the
    // tail of the section is BSS and exists only once the image is mapped,
    // nowhere in the file. An ILT entry naming an RVA there must be refused,
    // not answered with whatever bytes happen to sit at that file offset.
    let mut v = with_one_import_section();
    let sec = 0x98 + 0xe0;
    put_u32(&mut v, sec + 16, 0x40); // SizeOfRawData
    let raw = sec + 40;

    let ilt_rva = 0x1000u32;
    let name_rva = 0x1000u32 + 8;
    let bss_rva = 0x1000u32 + 0x40; // == SizeOfRawData: the first BSS byte

    put_u32(&mut v, raw, bss_rva); // ILT entry: a name/hint rva into the BSS tail
    put_u32(&mut v, raw + 4, 0);
    put_bytes(&mut v, raw + 8, b"X.DLL\0");

    let desc = raw + 0x10;
    put_u32(&mut v, desc, ilt_rva);
    put_u32(&mut v, desc + 4, 0);
    put_u32(&mut v, desc + 8, 0);
    put_u32(&mut v, desc + 12, name_rva);
    put_u32(&mut v, desc + 16, ilt_rva);

    set_import_directory(&mut v, 0x1000 + 0x10, 20);

    // The hint/name pointer read is `bss_rva + 2` (the 2-byte hint is
    // skipped before the name is resolved), so that -- not `bss_rva` itself
    // -- is the RVA that fails to resolve.
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnmappedRva { rva: bss_rva + 2 }
    );
}

#[test]
fn an_ilt_that_never_terminates_before_its_section_ends_is_refused() {
    // Two sections: DESC holds one descriptor and its library name with
    // plenty of room; THUNK holds exactly two ILT entries and nothing else
    // -- no room for a terminating zero anywhere in its raw data. The walk
    // must be refused, not silently continue reading whatever the file
    // places after THUNK.
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    let sec0 = 0x98 + 0xe0;
    let sec1 = sec0 + 40;
    let raw0 = sec1 + 40;
    let raw1 = raw0 + 0x100;
    v.resize(raw1 + 8 + 0x200, 0);

    put_bytes(&mut v, sec0, b"DESC\0\0\0\0");
    put_u32(&mut v, sec0 + 8, 0x100);
    put_u32(&mut v, sec0 + 12, 0x1000);
    put_u32(&mut v, sec0 + 16, 0x100);
    put_u32(&mut v, sec0 + 20, raw0 as u32);
    put_u32(&mut v, sec0 + 36, 0x4000_0040);

    put_bytes(&mut v, sec1, b"THUNK\0\0\0");
    put_u32(&mut v, sec1 + 8, 8);
    put_u32(&mut v, sec1 + 12, 0x1100); // right after DESC's virtual range
    put_u32(&mut v, sec1 + 16, 8); // exactly 2 u32 entries, no more
    put_u32(&mut v, sec1 + 20, raw1 as u32);
    put_u32(&mut v, sec1 + 36, 0x4000_0040);

    let thunk_rva = 0x1100u32;
    let name_rva = 0x1000u32 + 0x50;
    put_bytes(&mut v, raw0 + 0x50, b"X.DLL\0");

    // OriginalFirstThunk == FirstThunk == THUNK's rva: the walk reads THUNK
    // for both.
    put_u32(&mut v, raw0, thunk_rva);
    put_u32(&mut v, raw0 + 4, 0);
    put_u32(&mut v, raw0 + 8, 0);
    put_u32(&mut v, raw0 + 12, name_rva);
    put_u32(&mut v, raw0 + 16, thunk_rva);

    // THUNK: two ordinal entries, neither zero -- no terminator anywhere in
    // its 8 raw bytes.
    put_u32(&mut v, raw1, 0x8000_0000 | 1);
    put_u32(&mut v, raw1 + 4, 0x8000_0000 | 2);

    set_import_directory(&mut v, 0x1000, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnmappedRva { rva: thunk_rva + 8 },
        "the ILT walk must stop at THUNK's own end, not read past it"
    );
}

#[test]
fn an_import_descriptor_that_would_run_past_its_sections_end_is_refused() {
    // The directory points 5 bytes from the section's end -- not enough for
    // a 20-byte descriptor. This is `RvaSpansSectionEnd`, distinct from
    // `UnmappedRva`: the rva itself is inside the section, there simply are
    // not enough bytes left in it.
    let mut v = with_one_import_section();
    let rva = 0x1000u32 + 0x400 - 5;
    set_import_directory(&mut v, rva, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::RvaSpansSectionEnd {
            what: "import descriptor",
            rva,
            need: 20,
            remaining: 5,
        }
    );
}

#[test]
fn a_descriptor_table_that_never_terminates_before_its_section_ends_is_refused() {
    // A shared, valid ILT array and library name at the start of the
    // section, then ten identical nonzero descriptors tiled back-to-back
    // with no all-zero terminator among them, ending 7 bytes short of an
    // eleventh full descriptor. The walk can only be stopped here by
    // refusing to read a descriptor past the section's own end -- there is
    // no descriptor count anywhere in the format to bound it by instead.
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    const SHARED: usize = 16; // ILT (2 x u32) + "X.DLL\0" (6 bytes), padded
    const N: usize = 10;
    const RAW_SIZE: usize = SHARED + N * 20 + 7;
    v.resize(raw + RAW_SIZE + 0x200, 0);
    put_bytes(&mut v, sec, b"IMPORT\0\0");
    put_u32(&mut v, sec + 8, RAW_SIZE as u32);
    put_u32(&mut v, sec + 12, 0x1000);
    put_u32(&mut v, sec + 16, RAW_SIZE as u32);
    put_u32(&mut v, sec + 20, raw as u32);
    put_u32(&mut v, sec + 36, 0x4000_0040);

    let ilt_rva = 0x1000u32;
    let name_rva = 0x1000u32 + 8;
    put_u32(&mut v, raw, 0x8000_0000 | 7); // one ordinal entry
    put_u32(&mut v, raw + 4, 0); // ILT terminator
    put_bytes(&mut v, raw + 8, b"X.DLL\0");

    for i in 0..N {
        let d = raw + SHARED + i * 20;
        put_u32(&mut v, d, ilt_rva);
        put_u32(&mut v, d + 4, 0);
        put_u32(&mut v, d + 8, 0);
        put_u32(&mut v, d + 12, name_rva);
        put_u32(&mut v, d + 16, ilt_rva);
    }

    set_import_directory(&mut v, 0x1000 + SHARED as u32, 20);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::RvaSpansSectionEnd {
            what: "import descriptor",
            rva: 0x1000 + (SHARED + N * 20) as u32,
            need: 20,
            remaining: 7,
        }
    );
}

#[test]
fn no_imports_is_not_an_error() {
    // The common case for a section table with nothing that references the
    // import directory (rva 0 / size 0, `minimal()`'s and `with_one_section`'s
    // default): the directory is simply absent, not malformed.
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(image.imports, Vec::new());
}

/// A section big enough to lay out a whole synthetic export directory by
/// hand: the 40-byte `IMAGE_EXPORT_DIRECTORY` header, the functions/names/
/// name-ordinals arrays, and name strings, all addressable within one
/// section's RVA range (`0x1000..0x1400`).
fn with_one_export_section() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    v.resize(raw + 0x400 + 0x200, 0);
    put_bytes(&mut v, sec, b"EXPORT\0\0");
    put_u32(&mut v, sec + 8, 0x400); // VirtualSize
    put_u32(&mut v, sec + 12, 0x1000); // VirtualAddress
    put_u32(&mut v, sec + 16, 0x400); // SizeOfRawData
    put_u32(&mut v, sec + 20, raw as u32); // PointerToRawData
    put_u32(&mut v, sec + 36, 0x4000_0040);
    v
}

/// Points data directory 0 (export) at `rva`/`size`.
fn set_export_directory(v: &mut [u8], rva: u32, size: u32) {
    let dir = 0x98 + 96; // opt + 96 + DIR_EXPORT(0) * 8
    put_u32(v, dir, rva);
    put_u32(v, dir + 4, size);
}

#[test]
fn exports_resolve_through_the_name_ordinal_indirection_not_position_or_base() {
    // Deliberately breaks all three symmetries a green suite here could
    // otherwise hide behind:
    //   - NumberOfFunctions (4) != NumberOfNames (3): function index 1
    //     (0x2010) has no name at all, so a parser that conflates "how many
    //     functions" with "how many names" reads one array with the other's
    //     count.
    //   - AddressOfNameOrdinals is [3, 0, 2], not the identity [0, 1, 2]: a
    //     parser that resolves name i to function i (the loop's own
    //     position) instead of to AddressOfNameOrdinals[i] gets Beta and
    //     Alpha wrong (Gamma coincidentally lands right either way, at
    //     index 2, which is exactly why the other two entries matter).
    //   - Base is 5, not 0: nothing here combines it with an ordinal. The
    //     property that matters is `Base != 0` together with a non-identity
    //     ordinal array -- if the resolution were mistakenly
    //     `functions[ordinal - base]` or `functions[ordinal + base]`, every
    //     one of these ordinals (3, 0, 2) would be pushed out of bounds or
    //     onto the wrong entry, for any nonzero Base. `Base = 1` would catch
    //     the same bug just as reliably; 5 is used only so a mistaken
    //     subtraction underflows uniformly instead of underflowing for some
    //     ordinals and merely misindexing for others.
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let dir = raw;
    let functions = dir + 40;
    let names = functions + 4 * 4;
    let ordinals = names + 3 * 4;
    let name_alpha = ordinals + 3 * 2;
    let name_beta = name_alpha + 6; // "Alpha\0"
    let name_gamma = name_beta + 5; // "Beta\0"

    put_u32(&mut v, dir + 16, 5); // Base
    put_u32(&mut v, dir + 20, 4); // NumberOfFunctions
    put_u32(&mut v, dir + 24, 3); // NumberOfNames
    put_u32(&mut v, dir + 28, to_rva(functions)); // AddressOfFunctions
    put_u32(&mut v, dir + 32, to_rva(names)); // AddressOfNames
    put_u32(&mut v, dir + 36, to_rva(ordinals)); // AddressOfNameOrdinals

    // Function 1 (0x2010) is exported by ordinal only -- no name below ever
    // points at it.
    put_u32(&mut v, functions, 0x2000);
    put_u32(&mut v, functions + 4, 0x2010);
    put_u32(&mut v, functions + 8, 0x2020);
    put_u32(&mut v, functions + 12, 0x2030);

    put_u32(&mut v, names, to_rva(name_alpha));
    put_u32(&mut v, names + 4, to_rva(name_beta));
    put_u32(&mut v, names + 8, to_rva(name_gamma));

    put_u16(&mut v, ordinals, 3); // Alpha -> functions[3] == 0x2030
    put_u16(&mut v, ordinals + 2, 0); // Beta  -> functions[0] == 0x2000
    put_u16(&mut v, ordinals + 4, 2); // Gamma -> functions[2] == 0x2020

    put_bytes(&mut v, name_alpha, b"Alpha\0");
    put_bytes(&mut v, name_beta, b"Beta\0");
    put_bytes(&mut v, name_gamma, b"Gamma\0");

    // Nowhere near the export directory's own range (below), so none of
    // these are forwarders.
    set_export_directory(&mut v, to_rva(dir), 0x400);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(image.export_base, Some(5));
    assert_eq!(
        image.exports,
        vec![
            Export {
                name: "Alpha".to_string(),
                address: ExportAddress::Rva(0x2030),
            },
            Export {
                name: "Beta".to_string(),
                address: ExportAddress::Rva(0x2000),
            },
            Export {
                name: "Gamma".to_string(),
                address: ExportAddress::Rva(0x2020),
            },
        ],
        "3 named exports; the unnamed function 0x2010 is not among them"
    );
    assert_eq!(image.export_rva("Alpha"), Some(0x2030));
    assert_eq!(image.export_rva("Beta"), Some(0x2000));
    assert_eq!(image.export_rva("Gamma"), Some(0x2020));
    assert_eq!(image.export_rva("Missing"), None);

    // `export_rva_by_ordinal` reaches every function slot, not just the
    // three with names -- the property `export_rva` cannot prove at all,
    // since function index 1 (0x2010) has no name for it to look up.
    // Public ordinal = Base(5) + 0-based function index.
    assert_eq!(
        image.export_rva_by_ordinal(6),
        Some(0x2010),
        "ordinal 6 (Base 5 + index 1) is the ordinal-only export -- no name \
         ever pointed at it, so only ordinal lookup can find it"
    );
    assert_eq!(image.export_rva_by_ordinal(5), Some(0x2000), "Base + index 0 == Beta's function");
    assert_eq!(image.export_rva_by_ordinal(7), Some(0x2020), "Base + index 2 == Gamma's function");
    assert_eq!(image.export_rva_by_ordinal(8), Some(0x2030), "Base + index 3 == Alpha's function");
    assert_eq!(
        image.export_rva_by_ordinal(4),
        None,
        "ordinal 4 is below Base(5) -- checked_sub must refuse it, not wrap"
    );
    assert_eq!(
        image.export_rva_by_ordinal(9),
        None,
        "Base + index 4 is past NumberOfFunctions(4) -- out of range"
    );
}

#[test]
fn a_forwarder_is_not_mistaken_for_an_address() {
    // A function RVA that falls inside the export directory's own
    // [VirtualAddress, VirtualAddress + Size) range is not code: it is the
    // RVA of a "DLL.Symbol" string. `wccmmud.dll` has none of these, so only
    // a synthetic fixture can reach this arm.
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let dir = raw;
    let functions = dir + 40;
    let names = functions + 4;
    let ordinals = names + 4;
    let forward_str = ordinals + 2;
    let name_str = forward_str + "OTHER.dll.RealFunc\0".len();

    put_u32(&mut v, dir + 16, 1); // Base
    put_u32(&mut v, dir + 20, 1); // NumberOfFunctions
    put_u32(&mut v, dir + 24, 1); // NumberOfNames
    put_u32(&mut v, dir + 28, to_rva(functions));
    put_u32(&mut v, dir + 32, to_rva(names));
    put_u32(&mut v, dir + 36, to_rva(ordinals));

    // The function "address" points inside the directory's own range below.
    put_u32(&mut v, functions, to_rva(forward_str));
    put_u32(&mut v, names, to_rva(name_str));
    put_u16(&mut v, ordinals, 0);

    put_bytes(&mut v, forward_str, b"OTHER.dll.RealFunc\0");
    put_bytes(&mut v, name_str, b"Exported\0");

    set_export_directory(&mut v, to_rva(dir), 0x100);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "Exported");
    assert_eq!(
        image.exports[0].forwarder(),
        Some("OTHER.dll.RealFunc"),
        "the function rva fell inside the export directory's own range"
    );
    assert_eq!(
        image.export_rva("Exported"),
        None,
        "a forwarder has no function rva to hand back"
    );
    assert_eq!(
        image.export_rva_by_ordinal(1), // Base(1) + index 0
        None,
        "export_rva_by_ordinal must refuse a forwarder exactly like export_rva does"
    );
}

#[test]
fn a_function_rva_exactly_at_the_export_directorys_end_is_not_a_forwarder() {
    // The forwarder range is [VirtualAddress, VirtualAddress + Size) --
    // half-open. A function rva equal to VirtualAddress + Size is one past
    // the directory, not inside it, and must resolve as ordinary code.
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let dir = raw;
    let functions = dir + 40;
    let names = functions + 4;
    let ordinals = names + 4;
    let name_str = ordinals + 2;

    let dir_rva = to_rva(dir);
    let dir_size = (name_str - dir) as u32; // dir_end == to_rva(name_str)
    let boundary = to_rva(name_str);

    put_u32(&mut v, dir + 16, 1);
    put_u32(&mut v, dir + 20, 1);
    put_u32(&mut v, dir + 24, 1);
    put_u32(&mut v, dir + 28, to_rva(functions));
    put_u32(&mut v, dir + 32, to_rva(names));
    put_u32(&mut v, dir + 36, to_rva(ordinals));

    put_u32(&mut v, functions, boundary); // exactly dir_rva + dir_size
    put_u32(&mut v, names, boundary);
    put_u16(&mut v, ordinals, 0);

    put_bytes(&mut v, name_str, b"X\0");

    set_export_directory(&mut v, dir_rva, dir_size);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(image.exports[0].forwarder(), None);
    assert_eq!(image.export_rva("X"), Some(boundary));
}

#[test]
fn a_name_ordinal_indexing_past_the_functions_array_is_refused() {
    // AddressOfNameOrdinals[0] is 5, but only one function (index 0) exists.
    // The 2-byte read of the ordinal itself is perfectly in-bounds -- this
    // is a data inconsistency between two already-parsed arrays, not a
    // truncated read, so it needs its own check rather than an index panic
    // on `functions[5]`.
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let dir = raw;
    let functions = dir + 40;
    let names = functions + 4;
    let ordinals = names + 4;
    let name_str = ordinals + 2;

    put_u32(&mut v, dir + 16, 1);
    put_u32(&mut v, dir + 20, 1); // NumberOfFunctions
    put_u32(&mut v, dir + 24, 1); // NumberOfNames
    put_u32(&mut v, dir + 28, to_rva(functions));
    put_u32(&mut v, dir + 32, to_rva(names));
    put_u32(&mut v, dir + 36, to_rva(ordinals));

    put_u32(&mut v, functions, 0x2000);
    put_u32(&mut v, names, to_rva(name_str));
    put_u16(&mut v, ordinals, 5); // out of range: only index 0 exists

    put_bytes(&mut v, name_str, b"Only\0");

    set_export_directory(&mut v, to_rva(dir), 0x400);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::ExportOrdinalOutOfRange {
            name: "Only".to_string(),
            ordinal: 5,
            functions: 1,
        }
    );
}

#[test]
fn a_number_of_functions_claiming_more_entries_than_the_section_holds_is_refused() {
    // AddressOfFunctions is placed so exactly two u32 entries fit before the
    // section's raw data ends; NumberOfFunctions claims a third. The
    // directory's own Size is not what stops this (the export tables have
    // no length-bearing Size the way the base-relocation directory does) --
    // only the bounds-checked read of the third entry does.
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let dir = raw;

    let functions_rva = 0x1000u32 + 0x400 - 6;
    let functions_off = raw + 0x400 - 6;

    put_u32(&mut v, dir + 16, 1); // Base
    put_u32(&mut v, dir + 20, 2); // NumberOfFunctions: claims 2, only 1 fits
    put_u32(&mut v, dir + 24, 0); // NumberOfNames
    put_u32(&mut v, dir + 28, functions_rva);
    put_u32(&mut v, dir + 32, 0);
    put_u32(&mut v, dir + 36, 0);

    put_u32(&mut v, functions_off, 0x2000); // the one entry that fits

    set_export_directory(&mut v, 0x1000, 0x400);

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::RvaSpansSectionEnd {
            what: "export address table entry",
            rva: functions_rva + 4,
            need: 4,
            remaining: 2,
        }
    );
}

#[test]
fn no_exports_is_not_an_error() {
    // The common case: rva 0 / size 0, `with_one_section()`'s default. The
    // directory is simply absent, not malformed.
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(image.exports, Vec::new());
    assert_eq!(image.export_base, None);
}

/// The export table `Exports::rebased` is built from, with every symmetry a
/// lookup could silently lean on broken: `Base = 5`, a non-identity
/// `AddressOfNameOrdinals` (`Alpha -> 3`, `Beta -> 0`, `Gamma -> 2`), a
/// nameless function slot at index 1, and `Alpha` a forwarder (its
/// "address" points into the directory's own range). Same shape as
/// `exports_resolve_through_the_name_ordinal_indirection_not_position_or_base`
/// above, plus the forwarder.
fn rebase_fixture() -> PeImage {
    let mut v = with_one_export_section();
    let sec = 0x98 + 0xe0;
    let raw = sec + 40;
    let to_rva = |file_off: usize| 0x1000u32 + (file_off - raw) as u32;

    let dir = raw;
    let functions = dir + 40;
    let names = functions + 4 * 4;
    let ordinals = names + 3 * 4;
    let name_alpha = ordinals + 3 * 2;
    let name_beta = name_alpha + 6; // "Alpha\0"
    let name_gamma = name_beta + 5; // "Beta\0"
    let forward_str = name_gamma + 6; // "Gamma\0"

    put_u32(&mut v, dir + 16, 5); // Base
    put_u32(&mut v, dir + 20, 4); // NumberOfFunctions
    put_u32(&mut v, dir + 24, 3); // NumberOfNames
    put_u32(&mut v, dir + 28, to_rva(functions));
    put_u32(&mut v, dir + 32, to_rva(names));
    put_u32(&mut v, dir + 36, to_rva(ordinals));

    put_u32(&mut v, functions, 0x2000);
    put_u32(&mut v, functions + 4, 0x2010); // nameless
    put_u32(&mut v, functions + 8, 0x2020);
    put_u32(&mut v, functions + 12, to_rva(forward_str)); // forwarder

    put_u32(&mut v, names, to_rva(name_alpha));
    put_u32(&mut v, names + 4, to_rva(name_beta));
    put_u32(&mut v, names + 8, to_rva(name_gamma));

    put_u16(&mut v, ordinals, 3); // Alpha -> functions[3], the forwarder
    put_u16(&mut v, ordinals + 2, 0); // Beta  -> functions[0] == 0x2000
    put_u16(&mut v, ordinals + 4, 2); // Gamma -> functions[2] == 0x2020

    put_bytes(&mut v, name_alpha, b"Alpha\0");
    put_bytes(&mut v, name_beta, b"Beta\0");
    put_bytes(&mut v, name_gamma, b"Gamma\0");
    put_bytes(&mut v, forward_str, b"OTHER.Fn\0");

    // 0x100 covers the strings above (so `forward_str` is inside the
    // directory and reads as a forwarder) and nothing at 0x2000+.
    set_export_directory(&mut v, to_rva(dir), 0x100);

    PeImage::parse(&v).unwrap()
}

/// A loaded module's export table answers **linear addresses** -- the RVA
/// plus wherever `Image::load` actually landed -- exactly as
/// `Module::init`/`Module::entry` already do. A non-zero base is the
/// point: an un-rebased answer (the RVA itself) is off by `0x7000_0000`
/// here and fails every assertion below.
#[test]
fn rebased_exports_answer_a_name_with_the_images_linear_address_not_an_rva() {
    let base = 0x7000_0000;
    let exports = Exports::rebased(&rebase_fixture(), base);

    assert_eq!(exports.by_name("Beta"), Some(base + 0x2000));
    assert_eq!(exports.by_name("Gamma"), Some(base + 0x2020));
    assert_eq!(exports.by_name("Alpha"), None, "a forwarder has no address to rebase");
    assert_eq!(exports.by_name("beta"), None, "exact-case, like PeImage::export_rva");
    assert_eq!(exports.by_name("Missing"), None);

    // `Module` exposes the same table unchanged -- what `Abi::export_address`
    // reads from.
    let module = Module::new(base + 0x1000, None, Vec::new(), exports);
    assert_eq!(module.export_by_name("Beta"), Some(base + 0x2000));
    assert_eq!(module.export_by_name("Alpha"), None);
}

/// By *public* ordinal (`Base` + function index), reaching the nameless
/// slot no name lookup can -- mirroring `PeImage::export_rva_by_ordinal`,
/// forwarder and range refusals included.
#[test]
fn rebased_exports_answer_a_public_ordinal_including_the_nameless_slot() {
    let base = 0x7000_0000;
    let exports = Exports::rebased(&rebase_fixture(), base);

    assert_eq!(exports.by_ordinal(5), Some(base + 0x2000), "Base(5) + index 0");
    assert_eq!(exports.by_ordinal(6), Some(base + 0x2010), "the nameless slot");
    assert_eq!(exports.by_ordinal(7), Some(base + 0x2020));
    assert_eq!(exports.by_ordinal(8), None, "index 3 is the forwarder");
    assert_eq!(exports.by_ordinal(4), None, "below Base -- refused, not wrapped");
    assert_eq!(exports.by_ordinal(9), None, "past NumberOfFunctions(4)");

    let module = Module::new(base + 0x1000, None, Vec::new(), exports);
    assert_eq!(module.export_by_ordinal(6), Some(base + 0x2010));
    assert_eq!(module.export_by_ordinal(8), None);
}
