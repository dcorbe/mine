//! Parsing, against images built here rather than against a real module.
//!
//! The real-module tests live in `tests/wccmmud.rs`. These exist because a real
//! file exercises exactly one path through each branch, and the error paths need
//! an input built to reach them.

use mbbs32::{PeError, PeImage, Relocation};

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
    let mut v = with_one_section();
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
    let mut v = with_one_section();
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
