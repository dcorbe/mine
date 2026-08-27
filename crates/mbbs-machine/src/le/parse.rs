//! Parse the LE and LX "linear executable" headers far enough to load and
//! run one: the entry point, the object table, the per-object page map, and
//! where each page's bytes live in the file.
//!
//! LE (DOS extenders, e.g. DOS/4GW) and LX (OS/2 2.x, e.g. the DOS Btrieve
//! 6.15 engine) share the whole fixed header. They diverge in two places this
//! parser cares about: the field at header+0x2c (LE: bytes-on-last-page; LX:
//! page-offset shift) and the object page-map entry (LE: 4 bytes; LX: 8). Both
//! are handled; the discriminator is the signature.
//!
//! Grounded against the real LX `BTRIEVE.EXE` (a gitignored fixture) in the
//! tests below. LE has no real fixture on this machine, so its object-page
//! math is exercised only by synthetic images; validating it against a real
//! DOS/4GW `DOOM.EXE` is still owed.

/// Which linear-executable flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// `LE` -- DOS extenders (DOS/4GW).
    Le,
    /// `LX` -- OS/2 2.x 32-bit.
    Lx,
}

/// One object (a loadable segment in flat-model clothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeObject {
    /// Bytes this object occupies once loaded (may exceed the sum of its page
    /// sizes; the tail is zero-filled bss).
    pub virtual_size: u32,
    /// The link-time linear base. Absolute references are relocated off this;
    /// under `MAP_32BIT` the real base differs, so fixups matter.
    pub reloc_base: u32,
    /// Object flags (readable/writable/executable/big-bit …); passed through.
    pub flags: u32,
    /// 1-based index of this object's first entry in the page map.
    pub page_map_index: u32,
    /// How many pages the page map holds for this object.
    pub page_count: u32,
}

/// One page-map entry: where a page's bytes are and how many are real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageEntry {
    /// File offset of this page's bytes (already resolved from the flavour's
    /// own encoding, absolute from the start of the file).
    pub file_offset: u64,
    /// How many bytes of the page are present in the file; the rest of
    /// `page_size` is zero-fill.
    pub data_size: u32,
}

/// The initial `CS:EIP` / `SS:ESP`, as object number + offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeEntry {
    /// 1-based object the entry point lives in.
    pub eip_object: u32,
    /// Offset of the entry point within that object.
    pub eip: u32,
    /// 1-based object the initial stack lives in, or `0` when the loader must
    /// provide the stack itself (the DOS/4GW convention).
    pub esp_object: u32,
    /// Offset of the initial stack pointer within `esp_object`.
    pub esp: u32,
}

/// Everything the loader needs from a parsed image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeImage {
    pub flavour: Flavour,
    /// CPU type from the header (2 = 80386, the only one we run).
    pub cpu: u16,
    pub page_size: u32,
    pub entry: LeEntry,
    pub objects: Vec<LeObject>,
    pub pages: Vec<PageEntry>,
}

/// Why an image would not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeError {
    /// No `MZ` stub, or `e_lfanew` out of range.
    NoMzStub,
    /// The signature at `e_lfanew` was neither `LE` nor `LX`.
    BadSignature([u8; 2]),
    /// A field or table ran past the end of the file.
    Truncated(&'static str),
    /// `page_size` was zero, or some other value that cannot be right.
    Malformed(&'static str),
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, LeError> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(LeError::Truncated("u16"))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32, LeError> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(LeError::Truncated("u32"))
}

/// Parse `bytes` (a whole `.EXE` file image) into an [`LeImage`].
pub fn parse(bytes: &[u8]) -> Result<LeImage, LeError> {
    // MZ stub -> e_lfanew -> LE/LX header.
    if bytes.get(0..2) != Some(b"MZ") && bytes.get(0..2) != Some(b"ZM") {
        return Err(LeError::NoMzStub);
    }
    let e = u32_at(bytes, 0x3c)? as usize;
    if e == 0 || e + 0xc4 > bytes.len() {
        return Err(LeError::NoMzStub);
    }
    let sig = [bytes[e], bytes[e + 1]];
    let flavour = match &sig {
        b"LE" => Flavour::Le,
        b"LX" => Flavour::Lx,
        _ => return Err(LeError::BadSignature(sig)),
    };

    let cpu = u16_at(bytes, e + 0x08)?;
    let page_size = u32_at(bytes, e + 0x28)?;
    if page_size == 0 || page_size > 0x10000 {
        return Err(LeError::Malformed("page_size"));
    }
    // header+0x2c is the page-offset shift for LX, and bytes-on-last-page for
    // LE (irrelevant to us -- LE page data is page_size-aligned in the file).
    let page_offset_shift = if flavour == Flavour::Lx {
        u32_at(bytes, e + 0x2c)?
    } else {
        0
    };

    let entry = LeEntry {
        eip_object: u32_at(bytes, e + 0x18)?,
        eip: u32_at(bytes, e + 0x1c)?,
        esp_object: u32_at(bytes, e + 0x20)?,
        esp: u32_at(bytes, e + 0x24)?,
    };

    // Table offsets at 0x40.. are relative to the header start; data_pages at
    // 0x80 is absolute from the start of the file.
    let object_table = e + u32_at(bytes, e + 0x40)? as usize;
    let object_count = u32_at(bytes, e + 0x44)? as usize;
    let page_map = e + u32_at(bytes, e + 0x48)? as usize;
    let data_pages = u32_at(bytes, e + 0x80)? as u64;

    let mut objects = Vec::with_capacity(object_count);
    for i in 0..object_count {
        let o = object_table + i * 24;
        if o + 24 > bytes.len() {
            return Err(LeError::Truncated("object table"));
        }
        objects.push(LeObject {
            virtual_size: u32_at(bytes, o)?,
            reloc_base: u32_at(bytes, o + 0x04)?,
            flags: u32_at(bytes, o + 0x08)?,
            page_map_index: u32_at(bytes, o + 0x0c)?,
            page_count: u32_at(bytes, o + 0x10)?,
        });
    }

    // Total pages = the highest (index + count) any object references.
    let total_pages = objects
        .iter()
        .map(|o| (o.page_map_index + o.page_count).saturating_sub(1) as usize)
        .max()
        .unwrap_or(0);

    let mut pages = Vec::with_capacity(total_pages);
    for i in 0..total_pages {
        let entry = match flavour {
            Flavour::Lx => {
                // 8-byte entry: page_data_offset(4), data_size(2), flags(2).
                let p = page_map + i * 8;
                let off = u32_at(bytes, p)? as u64;
                let size = u16_at(bytes, p + 4)? as u32;
                PageEntry {
                    file_offset: data_pages + (off << page_offset_shift),
                    data_size: if size == 0 { page_size } else { size },
                }
            }
            Flavour::Le => {
                // 4-byte entry: 3-byte big-endian page number + 1 flag byte.
                // Page data is page_size-aligned: page N (1-based) at
                // data_pages + (N-1) * page_size.
                let p = page_map + i * 4;
                let hi = *bytes.get(p).ok_or(LeError::Truncated("LE page map"))? as u32;
                let mid = *bytes.get(p + 1).ok_or(LeError::Truncated("LE page map"))? as u32;
                let lo = *bytes.get(p + 2).ok_or(LeError::Truncated("LE page map"))? as u32;
                let page_number = (hi << 16) | (mid << 8) | lo;
                let index = page_number.max(1) - 1;
                PageEntry {
                    file_offset: data_pages + u64::from(index) * u64::from(page_size),
                    data_size: page_size,
                }
            }
        };
        pages.push(entry);
    }

    Ok(LeImage {
        flavour,
        cpu,
        page_size,
        entry,
        objects,
        pages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const BTRIEVE: &str = "../../archive/_acquire/goldstar/e615/BTRIEVE.EXE";

    #[test]
    fn real_lx_btrieve_header_and_object_table() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(BTRIEVE);
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skip: {} absent (gitignored fixture)", path.display());
            return;
        };
        let img = parse(&bytes).expect("BTRIEVE.EXE parses as LX");

        assert_eq!(img.flavour, Flavour::Lx);
        assert_eq!(img.cpu, 0x02, "80386");
        assert_eq!(img.page_size, 4096);
        assert_eq!(img.entry.eip_object, 1);
        assert_eq!(img.entry.eip, 0x37afc);
        assert_eq!(img.objects.len(), 2);

        let o1 = &img.objects[0];
        assert_eq!(o1.virtual_size, 0x382ab);
        assert_eq!(o1.reloc_base, 0x10000);
        assert_eq!(o1.page_map_index, 1);
        assert_eq!(o1.page_count, 57);

        let o2 = &img.objects[1];
        assert_eq!(o2.reloc_base, 0x50000);
        assert_eq!(o2.page_count, 5);

        // data pages begin at file 0x6200; pageshift 0, first entry offset 0.
        assert_eq!(img.pages[0].file_offset, 0x6200);
        assert_eq!(img.pages[0].data_size, 4096);
    }

    /// A minimal synthetic LE: one object, one page, entry at object offset 0.
    /// The builder and parser agree by construction; this pins the LE-specific
    /// page math (4-byte entries, page_size-aligned file data) until a real
    /// DOS/4GW binary can supersede it.
    fn tiny_le(code: &[u8]) -> Vec<u8> {
        let page_size = 0x1000u32;
        // Layout: [MZ 0x40][LE header 0xc4][obj table][page map][pad to data][page data]
        let mz_len = 0x40usize;
        let hdr = mz_len; // e_lfanew
        let hdr_len = 0xc4usize;
        let objtab = hdr_len; // relative to header
        let pagemap = objtab + 24;
        let data_pages = 0x2000usize; // absolute file offset, page-aligned

        let mut b = vec![0u8; data_pages + page_size as usize];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(hdr as u32).to_le_bytes());

        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        b[hdr..hdr + 2].copy_from_slice(b"LE");
        put32(&mut b, hdr + 0x08, 0x02); // cpu 386
        put32(&mut b, hdr + 0x14, 1); // module pages
        put32(&mut b, hdr + 0x18, 1); // eip object
        put32(&mut b, hdr + 0x1c, 0); // eip
        put32(&mut b, hdr + 0x20, 0); // esp object (loader provides)
        put32(&mut b, hdr + 0x28, page_size);
        put32(&mut b, hdr + 0x40, objtab as u32);
        put32(&mut b, hdr + 0x44, 1); // object count
        put32(&mut b, hdr + 0x48, pagemap as u32);
        put32(&mut b, hdr + 0x80, data_pages as u32);

        // object record
        let o = hdr + objtab;
        put32(&mut b, o, code.len() as u32); // virtual size
        put32(&mut b, o + 0x04, 0x10000); // reloc base
        put32(&mut b, o + 0x08, 0x2005); // flags: readable+executable+big
        put32(&mut b, o + 0x0c, 1); // page map index (1-based)
        put32(&mut b, o + 0x10, 1); // page count

        // LE page map entry: 3-byte page number (1) + flag byte
        let p = hdr + pagemap;
        b[p] = 0;
        b[p + 1] = 0;
        b[p + 2] = 1; // page number 1
        b[p + 3] = 0;

        b[data_pages..data_pages + code.len()].copy_from_slice(code);
        b
    }

    #[test]
    fn synthetic_le_parses() {
        let img = parse(&tiny_le(&[0xCD, 0x21])).expect("synthetic LE parses");
        assert_eq!(img.flavour, Flavour::Le);
        assert_eq!(img.page_size, 0x1000);
        assert_eq!(img.objects.len(), 1);
        assert_eq!(img.objects[0].reloc_base, 0x10000);
        assert_eq!(img.entry.eip_object, 1);
        assert_eq!(img.entry.eip, 0);
        assert_eq!(img.pages.len(), 1);
        assert_eq!(img.pages[0].file_offset, 0x2000);
    }

    #[test]
    fn rejects_non_le() {
        assert_eq!(parse(&[]).unwrap_err(), LeError::NoMzStub);
        // A PE: MZ stub, valid e_lfanew, buffer large enough for the header
        // window so the signature check is actually reached.
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x82].copy_from_slice(b"PE");
        assert_eq!(parse(&pe).unwrap_err(), LeError::BadSignature(*b"PE"));
    }
}
