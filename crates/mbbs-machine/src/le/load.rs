//! Map a parsed [`LeImage`] flat into a below-4 GiB [`Mapping`], ready to enter
//! under `crate::m32::dpmi`.
//!
//! Flat model: all objects share one address space. The lowest object's
//! link-time `reloc_base` anchors the layout, so object `o` lands at
//! `mapping.base() + (o.reloc_base - min_reloc_base)` and the constant
//! `load_delta = mapping.base() - min_reloc_base` turns any link-time linear
//! address into its runtime one -- which is exactly what fixups add.
//!
//! A loader-provided stack (`esp_object == 0`, the DOS/4GW convention) is
//! appended above the image.

use std::io;

use super::parse::LeImage;
use crate::m32::Mapping;

/// A loaded image and where to enter it.
pub struct LeLoaded {
    pub mapping: Mapping,
    /// Linear entry `EIP`.
    pub entry_eip: u32,
    /// Linear initial `ESP`.
    pub entry_esp: u32,
    /// The mapping's base -- link address `min_reloc_base` maps here.
    pub base: u32,
    /// `base - min_reloc_base`: add to any link-time linear address.
    pub load_delta: u32,
}

/// Bytes of loader-provided stack appended above the image when the header
/// asks the loader to supply one.
const LOADER_STACK: u32 = 0x10000;

fn page_up(n: u32, page: u32) -> u32 {
    n.div_ceil(page) * page
}

/// Map `img`'s objects out of `file` (the whole `.EXE`) into a fresh mapping.
pub fn load(img: &LeImage, file: &[u8]) -> io::Result<LeLoaded> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());

    if img.objects.is_empty() {
        return Err(bad("image has no objects"));
    }
    let min_base = img.objects.iter().map(|o| o.reloc_base).min().unwrap();
    let max_end = img
        .objects
        .iter()
        .map(|o| o.reloc_base.saturating_add(o.virtual_size))
        .max()
        .unwrap();

    let span = page_up(max_end - min_base, img.page_size);
    let total = span as usize + LOADER_STACK as usize;
    let mut mapping = Mapping::new(total)?;
    let base = mapping.base() as usize as u32;
    let load_delta = base.wrapping_sub(min_base);

    {
        let dst = mapping.as_mut_slice();
        for obj in &img.objects {
            let dest_base = (obj.reloc_base - min_base) as usize;
            let first = obj.page_map_index.saturating_sub(1) as usize;
            for k in 0..obj.page_count as usize {
                let page = img
                    .pages
                    .get(first + k)
                    .ok_or_else(|| bad("object references a page past the page map"))?;
                let src_lo = page.file_offset as usize;
                let src_hi = src_lo + page.data_size as usize;
                let bytes = file
                    .get(src_lo..src_hi)
                    .ok_or_else(|| bad("page data runs past the end of the file"))?;
                let d0 = dest_base + k * img.page_size as usize;
                let d1 = d0 + bytes.len();
                dst.get_mut(d0..d1)
                    .ok_or_else(|| bad("page does not fit the object span"))?
                    .copy_from_slice(bytes);
            }
        }
    }

    // Entry point.
    let entry_obj = img
        .objects
        .get(img.entry.eip_object.saturating_sub(1) as usize)
        .ok_or_else(|| bad("entry object out of range"))?;
    let entry_eip = load_delta
        .wrapping_add(entry_obj.reloc_base)
        .wrapping_add(img.entry.eip);

    // Stack: the header's own, or the loader-provided region above the image.
    let entry_esp = if img.entry.esp_object == 0 {
        base + span + LOADER_STACK - 16
    } else {
        let so = img
            .objects
            .get(img.entry.esp_object.saturating_sub(1) as usize)
            .ok_or_else(|| bad("stack object out of range"))?;
        load_delta
            .wrapping_add(so.reloc_base)
            .wrapping_add(img.entry.esp)
    };

    Ok(LeLoaded {
        mapping,
        entry_eip,
        entry_esp,
        base,
        load_delta,
    })
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::*;
    use crate::m32::dpmi::{Exit, Machine};

    /// A synthetic single-object LE whose entry page holds `code`. reloc_base
    /// 0x10000, loader-provided stack. Mirrors `parse::tests::tiny_le`.
    fn tiny_le(code: &[u8]) -> Vec<u8> {
        let page_size = 0x1000u32;
        let hdr = 0x40usize;
        let objtab = 0xc4usize;
        let pagemap = objtab + 24;
        let data_pages = 0x2000usize;

        let mut b = vec![0u8; data_pages + page_size as usize];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(hdr as u32).to_le_bytes());
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        b[hdr..hdr + 2].copy_from_slice(b"LE");
        put32(&mut b, hdr + 0x08, 0x02);
        put32(&mut b, hdr + 0x14, 1);
        put32(&mut b, hdr + 0x18, 1);
        put32(&mut b, hdr + 0x1c, 0);
        put32(&mut b, hdr + 0x20, 0);
        put32(&mut b, hdr + 0x28, page_size);
        put32(&mut b, hdr + 0x40, objtab as u32);
        put32(&mut b, hdr + 0x44, 1);
        put32(&mut b, hdr + 0x48, pagemap as u32);
        put32(&mut b, hdr + 0x80, data_pages as u32);
        let o = hdr + objtab;
        put32(&mut b, o, code.len() as u32);
        put32(&mut b, o + 0x04, 0x10000);
        put32(&mut b, o + 0x08, 0x2005);
        put32(&mut b, o + 0x0c, 1);
        put32(&mut b, o + 0x10, 1);
        let p = hdr + pagemap;
        b[p + 2] = 1;
        b[data_pages..data_pages + code.len()].copy_from_slice(code);
        b
    }

    #[test]
    fn loads_and_places_the_entry_page() {
        let file = tiny_le(&[0xCD, 0x21]); // int 21h
        let img = parse(&file).unwrap();
        let loaded = load(&img, &file).unwrap();

        // Object reloc_base == min_base, so the entry page sits at base+0.
        assert_eq!(loaded.entry_eip, loaded.base);
        // The entry bytes actually landed there.
        assert_eq!(loaded.mapping.as_slice()[0..2], [0xCD, 0x21]);
        // Loader-provided stack is above the image.
        assert!(loaded.entry_esp > loaded.base);
    }

    #[test]
    fn a_loaded_le_runs_to_its_first_service() {
        // int 21h ; the DPMI machine turns it into a service exit.
        let file = tiny_le(&[0xCD, 0x21]);
        let img = parse(&file).unwrap();
        let loaded = load(&img, &file).unwrap();

        let mut m = Machine::adopt(loaded.mapping, loaded.entry_eip, loaded.entry_esp).unwrap();
        match m.run().unwrap() {
            Exit::Service { vector: 0x21, .. } => {}
            other => panic!("expected Service(0x21) from the loaded image, got {other:?}"),
        }
    }
}
