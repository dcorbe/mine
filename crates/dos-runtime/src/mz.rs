//! Loading a real `.EXE`.
//!
//! The proof of concept's first program was a hand-assembled `.COM`, which is
//! just bytes at `seg:0x100`. Everything in `archive/` is an MZ instead:
//! a header, a relocation table, and a program that expects DOS to have built
//! it a PSP and an environment before it runs a single instruction.
//!
//! `LORDCFG.EXE` 4.06 carries 2,637 relocations, so this is not optional.

use std::io;

use crate::kvm::VmGuest;

/// Bytes DOS reserves ahead of the load image for the Program Segment Prefix.
pub const PSP_SIZE: u16 = 0x100;

/// A parsed MZ image, still at its link-time addresses.
pub struct MzImage {
    /// The load image, header stripped.
    pub bytes: Vec<u8>,
    /// Entry point, relative to the start of the load image.
    pub cs: u16,
    pub ip: u16,
    /// Initial stack, `ss` relative to the start of the load image.
    pub ss: u16,
    pub sp: u16,
    /// Where a paragraph fixup must be applied, as `(segment, offset)`
    /// relative to the load image.
    pub relocs: Vec<(u16, u16)>,
    /// Extra paragraphs the program needs beyond its image.
    pub min_alloc: u16,
    pub max_alloc: u16,
}

fn word(d: &[u8], at: usize) -> io::Result<u16> {
    d.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| io::Error::other(format!("truncated MZ header at {at:#x}")))
}

impl MzImage {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < 0x1c || (&data[0..2] != b"MZ" && &data[0..2] != b"ZM") {
            return Err(io::Error::other("not an MZ executable"));
        }
        let last_page = word(data, 0x02)?;
        let pages = word(data, 0x04)?;
        let reloc_count = word(data, 0x06)?;
        let header_para = word(data, 0x08)?;
        let min_alloc = word(data, 0x0a)?;
        let max_alloc = word(data, 0x0c)?;
        let ss = word(data, 0x0e)?;
        let sp = word(data, 0x10)?;
        let ip = word(data, 0x14)?;
        let cs = word(data, 0x16)?;
        let reloc_off = word(data, 0x18)? as usize;

        let header_len = header_para as usize * 16;
        // The last page is partial unless `last_page` is zero, in which case
        // DOS reads the whole 512 bytes -- a rule that is easy to get backwards.
        let image_end = (pages as usize).saturating_sub(1) * 512
            + if last_page == 0 { 512 } else { last_page as usize };
        if header_len > data.len() {
            return Err(io::Error::other("MZ header longer than the file"));
        }
        let end = image_end.min(data.len());
        if end < header_len {
            return Err(io::Error::other("MZ image ends before its header"));
        }
        let bytes = data[header_len..end].to_vec();

        let mut relocs = Vec::with_capacity(reloc_count as usize);
        for i in 0..reloc_count as usize {
            let at = reloc_off + i * 4;
            relocs.push((word(data, at + 2)?, word(data, at)?));
        }

        Ok(Self {
            bytes,
            cs,
            ip,
            ss,
            sp,
            relocs,
            min_alloc,
            max_alloc,
        })
    }

    /// Paragraphs of memory the loaded program occupies, PSP included.
    pub fn paragraphs(&self) -> usize {
        PSP_SIZE as usize / 16 + self.bytes.len().div_ceil(16) + self.min_alloc as usize
    }
}

/// Where a program was placed, and how to enter it.
pub struct Loaded {
    pub psp_seg: u16,
    pub image_seg: u16,
    pub cs: u16,
    pub ip: u16,
    pub ss: u16,
    pub sp: u16,
}

/// Build a PSP, apply relocations, and place the image.
///
/// `env_seg` must already hold the environment block. DOS enters a program
/// with `DS` and `ES` pointing at the PSP, not at the program's own data --
/// a Borland startup stub's first job is to fix that up itself.
pub fn load(
    vm: &mut VmGuest,
    img: &MzImage,
    psp_seg: u16,
    env_seg: u16,
    tail: &[u8],
) -> io::Result<Loaded> {
    let image_seg = psp_seg + PSP_SIZE / 16;

    let mut psp = [0u8; PSP_SIZE as usize];
    psp[0x00] = 0xcd; // int 20h, the ancient way to exit
    psp[0x01] = 0x20;
    psp[0x02..0x04].copy_from_slice(&0xa000u16.to_le_bytes()); // top of memory
    psp[0x2c..0x2e].copy_from_slice(&env_seg.to_le_bytes());
    psp[0x50] = 0xcd; // the PSP's own `int 21h; retf` thunk
    psp[0x51] = 0x21;
    psp[0x52] = 0xcb;
    // 80h is the command tail: a length byte, the text, then a carriage return.
    let n = tail.len().min(126);
    psp[0x80] = n as u8;
    psp[0x81..0x81 + n].copy_from_slice(&tail[..n]);
    psp[0x81 + n] = 0x0d;
    vm.load(psp_seg as usize * 16, &psp)?;

    // Relocate in a copy, so the same MzImage can be loaded twice.
    let mut bytes = img.bytes.clone();
    for &(seg, off) in &img.relocs {
        let at = seg as usize * 16 + off as usize;
        let slot = bytes.get_mut(at..at + 2).ok_or_else(|| {
            io::Error::other(format!("relocation {seg:#06x}:{off:#06x} is outside the image"))
        })?;
        let patched = u16::from_le_bytes([slot[0], slot[1]]).wrapping_add(image_seg);
        slot.copy_from_slice(&patched.to_le_bytes());
    }
    vm.load(image_seg as usize * 16, &bytes)?;

    Ok(Loaded {
        psp_seg,
        image_seg,
        cs: img.cs.wrapping_add(image_seg),
        ip: img.ip,
        ss: img.ss.wrapping_add(image_seg),
        sp: img.sp,
    })
}

/// Lay out a DOS environment block: `NAME=VALUE` strings, an empty string to
/// end them, then a count and the program's own path -- which is where
/// Turbo Pascal's `ParamStr(0)` comes from.
pub fn environment(vars: &[&str], program_path: &str) -> Vec<u8> {
    let mut env = Vec::new();
    for v in vars {
        env.extend_from_slice(v.as_bytes());
        env.push(0);
    }
    env.push(0);
    env.extend_from_slice(&1u16.to_le_bytes());
    env.extend_from_slice(program_path.as_bytes());
    env.push(0);
    env
}
