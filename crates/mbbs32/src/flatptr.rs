//! A 32-bit module's pointer: a linear address into its mapped [`Image`].
//!
//! **Linear, not an RVA.** [`Image::base()`] is almost never the module's
//! own `ImageBase` -- `Mapping::new` never requests a fixed address. A
//! `Flat32Ptr` therefore converts to an rva by subtracting `image.base()`,
//! not by being one directly.
//!
//! **Constructible only from a linear address, never from another
//! pointer type's bits.** `FarPtr` is also 32 bits total
//! (`selector: u16, offset: u16`), so a bit-reinterpreting conversion
//! between the two would silently type-check. There is deliberately no
//! `From<FarPtr>`/`as`-style path here.

use mbbs_ptr::ModulePtr;

use crate::Image;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flat32Ptr(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flat32PtrError {
    OutOfBounds { addr: u32, len: usize },
    Unterminated { addr: u32 },
}

impl std::fmt::Display for Flat32PtrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfBounds { addr, len } => {
                write!(f, "{len} bytes at {addr:#010x} runs past the end of the image")
            }
            Self::Unterminated { addr } => {
                write!(f, "string at {addr:#010x} has no terminator before the image ends")
            }
        }
    }
}

impl std::error::Error for Flat32PtrError {}

impl std::fmt::Display for Flat32Ptr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl ModulePtr for Flat32Ptr {
    type Memory = Image;
    type Error = Flat32PtrError;

    fn resolve<'m>(&self, memory: &'m Image, len: usize) -> Result<&'m [u8], Flat32PtrError> {
        let rva = self.0.wrapping_sub(memory.base());
        memory
            .read_at(rva, len)
            .map_err(|_| Flat32PtrError::OutOfBounds { addr: self.0, len })
    }

    fn read_cstr<'m>(&self, memory: &'m Image) -> Result<&'m [u8], Flat32PtrError> {
        let rva = self.0.wrapping_sub(memory.base());

        // A pointer with zero bytes left before the image ends is refused as
        // OutOfBounds, not treated as an empty Unterminated string -- the
        // same distinction `FarPtr::read_cstr` (mbbs16/src/lib.rs) draws via
        // its own `filter(|n| *n > 0)`. Kept explicit here rather than
        // saturating to zero and letting the terminator scan fail on an
        // empty slice, so the two ModulePtr impls agree at this boundary.
        let avail = memory
            .as_slice()
            .len()
            .checked_sub(rva as usize)
            .filter(|n| *n > 0)
            .ok_or(Flat32PtrError::OutOfBounds { addr: self.0, len: 1 })?;

        let tail = memory
            .read_at(rva, avail)
            .map_err(|_| Flat32PtrError::OutOfBounds { addr: self.0, len: 1 })?;
        let n = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(Flat32PtrError::Unterminated { addr: self.0 })?;
        Ok(&tail[..n])
    }

    fn write(&self, memory: &mut Image, bytes: &[u8]) -> Result<(), Flat32PtrError> {
        let rva = self.0.wrapping_sub(memory.base());
        memory
            .write_at(rva, bytes)
            .map_err(|_| Flat32PtrError::OutOfBounds { addr: self.0, len: bytes.len() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeImage;

    /// `size_of_image` this fixture's optional header plants -- large enough
    /// that a one-section image maps comfortably inside it, with room past
    /// the section for "past the mapped length" tests, and small enough that
    /// `read_cstr_without_a_terminator_before_the_images_end_is_unterminated`
    /// can afford to overwrite the *entire* tail of the image with non-zero
    /// bytes.
    const SIZE_OF_IMAGE: u32 = 0x0000_2000;

    /// Offset (within the file buffer this returns) of the one section's raw
    /// data: section table starts at `opt + SizeOfOptionalHeader`
    /// (`0x98 + 0xe0`), one 40-byte section header, then raw data
    /// immediately after.
    const RAW_OFFSET: usize = 0x98 + 0xe0 + 40;

    /// The smallest file `PeImage::parse` accepts, plus one `CODE` section
    /// covering rva `0x1000..0x1100` (raw `0x1000..0x1080`).
    ///
    /// This is `image.rs`'s own `read_write_tests::minimal_with_one_section`
    /// byte-for-byte in shape (same MZ/PE/COFF/optional header offsets),
    /// re-sized here rather than called directly: that helper lives in a
    /// private `#[cfg(test)]` module of a *different* source file, not
    /// reachable from here, and `image.rs`'s own doc comment on the same
    /// fixture already explains why this crate's convention is to inline
    /// the layout per test module rather than reach across one.
    fn minimal_with_one_section() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
        v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
        v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics
        v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

        let opt = 0x98;
        v[opt + 16..opt + 20].copy_from_slice(&0x0000_1111u32.to_le_bytes()); // entry point
        v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes()); // image base
        v[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes()); // section alignment
        v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes()); // file alignment
        v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

        let sec = opt + 0xe0;
        v.resize(sec + 40 + 0x200, 0);
        v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
        v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes()); // PointerToRawData
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        v
    }

    /// Parse `file` and load it, panicking on failure -- every test here
    /// starts from a fixture already proven to parse and load cleanly, so a
    /// failure here is a bug in the fixture, not something under test.
    fn load(file: &[u8]) -> Image {
        let image = PeImage::parse(file).expect("fixture parses");
        Image::load(file, &image).expect("fixture loads")
    }

    #[test]
    fn a_linear_address_resolves_through_its_image() {
        // Arrange: a known byte pattern at rva 0x1010 (file offset
        // RAW_OFFSET + 0x10, inside the CODE section's raw data).
        let mut file = minimal_with_one_section();
        file[RAW_OFFSET + 0x10..RAW_OFFSET + 0x14].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let image = load(&file);

        // `Mapping::new` (map.rs) never asks mmap for a fixed address --
        // `MAP_32BIT`, no `MAP_FIXED` -- so `image.base()` is a real,
        // kernel-chosen address. It is never 0 (Linux refuses to hand back
        // the zero page), and it dwarfs this fixture's rva scale (a few
        // KiB). That is exactly the property `Image::relocate`'s own
        // nonzero-delta tests (`tests/map.rs`) lean on, applied here to
        // `Flat32Ptr` instead of to relocation: a `resolve` that forgot to
        // subtract `memory.base()` and used `self.0` directly as the rva
        // would ask `Image::read_at` for a multi-hundred-megabyte offset,
        // far past `SIZE_OF_IMAGE` (0x2000) -- an `Err`, not a
        // coincidentally correct answer. Only an implementation that
        // actually computes `self.0 - memory.base()` can pass this.
        let rva = 0x1010u32;
        let base = image.base();
        assert_ne!(base, 0, "a real mmap base is never the null address");
        assert!(
            base > SIZE_OF_IMAGE,
            "base {base:#010x} must dwarf the rva {rva:#010x} for this test to prove the \
             subtraction rather than pass by delta-zero coincidence"
        );

        let ptr = Flat32Ptr(base + rva);
        assert_eq!(ptr.resolve(&image, 4).unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn a_pointer_past_the_image_is_refused() {
        let file = minimal_with_one_section();
        let image = load(&file);

        let ptr = Flat32Ptr(image.base() + SIZE_OF_IMAGE);
        let err = ptr.resolve(&image, 1).unwrap_err();
        assert_eq!(err, Flat32PtrError::OutOfBounds { addr: ptr.0, len: 1 });
    }

    #[test]
    fn read_cstr_stops_at_the_terminator() {
        let mut file = minimal_with_one_section();
        file[RAW_OFFSET + 0x20..RAW_OFFSET + 0x26].copy_from_slice(b"hello\0");
        // Past the terminator: must not show up in the answer.
        file[RAW_OFFSET + 0x26] = b'X';
        let image = load(&file);

        let ptr = Flat32Ptr(image.base() + 0x1020);
        assert_eq!(ptr.read_cstr(&image).unwrap(), b"hello");
    }

    #[test]
    fn read_cstr_without_a_terminator_before_the_images_end_is_unterminated() {
        let file = minimal_with_one_section();
        let mut image = load(&file);

        // Overwrite the entire tail of the image, from rva 0x1000 to
        // SIZE_OF_IMAGE, with a non-zero byte -- a fresh mapping's
        // untouched pages are zero, so leaving any of that tail alone would
        // let a stray zero byte answer this test whether or not
        // `read_cstr`'s "ran off the end" path is exercised at all.
        let rva = 0x1000u32;
        let tail_len = (SIZE_OF_IMAGE - rva) as usize;
        image.write_at(rva, &vec![0xAAu8; tail_len]).unwrap();

        let ptr = Flat32Ptr(image.base() + rva);
        let err = ptr.read_cstr(&image).unwrap_err();
        assert_eq!(err, Flat32PtrError::Unterminated { addr: ptr.0 });
    }

    #[test]
    fn read_cstr_with_nothing_left_before_the_images_end_is_out_of_bounds_not_unterminated() {
        // A pointer sitting exactly at the image's end has zero bytes to
        // scan -- that is a distinct failure from "scanned some bytes, found
        // no terminator," and FarPtr::read_cstr draws the same distinction.
        let file = minimal_with_one_section();
        let image = load(&file);

        let ptr = Flat32Ptr(image.base() + SIZE_OF_IMAGE);
        let err = ptr.read_cstr(&image).unwrap_err();
        assert_eq!(err, Flat32PtrError::OutOfBounds { addr: ptr.0, len: 1 });
    }

    #[test]
    fn read_cstr_with_exactly_one_byte_left_and_no_terminator_is_unterminated() {
        // Pins the boundary at `n > 0`, not `n > 1`: a mutation that changed
        // the filter's threshold by one would still pass both of this file's
        // other read_cstr tests (one starts with a wide-open tail, the other
        // sits at zero-bytes-left, neither is *exactly* one byte inside the
        // boundary) but must fail this one -- one non-zero byte available is
        // enough to scan, and scanning it and finding no terminator is
        // Unterminated, not OutOfBounds.
        let file = minimal_with_one_section();
        let mut image = load(&file);

        let rva = SIZE_OF_IMAGE - 1;
        image.write_at(rva, &[0xAA]).unwrap();

        let ptr = Flat32Ptr(image.base() + rva);
        let err = ptr.read_cstr(&image).unwrap_err();
        assert_eq!(err, Flat32PtrError::Unterminated { addr: ptr.0 });
    }

    #[test]
    fn write_then_resolve_sees_the_write() {
        let file = minimal_with_one_section();
        let mut image = load(&file);

        let ptr = Flat32Ptr(image.base() + 0x1030);
        ptr.write(&mut image, &[1, 2, 3, 4]).unwrap();
        assert_eq!(ptr.resolve(&image, 4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn write_past_the_image_is_refused() {
        // write()'s delegation to Image::write_at is otherwise untested on
        // its error path -- Image::write_at's own out-of-bounds case is
        // covered directly (image.rs), which proves the primitive but not
        // that Flat32Ptr::write forwards its failure rather than discarding
        // it. A mutation that kept the write_at call but always returned
        // Ok(()) passed the whole suite until this test existed.
        let file = minimal_with_one_section();
        let mut image = load(&file);

        let ptr = Flat32Ptr(image.base() + SIZE_OF_IMAGE);
        let err = ptr.write(&mut image, &[0]).unwrap_err();
        assert_eq!(err, Flat32PtrError::OutOfBounds { addr: ptr.0, len: 1 });
    }
}
