//! Far pointers, and why resolving one is not just addition.
//!
//! Galacticomm compiled these modules in Borland's huge model with `DS != SS`.
//! Every pointer is therefore a 4-byte `seg:off`, and the segment can name any
//! of the module's segments -- code, data, or the stack a local lives on. There
//! is no case where a pointer is implicitly in `DS`.
//!
//! So a host can never resolve a module pointer by adding a fixed base. It has
//! to look the selector up in the descriptor table it built, which is also the
//! only place the segment's length is known, and therefore the only way to
//! bounds-check the access. Module memory is untrusted input: a pointer that
//! names nothing, or runs off the end of what it names, has to come back as an
//! error rather than as a host-side out-of-bounds read.

use std::fmt;

/// A pointer as 16-bit code understands it: a 16-bit offset and a 16-bit
/// selector, offset first in memory.
///
/// `Hash` because a host that keeps a block's size out of the module's reach
/// keys it by the pointer it handed out. Equality is the pair of words as the
/// module holds them, which is the only identity there is -- two different
/// selectors can window the same memory, and they are not the same pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FarPtr {
    pub offset: u16,
    pub selector: u16,
}

impl FarPtr {
    /// The null pointer, as 16-bit code writes it.
    ///
    /// Selector 0 names nothing -- [`ldt_index`] rejects it before any access --
    /// so this is a value the host can hand back and a module can test, and
    /// never one that resolves. It is what a routine returns when absence is the
    /// answer: `fopen` of a file that is not there, `rstbtv` past the bottom of
    /// the stack.
    pub const NULL: Self = Self {
        offset: 0,
        selector: 0,
    };

    /// The four bytes an `lcall` operand -- or a pushed far pointer argument --
    /// consists of.
    pub fn to_bytes(self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&self.offset.to_le_bytes());
        out[2..4].copy_from_slice(&self.selector.to_le_bytes());
        out
    }

    /// Read a far pointer out of four little-endian bytes.
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self {
            offset: u16::from_le_bytes([bytes[0], bytes[1]]),
            selector: u16::from_le_bytes([bytes[2], bytes[3]]),
        }
    }
}

impl fmt::Display for FarPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.selector, self.offset)
    }
}

/// Why a module's pointer could not be honoured.
///
/// Every variant is something a module can cause, so none of them is a bug in
/// the host and none should be a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FarPtrError {
    /// Selector 0. Modules use `0000:0000` as a null pointer.
    Null,

    /// The selector's table-indicator bit is clear, so it names the GDT. Those
    /// are the kernel's, not ours.
    NotLocal { selector: u16 },

    /// A local selector with no segment of this module behind it.
    NoSuchSegment { selector: u16 },

    /// The access starts inside the segment but does not end there -- or starts
    /// outside it altogether.
    OutOfBounds {
        ptr: FarPtr,
        len: usize,
        limit: usize,
    },

    /// A string ran to the end of its segment without a terminator.
    Unterminated { ptr: FarPtr },
}

impl fmt::Display for FarPtrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null far pointer"),
            Self::NotLocal { selector } => {
                write!(f, "selector {selector:#06x} is not an LDT selector")
            }
            Self::NoSuchSegment { selector } => {
                write!(
                    f,
                    "selector {selector:#06x} names no segment of this module"
                )
            }
            Self::OutOfBounds { ptr, len, limit } => write!(
                f,
                "{len} bytes at {ptr} runs past the end of a {limit}-byte segment"
            ),
            Self::Unterminated { ptr } => {
                write!(
                    f,
                    "string at {ptr} has no terminator before its segment ends"
                )
            }
        }
    }
}

impl std::error::Error for FarPtrError {}

impl From<FarPtrError> for std::io::Error {
    fn from(e: FarPtrError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    }
}

/// Split a selector into the LDT index it names, rejecting the ones that name
/// nothing of ours.
///
/// A selector is `index << 3 | TI << 2 | RPL`. The table-indicator bit is what
/// distinguishes our LDT descriptors from the kernel's GDT ones, and checking
/// it is what stops a module passing, say, `0x33` and being handed something.
pub(crate) fn ldt_index(selector: u16) -> Result<u16, FarPtrError> {
    if selector == 0 {
        return Err(FarPtrError::Null);
    }
    if selector & 0b100 == 0 {
        return Err(FarPtrError::NotLocal { selector });
    }
    Ok(selector >> 3)
}
