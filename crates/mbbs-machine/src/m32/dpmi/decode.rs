//! A deliberately tiny decoder: exactly the instructions that fault in ring 3
//! and that this ABI turns into host services or handles in the fault arm.
//! Not a disassembler.
//!
//! Handled: `CD ib` (int), `E4/E5 ib` and `EC/ED` (in), `E6/E7 ib` and
//! `EE/EF` (out), `FA` (cli), `FB` (sti). A leading `0x66` operand-size prefix
//! selects the 16-bit width on the word forms; `0xF3` is tolerated and
//! ignored. Everything else -- including a null-dereference pattern -- returns
//! `None`, and the caller treats that as a genuine fault.
//!
//! Port *values* for the register forms (`in al, dx` / `out dx, al`) live in
//! `DX` at fault time; resolving them is the service layer's job, since it has
//! the registers. `decode` reports `port: 0` for those and the real port only
//! for the imm8 forms.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trap {
    /// `int n` -- a software interrupt (DOS `0x21`, DPMI `0x31`, BIOS, ...).
    Int(u8),
    /// `in` from a port. `port` is meaningful only for the imm8 forms;
    /// register forms carry it in `DX`. `size` is 1, 2 or 4 bytes.
    In { port: u16, size: u8 },
    /// `out` to a port. Same `port`/`size` rules as [`Trap::In`].
    Out { port: u16, size: u8 },
    /// `cli` -- clear the (virtual) interrupt flag.
    Cli,
    /// `sti` -- set the (virtual) interrupt flag.
    Sti,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    pub trap: Trap,
    /// Total instruction length in bytes, prefixes included, so the caller can
    /// advance EIP past it.
    pub len: u8,
}

/// Decode one trap instruction at the start of `bytes`, or `None` if the bytes
/// are not one this ABI handles.
pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    let mut i = 0usize;
    // Default operand size is 32-bit in a flat 32-bit segment; `0x66` narrows
    // the word `in`/`out` forms to 16-bit.
    let mut size = 4u8;
    loop {
        match bytes.get(i)? {
            0x66 => {
                size = 2;
                i += 1;
            }
            0xF3 => {
                i += 1;
            }
            _ => break,
        }
    }

    let op = *bytes.get(i)?;
    let prefix_len = i as u8;
    // Length of prefixes + the one opcode byte.
    let base = prefix_len + 1;

    match op {
        0xCD => Some(Decoded {
            trap: Trap::Int(*bytes.get(i + 1)?),
            len: base + 1,
        }),
        0xFA => Some(Decoded {
            trap: Trap::Cli,
            len: base,
        }),
        0xFB => Some(Decoded {
            trap: Trap::Sti,
            len: base,
        }),
        // in al, dx  /  in eax|ax, dx
        0xEC => Some(Decoded {
            trap: Trap::In { port: 0, size: 1 },
            len: base,
        }),
        0xED => Some(Decoded {
            trap: Trap::In { port: 0, size },
            len: base,
        }),
        // out dx, al  /  out dx, eax|ax
        0xEE => Some(Decoded {
            trap: Trap::Out { port: 0, size: 1 },
            len: base,
        }),
        0xEF => Some(Decoded {
            trap: Trap::Out { port: 0, size },
            len: base,
        }),
        // in al, imm8  /  in eax|ax, imm8
        0xE4 => Some(Decoded {
            trap: Trap::In {
                port: u16::from(*bytes.get(i + 1)?),
                size: 1,
            },
            len: base + 1,
        }),
        0xE5 => Some(Decoded {
            trap: Trap::In {
                port: u16::from(*bytes.get(i + 1)?),
                size,
            },
            len: base + 1,
        }),
        // out imm8, al  /  out imm8, eax|ax
        0xE6 => Some(Decoded {
            trap: Trap::Out {
                port: u16::from(*bytes.get(i + 1)?),
                size: 1,
            },
            len: base + 1,
        }),
        0xE7 => Some(Decoded {
            trap: Trap::Out {
                port: u16::from(*bytes.get(i + 1)?),
                size,
            },
            len: base + 1,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_trap_opcodes() {
        assert_eq!(
            decode(&[0xCD, 0x21]).unwrap(),
            Decoded { trap: Trap::Int(0x21), len: 2 }
        );
        assert_eq!(
            decode(&[0xCD, 0x31]).unwrap(),
            Decoded { trap: Trap::Int(0x31), len: 2 }
        );
        assert_eq!(decode(&[0xFA]).unwrap(), Decoded { trap: Trap::Cli, len: 1 });
        assert_eq!(decode(&[0xFB]).unwrap(), Decoded { trap: Trap::Sti, len: 1 });
        assert_eq!(
            decode(&[0xEE]).unwrap(),
            Decoded { trap: Trap::Out { port: 0, size: 1 }, len: 1 }
        );
        assert_eq!(
            decode(&[0xEC]).unwrap(),
            Decoded { trap: Trap::In { port: 0, size: 1 }, len: 1 }
        );
        // out 0x21, al  (imm8 port -- the PIC mask register)
        assert_eq!(
            decode(&[0xE6, 0x21]).unwrap(),
            Decoded { trap: Trap::Out { port: 0x21, size: 1 }, len: 2 }
        );
        // 0x66 prefix -> 16-bit width on `out dx, ax`
        assert_eq!(
            decode(&[0x66, 0xEF]).unwrap(),
            Decoded { trap: Trap::Out { port: 0, size: 2 }, len: 2 }
        );
        // 32-bit default width on the dword form
        assert_eq!(
            decode(&[0xED]).unwrap(),
            Decoded { trap: Trap::In { port: 0, size: 4 }, len: 1 }
        );
    }

    #[test]
    fn non_traps_return_none() {
        assert!(decode(&[0x90]).is_none(), "nop is not a trap");
        assert!(decode(&[0x00, 0x00]).is_none(), "null-deref pattern is not a trap");
        assert!(decode(&[0xFF, 0x25, 0, 0, 0, 0]).is_none(), "indirect jmp is not a trap");
        assert!(decode(&[]).is_none(), "empty input");
        assert!(decode(&[0xCD]).is_none(), "truncated int has no vector");
    }
}
