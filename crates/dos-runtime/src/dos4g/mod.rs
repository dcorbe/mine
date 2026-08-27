//! Run a DOS/4GW-era LE program natively: parse and load it with
//! `mbbs_machine::le`, then drive `mbbs_machine::m32::dpmi::Machine`, servicing
//! its `int 21h` calls against a terminal.
//!
//! The `int 21h` surface here is deliberately minimal -- the console calls a
//! text-mode program needs (`AH=02/09/40`) plus terminate (`AH=4C`). It is the
//! seed of a proper flat edge onto `crates/dos`'s battle-tested kernel: that
//! kernel resolves pointers as 16-bit `seg:off`, so reusing it for flat 32-bit
//! calls needs a `Guest32` trait it does not have yet. Until then this handles
//! exactly what a "hello, world" proves, and every other call is a named,
//! diagnosable stop rather than a silent zero. int 31h (DPMI) is likewise a
//! named stop for now.

use std::io::{self, Write};

use mbbs_machine::le;
use mbbs_machine::m32::dpmi::{Exit, Machine};

/// Run the LE image in `data`, writing program output to `out`. Returns the
/// program's exit code (`AH=4C`'s `AL`).
pub fn run_le(data: &[u8], out: &mut dyn Write) -> io::Result<i32> {
    let img = le::parse(data).map_err(|e| bad(format!("LE parse: {e:?}")))?;
    if img.cpu != 0x02 {
        return Err(bad(format!("LE cpu type {:#x} is not 80386", img.cpu)));
    }
    let loaded = le::load(&img, data)?;
    let mut m = Machine::adopt(loaded.mapping, loaded.entry_eip, loaded.entry_esp)?;

    loop {
        match m.run()? {
            Exit::Service { vector: 0x21, .. } => {
                if let Some(code) = service_int21(&mut m, out)? {
                    return Ok(code);
                }
                // Resume just past the two-byte `int 21h`.
                let eip = m.regs32().eip;
                m.set_eip(eip + 2);
            }
            Exit::Service { vector, eip } => {
                return Err(bad(format!(
                    "unimplemented int {vector:#04x} at eip {eip:#010x} \
                     (link-relative {:#x})",
                    eip.wrapping_sub(loaded.load_delta)
                )));
            }
            Exit::Fault { signo, eip } => {
                return Err(bad(format!(
                    "guest faulted with signal {signo} at eip {eip:#010x} \
                     (link-relative {:#x})",
                    eip.wrapping_sub(loaded.load_delta)
                )));
            }
        }
    }
}

/// Service one `int 21h`. `Ok(Some(code))` terminates the program; `Ok(None)`
/// continues.
fn service_int21(m: &mut Machine, out: &mut dyn Write) -> io::Result<Option<i32>> {
    let r = m.regs32();
    let ah = (r.eax >> 8) & 0xff;
    match ah {
        // 02h -- display the character in DL.
        0x02 => {
            out.write_all(&[(r.edx & 0xff) as u8])?;
            Ok(None)
        }
        // 09h -- display the `$`-terminated string at DS:DX (flat: EDX).
        0x09 => {
            let mut buf = Vec::new();
            let mut p = r.edx;
            loop {
                let byte = m
                    .read_mem(p, 1)
                    .ok_or_else(|| bad(format!("int 21h/09: bad string pointer {:#x}", r.edx)))?[0];
                if byte == b'$' {
                    break;
                }
                buf.push(byte);
                p = p.wrapping_add(1);
                if buf.len() > 0xffff {
                    return Err(bad("int 21h/09: unterminated string"));
                }
            }
            out.write_all(&buf)?;
            m.set_eax((r.eax & !0xff) | u32::from(b'$'));
            Ok(None)
        }
        // 40h -- write CX bytes at DS:DX (flat: ECX/EDX) to handle BX. Handles
        // 1 (stdout) and 2 (stderr) both go to `out`; a file handle needs the
        // files subsystem this seed does not have.
        0x40 => {
            let handle = r.ebx & 0xffff;
            if handle != 1 && handle != 2 {
                return Err(bad(format!("int 21h/40: handle {handle} is not stdout/stderr")));
            }
            let len = r.ecx as usize;
            let bytes = m
                .read_mem(r.edx, len)
                .ok_or_else(|| bad(format!("int 21h/40: buffer {:#x}+{len} out of range", r.edx)))?
                .to_vec();
            out.write_all(&bytes)?;
            m.set_eax(len as u32); // AX = bytes written
            Ok(None)
        }
        // 4Ch -- terminate with return code AL.
        0x4c => Ok(Some((r.eax & 0xff) as i32)),
        other => Err(bad(format!(
            "unimplemented int 21h AH={other:#04x} at eip {:#010x}",
            r.eip
        ))),
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a position-independent LE that writes `msg` via int 21h AH=40h
    /// then exits with `code`. The message address is taken PC-relatively (a
    /// `call`/`pop`), so it is correct at any load base -- no fixups needed.
    fn writer_le(msg: &[u8], code: u8) -> Vec<u8> {
        let mut prog = Vec::new();
        // call after_msg   (E8 rel32, rel32 = msg.len())
        prog.push(0xE8);
        prog.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        // msg bytes
        prog.extend_from_slice(msg);
        // after_msg:
        prog.push(0x5A); // pop edx  -> edx = &msg
        prog.push(0xB9); // mov ecx, imm32
        prog.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        prog.extend_from_slice(&[0xBB, 0x01, 0x00, 0x00, 0x00]); // mov ebx, 1 (stdout)
        prog.extend_from_slice(&[0xB4, 0x40]); // mov ah, 0x40
        prog.extend_from_slice(&[0xCD, 0x21]); // int 0x21
        // mov eax, 0x00004C00|code  (AH=4C, AL=code) -- B8 takes a full imm32
        prog.extend_from_slice(&[0xB8, code, 0x4C, 0x00, 0x00]);
        prog.extend_from_slice(&[0xCD, 0x21]); // int 0x21
        wrap_le(&prog)
    }

    /// Wrap raw 32-bit code as a one-object LE at reloc_base 0x10000, entry 0.
    fn wrap_le(code: &[u8]) -> Vec<u8> {
        let page_size = 0x1000u32;
        let hdr = 0x40usize;
        let objtab = 0xc4usize;
        let pagemap = objtab + 24;
        let data_pages = 0x2000usize;
        let mut b = vec![0u8; data_pages + page_size as usize];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(hdr as u32).to_le_bytes());
        let p32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        b[hdr..hdr + 2].copy_from_slice(b"LE");
        p32(&mut b, hdr + 0x08, 0x02);
        p32(&mut b, hdr + 0x14, 1);
        p32(&mut b, hdr + 0x18, 1);
        p32(&mut b, hdr + 0x28, page_size);
        p32(&mut b, hdr + 0x40, objtab as u32);
        p32(&mut b, hdr + 0x44, 1);
        p32(&mut b, hdr + 0x48, pagemap as u32);
        p32(&mut b, hdr + 0x80, data_pages as u32);
        let o = hdr + objtab;
        p32(&mut b, o, code.len() as u32);
        p32(&mut b, o + 0x04, 0x10000);
        p32(&mut b, o + 0x08, 0x2005);
        p32(&mut b, o + 0x0c, 1);
        p32(&mut b, o + 0x10, 1);
        b[hdr + pagemap + 2] = 1;
        b[data_pages..data_pages + code.len()].copy_from_slice(code);
        b
    }

    #[test]
    fn a_text_mode_le_writes_and_exits() {
        let file = writer_le(b"Hello, DOS/4GW!\n", 0);
        let mut out = Vec::new();
        let code = run_le(&file, &mut out).expect("runs");
        assert_eq!(out, b"Hello, DOS/4GW!\n");
        assert_eq!(code, 0);
    }

    #[test]
    fn exit_code_is_reported() {
        // mov eax, 0x00004C07 ; int 21h  (AH=4C terminate, AL=07)
        let file = wrap_le(&[0xB8, 0x07, 0x4C, 0x00, 0x00, 0xCD, 0x21]);
        let code = run_le(&file, &mut Vec::new()).expect("runs");
        assert_eq!(code, 7);
    }

    #[test]
    fn unknown_int21_names_itself() {
        // mov ah, 0x99 ; int 21h
        let file = wrap_le(&[0xB4, 0x99, 0xCD, 0x21]);
        let err = run_le(&file, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("AH=0x99"), "names the call: {err}");
    }
}
