//! Run a hand-assembled `.COM` under a real-mode KVM guest, servicing its
//! `int 21h` calls with the same `dos::dispatch` the unit tests drive.
//!
//! If this prints its line, the whole of Edge B is proven end to end: IVT,
//! trap stub, vmexit, register marshalling, guest memory, DOS dispatch, the
//! carry-on-the-stack convention, and program termination.

use std::io;

use dos_poc::dos::{DosState, Outcome, dispatch};
use dos_poc::kvm::{Stop, VmGuest};

/// Where the program is loaded. `.COM` convention: PSP at `seg:0`, code at
/// `seg:0x100`.
const PROG_SEG: u16 = 0x1000;
const PROG_OFF: u16 = 0x0100;
/// Somewhere above the IVT and the BIOS data area, and otherwise unused.
const STUB_SEG: u16 = 0x00f0;
/// The exit code the program asks for, chosen to be neither 0 nor 1 so that
/// "the code travelled" is distinguishable from "something returned success".
const WANT_EXIT: u8 = 7;

/// Assemble the guest program, patching the two string offsets once their
/// addresses are known rather than hand-counting them.
fn program() -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();

    c.extend_from_slice(&[0xb4, 0x09]); //  mov ah, 09h
    c.push(0xba); //                        mov dx, <msg>
    let msg_patch = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    c.extend_from_slice(&[0xcd, 0x21]); //  int 21h

    c.extend_from_slice(&[0xb4, 0x19]); //  mov ah, 19h   (get default drive)
    c.extend_from_slice(&[0xcd, 0x21]); //  int 21h
    c.extend_from_slice(&[0x04, b'A']); //  add al, 'A'
    c.extend_from_slice(&[0x88, 0xc2]); //  mov dl, al
    c.extend_from_slice(&[0xb4, 0x02]); //  mov ah, 02h   (display character)
    c.extend_from_slice(&[0xcd, 0x21]); //  int 21h

    c.extend_from_slice(&[0xb4, 0x09]); //  mov ah, 09h
    c.push(0xba); //                        mov dx, <tail>
    let tail_patch = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    c.extend_from_slice(&[0xcd, 0x21]); //  int 21h

    c.push(0xb8); //                        mov ax, 4C07h (terminate, code 7)
    c.extend_from_slice(&[WANT_EXIT, 0x4c]);
    c.extend_from_slice(&[0xcd, 0x21]); //  int 21h

    let msg: &[u8] = b"hello from real mode; the default drive is $";
    let tail: &[u8] = b":\r\n$";

    let msg_off = PROG_OFF as usize + c.len();
    c.extend_from_slice(msg);
    let tail_off = PROG_OFF as usize + c.len();
    c.extend_from_slice(tail);

    c[msg_patch..msg_patch + 2].copy_from_slice(&(msg_off as u16).to_le_bytes());
    c[tail_patch..tail_patch + 2].copy_from_slice(&(tail_off as u16).to_le_bytes());
    c
}

fn main() -> io::Result<()> {
    let code = program();

    let mut vm = VmGuest::new(1 << 20)?;
    vm.hook(0x21, STUB_SEG)?;
    vm.load(PROG_SEG as usize * 16 + PROG_OFF as usize, &code)?;
    vm.start(PROG_SEG, PROG_OFF, PROG_SEG, 0xfffe)?;

    let mut dos = DosState::default();
    let mut calls = 0u32;

    let exit = loop {
        match vm.run()? {
            Stop::Trap(_) => {
                calls += 1;
                match dispatch(&mut vm, &mut dos) {
                    Outcome::Continue => {}
                    Outcome::Terminate(c) => break i32::from(c),
                    Outcome::Fault(f) => {
                        eprintln!("guest handed over a bad pointer: {f:?}");
                        break -1;
                    }
                }
            }
            Stop::Halted => break 0,
            // This demo runs no helper threads, so nothing can interrupt it.
            Stop::Interrupted => break -3,
            Stop::Unexpected(reason) => {
                eprintln!("unexpected KVM exit reason {reason}");
                break -2;
            }
        }
    };

    print!("{}", String::from_utf8_lossy(&dos.out));
    println!("--- {calls} DOS calls serviced, guest exited with {exit}");

    if exit != i32::from(WANT_EXIT) {
        return Err(io::Error::other(format!(
            "expected exit code {WANT_EXIT}, got {exit}"
        )));
    }
    Ok(())
}
