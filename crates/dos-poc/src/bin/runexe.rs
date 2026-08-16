//! Load a real DOS `.EXE` into the real-mode guest and report what it asks
//! DOS for, in the order it asks.
//!
//! This is a probe, not a runtime. `dos::dispatch` implements seven functions;
//! everything else comes back as "invalid function" with CF set. The point is
//! to replace a static byte-scan's *guess* at the required surface with the
//! program's own answer, since a scan cannot tell a reachable call from a
//! string of bytes that happens to read as `CD 21`.
//!
//! Usage: `runexe <program.exe> [command tail]`

use std::collections::BTreeMap;
use std::io;

use dos_poc::bios::{Video, int10};
use dos_poc::dos::{DosState, Outcome, dispatch, is_implemented};
use dos_poc::guest::{DosGuest, DosPtr};
use dos_poc::kvm::{Stop, VmGuest};
use dos_poc::mz::{self, MzImage};

/// 1 MiB: the whole real-mode address space.
const MEM: usize = 1 << 20;
/// Above the BIOS data area. 256 vectors x 4 bytes occupies 0x600..0xa00, so
/// the environment block below must start past that.
const STUB_SEG: u16 = 0x0060;
const ENV_SEG: u16 = 0x00a0;
/// Leaves ~576 KiB for the program, which is more than a 1994 config utility
/// was ever going to see.
const PSP_SEG: u16 = 0x1000;

/// Stop rather than spin if the program loops on a call we keep refusing.
const MAX_CALLS: u32 = 2000;

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or_else(|| io::Error::other("usage: runexe <program.exe> [command tail]"))?;
    let tail: String = args.collect::<Vec<_>>().join(" ");

    let data = std::fs::read(&path)?;
    let img = MzImage::parse(&data)?;
    println!(
        "{path}: {} byte image, {} relocations, entry {:#06x}:{:#06x}, \
         stack {:#06x}:{:#06x}, needs {} paragraphs",
        img.bytes.len(),
        img.relocs.len(),
        img.cs,
        img.ip,
        img.ss,
        img.sp,
        img.paragraphs(),
    );

    let mut vm = VmGuest::new(MEM)?;
    vm.hook_all(STUB_SEG)?;

    let env = mz::environment(&["PATH=C:\\", "COMSPEC=C:\\COMMAND.COM"], "C:\\LORDCFG.EXE");
    vm.load(ENV_SEG as usize * 16, &env)?;

    let at = mz::load(&mut vm, &img, PSP_SEG, ENV_SEG, tail.as_bytes())?;
    println!(
        "loaded: psp {:#06x}, image {:#06x}, entering {:#06x}:{:#06x} sp {:#06x}:{:#06x}",
        at.psp_seg, at.image_seg, at.cs, at.ip, at.ss, at.sp
    );
    vm.enter(at.cs, at.ip, at.ss, at.sp, at.psp_seg, at.psp_seg)?;
    let _helpers = vm.helpers(10_000);

    let mut dos = DosState::default();
    let mut video = Video::default();
    video.install_bda(&mut vm);
    let mut order: Vec<u8> = Vec::new();
    let mut seen: BTreeMap<u8, u32> = BTreeMap::new();
    let mut missing: BTreeMap<u8, u32> = BTreeMap::new();
    let mut bios: BTreeMap<(u8, u8), u32> = BTreeMap::new();
    let mut calls = 0u32;

    let ending = loop {
        if calls >= MAX_CALLS {
            break format!("stopped after {MAX_CALLS} calls");
        }
        match vm.run()? {
            Stop::Trap(0x10) => {
                *bios.entry((0x10, vm.regs().ah())).or_insert(0) += 1;
                calls += 1;
                int10(&mut vm, &mut video);
            }
            Stop::Trap(vector) if vector != 0x21 => {
                // Not DOS. Record it and let the stub's `iret` return, which
                // is wrong but keeps the program moving so the next gap shows.
                *bios.entry((vector, vm.regs().ah())).or_insert(0) += 1;
                calls += 1;
            }
            Stop::Trap(_) => {
                let ah = vm.regs().ah();
                calls += 1;
                *seen.entry(ah).or_insert(0) += 1;
                if !is_implemented(ah) {
                    *missing.entry(ah).or_insert(0) += 1;
                }
                if order.len() < 40 {
                    order.push(ah);
                }
                match dispatch(&mut vm, &mut dos) {
                    Outcome::Continue => {}
                    Outcome::Terminate(code) => break format!("exited with code {code}"),
                    Outcome::Fault(f) => break format!("bad guest pointer: {f:?}"),
                }
            }
            Stop::Halted => break "halted".to_string(),
            Stop::Interrupted => {
                let (cs, ip) = vm.cs_ip();
                break format!("watchdog: still running at {cs:#06x}:{ip:#06x}, no DOS call");
            }
            Stop::Unexpected(reason) => break format!("unexpected KVM exit {reason}"),
        }
    };

    // The program painted straight into the text buffer, which is just guest
    // memory -- so the screen can be read back out without the guest's help.
    println!("--- screen at B800:0000 ---");
    for row in 0..25u16 {
        let at = DosPtr::new(0xb800, row * 160);
        let line: String = match vm.read(at, 160) {
            Ok(cells) => cells
                .chunks(2)
                .map(|c| match c[0] {
                    0x00 | 0xff => ' ',
                    b if b.is_ascii_graphic() || b == b' ' => b as char,
                    _ => '.',
                })
                .collect(),
            Err(_) => continue,
        };
        if !line.trim().is_empty() {
            println!("|{}|", line.trim_end());
        }
    }

    if !dos.out.is_empty() {
        println!("--- program output ---");
        println!("{}", String::from_utf8_lossy(&dos.out));
    }

    println!("--- {calls} DOS calls, {ending} ---");
    let shown: Vec<String> = order.iter().map(|a| format!("{a:02X}")).collect();
    println!("first calls: {}", shown.join(" "));

    println!("\n{:>4}  {:>6}  {}", "AH", "calls", "status");
    for (ah, n) in &seen {
        let status = if is_implemented(*ah) {
            "implemented"
        } else {
            "MISSING"
        };
        println!("  {ah:02X}  {n:6}  {status}");
    }
    if !missing.is_empty() {
        let list: Vec<String> = missing.keys().map(|a| format!("{a:02X}")).collect();
        println!("\nstill to implement: {}", list.join(" "));
    }

    if !bios.is_empty() {
        println!("\nBIOS and other interrupts called (int 10h serviced, rest ignored):");
        for ((vector, ah), n) in &bios {
            println!("  int {vector:02X}h  AH={ah:02X}  {n:6} calls");
        }
    }

    if !vm.port_log.is_empty() {
        println!("\nhardware ports touched (answered as an absent device):");
        for (port, n) in &vm.port_log {
            println!("  {port:#06x}  {n:6}  {}", port_name(*port));
        }
    }
    Ok(())
}

/// Name the ports a DOS-era runtime is likely to reach for, so the log reads
/// as a finding rather than a list of numbers.
fn port_name(port: u16) -> &'static str {
    match port {
        0x20 | 0x21 => "8259 interrupt controller",
        0x40..=0x43 => "8253 timer (Turbo Pascal calibrates its delay loop here)",
        0x60 | 0x64 => "keyboard controller",
        0x70 | 0x71 => "CMOS / real-time clock",
        0x3b0..=0x3bf => "MDA video",
        0x3c0..=0x3cf => "VGA",
        0x3d0..=0x3df => "CGA/EGA video",
        0x3f8..=0x3ff => "COM1 serial",
        0x2f8..=0x2ff => "COM2 serial",
        _ => "",
    }
}
