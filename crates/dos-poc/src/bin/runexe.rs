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

use dos_poc::bios::{Keyboard, Video, int10, int16};
use dos_poc::dos::{DosState, Outcome, dispatch, is_implemented};
use dos_poc::guest::{DosGuest, DosPtr};
use dos_poc::kvm::{Stop, VmGuest};
use dos_poc::driver::{Driver, Script};
use dos_poc::terminal::Terminal;
use dos_poc::files::Files;
use dos_poc::mz::{self, MzImage};
use dos_poc::screen::Screen;

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
    let rest: Vec<String> = args.collect();
    let mut tail = String::new();
    let mut keys = String::new();
    let mut root_dir = String::from("tmp/lordroot");
    let mut script_path: Option<String> = None;
    let mut trace = false;
    let mut interactive = false;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--keys" => keys = it.next().cloned().unwrap_or_default(),
            "--root" => root_dir = it.next().cloned().unwrap_or(root_dir),
            "--script" => script_path = it.next().cloned(),
            "--trace" => trace = true,
            "--interactive" | "-i" => interactive = true,
            other => {
                if !tail.is_empty() {
                    tail.push(' ');
                }
                tail.push_str(other);
            }
        }
    }

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
    // A human takes as long as they take, so the watchdog that rescues an
    // unattended probe from a spinning guest must not fire on them.
    let _helpers = vm.helpers(if interactive { 24 * 60 * 60 * 1000 } else { 10_000 });

    // The sandbox. Everything the guest opens resolves beneath this one
    // descriptor, enforced by openat2(RESOLVE_BENEATH), not by path munging.
    std::fs::create_dir_all(&root_dir)?;
    let root = std::fs::File::open(&root_dir)?;
    println!("root: {root_dir}");

    let mut dos = DosState::default();
    dos.files = Some(Files::new(root.into()));
    let mut keyboard = Keyboard::default();
    keyboard.feed(&keys);
    let mut driver: Option<Box<dyn Driver>> = if interactive {
        // The terminal takes the screen from here; anything printed while it
        // holds the alternate screen would land in the middle of the guest's
        // output, so the report waits until it is dropped.
        println!("interactive: Ctrl-] gives control back");
        Some(Box::new(Terminal::new()?))
    } else {
        match &script_path {
            Some(path) => {
                let text = std::fs::read_to_string(path)?;
                Some(Box::new(Script::parse(&text).map_err(io::Error::other)?))
            }
            None => None,
        }
    };
    let mut video = Video::default();
    video.install_bda(&mut vm);
    let mut order: Vec<u8> = Vec::new();
    let mut seen: BTreeMap<u8, u32> = BTreeMap::new();
    let mut missing: BTreeMap<u8, u32> = BTreeMap::new();
    let mut bios: BTreeMap<(u8, u8), u32> = BTreeMap::new();
    let mut vectors: Vec<String> = Vec::new();
    let mut settles = 0u32;
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
            Stop::Trap(0x16) => {
                *bios.entry((0x16, vm.regs().ah())).or_insert(0) += 1;
                calls += 1;
                if !int16(&mut vm, &mut keyboard) {
                    // The guest has drained its input and finished painting.
                    // This is the settle point: hand the screen to the driver.
                    let Some(script) = driver.as_mut() else {
                        break "waiting for a keystroke, none queued".to_string();
                    };
                    let screen = Screen::snapshot(
                        &vm,
                        video.columns as usize,
                        video.rows as usize,
                        (video.cursor_row, video.cursor_col),
                    );
                    settles += 1;
                    if trace && !interactive {
                        println!(
                            "  [settle {settles}] selected={:?} cursor={:?}",
                            screen.selected(),
                            screen.cursor
                        );
                    }
                    match script.next_key(&screen) {
                        Some(key) => {
                            if trace && !interactive {
                                println!("  [settle {settles}] send {key:?}");
                            }
                            keyboard.push_key(key);
                            int16(&mut vm, &mut keyboard);
                        }
                        None => break script.ending(),
                    }
                }
            }
            Stop::Trap(vector) if vector != 0x21 => {
                // Not DOS. Record it and let the stub's `iret` return, which
                // is wrong but keeps the program moving so the next gap shows.
                *bios.entry((vector, vm.regs().ah())).or_insert(0) += 1;
                calls += 1;
            }
            Stop::Trap(_) => {
                let ah = vm.regs().ah();
                if ah == 0x25 || ah == 0x35 {
                    let vec = vm.regs().al();
                    let verb = if ah == 0x25 { "hooks" } else { "saves" };
                    vectors.push(format!("{verb} int {vec:02X}h"));
                }
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

    drop(driver);

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
        println!("{row:2} |{}|", line.trim_end());
    }

    if !vectors.is_empty() {
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for v in &vectors {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
        println!("--- interrupt vectors the program touched ---");
        for (what, n) in &counts {
            println!("  {what}  x{n}");
        }
    }

    if let Some(files) = dos.files.as_ref() {
        if !files.attempts.is_empty() {
            println!("--- every file the guest asked for ---");
            for (name, how, okd) in &files.attempts {
                println!("  {how:<7} {name:<16} {}", if *okd { "ok" } else { "FAILED" });
            }
        }
        if files.touched.is_empty() {
            println!("--- no files were created or written ---");
        } else {
            println!("--- files the guest created or wrote ---");
            for name in &files.touched {
                let host = std::path::Path::new(&root_dir).join(name);
                let size = std::fs::metadata(&host).map(|m| m.len());
                match size {
                    Ok(n) => println!("  {name}  ({n} bytes at {})", host.display()),
                    Err(_) => println!("  {name}  (not present on the host)"),
                }
            }
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
