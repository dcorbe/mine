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

use dos_poc::bios::{
    Keyboard, Video, int10, int10_implemented, int15, int16, int16_implemented, missing,
};
use dos_poc::dos::{DosState, Outcome, dispatch, is_implemented};
use dos_poc::guest::{DosGuest, DosPtr};
use dos_poc::kvm::{Stop, VmGuest};
use dos_poc::driver::{Driver, Script};
use dos_poc::terminal::{RawStdin, Terminal};
use dos_poc::uart::{COM1_BASE, IRQ4_VECTOR, Pic, Uart};
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

/// CPU this process has burned, and how long it has been alive.
///
/// Reported at exit because "what did the CPU look like?" is otherwise
/// unanswerable the moment the process ends -- /proc goes with it, and a
/// session that has already finished cannot be measured retroactively.
fn cpu_report(started: std::time::Instant, calls: u32) -> String {
    // SAFETY: getrusage fills a caller-owned struct.
    let usage = unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, std::ptr::from_mut(&mut u));
        u
    };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    let (user, sys) = (secs(usage.ru_utime), secs(usage.ru_stime));
    let wall = started.elapsed().as_secs_f64().max(1e-9);
    let busy = user + sys;
    let per_call = if calls > 0 {
        format!(", {:.1} us per DOS call", busy / f64::from(calls) * 1e6)
    } else {
        String::new()
    };
    format!(
        "cpu: {busy:.2}s ({user:.2} user + {sys:.2} sys) over {wall:.1}s wall \
         = {:.1}% of one core{per_call}",
        busy / wall * 100.0
    )
}

fn main() -> io::Result<()> {
    let started = std::time::Instant::now();
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
    let mut strict = false;
    let mut max_calls = MAX_CALLS;
    let mut interactive = false;
    let mut door = false;
    let mut baud: Option<u32> = None;
    let mut dropfile: Option<String> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--keys" => keys = it.next().cloned().unwrap_or_default(),
            "--root" => root_dir = it.next().cloned().unwrap_or(root_dir),
            "--script" => script_path = it.next().cloned(),
            "--trace" => trace = true,
            "--strict" => strict = true,
            "--max-calls" => {
                max_calls = it.next().and_then(|v| v.parse().ok()).unwrap_or(MAX_CALLS);
            }
            "--interactive" | "-i" => interactive = true,
            "--door" => door = true,
            "--baud" => baud = it.next().and_then(|v| v.parse().ok()),
            "--dropfile" => dropfile = it.next().cloned(),
            other => {
                if !tail.is_empty() {
                    tail.push(' ');
                }
                tail.push_str(other);
            }
        }
    }

    // Somebody is on the other end. Every guard in here exists to rescue an
    // *unattended* probe from a guest that will not stop, and every one has now
    // fired on a real session at least once -- the call cap, and the watchdog
    // twice. One name for the condition, used everywhere, is the fix.
    let attended = interactive || door;

    // The BBS already knows the line rate, so ask it rather than making the
    // sysop repeat it: DOOR.SYS carries the connect rate on line 2 and the DTE
    // rate on line 5. An explicit --baud still wins, and 0 means no pacing.
    let baud = baud.or_else(|| dropfile.as_deref().and_then(dropfile_baud));

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

    // The program's own path, which a DOS program reads back as ParamStr(0)
    // and routinely uses to find its home directory. Hardcoding a name here
    // silently misdirects that: LORD strips its own filename off the end, so a
    // stale "C:\LORDCFG.EXE" had it hunting for C:\LOR\NODE0.DAT.
    let program = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("PROGRAM.EXE")
        .to_ascii_uppercase();
    let env = mz::environment(
        &["PATH=C:\\", "COMSPEC=C:\\COMMAND.COM"],
        &format!("C:\\{program}"),
    );
    vm.load(ENV_SEG as usize * 16, &env)?;

    let at = mz::load(&mut vm, &img, PSP_SEG, ENV_SEG, tail.as_bytes())?;
    println!(
        "loaded: psp {:#06x}, image {:#06x}, entering {:#06x}:{:#06x} sp {:#06x}:{:#06x}",
        at.psp_seg, at.image_seg, at.cs, at.ip, at.ss, at.sp
    );
    vm.enter(at.cs, at.ip, at.ss, at.sp, at.psp_seg, at.psp_seg)?;
    // A human takes as long as they take, so the watchdog that rescues an
    // unattended probe from a spinning guest must not fire on them.
    let helpers = vm.helpers(if attended { 24 * 60 * 60 * 1000 } else { 10_000 });

    // The sandbox. Everything the guest opens resolves beneath this one
    // descriptor, enforced by openat2(RESOLVE_BENEATH), not by path munging.
    std::fs::create_dir_all(&root_dir)?;
    let root = std::fs::File::open(&root_dir)?;
    println!("root: {root_dir}");

    // In door mode the guest talks to a UART, not to our screen: LORD programs
    // the chip directly rather than using int 14h or a FOSSIL driver.
    let mut serial = door.then(|| Uart::new(baud));
    let mut pic = Pic::default();
    let _raw = door.then(RawStdin::enter).transpose()?;
    if door {
        println!("door mode: COM1 at {COM1_BASE:#06x}, IRQ4, baud {baud:?}\r");
    }

    let mut dos = DosState::default();
    dos.files = Some(Files::new(root.into(), std::path::PathBuf::from(&root_dir)));
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
    let mut missing_dos: BTreeMap<u8, u32> = BTreeMap::new();
    let mut bios: BTreeMap<(u8, u8), u32> = BTreeMap::new();
    let mut vectors: Vec<String> = Vec::new();
    let mut settles = 0u32;
    // Calls a real machine services and we do not, named at the moment they
    // happen rather than inferred later from a screen that looks wrong.
    let mut gaps: BTreeMap<String, u32> = BTreeMap::new();
    let mut calls = 0u32;
    // Where the wall clock goes. "Is the pause the program working, or us?" is
    // not answerable from a total; it needs the split.
    let mut in_guest = std::time::Duration::ZERO;
    let mut slept = std::time::Duration::ZERO;
    let mut longest = (std::time::Duration::ZERO, String::new());
    // Blocked on a person. Lumping this in with our own work makes the harness
    // look like the slow part when it is simply waiting to be typed at.
    let mut waiting = std::time::Duration::ZERO;
    // The busiest stretch between two moments the guest asked for input --
    // which is exactly one user-visible action, so this characterises the
    // pause rather than averaging it away over a whole session.
    let mut since_settle = (0u32, std::time::Duration::ZERO, std::time::Instant::now());
    let mut busiest = (0u32, std::time::Duration::ZERO, std::time::Duration::ZERO);

    let ending = loop {
        // The cap rescues an unattended probe from a program looping on a call
        // we keep refusing. A person playing a game is not that, and LORD idles
        // by polling -- it burns thousands of calls just waiting for a turn.
        // A door serves a person, same as an interactive session: the cap is
        // for unattended probes only.
        if !attended && calls >= max_calls {
            break format!("stopped after {max_calls} calls");
        }
        if let Some(uart) = serial.as_mut() {
            // Host -> guest: anything the far end has typed.
            let mut buf = [0u8; 256];
            let mut fds = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: polling and reading our own stdin.
            let ready = unsafe { libc::poll(std::ptr::from_mut(&mut fds), 1, 0) };
            if ready > 0 && fds.revents & libc::POLLIN != 0 {
                // SAFETY: `buf` is a live buffer of the stated length.
                let n = unsafe {
                    libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len())
                };
                if n > 0 {
                    for b in &buf[..n as usize] {
                        uart.receive(*b);
                    }
                } else if n == 0 {
                    // The far end hung up. Telling the guest is what lets it
                    // save and exit instead of playing to nobody.
                    uart.set_carrier(false);
                }
            }
            // Guest -> host: whatever the transmitter has clocked out.
            if !uart.tx.is_empty() {
                let out = std::mem::take(&mut uart.tx);
                // SAFETY: writing a live buffer to our own stdout.
                unsafe { libc::write(libc::STDOUT_FILENO, out.as_ptr().cast(), out.len()) };
            }
            let want = uart.interrupting() && pic.may_deliver_irq4();
            vm.set_interrupt_window(want);
            if want && vm.ready_for_interrupt() {
                pic.begin_irq4();
                vm.inject(IRQ4_VECTOR)?;
            }
        }

        let ran = std::time::Instant::now();
        let stop = vm.run()?;
        let took = ran.elapsed();
        in_guest += took;
        since_settle.0 += 1;
        since_settle.1 += took;
        if took > longest.0 {
            longest = (took, format!("{stop:?}"));
        }
        match stop {
            Stop::Trap(0x10) => {
                let ah = vm.regs().ah();
                *bios.entry((0x10, ah)).or_insert(0) += 1;
                calls += 1;
                if !int10_implemented(ah)
                    && let Some(what) = missing(0x10, ah)
                {
                    *gaps.entry(format!("int 10h AH={ah:02X}  {what}")).or_insert(0) += 1;
                    if strict {
                        break format!("unimplemented: int 10h AH={ah:02X} ({what})");
                    }
                }
                int10(&mut vm, &mut video);
            }
            Stop::Trap(0x16) => {
                let ah = vm.regs().ah();
                *bios.entry((0x16, ah)).or_insert(0) += 1;
                calls += 1;
                if !int16_implemented(ah)
                    && let Some(what) = missing(0x16, ah)
                {
                    *gaps.entry(format!("int 16h AH={ah:02X}  {what}")).or_insert(0) += 1;
                    if strict {
                        break format!("unimplemented: int 16h AH={ah:02X} ({what})");
                    }
                }
                if ah == 0x01 || ah == 0x11 {
                    // "Is a key ready?" with none queued is the other way a
                    // program idles. Offer the driver a chance without making
                    // the guest wait for an answer it asked not to wait for.
                    if keyboard.is_empty()
                        && let Some(script) = driver.as_mut()
                        && script.poll_due()
                    {
                        let screen = Screen::snapshot(
                            &vm,
                            video.columns as usize,
                            video.rows as usize,
                            (video.cursor_row, video.cursor_col),
                            video.cursor_visible,
                        );
                        match script.poll_key(&screen) {
                            Some(key) => keyboard.push_key(key),
                            // A driver with nothing left to say ends the run,
                            // exactly as it does at a blocking read -- otherwise
                            // an exhausted script leaves the guest polling for a
                            // key that will never come.
                            // "No key right now" is not "nothing left to say":
                            // a `wait` step deliberately answers nothing while
                            // the guest gets on with something.
                            None if !interactive && script.finished() => break script.ending(),
                            None => {}
                        }
                    }
                    int16(&mut vm, &mut keyboard);
                } else if !int16(&mut vm, &mut keyboard) {
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
                        video.cursor_visible,
                    );
                    if since_settle.0 > busiest.0 {
                        busiest = (since_settle.0, since_settle.1, since_settle.2.elapsed());
                    }
                    since_settle = (0, std::time::Duration::ZERO, std::time::Instant::now());
                    settles += 1;
                    if trace && !interactive {
                        println!(
                            "  [settle {settles}] selected={:?} cursor={:?}",
                            screen.selected(),
                            screen.cursor
                        );
                    }
                    let idle = std::time::Instant::now();
                    // A driver with nothing to say *yet* is not finished. The
                    // guest is blocked, so the only correct answer is to wait
                    // for it rather than to end the run.
                    let mut answer = script.next_key(&screen);
                    while answer.is_none() && !script.finished() {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        answer = script.next_key(&screen);
                    }
                    waiting += idle.elapsed();
                    match answer {
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
            Stop::Trap(0x15) => {
                let ah = vm.regs().ah();
                *bios.entry((0x15, ah)).or_insert(0) += 1;
                calls += 1;
                if let Some(nap) = int15(&mut vm) {
                    let before = std::time::Instant::now();
                    std::thread::sleep(nap);
                    slept += before.elapsed();
                }
            }
            Stop::Trap(vector) if vector != 0x21 => {
                // Not DOS. Record it and let the stub's `iret` return, which
                // is wrong but keeps the program moving so the next gap shows.
                let ah = vm.regs().ah();
                *bios.entry((vector, ah)).or_insert(0) += 1;
                calls += 1;
                if vector == 0x2f && vm.regs().ax == 0x1680 {
                    let before = std::time::Instant::now();
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    slept += before.elapsed();
                }
                if let Some(what) = missing(vector, ah) {
                    *gaps.entry(format!("int {vector:02X}h AH={ah:02X}  {what}")).or_insert(0) += 1;
                    if strict {
                        break format!("unimplemented: int {vector:02X}h AH={ah:02X} ({what})");
                    }
                }
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
                    *missing_dos.entry(ah).or_insert(0) += 1;
                    if strict {
                        break format!("unimplemented: int 21h AH={ah:02X}");
                    }
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
            Stop::PortWrite { port, value } => match (&mut serial, port) {
                (Some(uart), p) if (COM1_BASE..COM1_BASE + 8).contains(&p) => uart.write(p, value),
                (_, 0x20 | 0x21) => pic.write(port, value),
                _ => video.port_out(port, value),
            },
            Stop::PortRead { port } => {
                let value = match (&mut serial, port) {
                    (Some(uart), p) if (COM1_BASE..COM1_BASE + 8).contains(&p) => uart.read(p),
                    (_, 0x20 | 0x21) => pic.read(port),
                    _ => video.port_in(port),
                };
                vm.complete_port_read(value);
            }
            Stop::IrqWindow => {}
            // With a UART present, `hlt` is not the end -- it is the guest
            // saying it has nothing to do until an interrupt arrives, which is
            // the whole point of having one.
            Stop::Halted if serial.is_some() => {
                std::thread::sleep(std::time::Duration::from_millis(1));
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
    // A ruler, and lines marked at their true end. Trimming trailing spaces
    // makes a correctly placed cursor look like it overshoots: the space it
    // sits past is invisible, so "one past the content" reads as "two past the
    // text". A dump that silently drops content is a dump that lies.
    let screen_cursor = (video.cursor_row, video.cursor_col);
    println!("--- screen at B800:0000 ---");
    let ruler: String = (0..80).map(|c| char::from(b'0' + (c / 10) % 10)).collect();
    println!("    {ruler}");
    let ruler: String = (0..80).map(|c| char::from(b'0' + c % 10)).collect();
    println!("    {ruler}");
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
        let end = line.trim_end().len();
        let (crow, ccol) = screen_cursor;
        // Marking the cursor is what makes a trailing space visible: the text
        // stops at one column and the cursor sits past it, and the gap between
        // the two numbers is the content a trimmed dump silently dropped.
        let note = if u16::from(crow) == row {
            format!(" text ends col {end}, cursor at col {ccol}")
        } else {
            format!(" text ends col {end}")
        };
        println!("{row:2} |{}|{note}", &line[..end]);
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

    if !video.moves.is_empty() {
        println!("--- last cursor moves ---");
        for m in &video.moves {
            println!("  {m}");
        }
    }

    if let Some(files) = dos.files.as_ref() {
        if !files.ambiguous.is_empty() {
            println!("--- names the host cannot uniquely resolve ---");
            for note in &files.ambiguous {
                println!("  {note}");
            }
        }
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
    println!("{}", cpu_report(started, calls));
    let wall = started.elapsed();
    let other = wall
        .saturating_sub(in_guest)
        .saturating_sub(slept)
        .saturating_sub(waiting);
    println!(
        "wall: {:.1}s total = {:.1}s in the guest + {:.1}s asleep on its yields \
         + {:.1}s waiting for you + {:.1}s ours",
        wall.as_secs_f64(),
        in_guest.as_secs_f64(),
        slept.as_secs_f64(),
        waiting.as_secs_f64(),
        other.as_secs_f64()
    );
    let ticks = helpers.ticks.load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "bios clock: {ticks} ticks over {:.1}s = {:.2} Hz (should be 18.20)",
        started.elapsed().as_secs_f64(),
        f64::from(ticks) / started.elapsed().as_secs_f64()
    );
    println!(
        "busiest single action: {} calls, {:.0} ms in the guest, {:.0} ms wall",
        busiest.0,
        busiest.1.as_secs_f64() * 1000.0,
        busiest.2.as_secs_f64() * 1000.0
    );
    println!(
        "longest single guest run: {:.0} ms, ended in {}",
        longest.0.as_secs_f64() * 1000.0,
        longest.1
    );
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
    if !missing_dos.is_empty() {
        let list: Vec<String> = missing_dos.keys().map(|a| format!("{a:02X}")).collect();
        println!("\nstill to implement: {}", list.join(" "));
    }

    if !gaps.is_empty() {
        println!("\n*** CALLS A REAL MACHINE SERVICES AND WE DO NOT ***");
        for (what, n) in &gaps {
            println!("  {what}   x{n}");
        }
    }

    if !bios.is_empty() {
        println!("\nBIOS and other interrupts called (int 10h serviced, rest ignored):");
        for ((vector, ah), n) in &bios {
            println!("  int {vector:02X}h  AH={ah:02X}  {n:6} calls");
        }
    }

    if !vm.port_log.is_empty() {
        println!("\nhardware ports touched:");
        for (port, n) in &vm.port_log {
            let modelled = door && ((COM1_BASE..COM1_BASE + 8).contains(port) || matches!(port, 0x20 | 0x21))
                || matches!(port, 0x3d4 | 0x3d5 | 0x3b4 | 0x3b5 | 0x3da | 0x3ba);
            let how = if modelled { "modelled" } else { "absent device" };
            println!("  {port:#06x}  {n:6}  {:<48} {how}", port_name(*port));
        }
    }
    Ok(())
}

/// The line rate a DOOR.SYS describes, if it describes one.
///
/// Line 2 is the connect rate and line 5 the DTE rate. A telnet door often
/// reports 0 on line 2, meaning "no modem involved", which is exactly the case
/// where pacing should be off rather than defaulted to something invented.
fn dropfile_baud(path: &str) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines().map(|l| l.trim().parse::<u32>().ok());
    let connect = lines.nth(1).flatten();
    let dte = lines.nth(2).flatten();
    match (connect, dte) {
        (Some(0), Some(d)) if d > 0 => Some(d),
        (Some(c), _) => Some(c),
        (None, Some(d)) => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::dropfile_baud;

    fn drop_with(connect: &str, dte: &str) -> String {
        let mut lines: Vec<String> = (0..52).map(|i| format!("field{i}")).collect();
        lines[0] = "COM1:".into();
        lines[1] = connect.into(); // line 2
        lines[4] = dte.into(); // line 5
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/dos-poc-tests")
            .join(format!("drop{connect}_{dte}.sys"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, lines.join("\r\n")).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn the_connect_rate_is_line_two_and_the_dte_rate_is_line_five() {
        // Off by one either way silently picks a neighbouring field, which is
        // a plausible-looking number rather than an error.
        assert_eq!(dropfile_baud(&drop_with("14400", "38400")), Some(14400));
    }

    #[test]
    fn a_telnet_door_reporting_no_modem_falls_back_to_the_dte_rate() {
        assert_eq!(dropfile_baud(&drop_with("0", "38400")), Some(38400));
    }

    #[test]
    fn zero_on_both_means_no_pacing_rather_than_a_made_up_default() {
        assert_eq!(dropfile_baud(&drop_with("0", "0")), Some(0));
    }

    #[test]
    fn a_dropfile_that_is_not_there_yields_nothing() {
        assert_eq!(dropfile_baud("/nonexistent/DOOR.SYS"), None);
    }
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
