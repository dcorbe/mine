//! Call the genuine MajorBBS host's `fsdppc` and print what it computed.
//!
//! ```sh
//! cargo run -p mbbs16 --example fsd_oracle
//! ```
//!
//! # Why this can be called cold
//!
//! `fsdppc(templt, ascn)` at `ascn=0` is a pure function of two byte strings and
//! the `fsdscb` the caller points at. It needs no channel, no message file and no
//! GSBL: `FSD.C:463` runs `fspscn`, `chkops`, `tmpscn` and `embscn`, and at
//! `ascn=0` every screen-library branch in `tmpscn` is skipped.
//!
//! Two globals decide whether it does anything, and both are already right in a
//! freshly loaded image:
//!
//! - `maxfld` bounds `fspscn`'s loop (`FSD.C:189`). It is `int maxfld=1000` at
//!   `FSD.C:38` -- initialized data, so it is 1000 in the image. `fsdroom`
//!   overwrites it with `(outbsz-MBPMAX)/sizeof(struct fsdfld)`, and we never
//!   call `fsdroom`, so the initializer stands.
//! - `fsdscb` is a pointer the caller owns. It is exported at NE segment 154,
//!   offset 762, and the module *tests it for null*, so it must be pointed
//!   somewhere real before the call.
//!
//! # The export is `_FSDPPC`
//!
//! Uppercase, one leading underscore, as everything in this binary's name tables
//! is. `re/ne_exports.py` will not show you that -- it `lstrip("_").lower()`s
//! both sides of its lookup -- so the spelling comes from the name table itself
//! and is pinned by `crates/mbbs16/tests/majorbbs.rs`.
//!
//! # Why `ascn=1` needs two more things
//!
//! At `ascn=1` `tmpscn` paints the template into an off-screen window and reads
//! the cursor back per field (`FSD.C:313`). Two of its six preamble calls need
//! something this machine does not otherwise provide.
//!
//! **`fsdbuf`, the window itself.** `FSDBBS.C:85` fills it with `alcmem(fsdbln)`
//! from `inifsd()`, which never runs here, so it is a null far pointer in the
//! image. It is not exported, and it was located by disassembly instead: segment
//! 28 holds exactly one internal-ref relocation to `setwin` (93:2310), at
//! `0x0572`, and the seven pushes ahead of it are the literal argument list of
//! `setwin(fsdbuf,0,0,ANSIWD-1,ANSILN-1,0)` --
//!
//! ```text
//! 0558  6a00        push 0          ; scroll
//! 055a  6a18        push 0x18       ; ANSILN-1
//! 055c  6a4f        push 0x4f       ; ANSIWD-1
//! 055e  6a00        push 0
//! 0560  6a00        push 0
//! 0562  b80000      mov ax, 0       ; additive segment fixup -> NE segment 155
//! 0565  8ec0        mov es, ax
//! 0567  26ff365200  push es:[0x52]  ; fsdbuf, segment half
//! 056c  26ff365000  push es:[0x50]  ; fsdbuf, offset half
//! 0571  9a....      lcall setwin
//! ```
//!
//! **A video BIOS.** The third preamble call is `cursiz(NOCURS)`, and segment 55
//! -- `cursiz`, `rstcur`, `curcurs` -- is the *hardware* cursor library. It reads
//! the video mode with `INT 10h AH=0Fh`, indexes a scanline table on whether the
//! mode is 7, and sets the cursor shape with `INT 10h AH=01h`. Nothing it does is
//! visible in the window, but it has to answer before `tmpscn` proceeds.
//!
//! Phar Lap's `int86` reaches the BIOS by assembling `push bp / INT n / pop bp /
//! retf` **on the stack** and asking `DosCreateCSAlias` (`DOSCALLS.43`) to make
//! the stack executable, so implementing that import faithfully only moves the
//! problem: the machine would then execute a protected-mode `INT`, which arrives
//! as [`Exit::Fault`] and cannot be resumed. So the BIOS is supplied one level
//! up, at `int86` itself.
//!
//! The interception point is segment 128 **offset 0x38**, not offset 0. `int86`
//! (128:0) is a wrapper that does `push cs / call near 0x38` -- deliberately
//! faking a far frame -- so `int86x` (128:56) is the shared body and both entries
//! arrive there with the same layout: `intno` at `bp+6`, `inregs` at `bp+8`,
//! `outregs` at `bp+0xc`, `sregs` at `bp+0x10`. One `JMP FAR` covers both, and
//! `retf` with caller-cleans is correct on either path.
//!
//! It answers the two calls `cursiz` makes and **refuses everything else by
//! name**. A BIOS that quietly returned zero would let an unmodelled dependency
//! deeper in the ANSI path pass for a measurement.

use std::path::Path;

use mbbs16::{Exit, FarPtr, Import, Machine, Ret, Symbol};

/// Where `fsdscb` lives: NE segment 154, offset 762. From the entry table, via
/// `re/ne_exports.py re/hosts/MAJORBBS-mbbstd.EXE fsdscb`.
const FSDSCB_SEGMENT: u16 = 154;
const FSDSCB_OFFSET: u16 = 762;

/// Where `fsdbuf` lives: NE segment 155, offset 0x50. Not exported; located by
/// the disassembly quoted in this file's header.
const FSDBUF_SEGMENT: u16 = 155;
const FSDBUF_OFFSET: u16 = 0x50;

/// `fsdbln`, `FSD.C:100` -- `ANSILN*ANSIWD*2`, two bytes per cell.
const FSDBLN: usize = 25 * 80 * 2;

/// `int86x`, the shared body of `int86`/`int86x`: NE segment 128, offset 0x38.
const INT86X_SEGMENT: u16 = 128;
const INT86X_OFFSET: u16 = 0x38;

/// The screen library's own hardware-cursor flag, in the NE auto data segment.
///
/// `locate`, `rstloc`, `curcurx` and `curcury` all reach the cursor through one
/// pair of helpers at segment 93 offsets `0xa48`/`0xa82`, and both begin:
///
/// ```text
/// 0a48  f6066822ff    test byte [0x2268], 0xff
/// 0a4d  7505          jne 0xa54
/// 0a4f  8b166922      mov dx, [0x2269]     ; software cursor
/// 0a53  c3            ret
/// 0a54  813e9b2200f0  cmp word [0x229b], 0xf000
/// 0a5a  7307          jae 0xa63            ; direct 6845 CRTC port I/O
/// 0a5c  32ff b403 cd10                     ; else INT 10h AH=03h
/// ```
///
/// It is `0x01` in the image and `[0x229b]` is 0, so the untouched library reads
/// the cursor with an inline `INT 10h` -- an instruction, not a call, so no
/// thunk can intercept it.
const CURSOR_HARDWARE: u16 = 0x2268;
/// The software cursor position the flag selects instead: `DL` = x, `DH` = y.
const CURSOR_POSITION: u16 = 0x2269;

/// `frzseg`'s cached screen segment, and the flag saying it has been chosen.
///
/// `frzseg` (segment 93, offset 0) probes the video mode with an inline
/// `INT 10h AH=0Fh` and caches `[0x229f]` (`0xb800`, colour) or `[0x22a1]`
/// (`0xb000`, mono) into `[0x229b]`, guarded by `[0x229d]`. Both cached values
/// are real-mode paragraphs, which Phar Lap's extender turns into usable
/// selectors and this machine does not, so the post-state is written by hand and
/// aimed at a segment that exists here.
const SCREEN_SELECTOR: u16 = 0x229b;
const SCREEN_CHOSEN: u16 = 0x229d;
/// 80x25 cells of two bytes, the same size as the window.
const SCREEN_BYTES: usize = FSDBLN;

/// `sizeof(struct fsdscb)`, `FSD.H:275`.
const FSDSCB: u16 = 166;
/// `sizeof(struct fsdfld)`, `FSD.H:262` -- "(23 bytes long)".
const FSDFLD: u16 = 23;
/// `MBPMAX`, `FSDBBS.H:208`.
const MBPMAX: u16 = 200;

/// Where each member of `struct fsdscb` sits. Mirrors `crates/mbbs/src/fsd.rs`'s
/// `scb` module rather than re-deriving them.
mod scb {
    pub const FLDSPC: u16 = 0;
    pub const FLDDAT: u16 = 4;
    pub const MBPUNC: u16 = 8;
    pub const NUMFLD: u16 = 21;
    pub const NUMTPL: u16 = 23;
    pub const MBLENG: u16 = 25;
    pub const MAXANS: u16 = 27;
    pub const HLPLEN: u16 = 29;
    pub const HLPGTO: u16 = 30;
    pub const HLPATR: u16 = 39;
    pub const HLPOFF: u16 = 40;
    /// The last byte of the block: `char maxy`, at `FSDSCB - 1`.
    pub const MAXY: u16 = 165;
}

/// Where each member of `struct fsdfld` sits. `FSD.H:247`.
///
/// Taken from `crates/mbbs/src/fsd.rs`'s `fld` module, not re-derived. The first
/// draft of this file re-derived them and got every one wrong, which printed
/// plausible-looking nonsense (`fspoff 9223`) beside a correct `maxans` -- the
/// exact failure the oracle exists to catch, arriving first in the oracle's own
/// reader.
mod fld {
    /// `char ansgto[GTOLEN+1]`, `GTOLEN` 8. Empty off the ANSI path.
    pub const ANSGTO: u16 = 0;
    pub const ANSGTO_LEN: u16 = 9;
    pub const WIDTH: u16 = 9;
    pub const XWIDTH: u16 = 10;
    /// `char attr`, the attribute in force where the field starts. Off the ANSI
    /// path it is left at 0, which is itself worth printing beside the ANSI run.
    pub const ATTR: u16 = 11;
    pub const FLAGS: u16 = 12;
    pub const FLDTYP: u16 = 13;
    pub const FSPOFF: u16 = 14;
    pub const TMPOFF: u16 = 16;
    pub const MBPOFF: u16 = 18;
}

/// MajorMUD's own field specification, extracted by
/// `cargo run -p mbbs --example fsd_inputs`. Gitignored: it is module content.
const SPEC_FILE: &str = "tmp/fsd-spec.bin";

fn main() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("re/hosts/MAJORBBS-mbbstd.EXE");
    let file = std::fs::read(&path)?;

    // Inputs: MajorMUD's own, extracted to gitignored files by the mbbs-side
    // helper. Passed as argv[1] = template file, defaulting to template 7.
    let template_file = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tmp/fsd-template-7.bin".to_string());
    let mut spec = std::fs::read(SPEC_FILE)?;
    spec.push(0);
    let mut template = std::fs::read(&template_file)?;
    template.push(0);
    println!("spec {} bytes, template {} bytes from {template_file}", spec.len(), template.len());

    let mut machine = Machine::new()?;
    // Every import a thunk: if host code reaches PHAPI, GALGSBL or DOSCALLS we
    // want `Exit::Call` naming the symbol, not a far call into nothing.
    let module = machine.load_ne(&file, &|_: &str, _: &Symbol| Some(Import::Routine))?;

    let fsdppc = module
        .entry_by_name("_FSDPPC")
        .expect("the host exports _FSDPPC");
    println!("_FSDPPC at {fsdppc}");

    let globals = module
        .segment_selector(FSDSCB_SEGMENT)
        .expect("segment 154 is mapped");
    let fsdscb_at = FarPtr {
        offset: FSDSCB_OFFSET,
        selector: globals,
    };
    println!("fsdscb global at {fsdscb_at}");

    // One working segment, laid out by hand. Everything the host will write
    // through `fsdscb` lives here, so a stray write lands in our memory and not
    // in the host's data.
    const FIELDS: u16 = 64;
    let scb_off = 0u16;
    let punct_off = scb_off + FSDSCB;
    let flddat_off = punct_off + MBPMAX;
    let spec_off = flddat_off + FIELDS * FSDFLD;
    let template_off = spec_off + spec.len() as u16;
    let total = usize::from(template_off) + template.len();

    let work = machine.alloc_segment(total)?;
    let at = |offset: u16| FarPtr {
        offset,
        selector: work,
    };

    machine.write(at(spec_off), &spec)?;
    machine.write(at(template_off), &template)?;

    // `struct fsdscb`, zeroed, then the three pointers `fsdppc` reads.
    machine.write(at(scb_off), &vec![0u8; usize::from(FSDSCB)])?;
    for (member, target) in [
        (scb::FLDSPC, spec_off),
        (scb::FLDDAT, flddat_off),
        (scb::MBPUNC, punct_off),
    ] {
        machine.write(at(scb_off + member), &at(target).to_bytes())?;
    }

    // Point the global at it. The module tests this for null.
    machine.write(fsdscb_at, &at(scb_off).to_bytes())?;

    let ascn: u16 = std::env::args().nth(2).map_or(0, |a| a.parse().unwrap_or(0));

    // The two things the ANSI path needs and `ascn=0` does not. Both are set
    // unconditionally: at `ascn=0` neither is reached, so leaving them in place
    // keeps the two runs the same program with one argument changed.
    let window = machine.alloc_segment(FSDBLN)?;
    let fsdbuf_at = FarPtr {
        offset: FSDBUF_OFFSET,
        selector: module
            .segment_selector(FSDBUF_SEGMENT)
            .expect("segment 155 is mapped"),
    };
    machine.write(
        fsdbuf_at,
        &FarPtr {
            offset: 0,
            selector: window,
        }
        .to_bytes(),
    )?;
    println!("fsdbuf global at {fsdbuf_at} -> {FSDBLN}-byte window");

    // The BIOS. `imports()` is dense from zero, so the next index is free, and
    // every one of `MAX_THUNKS` slots is built at `Machine::new` whether the
    // loader claimed it or not.
    let bios = module.imports().len() as u16;
    let int86x = FarPtr {
        offset: INT86X_OFFSET,
        selector: module
            .segment_selector(INT86X_SEGMENT)
            .expect("segment 128 is mapped"),
    };
    let jmp_far = {
        let to = machine.thunk_address(bios);
        let mut b = vec![0xea];
        b.extend_from_slice(&to.to_bytes());
        b
    };
    machine.write(int86x, &jmp_far)?;
    println!("int86x at {int86x} -> thunk {bios} (video BIOS)");

    // Detach the cursor from the hardware. This is a *state* change, not a code
    // change: it is exactly the post-condition of the library's own `cursact(0)`
    // (segment 93, offset 0xa09), which cannot be called here because it seeds
    // the software cursor by reading the hardware one first and would fault on
    // the way to switching the hardware off. Seeding it at (0, 0) rather than
    // with whatever a real console held is harmless -- `tmpscn` calls
    // `locate(0, 0)` before it measures anything.
    let dgroup = module.data_selector();
    let global = |offset: u16| FarPtr {
        offset,
        selector: dgroup,
    };
    machine.write(global(CURSOR_HARDWARE), &[0])?;
    machine.write(global(CURSOR_POSITION), &[0, 0])?;

    // Same move for the screen segment: `frzseg`'s post-state, pointed at real
    // memory. Giving it a segment of its own rather than aliasing the window
    // means anything that writes to "the screen" instead of the window lands
    // somewhere we can look at, rather than corrupting what we are measuring.
    let screen = machine.alloc_segment(SCREEN_BYTES)?;
    machine.write(global(SCREEN_SELECTOR), &screen.to_le_bytes())?;
    machine.write(global(SCREEN_CHOSEN), &[1])?;

    // And prove it took, before trusting anything the scan reports. `locate` and
    // `curcurx`/`curcury` are the exact three routines `tmpscn` measures with, so
    // a round trip through them is the narrowest check that says the software
    // cursor path is live.
    for (x, y) in [(0u16, 0u16), (37, 11)] {
        let locate = module.entry_by_name("_LOCATE").expect("the host exports locate");
        let (cx, cy) = (
            module.entry_by_name("_CURCURX").expect("_CURCURX"),
            module.entry_by_name("_CURCURY").expect("_CURCURY"),
        );
        machine.call(locate, &[x, y])?;
        let got = (machine.call(cx, &[])?, machine.call(cy, &[])?);
        let (Exit::Returned { ax: gx, .. }, Exit::Returned { ax: gy, .. }) = got else {
            panic!("the cursor round trip did not return: {got:?}");
        };
        assert_eq!(
            (gx, gy),
            (x, y),
            "locate({x},{y}) then curcurx/curcury read back ({gx},{gy})"
        );
    }
    println!("cursor detached from hardware: locate/curcurx/curcury round-trip clean");

    println!("calling _FSDPPC(template, ascn={ascn}) ...");
    let templt = at(template_off);
    let mut exit = machine.call(fsdppc, &[templt.offset, templt.selector, ascn])?;

    // Service the BIOS until `fsdppc` returns. Anything else that comes back as
    // a call is a genuine import and stops the run.
    loop {
        match exit {
            Exit::Returned { ax, .. } => {
                println!("Returned: {} error(s)\n", ax as i16);
                report(&machine, at(scb_off), at(flddat_off))?;
                if std::env::var_os("FSD_DUMP").is_some() {
                    dump("window (fsdbuf)", &machine, window)?;
                    dump("screen", &machine, screen)?;
                }
                return Ok(());
            }
            Exit::Call { index } if index == bios => {
                let ax = int86(&mut machine)?;
                exit = machine.resume(Ret::U16(ax))?;
            }
            Exit::Call { index } => {
                let who = module
                    .import(index)
                    .map(|i| format!("{}.{:?}", i.module, i.symbol))
                    .unwrap_or_else(|| format!("thunk {index}, no import site"));
                println!("Call out to an import: {who}");
                println!("  -- host code reached one of its own imports. Which symbol");
                println!("     it is decides whether this is stubbable or fatal.");
                return Ok(());
            }
            other => {
                println!("{other:?}");
                return Ok(());
            }
        }
    }
}

/// Print an 80x25 cell buffer as glyphs, one row per line.
///
/// A cell is `[character][attribute]`, which is the layout of both the physical
/// screen and the window `setwin` paints into. Non-printable bytes become `.`
/// and a wholly blank row becomes `~`, so the shape of what was painted -- and
/// on which rows -- reads at a glance.
fn dump(what: &str, machine: &Machine, selector: u16) -> std::io::Result<()> {
    println!("\n--- {what} ---");
    let cells = machine.resolve(
        FarPtr {
            offset: 0,
            selector,
        },
        SCREEN_BYTES,
    )?;
    for y in 0..25 {
        let glyphs = || (0..80).map(move |x| cells[(y * 80 + x) * 2]);
        // Blank means blank -- space or NUL. A row of box-drawing characters is
        // not blank, and an earlier version of this that folded them in with the
        // unprintables reported the sheet's top border as an empty line.
        if glyphs().all(|b| b == b' ' || b == 0) {
            println!("{y:2} ~");
            continue;
        }
        let row: String = glyphs()
            .map(|b| match b {
                0x20..=0x7e => b as char,
                _ => '.',
            })
            .collect();
        println!("{y:2} |{}|", row.trim_end());
    }
    Ok(())
}

/// Answer `int86x(intno, inregs, outregs, sregs)` for the machine.
///
/// `union REGS` is Borland's: `x` is `ax bx cx dx si di cflag flags` as words,
/// `h` is `al ah bl bh cl ch dl dh` as bytes over the first four of them. The
/// whole 16 bytes are copied `in -> out` first, which is what a real `int86`
/// leaves behind for registers the interrupt did not touch.
///
/// Returns what `int86` returns: `outregs.x.ax`.
fn int86(machine: &mut Machine) -> std::io::Result<u16> {
    /// `sizeof(union REGS)`: eight words.
    const REGS: usize = 16;

    let intno = machine.arg_u16(0);
    let inregs = machine.arg_far(1);
    let outregs = machine.arg_far(3);

    let mut regs: [u8; REGS] = machine
        .resolve(inregs, REGS)
        .expect("int86's inregs is addressable")
        .try_into()
        .expect("resolve returned the length asked for");
    let (al, ah) = (regs[0], regs[1]);

    match (intno, ah) {
        // AH=0Fh, get video mode: AL = mode, AH = columns, BH = active page.
        // Mode 3 is 80x25 colour, which is what ANSIWD/ANSILN describe. The one
        // thing `cursiz` does with it is `mode == 7`, the monochrome adapter.
        (0x10, 0x0f) => {
            regs[0] = 0x03;
            regs[1] = 80;
            regs[3] = 0x00;
        }
        // AH=01h, set cursor shape. Hardware only: there is no hardware, and
        // nothing downstream reads back what it set.
        (0x10, 0x01) => {}
        _ => {
            return Err(std::io::Error::other(format!(
                "int86x(0x{intno:02x}) with AH=0x{ah:02x} AL=0x{al:02x}: this rig \
                 supplies only INT 10h AH=0Fh and AH=01h, the two calls `cursiz` \
                 makes. Something else on the ANSI path wants the BIOS, and it \
                 has to be identified rather than answered with zero."
            )));
        }
    }

    // cflag and flags: the interrupt succeeded.
    regs[12..16].fill(0);
    machine
        .write(outregs, &regs)
        .expect("int86's outregs is writable");
    Ok(u16::from_le_bytes([regs[0], regs[1]]))
}

/// Print what `fsdppc` wrote into the control block and the field array.
fn report(machine: &Machine, scb_at: FarPtr, flddat_at: FarPtr) -> std::io::Result<()> {
    let word = |ptr: FarPtr, off: u16| -> std::io::Result<u16> {
        let b = machine.resolve(
            FarPtr {
                offset: ptr.offset + off,
                selector: ptr.selector,
            },
            2,
        )?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    };
    let byte = |ptr: FarPtr, off: u16| -> std::io::Result<u8> {
        Ok(machine.resolve(
            FarPtr {
                offset: ptr.offset + off,
                selector: ptr.selector,
            },
            1,
        )?[0])
    };

    let numfld = word(scb_at, scb::NUMFLD)?;
    println!(
        "numfld {numfld}  numtpl {}  mbleng {}  maxans {}",
        word(scb_at, scb::NUMTPL)?,
        word(scb_at, scb::MBLENG)?,
        word(scb_at, scb::MAXANS)?
    );
    println!(
        "maxy {}  hlplen {}  hlpoff {}  hlpatr {:#04x}  hlpgto {}",
        byte(scb_at, scb::MAXY)?,
        byte(scb_at, scb::HLPLEN)?,
        word(scb_at, scb::HLPOFF)? as i16,
        byte(scb_at, scb::HLPATR)?,
        gto(machine, scb_at, scb::HLPGTO)?,
    );

    for n in 0..numfld.min(64) {
        let f = FarPtr {
            offset: flddat_at.offset + n * FSDFLD,
            selector: flddat_at.selector,
        };
        println!(
            "  field {n:2}: fspoff {:4} tmpoff {:5} width {:3} xwidth {:3} mbpoff {:6} \
             flags {:#04x} type {:?} attr {:#04x} ansgto {}",
            word(f, fld::FSPOFF)? as i16,
            word(f, fld::TMPOFF)? as i16,
            byte(f, fld::WIDTH)?,
            byte(f, fld::XWIDTH)?,
            word(f, fld::MBPOFF)? as i16,
            byte(f, fld::FLAGS)?,
            byte(f, fld::FLDTYP)? as char,
            byte(f, fld::ATTR)?,
            gto(machine, f, fld::ANSGTO)?,
        );
    }
    Ok(())
}

/// One `char[GTOLEN+1]` cursor-goto command, rendered so an `ESC` is visible.
///
/// Printed as the bytes actually stored rather than as a parsed `(y, x)`: the
/// point of the oracle is that the cursor tracker has to reproduce this string,
/// not merely agree about where the cursor ended up.
fn gto(machine: &Machine, at: FarPtr, off: u16) -> std::io::Result<String> {
    let raw = machine.resolve(
        FarPtr {
            offset: at.offset + off,
            selector: at.selector,
        },
        usize::from(fld::ANSGTO_LEN),
    )?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end == 0 {
        return Ok("(empty)".to_string());
    }
    let mut out = String::from("\"");
    for &b in &raw[..end] {
        match b {
            0x1b => out.push_str("\\e"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('"');
    Ok(out)
}
