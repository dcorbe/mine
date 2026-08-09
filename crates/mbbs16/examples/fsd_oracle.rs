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

use std::path::Path;

use mbbs16::{Exit, FarPtr, Import, Machine, Symbol};

/// Where `fsdscb` lives: NE segment 154, offset 762. From the entry table, via
/// `re/ne_exports.py re/hosts/MAJORBBS-mbbstd.EXE fsdscb`.
const FSDSCB_SEGMENT: u16 = 154;
const FSDSCB_OFFSET: u16 = 762;

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
}

/// Where each member of `struct fsdfld` sits. `FSD.H:247`.
///
/// Taken from `crates/mbbs/src/fsd.rs`'s `fld` module, not re-derived. The first
/// draft of this file re-derived them and got every one wrong, which printed
/// plausible-looking nonsense (`fspoff 9223`) beside a correct `maxans` -- the
/// exact failure the oracle exists to catch, arriving first in the oracle's own
/// reader.
mod fld {
    pub const WIDTH: u16 = 9;
    pub const XWIDTH: u16 = 10;
    /// `char attr`. Off the ANSI path it is always 0x07, so nothing prints it;
    /// named here because the offsets after it are only checkable as a run.
    #[allow(dead_code)]
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

    println!("calling _FSDPPC(template, ascn={}) ...", std::env::args().nth(2).unwrap_or_else(|| "0".into()));
    let templt = at(template_off);
    let exit = machine.call(fsdppc, &[templt.offset, templt.selector, std::env::args().nth(2).map_or(0, |a| a.parse().unwrap_or(0))])?;

    match exit {
        Exit::Returned { ax, .. } => {
            println!("Returned: {} error(s)\n", ax as i16);
            report(&machine, at(scb_off), at(flddat_off))?;
        }
        Exit::Call { index } => {
            let who = module
                .import(index)
                .map(|i| format!("{}.{:?}", i.module, i.symbol))
                .unwrap_or_else(|| format!("thunk {index}, no import site"));
            println!("Call out to an import: {who}");
            println!("  -- host code reached one of its own imports. Which symbol");
            println!("     it is decides whether this is stubbable or fatal.");
        }
        other => println!("{other:?}"),
    }
    Ok(())
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

    for n in 0..numfld.min(64) {
        let f = FarPtr {
            offset: flddat_at.offset + n * FSDFLD,
            selector: flddat_at.selector,
        };
        println!(
            "  field {n:2}: fspoff {:4} tmpoff {:5} width {:3} xwidth {:3} mbpoff {:6} \
             flags {:#04x} type {:?}",
            word(f, fld::FSPOFF)? as i16,
            word(f, fld::TMPOFF)? as i16,
            byte(f, fld::WIDTH)?,
            byte(f, fld::XWIDTH)?,
            word(f, fld::MBPOFF)? as i16,
            byte(f, fld::FLAGS)?,
            byte(f, fld::FLDTYP)? as char,
        );
    }
    Ok(())
}
