//! The NE loader, against modules built byte by byte in the test.
//!
//! Synthetic rather than real on purpose. `WCCMMUD.DLL` exercises six of the
//! format's relocation combinations and no more: every one of its non-additive
//! chains is one element long, none of its additive SEGMENT sites holds a
//! nonzero word, and it has no LOBYTE sources at all. Testing only against it
//! would ship the chain walk unverified and the additive rules half-verified.
//!
//! `tests/wccmmud.rs` is the other half: the real file, if it is present.

use std::collections::HashMap;

use mbbs_machine::m16::{Exit, FarPtr, Import, Machine, NeError, NeImage, Ret, Symbol, Target};

/// Logical sector alignment, as a shift count. Four rather than the usual nine
/// so a two-segment test module is a few hundred bytes instead of a few
/// thousand.
const ALIGN: u16 = 4;
const SECTOR: usize = 1 << ALIGN;

/// Relocation source types.
const LOBYTE: u8 = 0;
const SEGMENT: u8 = 2;
const FAR_ADDR: u8 = 3;
const OFFSET: u8 = 5;

/// Relocation target types, and the flag that means "one site, not a chain".
const INTERNALREF: u8 = 0;
const IMPORTORDINAL: u8 = 1;
const IMPORTNAME: u8 = 2;
const ADDITIVE: u8 = 4;

/// Segment table flags.
const SEG_DATA: u16 = 0x0001;
/// The flag that told the real memory manager a segment could be relocated and
/// reached through a handle. This host maps every segment once at a fixed
/// address, so it loads exactly as a fixed one does -- see `parse_segment`.
const SEG_MOVEABLE: u16 = 0x0010;
const SEG_RELOCINFO: u16 = 0x0100;

/// A relocation record, as eight bytes in the file. Spelled out rather than
/// built from a friendlier type so that a test can write a record the loader
/// must reject.
#[derive(Clone, Copy)]
struct Reloc {
    source: u8,
    flags: u8,
    offset: u16,
    lo: u16,
    hi: u16,
}

impl Reloc {
    /// A fixup pointing at segment `segment` of this same module.
    fn internal(source: u8, offset: u16, segment: u8, target: u16) -> Self {
        Self {
            source,
            flags: INTERNALREF,
            offset,
            lo: u16::from(segment),
            hi: target,
        }
    }

    /// A fixup pointing at ordinal `ordinal` of module reference `module`.
    fn import(source: u8, offset: u16, module: u16, ordinal: u16) -> Self {
        Self {
            source,
            flags: IMPORTORDINAL,
            offset,
            lo: module,
            hi: ordinal,
        }
    }

    fn additive(mut self) -> Self {
        self.flags |= ADDITIVE;
        self
    }
}

#[derive(Clone, Default)]
struct Seg {
    data: Vec<u8>,
    /// Sets `SEG_MOVEABLE` in the segment table row.
    moveable: bool,
    /// Bytes to allocate. Zero means 64 KiB, as the format has it.
    minalloc: u16,
    is_data: bool,
    relocs: Vec<Reloc>,
}

impl Seg {
    fn code(data: Vec<u8>) -> Self {
        Self {
            minalloc: data.len() as u16,
            data,
            ..Self::default()
        }
    }

    fn data(data: Vec<u8>) -> Self {
        Self {
            minalloc: data.len() as u16,
            data,
            is_data: true,
            ..Self::default()
        }
    }

    fn allocating(mut self, bytes: u16) -> Self {
        self.minalloc = bytes;
        self
    }

    fn with(mut self, relocs: &[Reloc]) -> Self {
        self.relocs.extend_from_slice(relocs);
        self
    }
}

/// A module, assembled into the bytes a loader sees.
#[derive(Default)]
struct Ne {
    segments: Vec<Seg>,
    /// Imported module names, in module-reference-table order.
    modules: Vec<String>,
    /// Imported-by-name symbols, which share the imported names table.
    imported_names: Vec<String>,
    /// Entry points by ordinal from 1. `None` is an ordinal the linker skipped.
    entries: Vec<Option<(u8, u16)>>,
    /// Emit `entries` as MOVEABLE bundles -- six bytes each, carrying the
    /// segment per entry with an `INT 3Fh` between, rather than three bytes
    /// under a segment-numbered indicator. Measured layout: see
    /// `a_moveable_entry_bundle_names_its_segment_per_entry`.
    moveable_entries: bool,
    /// Corrupt the `INT 3Fh` marker, to check the loader notices.
    break_moveable_thunk: bool,
    /// Exports in the resident name table, and in the non-resident one.
    resident: Vec<(String, u16)>,
    nonresident: Vec<(String, u16)>,
    /// 1-based segment number of DGROUP.
    autodata: u16,
}

impl Ne {
    /// The imported names table, and where each string in it starts.
    ///
    /// Offset zero is an empty string by convention, so that a relocation can
    /// name "no string" without naming a real one.
    fn imported_names(&self) -> (Vec<u8>, HashMap<String, u16>) {
        let mut bytes = vec![0u8];
        let mut offsets = HashMap::new();
        for name in self.modules.iter().chain(self.imported_names.iter()) {
            offsets.insert(name.clone(), bytes.len() as u16);
            bytes.push(name.len() as u8);
            bytes.extend_from_slice(name.as_bytes());
        }
        (bytes, offsets)
    }

    /// Where `name` sits in the imported names table, for an IMPORTNAME fixup.
    fn name_offset(&self, name: &str) -> u16 {
        self.imported_names().1[name]
    }

    fn finish(&self) -> Vec<u8> {
        let (impnames, offsets) = self.imported_names();

        // Resident name table: the module's own name first, whose ordinal is
        // ignored, then the exports. Terminated by a zero-length string.
        let mut restab = pstring("TESTMOD", 0);
        for (name, ordinal) in &self.resident {
            restab.extend_from_slice(&pstring(name, *ordinal));
        }
        restab.push(0);

        // Non-resident: a module description first, on the same terms.
        let mut nrtab = pstring("a test module", 0);
        for (name, ordinal) in &self.nonresident {
            nrtab.extend_from_slice(&pstring(name, *ordinal));
        }
        nrtab.push(0);

        // One bundle per entry, which the linker would not do but the format
        // permits. A skipped ordinal is an unused bundle with no entry data.
        let mut entrytab = Vec::new();
        for entry in &self.entries {
            match entry {
                None => entrytab.extend_from_slice(&[1, 0]),
                Some((segment, offset)) if self.moveable_entries => {
                    // count, then 0xFF for a moveable bundle; then per entry:
                    // flags, INT 3Fh, segment, offset.
                    entrytab.extend_from_slice(&[1, 0xff, 0x01]);
                    if self.break_moveable_thunk {
                        entrytab.extend_from_slice(&[0x90, 0x90]);
                    } else {
                        entrytab.extend_from_slice(&[0xcd, 0x3f]);
                    }
                    entrytab.push(*segment);
                    entrytab.extend_from_slice(&offset.to_le_bytes());
                }
                Some((segment, offset)) => {
                    entrytab.extend_from_slice(&[1, *segment, 0x01]);
                    entrytab.extend_from_slice(&offset.to_le_bytes());
                }
            }
        }
        entrytab.push(0);

        let mut out = vec![0u8; 0x80];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out[0x40..0x42].copy_from_slice(b"NE");

        // The segment table sits immediately after the header; its rows are
        // filled in once the segment data has been placed.
        let segtab = 0x80;
        out.resize(segtab + self.segments.len() * 8, 0);

        let modtab = out.len();
        for name in &self.modules {
            out.extend_from_slice(&offsets[name].to_le_bytes());
        }
        let imptab = out.len();
        out.extend_from_slice(&impnames);
        let restab_at = out.len();
        out.extend_from_slice(&restab);
        let entrytab_at = out.len();
        out.extend_from_slice(&entrytab);
        let nrtab_at = out.len();
        out.extend_from_slice(&nrtab);

        // Segment data, each starting on a sector boundary, with its relocation
        // records immediately after it.
        let mut sectors = Vec::new();
        for seg in &self.segments {
            if seg.data.is_empty() {
                sectors.push(0u16);
                continue;
            }
            while !out.len().is_multiple_of(SECTOR) {
                out.push(0);
            }
            sectors.push((out.len() / SECTOR) as u16);
            out.extend_from_slice(&seg.data);

            if !seg.relocs.is_empty() {
                out.extend_from_slice(&(seg.relocs.len() as u16).to_le_bytes());
                for r in &seg.relocs {
                    out.push(r.source);
                    out.push(r.flags);
                    out.extend_from_slice(&r.offset.to_le_bytes());
                    out.extend_from_slice(&r.lo.to_le_bytes());
                    out.extend_from_slice(&r.hi.to_le_bytes());
                }
            }
        }

        for (i, seg) in self.segments.iter().enumerate() {
            let mut flags = 0u16;
            if seg.is_data {
                flags |= SEG_DATA;
            }
            if seg.moveable {
                flags |= SEG_MOVEABLE;
            }
            if !seg.relocs.is_empty() {
                flags |= SEG_RELOCINFO;
            }
            let row = segtab + i * 8;
            out[row..row + 2].copy_from_slice(&sectors[i].to_le_bytes());
            out[row + 2..row + 4].copy_from_slice(&(seg.data.len() as u16).to_le_bytes());
            out[row + 4..row + 6].copy_from_slice(&flags.to_le_bytes());
            out[row + 6..row + 8].copy_from_slice(&seg.minalloc.to_le_bytes());
        }

        let w = |out: &mut Vec<u8>, at: usize, v: u16| {
            out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
        };
        w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
        w(&mut out, 0x06, entrytab.len() as u16);
        w(&mut out, 0x0c, 0x8001); // a single-data library
        w(&mut out, 0x0e, self.autodata);
        w(&mut out, 0x1c, self.segments.len() as u16);
        w(&mut out, 0x1e, self.modules.len() as u16);
        w(&mut out, 0x20, nrtab.len() as u16);
        w(&mut out, 0x22, (segtab - 0x40) as u16);
        w(&mut out, 0x26, (restab_at - 0x40) as u16);
        w(&mut out, 0x28, (modtab - 0x40) as u16);
        w(&mut out, 0x2a, (imptab - 0x40) as u16);
        w(&mut out, 0x32, ALIGN);
        out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
        out[0x40 + 0x36] = 0x02;

        out
    }
}

/// A length-prefixed name followed by its ordinal, as both name tables store it.
fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ordinal.to_le_bytes());
    out
}

/// A resolver that knows nothing, so every import gets a thunk.
fn nothing(_: &str, _: &Symbol) -> Option<Import> {
    None
}

/// Read `len` bytes out of a loaded segment.
fn peek(machine: &Machine, selector: u16, offset: u16, len: usize) -> Vec<u8> {
    machine
        .resolve(FarPtr { offset, selector }, len)
        .expect("inside the segment")
        .to_vec()
}

fn word(machine: &Machine, selector: u16, offset: u16) -> u16 {
    let b = peek(machine, selector, offset, 2);
    u16::from_le_bytes([b[0], b[1]])
}

#[test]
fn a_minimal_module_parses() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0xcb]), Seg::data(vec![1, 2, 3, 4])],
        modules: vec!["MAJORBBS".into(), "GALGSBL".into()],
        entries: vec![Some((1, 0x1234)), None, Some((2, 0x0002))],
        resident: vec![("VISIBLE".into(), 1)],
        nonresident: vec![("_INIT__TESTMOD".into(), 3)],
        autodata: 2,
        ..Ne::default()
    };

    let image = NeImage::parse(&ne.finish()).expect("a well-formed module");

    assert_eq!(image.segments.len(), 2);
    assert_eq!(image.autodata, 2);
    assert_eq!(image.align, ALIGN);
    assert_eq!(image.flags, 0x8001, "a single-data library");
    assert_eq!(image.exetype, 0x02);
    assert_eq!(image.modules, ["MAJORBBS", "GALGSBL"]);

    assert!(!image.segments[0].is_data(), "segment 1 is code");
    assert!(image.segments[1].is_data(), "segment 2 is data");

    assert_eq!(image.entries.len(), 3);
    assert_eq!(image.entries[0].expect("ordinal 1").offset, 0x1234);
    assert!(image.entries[1].is_none(), "ordinal 2 was skipped");
    assert_eq!(image.entries[2].expect("ordinal 3").segment, 2);

    // Both name tables, and neither table's leading string.
    assert_eq!(image.names.get("VISIBLE"), Some(&1));
    assert_eq!(image.names.get("_INIT__TESTMOD"), Some(&3));
    assert_eq!(image.names.get("TESTMOD"), None, "the module's own name");
    assert_eq!(image.names.get("a test module"), None, "the description");
}

#[test]
fn every_relocation_combination_the_real_module_uses_applies() {
    // One site per combination, laid out at 8-byte intervals so a fixup landing
    // on its neighbour is visible rather than absorbed.
    //
    //  0x00  FAR_ADDR  IMPORTORDINAL
    //  0x08  FAR_ADDR  INTERNALREF
    //  0x10  OFFSET    IMPORTORDINAL  additive
    //  0x18  SEGMENT   IMPORTORDINAL
    //  0x20  SEGMENT   INTERNALREF    additive
    //  0x28  SEGMENT   INTERNALREF
    //  0x30  FAR_ADDR  IMPORTNAME
    let mut code = vec![0u8; 0x40];
    // Every non-additive site is a one-element chain, which is what the real
    // module's 8,105 of them are.
    for at in [0x00, 0x08, 0x18, 0x28, 0x30] {
        code[at..at + 2].copy_from_slice(&0xffffu16.to_le_bytes());
    }

    let mut ne = Ne {
        segments: vec![Seg::code(code), Seg::data(vec![0xaa; 16])],
        modules: vec!["MAJORBBS".into()],
        imported_names: vec!["DOSCREATEDSALIAS".into()],
        entries: vec![Some((1, 0))],
        autodata: 2,
        ..Ne::default()
    };
    let name_at = ne.name_offset("DOSCREATEDSALIAS");
    ne.segments[0] = ne.segments[0].clone().with(&[
        Reloc::import(FAR_ADDR, 0x00, 1, 100),
        Reloc::internal(FAR_ADDR, 0x08, 2, 0x0006),
        Reloc::import(OFFSET, 0x10, 1, 101).additive(),
        Reloc::import(SEGMENT, 0x18, 1, 102),
        Reloc::internal(SEGMENT, 0x20, 2, 0).additive(),
        Reloc::internal(SEGMENT, 0x28, 2, 0),
        Reloc {
            source: FAR_ADDR,
            flags: IMPORTNAME,
            offset: 0x30,
            lo: 1,
            hi: name_at,
        },
    ]);

    let mut machine = Machine::new().expect("16-bit machine");
    // Ordinal 101 is a datum: the module addresses it, never calls it.
    let global = FarPtr {
        offset: 0x0042,
        selector: machine.data_selector(),
    };
    let module = machine
        .load_ne(&ne.finish(), &|_: &str, symbol: &Symbol| match symbol {
            Symbol::Ordinal(101) => Some(Import::Data(global)),
            _ => Some(Import::Routine),
        })
        .expect("loaded");

    let code = module.segment_selector(1).expect("segment 1");
    let data = module.segment_selector(2).expect("segment 2");

    // And back again, which is what turns a refusal's return address into
    // something you can find in a disassembly.
    assert_eq!(module.segment_at(code), Some(1));
    assert_eq!(module.segment_at(data), Some(2));
    assert_eq!(
        module.segment_at(0xFFFF),
        None,
        "a selector this module does not own is not one of its segments"
    );

    assert_eq!(module.relocations_applied(), 7);

    // FAR_ADDR IMPORTORDINAL: offset then selector, both from the thunk.
    let thunk_100 = machine.thunk_address(
        module
            .imports()
            .iter()
            .position(|i| i.symbol == Symbol::Ordinal(100))
            .expect("ordinal 100 has a thunk") as u16,
    );
    assert_eq!(word(&machine, code, 0x00), thunk_100.offset);
    assert_eq!(word(&machine, code, 0x02), thunk_100.selector);

    // FAR_ADDR INTERNALREF: the named offset, and the named segment's selector.
    assert_eq!(word(&machine, code, 0x08), 0x0006);
    assert_eq!(word(&machine, code, 0x0a), data);

    // OFFSET IMPORTORDINAL additive: the datum's offset, added to a zero word.
    assert_eq!(word(&machine, code, 0x10), 0x0042);

    // SEGMENT IMPORTORDINAL: the thunk's selector, and nothing else touched.
    let thunk_102 = machine.thunk_address(
        module
            .imports()
            .iter()
            .position(|i| i.symbol == Symbol::Ordinal(102))
            .expect("ordinal 102 has a thunk") as u16,
    );
    assert_eq!(word(&machine, code, 0x18), thunk_102.selector);

    // SEGMENT INTERNALREF, additive and not: the segment's selector either way.
    assert_eq!(word(&machine, code, 0x20), data);
    assert_eq!(word(&machine, code, 0x28), data);

    // FAR_ADDR IMPORTNAME.
    let by_name = module
        .imports()
        .iter()
        .position(|i| i.symbol == Symbol::Name("DOSCREATEDSALIAS".into()))
        .expect("the named import has a thunk") as u16;
    assert_eq!(
        word(&machine, code, 0x30),
        machine.thunk_address(by_name).offset
    );
    assert_eq!(
        word(&machine, code, 0x32),
        machine.thunk_address(by_name).selector
    );

    // A data import consumes no thunk at all: only the three routines did.
    assert_eq!(module.imports().len(), 3);
}

/// An OSFIXUP relocation is parsed and carried, not refused.
///
/// Target type 3 is the floating-point emulator fixup. A real image can carry a
/// handful among thousands of ordinary fixups -- `MAJORBBS-mbbstd.EXE` has 50 of
/// 10,234 -- and refusing the file over them costs the whole binary to save
/// nothing. The site is left as the image had it, which is the emulator
/// interrupt the linker already wrote there.
#[test]
fn an_osfixup_relocation_is_carried_rather_than_refused() {
    // Built directly from `Reloc`'s raw fields rather than a new helper: those
    // fields already are the record's eight bytes (source, flags, offset, lo,
    // hi), so there is nothing an "image with a relocation" helper would add.
    // Source OFFSET (5), flags 0x03 (TGT_OSFIXUP, no ADDITIVE bit), fixup kind 5
    // (FIDRQQ).
    let ne = Ne {
        segments: vec![
            Seg::code(vec![0u8; 0x10]).with(&[Reloc {
                source: OFFSET,
                flags: 0x03,
                offset: 0x00,
                lo: 5,
                hi: 0,
            }]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let image = NeImage::parse(&ne.finish()).expect("an OSFIXUP does not refuse the file");
    let relocs = &image.segments[0].relocations;
    assert_eq!(relocs.len(), 1);
    assert_eq!(relocs[0].target, Target::OsFixup { kind: 5 });

    // And it loads: the site is untouched, still exactly the zero byte the
    // synthetic segment started with, because it was carried and not applied.
    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    assert_eq!(
        module.relocations_applied(),
        0,
        "an OSFIXUP site is not one this loader wrote"
    );
    let code_sel = module.segment_selector(1).unwrap();
    assert_eq!(
        word(&machine, code_sel, 0x00),
        0,
        "the site is left exactly as the image had it"
    );
}

/// The case `WCCMMUD.DLL` cannot check. Every non-additive chain in it is one
/// element long, so without this the walk ships untested.
#[test]
fn a_chain_longer_than_one_element_is_walked() {
    for source in [SEGMENT, OFFSET, FAR_ADDR] {
        // Three sites, linked 0x00 -> 0x10 -> 0x20, terminated there.
        let mut code = vec![0u8; 0x30];
        code[0x00..0x02].copy_from_slice(&0x0010u16.to_le_bytes());
        code[0x10..0x12].copy_from_slice(&0x0020u16.to_le_bytes());
        code[0x20..0x22].copy_from_slice(&0xffffu16.to_le_bytes());

        let ne = Ne {
            segments: vec![
                Seg::code(code).with(&[Reloc::internal(source, 0x00, 2, 0x1234)]),
                Seg::data(vec![0; 16]),
            ],
            entries: vec![Some((1, 0))],
            autodata: 2,
            ..Ne::default()
        };

        let mut machine = Machine::new().expect("16-bit machine");
        let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
        let code_sel = module.segment_selector(1).expect("segment 1");
        let data_sel = module.segment_selector(2).expect("segment 2");

        for at in [0x00u16, 0x10, 0x20] {
            match source {
                SEGMENT => assert_eq!(
                    word(&machine, code_sel, at),
                    data_sel,
                    "SEGMENT chain site {at:#x}"
                ),
                OFFSET => assert_eq!(
                    word(&machine, code_sel, at),
                    0x1234,
                    "OFFSET chain site {at:#x}"
                ),
                _ => {
                    assert_eq!(
                        word(&machine, code_sel, at),
                        0x1234,
                        "FAR_ADDR chain site {at:#x} offset"
                    );
                    assert_eq!(
                        word(&machine, code_sel, at + 2),
                        data_sel,
                        "FAR_ADDR chain site {at:#x} selector"
                    );
                }
            }
        }
    }
}

/// A chain whose last link points at itself. Wine stops here rather than
/// looping, and stopping is the only reading of it that terminates.
#[test]
fn a_chain_link_pointing_at_itself_ends_the_walk() {
    let mut code = vec![0u8; 0x20];
    code[0x00..0x02].copy_from_slice(&0x0010u16.to_le_bytes());
    code[0x10..0x12].copy_from_slice(&0x0010u16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::internal(OFFSET, 0x00, 2, 0x1234)]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    let code_sel = module.segment_selector(1).unwrap();

    assert_eq!(word(&machine, code_sel, 0x00), 0x1234);
    assert_eq!(word(&machine, code_sel, 0x10), 0x1234);
}

/// A chain the walk cannot destroy as it goes.
///
/// Most cycles break themselves: the fixup overwrites the very word the next
/// link lives in, so a second visit reads the value just written rather than
/// the link. A LOBYTE fixup writes one byte, so a chain whose links differ only
/// in their high byte survives being walked and would loop forever.
#[test]
fn a_chain_that_survives_being_walked_is_an_error_rather_than_a_hang() {
    let mut code = vec![0u8; 0x300];
    code[0x0100..0x0102].copy_from_slice(&0x0200u16.to_le_bytes());
    code[0x0200..0x0202].copy_from_slice(&0x0100u16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            // Target offset 0, so the byte written is the low byte both links
            // already have, and neither link is disturbed.
            Seg::code(code).with(&[Reloc::internal(LOBYTE, 0x0100, 2, 0x0000)]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let err = machine
        .load_ne(&ne.finish(), &nothing)
        .expect_err("a chain that loops should not load");
    assert!(
        err.to_string().contains("does not end"),
        "unexpected error: {err}"
    );
}

/// The largest single correctness trap in the loader. 1,670 of `WCCMMUD.DLL`'s
/// additive OFFSET sites already hold a nonzero word -- `margv[-1]`, `sv.numact`
/// -- so writing where the format says add produces wrong addresses, silently.
#[test]
fn an_additive_offset_adds_to_what_is_already_there() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0x0100u16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::import(OFFSET, 0x00, 1, 7).additive()]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine
        .load_ne(&ne.finish(), &|_: &str, _: &Symbol| {
            Some(Import::Data(FarPtr {
                offset: 0x0020,
                selector: 0x0f,
            }))
        })
        .expect("loaded");

    assert_eq!(
        word(&machine, module.segment_selector(1).unwrap(), 0x00),
        0x0120,
        "0x0100 + 0x0020, not 0x0020"
    );
}

/// An export can be a constant rather than an address, and `WCCMMUD.DLL` needs
/// one: `DOSCALLS.135` is the huge shift, resolved into the immediate of a
/// `mov $x, %cx` that precedes a `shl`. Given a thunk's address instead, the
/// module shifts by whatever slot that thunk landed in -- which is a wrong
/// number, not a crash.
#[test]
fn an_absolute_import_writes_its_value_into_the_instruction() {
    let ne = Ne {
        segments: vec![
            Seg::code(vec![0u8; 0x10]).with(&[Reloc::import(OFFSET, 0x02, 1, 135).additive()]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["DOSCALLS".into()],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine
        .load_ne(&ne.finish(), &|_: &str, _: &Symbol| {
            Some(Import::Absolute(3))
        })
        .expect("loaded");

    assert_eq!(
        word(&machine, module.segment_selector(1).unwrap(), 0x02),
        3,
        "the constant itself, and no address anywhere"
    );
    assert!(
        module.imports().is_empty(),
        "a constant is not called, so it gets no thunk"
    );
}

#[test]
fn an_absolute_import_refuses_a_fixup_that_wants_a_selector() {
    // A constant has no selector. Writing half of it as one would produce a
    // wrong address and no complaint, which is exactly what this loader is for.
    for source in [SEGMENT, FAR_ADDR] {
        let ne = Ne {
            segments: vec![
                Seg::code(vec![0u8; 0x10]).with(&[Reloc::import(source, 0x02, 1, 135)]),
                Seg::data(vec![0; 16]),
            ],
            modules: vec!["DOSCALLS".into()],
            autodata: 2,
            ..Ne::default()
        };

        let mut machine = Machine::new().expect("16-bit machine");
        let failed = machine
            .load_ne(&ne.finish(), &|_: &str, _: &Symbol| {
                Some(Import::Absolute(3))
            })
            .expect_err("a constant cannot fill an address fixup");
        assert_eq!(
            failed.to_string(),
            NeError::AbsoluteNeedsAnAddress {
                segment: 1,
                offset: 0x02
            }
            .to_string()
        );
    }
}

#[test]
fn an_addend_may_wrap_past_the_end_of_the_segment() {
    // The real shape of this: `margv` is reached with an addend of 0xfffe,
    // which is -2 -- the module wants the word before the array.
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xfffeu16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::import(OFFSET, 0x00, 1, 7).additive()]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine
        .load_ne(&ne.finish(), &|_: &str, _: &Symbol| {
            Some(Import::Data(FarPtr {
                offset: 0x0004,
                selector: 0x0f,
            }))
        })
        .expect("loaded");

    assert_eq!(
        word(&machine, module.segment_selector(1).unwrap(), 0x00),
        0x0002,
        "0xfffe + 4 wraps to 2"
    );
}

#[test]
fn a_lobyte_source_writes_and_adds_one_byte() {
    let mut code = vec![0u8; 0x10];
    code[0x00] = 0x20;
    code[0x04] = 0x20;
    code[0x05] = 0x77; // the high half of the word, which must survive

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[
                Reloc::internal(LOBYTE, 0x00, 2, 0x0134).additive(),
                Reloc::internal(LOBYTE, 0x04, 2, 0x0156).additive(),
            ]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    let code_sel = module.segment_selector(1).unwrap();

    assert_eq!(peek(&machine, code_sel, 0x00, 1), [0x54], "0x20 + 0x34");
    assert_eq!(peek(&machine, code_sel, 0x04, 1), [0x76], "0x20 + 0x56");
    assert_eq!(
        peek(&machine, code_sel, 0x05, 1),
        [0x77],
        "the neighbouring byte is untouched"
    );
}

#[test]
fn a_segment_larger_than_its_file_data_has_a_zeroed_tail() {
    let ne = Ne {
        segments: vec![
            Seg::code(vec![0xcb]),
            Seg::data(vec![0xab; 4]).allocating(64),
        ],
        entries: vec![Some((1, 0))],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    let data = module.segment_selector(2).expect("segment 2");

    assert_eq!(peek(&machine, data, 0, 4), [0xab; 4], "the file's bytes");
    assert_eq!(
        peek(&machine, data, 4, 60),
        vec![0u8; 60],
        "and BSS behind them"
    );
    // The segment is exactly its minalloc, so reading one byte past it fails.
    assert!(
        machine
            .resolve(
                FarPtr {
                    offset: 63,
                    selector: data
                },
                2
            )
            .is_err(),
        "the segment's limit is its allocation"
    );
}

#[test]
fn an_unresolved_import_still_gets_a_thunk_that_names_it() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xffffu16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::import(FAR_ADDR, 0x00, 1, 474)]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        entries: vec![Some((1, 0))],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    let site = module.import(0).expect("a thunk was assigned anyway");
    assert_eq!(site.module, "MAJORBBS");
    assert_eq!(site.symbol, Symbol::Ordinal(474));
    assert!(!site.resolved, "the host had no answer for it");
    assert_eq!(site.to_string(), "MAJORBBS.474");

    // And the fixup points at that thunk, so reaching it is a diagnosable
    // event rather than a far call into nothing.
    let thunk = machine.thunk_address(0);
    let code_sel = module.segment_selector(1).unwrap();
    assert_eq!(word(&machine, code_sel, 0x00), thunk.offset);
    assert_eq!(word(&machine, code_sel, 0x02), thunk.selector);
}

/// A resolver is asked about each distinct symbol exactly once.
///
/// The natural way to write a host's data resolver is to hand out a slot of
/// memory per global, allocating on first sight. If the loader asks per fixup
/// instead of per symbol, that resolver scatters one global across as many
/// addresses as it has fixups -- 1,285 of them for `usrnum` -- and the module
/// uses whichever the last one happened to be. Nothing about it looks wrong.
#[test]
fn a_symbol_is_resolved_once_however_many_fixups_name_it() {
    let mut code = vec![0u8; 0x40];
    for at in [0x00usize, 0x08, 0x10] {
        code[at..at + 2].copy_from_slice(&0xffffu16.to_le_bytes());
    }

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[
                // Three fixups, one symbol.
                Reloc::import(FAR_ADDR, 0x00, 1, 55),
                Reloc::import(FAR_ADDR, 0x08, 1, 55),
                Reloc::import(FAR_ADDR, 0x10, 1, 55),
            ]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        autodata: 2,
        ..Ne::default()
    };

    // A resolver that hands out a fresh address every time it is asked, which
    // is what an allocating one does.
    let asked = std::cell::Cell::new(0u16);
    let mut machine = Machine::new().expect("16-bit machine");
    let scratch = machine.data_selector();
    let module = machine
        .load_ne(&ne.finish(), &|_: &str, _: &Symbol| {
            let n = asked.get();
            asked.set(n + 1);
            Some(Import::Data(FarPtr {
                offset: n * 16,
                selector: scratch,
            }))
        })
        .expect("loaded");

    assert_eq!(asked.get(), 1, "the resolver was asked once");

    let code_sel = module.segment_selector(1).unwrap();
    for at in [0x00u16, 0x08, 0x10] {
        assert_eq!(word(&machine, code_sel, at), 0, "every fixup got slot zero");
        assert_eq!(word(&machine, code_sel, at + 2), scratch);
    }
}

#[test]
fn a_loaded_module_can_be_entered_by_ordinal_and_by_name() {
    // 0: 9a <far ptr>   lcall $CS, $import
    // 5: cb             lret
    let mut code = vec![0u8; 0x20];
    code[0x10] = 0x9a;
    code[0x11..0x13].copy_from_slice(&0xffffu16.to_le_bytes());
    code[0x15] = 0xcb;

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::import(FAR_ADDR, 0x11, 1, 68)]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        entries: vec![Some((1, 0x10))],
        nonresident: vec![("_INIT__TESTMOD".into(), 1)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    let by_ordinal = module.entry(1).expect("ordinal 1");
    let by_name = module.entry_by_name("_INIT__TESTMOD").expect("by name");
    assert_eq!(by_ordinal, by_name);
    assert_eq!(by_ordinal.offset, 0x10);
    assert_eq!(by_ordinal.selector, module.segment_selector(1).unwrap());

    // DS is the module's DGROUP, not the scratch segment.
    assert_eq!(machine.data_selector(), module.segment_selector(2).unwrap());

    let mut exit = machine.call(by_ordinal, &[]).expect("entered the module");
    match exit {
        Exit::Call { index } => {
            assert_eq!(
                module.import(index).map(ToString::to_string).as_deref(),
                Some("MAJORBBS.68")
            );
        }
        other => panic!("expected a call to the import, got {other:?}"),
    }
    exit = machine.resume(Ret::U16(1)).expect("resumed");
    assert!(matches!(exit, Exit::Returned { ax: 1, .. }), "got {exit:?}");
}

/// `Module::init` used to be `module.entry(1)`, called directly by
/// `Wg16::init_entry` -- "ordinal 1 is the init routine" believed to be
/// Galacticomm's own convention on the strength of `WCCMMUD.DLL`, whose
/// ordinal 1 genuinely is `_INIT__WCCMMUD`. Measured against a second NE
/// module, `RCIROSE.DLL`, that agreement turned out to be coincidence: its
/// ordinal 1 is `BCC286_EXE`, Borland C++ 286's crt0 startup stub, while its
/// real init routine, `_INIT__RCIROSE`, sits at ordinal 403 (both spellings
/// and both ordinals measured directly off the file's resident name table).
/// This test reproduces that shape synthetically: a decoy at ordinal 1 with
/// a crt0-shaped name, and the real `_INIT__TESTMOD` several ordinals away.
#[test]
fn init_resolves_by_name_even_when_ordinal_one_is_something_else() {
    let ne = Ne {
        segments: vec![
            Seg::code(vec![0u8; 0x20]),
            Seg::data(vec![0; 16]),
        ],
        // Ordinal 1 is the crt0-shaped decoy; the real init routine sits
        // four ordinals later, at a different offset in the same segment.
        entries: vec![Some((1, 0x04)), None, None, None, Some((1, 0x10))],
        resident: vec![("BCC286_EXE".into(), 1), ("_INIT__TESTMOD".into(), 5)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    let decoy = module.entry(1).expect("ordinal 1, the crt0-shaped decoy");
    let real_init = module.entry(5).expect("ordinal 5, the real init routine");
    assert_ne!(decoy, real_init, "the two ordinals must land at different offsets");

    assert_eq!(
        module.init(),
        Some(real_init),
        "init() must resolve _INIT__TESTMOD by name, not answer ordinal 1's decoy"
    );
    assert_ne!(
        module.init(),
        Some(decoy),
        "the whole bug: init() must NOT answer what ordinal 1 answers here"
    );
}

/// The init routine's name need not contain the module's own name at all.
/// `MAJORBBS.EXE` 6.25's `initdlls` (`seg 22:0x233`) walks every exported
/// name with `DosEnumProc` and takes the first one `sameto("_INIT__", ..)`
/// accepts -- a prefix test, nothing more. `TSGARN.DLL` (Tele-Arena 5.6d) is
/// the measured shape: its own name is `TSGARN`, ordinal 1 is `_DELARN`, and
/// the init routine is `_INIT__TA` at ordinal 251. Matching `_INIT__TSGARN`
/// found nothing and the ordinal-1 guess ran `delarn` as init.
#[test]
fn init_is_the_first_export_whose_name_starts_with_init_prefix() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0u8; 0x20]), Seg::data(vec![0; 16])],
        entries: vec![Some((1, 0x04)), Some((1, 0x08)), Some((1, 0x10))],
        resident: vec![("_DELARN".into(), 1), ("_CLSARN".into(), 2), ("_INIT__TA".into(), 3)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    assert_eq!(
        module.init(),
        module.entry(3),
        "init() must be _INIT__TA, whose suffix is not the module's own name"
    );
    assert_ne!(module.init(), module.entry(1), "ordinal 1 (_DELARN) is not init");
}

/// `sameto` upper-cases both strings before comparing (`MAJORBBS.EXE` seg
/// 35:0x1ec4), so a lower-case `_init__` export is the same routine.
#[test]
fn init_prefix_match_is_case_insensitive() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0u8; 0x20]), Seg::data(vec![0; 16])],
        entries: vec![Some((1, 0x04)), Some((1, 0x08))],
        resident: vec![("_delarn".into(), 1), ("_init__ta".into(), 2)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    assert_eq!(module.init(), module.entry(2));
}

/// Two `_INIT__` exports: the first in name-table order wins, resident table
/// before non-resident, which is the order `DosEnumProc` hands names out
/// in. No module in the corpus has two, so this pins determinism rather
/// than a measured vendor choice.
#[test]
fn init_prefers_the_resident_table_and_then_table_order() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0u8; 0x20]), Seg::data(vec![0; 16])],
        entries: vec![Some((1, 0x04)), Some((1, 0x08)), Some((1, 0x10))],
        resident: vec![("_INIT__SECOND".into(), 2), ("_INIT__THIRD".into(), 3)],
        nonresident: vec![("_INIT__FIRST".into(), 1)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    assert_eq!(module.init(), module.entry(2));
}

/// No `_INIT__` export means no init routine -- the vendor host's
/// `catastro("%s.DLL has no initialization routine!")`. Ordinal 1 is not a
/// fallback: in every measured module where no `_INIT__` name exists it is
/// something else (`GALGSBL.DLL`'s `_BTUBSE`, `FW_MSG.DLL`'s
/// `_FW_MSG_GET_VERSION`, a `WEP`), and where an `_INIT__` name does exist
/// ordinal 1 is a crt0 stub or gameplay code as often as it is init.
#[test]
fn init_is_none_when_no_export_starts_with_init_prefix() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0xcbu8; 4]), Seg::data(vec![0; 4])],
        entries: vec![Some((1, 0x02))],
        resident: vec![("_BTUBSE".into(), 1)],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");

    assert!(module.entry(1).is_some(), "ordinal 1 is exported and resolves fine on its own");
    assert_eq!(module.init(), None, "no _INIT__ export, so there is no init routine to guess at");
}

#[test]
fn a_file_that_is_not_ne_is_rejected() {
    assert_eq!(NeImage::parse(b"not an executable"), Err(NeError::NotNe));

    let mut ne = Ne {
        segments: vec![Seg::code(vec![0xcb])],
        autodata: 1,
        ..Ne::default()
    }
    .finish();
    ne[0x40] = b'P';
    assert_eq!(NeImage::parse(&ne), Err(NeError::NotNe));
}

#[test]
fn a_truncated_file_is_an_error_rather_than_a_short_read() {
    let whole = Ne {
        segments: vec![
            Seg::code(vec![0xcb; 8]).with(&[Reloc::internal(OFFSET, 0x00, 2, 0)]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    }
    .finish();

    // Every prefix of a valid file is either an error or, for the very shortest,
    // not an NE file at all. None of them may parse.
    for cut in (8..whole.len()).step_by(7) {
        assert!(
            NeImage::parse(&whole[..cut]).is_err(),
            "a {cut}-byte prefix of a {}-byte module parsed",
            whole.len()
        );
    }
    assert!(
        NeImage::parse(&whole).is_ok(),
        "the whole file still parses"
    );
}

#[test]
fn a_relocation_site_outside_its_segment_is_an_error() {
    let ne = Ne {
        segments: vec![
            // The segment is 16 bytes; the fixup is at 0x14.
            Seg::code(vec![0u8; 16]).with(&[Reloc::internal(FAR_ADDR, 0x14, 2, 0)]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let err = machine
        .load_ne(&ne.finish(), &nothing)
        .expect_err("a fixup outside its segment should not load");
    assert!(err.to_string().contains("outside segment"), "got {err}");
}

#[test]
fn a_relocation_naming_a_segment_that_does_not_exist_is_an_error() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xffffu16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            Seg::code(code).with(&[Reloc::internal(SEGMENT, 0x00, 9, 0)]),
            Seg::data(vec![0; 16]),
        ],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let err = machine
        .load_ne(&ne.finish(), &nothing)
        .expect_err("segment 9 does not exist");
    assert!(err.to_string().contains("no segment 9"), "got {err}");
}

#[test]
fn a_relocation_naming_a_module_that_does_not_exist_is_an_error() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xffffu16.to_le_bytes());

    let ne = Ne {
        segments: vec![
            // Module reference 3, with one module in the table.
            Seg::code(code).with(&[Reloc::import(FAR_ADDR, 0x00, 3, 1)]),
            Seg::data(vec![0; 16]),
        ],
        modules: vec!["MAJORBBS".into()],
        autodata: 2,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let err = machine
        .load_ne(&ne.finish(), &nothing)
        .expect_err("module reference 3 does not exist");
    assert!(
        err.to_string().contains("no module reference 3"),
        "got {err}"
    );
}

#[test]
fn an_autodata_segment_that_does_not_exist_is_an_error() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0xcb])],
        autodata: 7,
        ..Ne::default()
    };

    let mut machine = Machine::new().expect("16-bit machine");
    let err = machine
        .load_ne(&ne.finish(), &nothing)
        .expect_err("segment 7 does not exist");
    assert!(
        err.to_string().contains("automatic data segment"),
        "got {err}"
    );
}

/// A moveable segment loads, exactly as a fixed one does.
///
/// `SEG_MOVEABLE` told the real memory manager the segment could be relocated
/// and reached through a handle. This host maps every segment once, at a fixed
/// address, with its own LDT descriptor, so the flag describes a facility that
/// does not exist here rather than one this loader lacks.
///
/// This was a refusal until 2026-08-20, and it was the single reason 148 of the
/// 254 module binaries under `archive/modules/dlls` could not be loaded at all.
#[test]
fn a_moveable_segment_loads_like_a_fixed_one() {
    let ne = Ne {
        segments: vec![
            Seg {
                moveable: true,
                ..Seg::code(vec![0xcb])
            },
            Seg::data(vec![1, 2, 3, 4]),
        ],
        entries: vec![Some((1, 0))],
        autodata: 2,
        ..Ne::default()
    };

    let image = NeImage::parse(&ne.finish()).expect("a moveable segment is not a refusal");
    assert_eq!(image.segments.len(), 2);

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    assert!(
        module.segment_selector(1).is_some(),
        "the moveable segment got a descriptor like any other"
    );
}

/// A moveable entry bundle carries the segment number per entry, with the real
/// loader's `INT 3Fh` thunk between the flags and it.
///
/// Measured, not taken from a specification: the first moveable bundle of
/// `archive/modules/dlls/ISVADV__Advbdynt/_SETUP.DLL` reads
/// `03 cd 3f 01 24 00` -- flags `03`, `cd 3f`, segment `01`, offset `0x0024`.
#[test]
fn a_moveable_entry_bundle_names_its_segment_per_entry() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0xcb]), Seg::data(vec![0; 4])],
        entries: vec![Some((1, 0x0024)), Some((2, 0x05d4))],
        moveable_entries: true,
        autodata: 2,
        ..Ne::default()
    };

    let image = NeImage::parse(&ne.finish()).expect("moveable bundles parse");
    assert_eq!(image.entries.len(), 2);
    let first = image.entries[0].expect("ordinal 1");
    assert_eq!((first.segment, first.offset), (1, 0x0024));
    let second = image.entries[1].expect("ordinal 2");
    assert_eq!((second.segment, second.offset), (2, 0x05d4));
}

/// A relocation whose target segment byte is `0xFF` names an entry-table
/// ordinal, not a segment, and resolves through the entry table.
///
/// The fixup that lands is an ordinary internal one, which is the whole point:
/// resolving here means `Target` and every fixup path below stay unchanged.
/// Asserted on the patched bytes rather than on the parse, because a resolution
/// that produced the right `Target` and wrote it to the wrong place would pass
/// a parse-level check.
#[test]
fn a_moveable_relocation_resolves_through_the_entry_table() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xffffu16.to_le_bytes());

    let mut ne = Ne {
        segments: vec![Seg::code(code), Seg::data(vec![0xaa; 16])],
        // Ordinal 1 names segment 2, offset 6 -- the same place the fixed-target
        // case in `every_relocation_combination_the_real_module_uses_applies`
        // points at, so the two are directly comparable.
        entries: vec![Some((2, 0x0006))],
        moveable_entries: true,
        autodata: 2,
        ..Ne::default()
    };
    ne.segments[0] = ne.segments[0].clone().with(&[Reloc {
        source: FAR_ADDR,
        flags: INTERNALREF,
        offset: 0x00,
        lo: 0x00ff, // moveable: the segment byte is 0xFF
        hi: 1,      // entry-table ordinal 1
    }]);

    let mut machine = Machine::new().expect("16-bit machine");
    let module = machine.load_ne(&ne.finish(), &nothing).expect("loaded");
    let code_sel = module.segment_selector(1).expect("segment 1");
    let data_sel = module.segment_selector(2).expect("segment 2");

    assert_eq!(module.relocations_applied(), 1);
    assert_eq!(
        word(&machine, code_sel, 0x00),
        0x0006,
        "the offset came from the entry table, not from the relocation's own hi word"
    );
    assert_eq!(
        word(&machine, code_sel, 0x02),
        data_sel,
        "and the selector is segment 2's, which is what ordinal 1 names"
    );
}

/// A moveable bundle without its `INT 3Fh` marker is a malformed file, and is
/// refused as one rather than read as though the bytes lined up.
#[test]
fn a_moveable_bundle_without_its_thunk_is_refused() {
    let ne = Ne {
        segments: vec![Seg::code(vec![0xcb])],
        entries: vec![Some((1, 0x0024))],
        moveable_entries: true,
        break_moveable_thunk: true,
        autodata: 1,
        ..Ne::default()
    };

    let e = NeImage::parse(&ne.finish()).expect_err("the marker is part of the format");
    let text = e.to_string();
    assert!(text.contains("moveable entry bundle"), "{text}");
    assert!(text.contains("3fcd") || text.contains("0x3fcd"), "{text}");
}

/// A moveable relocation naming an ordinal the entry table does not define is
/// refused, naming the ordinal. Answering it would mean inventing a target.
#[test]
fn a_moveable_relocation_past_the_entry_table_is_refused() {
    let mut code = vec![0u8; 0x10];
    code[0x00..0x02].copy_from_slice(&0xffffu16.to_le_bytes());

    let mut ne = Ne {
        segments: vec![Seg::code(code), Seg::data(vec![0; 4])],
        entries: vec![Some((1, 0x0006))],
        moveable_entries: true,
        autodata: 2,
        ..Ne::default()
    };
    ne.segments[0] = ne.segments[0].clone().with(&[Reloc {
        source: FAR_ADDR,
        flags: INTERNALREF,
        offset: 0x00,
        lo: 0x00ff,
        hi: 9, // there is one ordinal, not nine
    }]);

    let e = NeImage::parse(&ne.finish()).expect_err("ordinal 9 does not exist");
    let text = e.to_string();
    assert!(text.contains("moveable relocation"), "{text}");
    assert!(text.contains('9'), "{text}");
}
