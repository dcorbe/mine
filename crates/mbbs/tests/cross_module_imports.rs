//! `Host::load` letting one loaded module import symbols another loaded
//! module exports -- the capability `WCCMMPLS.DLL` needs to reach
//! `WCCMMUD.DLL`'s own `mmlog`/`retrieve_public_usrnum_userinfo`/etc (see
//! `re/importgaps.py`'s output against a real `WCCMMPLS.DLL`, which is what
//! this file's own module doc comment would cite if this crate's tests were
//! allowed to depend on a checked-in copy of it -- they are not, so this is
//! a purpose-built two-module fixture instead, the same approach
//! `wg32_round_trip.rs` uses for the border it proves).
//!
//! Two tiny hand-built NE images, in the same shape `crate::testing`'s own
//! `minimal_module_bytes`/`module_bytes_importing` use (a real NE header, one
//! segment, built byte-for-byte rather than through any builder, so the test
//! agrees with `NeImage::parse` about the file format by construction rather
//! than by sharing code with it):
//!
//! - `exporter_bytes()`: declares itself `EXPORTER` (the resident name
//!   table's own first entry -- what `mbbs_machine::m16::Module::name`
//!   answers), and exports one routine at ordinal 1, also reachable by the
//!   name `dowork`. The routine's own machine code is `mov ax,0x1234 ; retf`
//!   -- two instructions, four bytes, chosen because a caller that reaches
//!   them can *prove* it reached them: `AX` comes back `0x1234` only if the
//!   call really landed on this code, in this segment, at this offset.
//!
//! - `importer_bytes(symbol)`: imports one symbol -- `symbol`, ordinal or
//!   name -- from a module named `EXPORTER`, and its own single instruction
//!   is `jmp far <the fixup site>` (opcode `0xEA`). A `jmp far`, not a
//!   `call far`, on purpose: it does not push a return address of its own,
//!   so calling the importer's entry point and landing (via the fixup) on
//!   `EXPORTER`'s `retf` returns control straight back to *this test*, with
//!   `EXPORTER`'s own `AX` still in the register. One instruction is enough
//!   to prove the fixup site holds a real, callable, correct far pointer --
//!   anything wrong with the address (wrong offset, wrong selector, a thunk
//!   instead of a direct address) either faults or returns a different `AX`.

use mbbs::testing::Fixture;
use mbbs::{LoadError, Why};
use mbbs_machine::m16::{Exit, FarPtr, Symbol};

const ALIGN: u16 = 4;
const SECTOR: usize = 1 << ALIGN;

const SRC_FAR_ADDR: u8 = 3;
const TGT_IMPORTORDINAL: u8 = 1;
const TGT_IMPORTNAME: u8 = 2;
const TGT_ADDITIVE: u8 = 0x04;

/// A pstring as the *exported*-name tables want it: a length byte, the bytes,
/// then a trailing ordinal word.
fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ordinal.to_le_bytes());
    out
}

/// A pstring as the module- and imported-name tables want it: no trailing
/// ordinal at all.
fn plain_pstring(name: &str) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out
}

/// Fill in the fixed NE header fields every fixture below shares: one
/// segment, one autodata (that same segment), no `NOAUTODATA` -- see
/// `crates/mbbs/src/testing.rs`'s own builders, whose header-writing this
/// mirrors exactly.
fn write_header(
    out: &mut Vec<u8>,
    segtab: usize,
    entrytab_at: usize,
    entrytab_len: usize,
    module_count: u16,
    modtab: usize,
    imptab: usize,
    restab_at: usize,
    nrtab_at: usize,
    nrtab_len: usize,
) {
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(out, 0x04, (entrytab_at - 0x40) as u16);
    w(out, 0x06, entrytab_len as u16);
    w(out, 0x0c, 0x8001);
    w(out, 0x0e, 1); // autodata: the one segment
    w(out, 0x1c, 1); // segment count
    w(out, 0x1e, module_count);
    w(out, 0x20, nrtab_len as u16);
    w(out, 0x22, (segtab - 0x40) as u16);
    w(out, 0x26, (restab_at - 0x40) as u16);
    w(out, 0x28, (modtab - 0x40) as u16);
    w(out, 0x2a, (imptab - 0x40) as u16);
    w(out, 0x32, ALIGN);
    out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
    out[0x40 + 0x36] = 0x02;
}

/// A module named `EXPORTER`, no imports, exporting one routine two ways:
/// ordinal 1, and the name `dowork` (also ordinal 1 -- one routine, two
/// handles onto it, exactly as a real NE export table lets a symbol have
/// both). See this file's own module doc comment for what the routine's
/// code does and why.
fn exporter_bytes() -> Vec<u8> {
    exporter_bytes_named("EXPORTER", "dowork")
}

/// [`exporter_bytes`], generalised over its own declared name and the one
/// name its routine exports -- both ordinal 1 either way. Used directly by
/// `a_loaded_module_cannot_shadow_a_host_routine_of_the_same_name`, which
/// needs a module that declares itself `MAJORBBS` (the host's own name) and
/// exports something the host also implements, without hand-editing
/// `exporter_bytes`'s own raw bytes to get there.
fn exporter_bytes_named(own_name: &str, export_name: &str) -> Vec<u8> {
    let impnames = vec![0u8]; // no imports at all

    // The module's own name, then the one exported name, then a terminator.
    let mut restab = pstring(own_name, 0);
    restab.extend_from_slice(&pstring(export_name, 1));
    restab.push(0);

    let mut nrtab = pstring("a synthetic export source", 0);
    nrtab.push(0);

    // One bundle: segment 1, one entry (exported, offset 0), then the
    // zero-count terminator.
    let entrytab = vec![1u8, 1u8, 0x01u8, 0x00, 0x00, 0u8];

    let mut out = vec![0u8; 0x80];
    let segtab = 0x80;
    out.resize(segtab + 8, 0);

    let modtab = out.len();
    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector = (out.len() / SECTOR) as u16;
    // mov ax, 0x1234 ; retf
    let code = [0xB8u8, 0x34, 0x12, 0xCB];
    out.extend_from_slice(&code);

    out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(code.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0000u16.to_le_bytes()); // code, no relocations
    out[segtab + 6..segtab + 8].copy_from_slice(&(code.len() as u16).to_le_bytes());

    write_header(
        &mut out, segtab, entrytab_at, entrytab.len(), 0, modtab, imptab, restab_at, nrtab_at,
        nrtab.len(),
    );

    out
}

/// A module named `IMPORTER` that imports `symbol` from a module named
/// `export_module`, and whose entry point (segment 1, offset 0) is a single
/// `jmp far` straight through the fixup site.
fn importer_bytes(export_module: &str, symbol: Symbol) -> Vec<u8> {
    let mut impnames = vec![0u8];
    let module_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring(export_module));
    let symbol_at = impnames.len();
    if let Symbol::Name(name) = &symbol {
        impnames.extend_from_slice(&plain_pstring(name));
    }

    let mut restab = pstring("IMPORTER", 0);
    restab.push(0);

    let mut nrtab = pstring("a synthetic import sink", 0);
    nrtab.push(0);

    // No exports of its own: a zero-count bundle ends the table immediately.
    let entrytab = vec![0u8];

    let mut out = vec![0u8; 0x80];
    let segtab = 0x80;
    out.resize(segtab + 8, 0);

    let modtab = out.len();
    out.extend_from_slice(&(module_at as u16).to_le_bytes());

    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector = (out.len() / SECTOR) as u16;
    // 0xEA = JMP FAR ptr16:16. The four operand bytes are the fixup site --
    // placeholder zeros the relocation below patches with the real address.
    let code = [0xEAu8, 0x00, 0x00, 0x00, 0x00];
    out.extend_from_slice(&code);

    // The one relocation: a FAR_ADDR fixup, additive with a zero addend, so
    // it writes exactly the resolved offset and selector with no chain to
    // walk -- the same technique `crate::testing::module_bytes_importing`
    // uses for its own single, non-chained site.
    let (target_flag, hi) = match &symbol {
        Symbol::Ordinal(n) => (TGT_IMPORTORDINAL, *n),
        Symbol::Name(_) => (TGT_IMPORTNAME, symbol_at as u16),
    };
    out.extend_from_slice(&1u16.to_le_bytes()); // relocation count
    out.push(SRC_FAR_ADDR);
    out.push(target_flag | TGT_ADDITIVE);
    out.extend_from_slice(&1u16.to_le_bytes()); // site: right after the opcode byte
    out.extend_from_slice(&1u16.to_le_bytes()); // module reference index, 1-based
    out.extend_from_slice(&hi.to_le_bytes());

    out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(code.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0100u16.to_le_bytes()); // code, has relocations
    out[segtab + 6..segtab + 8].copy_from_slice(&(code.len() as u16).to_le_bytes());

    write_header(
        &mut out, segtab, entrytab_at, entrytab.len(), 1, modtab, imptab, restab_at, nrtab_at,
        nrtab.len(),
    );

    out
}

/// The importer's own entry point: segment 1, offset 0 -- where its `jmp
/// far` sits. There is no export table entry for it (the importer exports
/// nothing), so this is built from the module's own segment selector rather
/// than through `Module::entry`.
fn importer_entry(module: &mbbs_machine::m16::Module) -> FarPtr {
    FarPtr {
        offset: 0,
        selector: module.segment_selector(1).expect("the importer's one segment"),
    }
}

/// The centrepiece: load `EXPORTER` first, then an `IMPORTER` that imports
/// its routine **by ordinal**, and prove the fixup is a real, direct,
/// callable far pointer into `EXPORTER`'s own code -- not a thunk, and not a
/// fault.
#[test]
fn an_ordinal_import_reaches_another_loaded_modules_own_code() {
    let mut f = Fixture::new();
    f.host
        .load(&mut f.machine, &exporter_bytes())
        .expect("EXPORTER loads");
    let importer = f
        .host
        .load(&mut f.machine, &importer_bytes("EXPORTER", Symbol::Ordinal(1)))
        .expect("IMPORTER, loaded after its dependency, resolves cleanly");

    match f.machine.call(importer_entry(&importer), &[]).expect("a clean far call") {
        Exit::Returned { ax, .. } => {
            assert_eq!(ax, 0x1234, "AX must be EXPORTER's own value: the jmp far landed on its code");
        }
        other => panic!("expected a direct return, got {other:?}"),
    }
}

/// The same proof, but the import names its target **by name** rather than
/// ordinal -- `WCCMMPLS.DLL`'s own real imports are named this way (see this
/// file's own module doc comment), and ordinal and name resolve through two
/// different tables in the exporting module (`Module::entry` vs
/// `entry_by_name`), so this is not redundant with the ordinal test above.
#[test]
fn a_named_import_reaches_another_loaded_modules_own_code() {
    let mut f = Fixture::new();
    f.host
        .load(&mut f.machine, &exporter_bytes())
        .expect("EXPORTER loads");
    let importer = f
        .host
        .load(
            &mut f.machine,
            &importer_bytes("EXPORTER", Symbol::Name("dowork".to_owned())),
        )
        .expect("IMPORTER, loaded after its dependency, resolves cleanly");

    match f.machine.call(importer_entry(&importer), &[]).expect("a clean far call") {
        Exit::Returned { ax, .. } => {
            assert_eq!(ax, 0x1234, "AX must be EXPORTER's own value: the jmp far landed on its code");
        }
        other => panic!("expected a direct return, got {other:?}"),
    }
}

/// Load ordering: a module that imports from a dependency **not yet
/// loaded** does not refuse to load at all -- it degrades exactly the way an
/// import from a host DLL this crate has not implemented every symbol of
/// already does, a thunk that would fault only if the module actually
/// called it. See `Why::NotExported`'s own doc comment for why this is the
/// right call: the resolver cannot tell "EXPORTER was never loaded" apart
/// from "EXPORTER is a host DLL nobody has written shims for", and must not
/// refuse the second case.
#[test]
fn importing_from_a_module_not_yet_loaded_still_loads_and_only_faults_if_called() {
    let mut f = Fixture::new();

    let importer = f
        .host
        .load(&mut f.machine, &importer_bytes("EXPORTER", Symbol::Ordinal(1)))
        .expect("a module importing an unloaded dependency still loads");

    // The unresolved import got a thunk, exactly like any other
    // unimplemented symbol -- so calling through it stops the machine and
    // names what was reached, rather than faulting on a bogus address.
    match f.machine.call(importer_entry(&importer), &[]).expect("a clean far call") {
        Exit::Call { .. } => {}
        other => panic!("expected a thunk call (the import is still unresolved), got {other:?}"),
    }
}

/// A dependency that **is** loaded, but does not export what was asked for,
/// is a hard refusal naming both -- the one case this feature makes a load
/// error rather than a graceful thunk, because the ambiguity that protects
/// the "not yet loaded" case above does not exist here: the module is
/// right here, in memory, and simply does not have it.
#[test]
fn a_loaded_dependency_missing_the_requested_export_is_refused() {
    let mut f = Fixture::new();
    f.host
        .load(&mut f.machine, &exporter_bytes())
        .expect("EXPORTER loads");

    match f.host.load(
        &mut f.machine,
        &importer_bytes("EXPORTER", Symbol::Ordinal(99)),
    ) {
        Ok(_) => panic!("importing an export EXPORTER does not have must be refused"),
        Err(LoadError::Globals(missing)) => {
            assert_eq!(missing.len(), 1, "exactly the one symbol was requested");
            let m = &missing[0];
            assert_eq!(m.module, "EXPORTER");
            // `symbol_name` names an ordinal no export table maps by its
            // `"#{n}"` convention -- see `Resolver::resolve`'s own doc
            // comment ("shims::entry(module, \"#42\")") for why that is the
            // one true name to use, not a bare number.
            assert_eq!(m.symbol, "#99");
            assert_eq!(m.why, Why::NotExported);
        }
        Err(e) => panic!("wrong error: {e}"),
    }
}

/// Order matters: a loaded module may never shadow a host routine. A module
/// that declares itself `MAJORBBS` -- the host's own name -- and exports
/// something called `spr` must not intercept an import of `MAJORBBS.spr`;
/// the host's real `spr` shim must win, exactly as it would if no such
/// module had ever been loaded. Checked structurally, not by calling
/// anything: a host-table hit produces a thunk (an `ImportSite` in the
/// loaded module's own `imports()`), where a registry hit would instead
/// write a direct address and leave no thunk behind at all -- so the
/// presence of a thunk here *is* the proof host tables won.
#[test]
fn a_loaded_module_cannot_shadow_a_host_routine_of_the_same_name() {
    let mut f = Fixture::new();

    // A module that declares itself `MAJORBBS` and exports a routine named
    // `spr` -- `exporter_bytes_named`'s own shape, aimed at the host's own
    // name instead of a synthetic one.
    let shadow = exporter_bytes_named("MAJORBBS", "spr");
    f.host.load(&mut f.machine, &shadow).expect("the shadow module loads");

    let importer = f
        .host
        .load(
            &mut f.machine,
            &importer_bytes("MAJORBBS", Symbol::Name("spr".to_owned())),
        )
        .expect("MAJORBBS.spr is a real host routine, so this resolves through the host, not the shadow");

    assert_eq!(
        importer.imports().len(),
        1,
        "a host-table hit gets a thunk -- exactly one import site, not zero"
    );
    assert!(
        importer.imports()[0].resolved,
        "the host's own spr must have answered, not the shadow module's"
    );
}
