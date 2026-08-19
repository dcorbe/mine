//! A module's GALGSBL call reaching the host through a synthesised forwarder.
//!
//! `mbbs_machine::m16::emit` (`crates/mbbs-machine/src/m16/ne_emit.rs`) can
//! build an NE image that stands in for a host library on disk: every export
//! is a `jmp far` through a relocation that imports a routine of the same
//! name from a module of its own name, so the host's ordinary loader binds
//! it to a real thunk. Nothing before this file has ever loaded one of those
//! images and actually called through it -- Task 1/6's own tests all read
//! the emitted bytes back with `NeImage::parse` and stop there. This is the
//! caller: build a forwarder for `GALGSBL`, load it, then load a second,
//! synthetic module that imports `GALGSBL` ordinal 59 (`btuxmt`) and calls
//! it for real, through the machine, and check that the call really landed
//! in `gsbl::btuxmt` rather than merely returning.

use mbbs::shims::gsbl::btutsw;
use mbbs::testing::Fixture;
use mbbs::Outcome;
use mbbs_machine::m16::{FarPtr, Module, emit};

const ALIGN: u16 = 4;
const SECTOR: usize = 1 << ALIGN;

// The same relocation-record constants `cross_module_imports.rs` and
// `detection.rs` use, restated here because each `tests/*.rs` file is its
// own crate and cannot import another integration test's private helpers.
const SRC_FAR_ADDR: u8 = 3;
const TGT_IMPORTORDINAL: u8 = 1;
const TGT_ADDITIVE: u8 = 0x04;

/// A pstring as the exported-name tables want it: a length byte, the bytes,
/// then a trailing ordinal word.
fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ordinal.to_le_bytes());
    out
}

/// A pstring as the module- and imported-name tables want it: no trailing
/// ordinal.
fn plain_pstring(name: &str) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out
}

/// Fill in the fixed NE header fields, mirroring
/// `cross_module_imports.rs::write_header` and `crate::testing`'s own
/// builders: one segment, one autodata (that same segment), no
/// `NOAUTODATA`.
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

/// A module named `CALLER` that imports `GALGSBL` ordinal 59 (`btuxmt`) and
/// whose entry point (segment 1, offset 0) is `call far <the fixup site> ;
/// retf` -- a genuine call/return pair, not `cross_module_imports.rs`'s bare
/// `jmp far`. That distinction matters here: a `jmp far` works there because
/// the far call landing on it already pushed a return address the target's
/// own `retf` can pop directly. Here the fixup resolves to the forwarder's
/// own `jmp far`, which lands on a host thunk with no `retf` of its own at
/// all (`Host::run` services the call and then `retf`s on this module's
/// behalf) -- so this module needs to have pushed a return address itself
/// for that `retf` to find, which only a real `call far` does.
///
/// `btuxmt(int chan, char *datstg)`'s own two arguments are pushed by this
/// module's own code as three immediate words -- `chan`, then `text`'s
/// offset, then its selector -- exactly the shape
/// `crate::testing::Fixture::call_with` pushes and `Call::int`/`Call::ptr`
/// read back. They are **not** carried in through [`mbbs::Host::run`]'s own
/// `args`: those are pushed *below* this entry point on the stack, for use
/// by a retf this entry point would issue itself once done with them (the
/// ordinary module-init calling convention) -- but this entry point never
/// reads or pops them, it immediately calls further in, so anything passed
/// that way would sit untouched under the far call's own fresh return
/// address rather than where `btuxmt` looks for its arguments.
fn caller_bytes(chan: u16, text: FarPtr) -> Vec<u8> {
    let mut impnames = vec![0u8];
    let module_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring("GALGSBL"));

    let mut restab = pstring("CALLER", 0);
    restab.push(0);

    let mut nrtab = pstring("a synthetic GALGSBL caller", 0);
    nrtab.push(0);

    // No exports: a zero-count bundle ends the table immediately.
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

    // Push `btuxmt`'s two arguments as three immediate words, in the order
    // `Call::int`/`Call::ptr` read them back: `chan` nearest the top of the
    // stack (pushed last), then `text`'s offset, then its selector -- the
    // same layout `Fixture::call_with` builds and the same reasoning this
    // function's own doc comment gives for why `Host::run`'s `args` cannot
    // be used here instead.
    let mut code = Vec::new();
    for word in [text.selector, text.offset, chan] {
        code.push(0xB8); // mov ax, imm16
        code.extend_from_slice(&word.to_le_bytes());
        code.push(0x50); // push ax
    }
    // 0x9A = CALL FAR ptr16:16 (operand patched by the relocation below).
    let call_far_at = code.len();
    code.extend_from_slice(&[0x9Au8, 0x00, 0x00, 0x00, 0x00]);
    // `btuxmt` is `Cleans::Caller` (`shims/mod.rs`'s own routine table): the
    // callee does not pop its own arguments, so the three words this code
    // pushed above are still on the stack when the call returns here. Three
    // `pop ax`es discard them (their value is unused) before the final
    // `0xCB` retf, which must find *its own* return address at the top of
    // the stack, not six leftover argument bytes underneath it.
    code.extend_from_slice(&[0x58, 0x58, 0x58]); // pop ax; pop ax; pop ax
    code.push(0xCB); // retf
    out.extend_from_slice(&code);

    // One relocation: a FAR_ADDR fixup, additive with a zero addend (one
    // site, no chain), naming ordinal 59 of module reference 1 (`GALGSBL`).
    out.extend_from_slice(&1u16.to_le_bytes()); // relocation count
    out.push(SRC_FAR_ADDR);
    out.push(TGT_IMPORTORDINAL | TGT_ADDITIVE);
    out.extend_from_slice(&((call_far_at + 1) as u16).to_le_bytes()); // site: right after the opcode byte
    out.extend_from_slice(&1u16.to_le_bytes()); // module reference index, 1-based
    out.extend_from_slice(&59u16.to_le_bytes()); // ordinal

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

/// The caller's own entry point: segment 1, offset 0. There is no export
/// table entry for it (the caller exports nothing), so this is built from
/// the module's own segment selector, exactly as
/// `cross_module_imports.rs::importer_entry` does.
fn caller_entry(module: &Module) -> FarPtr {
    FarPtr {
        offset: 0,
        selector: module.segment_selector(1).expect("the caller's one segment"),
    }
}

/// The end-to-end assertion the forwarder exists for. A module imports
/// GALGSBL ordinal 59 (`btuxmt`); the host loads a synthesised GALGSBL
/// first and resolves that import into it; calling it must land in
/// `gsbl::btuxmt` and have the effect that routine has.
///
/// Without this the forwarder is a shape nothing exercises.
#[test]
fn a_module_call_through_the_forwarder_reaches_the_host_routine() {
    let mut f = Fixture::new();

    // 1. Build the forwarder from the registry's own wg101 GALGSBL table:
    // ordinal 59 is `_BTUXMT` in `crates/mbbs-machine/data/galgsbl_wg101.tsv`,
    // which canonicalises (`mbbs_machine::library::c_name`) to `btuxmt` --
    // the exact name `shims::entry` answers, and the name this emitted
    // image's own self-import must carry for the host tables to bind it.
    let forwarder = emit("GALGSBL", &[(59, "btuxmt")], b"");

    // f.host.load(&mut f.machine, &forwarder) -- unflipped resolver, imports
    // bind to shims. Never `load_with_precedence` for the forwarder's own
    // load: see that method's doc comment for the self-import loop that
    // would create.
    f.host.load(&mut f.machine, &forwarder).expect("the forwarder loads");

    // A generous wrap width so btuxmt's own transmit is not reshaped by
    // word-wrap -- the effect under test is "did the call land here", not
    // "does btutsw's own wrapping logic work", which `shims/gsbl.rs`
    // already covers on its own.
    let console = f.console();
    f.invoke(btutsw, &[0, 200]).expect("wrap width set");
    let text = f.text("through the forwarder");
    let chan = 0u16;

    // f.host.load(&mut f.machine, &module) -- flipped for GALGSBL, so the
    // caller's own GALGSBL.btuxmt import binds to the forwarder just loaded
    // rather than straight to the host.
    let module = f
        .host
        .load_with_precedence(&mut f.machine, &caller_bytes(chan, text), &["GALGSBL"])
        .expect("the caller loads, its GALGSBL import resolving to the forwarder");

    // Call the module's entry point with no args of its own -- `chan` and
    // `text` are already baked into its code as the three immediate pushes
    // `caller_bytes` built; see that function's own doc comment for why
    // `Host::run`'s own `args` cannot carry them instead.
    let outcome = f
        .host
        .run(&mut f.machine, &module, caller_entry(&module), &[], None)
        .expect("no io error servicing the call");
    assert!(
        matches!(outcome, Outcome::Returned { .. }),
        "the call must return cleanly through the forwarder's own retf, got {outcome:?}"
    );

    // The observable effect of `gsbl::btuxmt`, read back off the host's own
    // state -- not `outcome` above (whose `lo` is not even `btuxmt`'s own
    // return value by the time this reads it: the three `pop ax`es
    // `caller_bytes` cleans its own call with run *after* `resume` sets `AX`
    // from the shim's return, so `outcome.lo` is leftover stack, not
    // `btuxmt`'s answer). A call that landed nowhere in particular could
    // still produce some `Outcome::Returned`; only the transmitted bytes
    // prove it landed in `gsbl::btuxmt` itself.
    assert_eq!(
        f.host.gsbl_mut().drain_output(console),
        b"through the forwarder".to_vec(),
        "btuxmt's own effect must be visible on the channel the call named, \
         or the call did not really land in gsbl::btuxmt"
    );
}
