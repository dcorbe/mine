//! Regression test for a host-crashing bug found in code review, not by any
//! of `dosenv.rs`'s own unit tests: `DosFreeSeg(SS)` used to succeed and
//! then panic the *host* process, not merely misbehave for the guest.
//!
//! # Why `dosenv.rs`'s own tests could not have caught this
//!
//! Every test there drives a shim through `Fixture::invoke`, which builds a
//! `Call<Wg16>` and calls the shim function directly -- it never calls
//! `Abi::resume`/`Machine::resume_cleaning`, because nothing in that path
//! needs to: the shim's `Result` is read straight off, and the test ends.
//! The panic this file exists to guard against lives one level up, in the
//! genuine dispatch loop (`Host::run`, `crates/mbbs/src/lib.rs`) reaching
//! `Segments::stack()` (`crates/mbbs-machine/src/m16/segments.rs`,
//! `.expect("the stack segment is this machine's own")`) on the *next*
//! machine access after a module's own stack segment has been freed out
//! from under it -- a line `Fixture::invoke` structurally cannot reach.
//!
//! So this builds a real, tiny NE module -- the same low-level construction
//! `cross_module_imports.rs` uses -- with one genuine `DOSCALLS!dosfreeseg`
//! import, and drives it through `Host::load` + `Host::run`: the real
//! loader, the real thunk table, the real `Abi::resume`. The module's own
//! code fetches its own stack selector at runtime (`MOV AX,SS`) exactly the
//! way a hostile or merely careless module could, and passes it as the one
//! argument `DosFreeSeg` takes.

use mbbs::testing::Fixture;
use mbbs::Outcome;
use mbbs_machine::m16::FarPtr;

const ALIGN: u16 = 4;
const SECTOR: usize = 1 << ALIGN;

const SRC_FAR_ADDR: u8 = 3;
const TGT_IMPORTNAME: u8 = 2;
const TGT_ADDITIVE: u8 = 0x04;

fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&ordinal.to_le_bytes());
    out
}

fn plain_pstring(name: &str) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out
}

/// A module named `CALLER` whose one segment (offset 0, its entry point)
/// runs:
///
/// ```text
/// mov ax, ss          ; this module's OWN stack selector -- MOV AX,SS trivially
/// push ax             ; the one SEL argument DosFreeSeg (Cleans::Callee(2)) takes
/// call far DOSCALLS!dosfreeseg   ; a real FAR_ADDR/IMPORTNAME fixup, patched by the loader
/// retf                ; back to this test, through Host::run's own dispatch loop
/// ```
///
/// Callee-cleaned (`Cleans::Callee(2)`), so nothing here has to `add sp` --
/// `A::resume` already popped the argument by the time control lands back
/// on `retf`.
fn caller_bytes() -> Vec<u8> {
    let mut impnames = vec![0u8]; // leading empty string, offset 0 is never a valid reference
    let module_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring("DOSCALLS"));
    let symbol_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring("dosfreeseg"));

    let mut restab = pstring("CALLER", 0);
    restab.push(0);

    let mut nrtab = pstring("dosfreeseg stack-selector guard fixture", 0);
    nrtab.push(0);

    // No exports: a zero-count bundle ends the table immediately.
    let entrytab = vec![0u8];

    let mut out = vec![0u8; 0x80];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

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

    // 8C D0        mov ax, ss
    // 50           push ax
    // 9A <4 bytes> call far ptr16:16 -- the 4 operand bytes are the fixup
    //              site, placeholder zeros the relocation below patches
    // CB           retf
    let code = [0x8Cu8, 0xD0, 0x50, 0x9A, 0x00, 0x00, 0x00, 0x00, 0xCB];
    let far_addr_site = 4u16; // right after the 0x9A opcode byte
    out.extend_from_slice(&code);

    out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(code.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0100u16.to_le_bytes()); // code, has relocations
    out[segtab + 6..segtab + 8].copy_from_slice(&(code.len() as u16).to_le_bytes());

    // One relocation: FAR_ADDR/IMPORTNAME, additive with a zero addend --
    // the same shape `cross_module_imports.rs`'s own `importer_bytes` uses,
    // naming a host DLL's routine instead of another loaded module's.
    out.extend_from_slice(&1u16.to_le_bytes()); // relocation count
    out.push(SRC_FAR_ADDR);
    out.push(TGT_IMPORTNAME | TGT_ADDITIVE);
    out.extend_from_slice(&far_addr_site.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // module reference index, 1-based
    out.extend_from_slice(&(symbol_at as u16).to_le_bytes());

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
    w(&mut out, 0x06, entrytab.len() as u16);
    w(&mut out, 0x0c, 0x8001);
    w(&mut out, 0x0e, 1); // autodata: the one segment
    w(&mut out, 0x1c, 1); // segment count
    w(&mut out, 0x1e, 1); // one imported module reference: DOSCALLS
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

/// `MOV AX,SS ; PUSH AX ; CALL FAR DOSCALLS!dosfreeseg ; RETF`, driven
/// through the real loader and the real dispatch loop, must not panic the
/// host -- and, with the allowlist guard in place, answers
/// `ERROR_INVALID_SELECTOR` (490) rather than freeing the module's own
/// stack out from under it.
///
/// Before the fix: `Segments::free_segment` matched purely on LDT entry, so
/// this selector -- genuinely the module's own stack, not a forged or
/// out-of-range one -- passed straight through, the `Segment` (and its
/// mapping) were dropped, and the very next `Segments::stack()` call inside
/// `A::resume` (`.expect("the stack segment is this machine's own")`)
/// panicked this test's thread. That panic is exactly what running this
/// test against the pre-fix code demonstrates (see the fix report for the
/// mutation that reproduces it).
#[test]
fn dosfreeseg_on_the_modules_own_stack_selector_does_not_crash_the_host() {
    let mut f = Fixture::new();
    let module = f
        .host
        .load(&mut f.machine, &caller_bytes())
        .expect("CALLER loads, its one import resolving to the real dosfreeseg thunk");

    let entry = FarPtr {
        offset: 0,
        selector: module.segment_selector(1).expect("CALLER's one segment"),
    };

    let outcome = f
        .host
        .run(&mut f.machine, &module, entry, &[], None)
        .expect("the machine itself does not fault or error");

    match outcome {
        Outcome::Returned { lo, .. } => {
            assert_eq!(
                lo, 490,
                "ERROR_INVALID_SELECTOR: the module's own stack selector was never \
                 allocator-issued, so DosFreeSeg must refuse it, not free it"
            );
        }
        other => panic!("expected a clean return through retf, got {other:?}"),
    }
}
