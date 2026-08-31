//! A 16-bit module's `int 21h` is serviced by the host and resumed.

use mbbs::testing::{scratch, Fixture};
use mbbs::Outcome;

/// `mov ah,19h; int 21h; retf` -- AL comes back holding the default drive.
fn get_drive() -> Vec<u8> {
    vec![0xb4, 0x19, 0xcd, 0x21, 0xcb]
}

/// `mov ah,36h; int 21h; retf` -- a service this host does not have.
fn disk_free_space() -> Vec<u8> {
    vec![0xb4, 0x36, 0xcd, 0x21, 0xcb]
}

/// `mov ax,ds_sel; mov ds,ax` (DS is the module's own DGROUP after load, not
/// the fixture's scratch segment -- this loads it explicitly so DS:DX names
/// `dta`/`spec`), `1Ah` (set DTA to DS:DX = `dta`), `4Eh` (find `spec`), then
/// `jc L; mov ax,0; retf; L: retf` -- AX is 0 when found, the error when not.
fn find_first(ds_sel: u16, dta: u16, spec: u16) -> Vec<u8> {
    let mut v = vec![0xb8]; // mov ax, ds_sel
    v.extend_from_slice(&ds_sel.to_le_bytes());
    v.extend_from_slice(&[0x8e, 0xd8]); // mov ds, ax
    v.push(0xba); // mov dx, dta
    v.extend_from_slice(&dta.to_le_bytes());
    v.extend_from_slice(&[0xb4, 0x1a, 0xcd, 0x21]); // mov ah,1Ah; int 21h
    v.extend_from_slice(&[0xb9, 0x00, 0x00]); // mov cx, 0 (attribute mask)
    v.push(0xba); // mov dx, spec
    v.extend_from_slice(&spec.to_le_bytes());
    v.extend_from_slice(&[0xb4, 0x4e, 0xcd, 0x21]); // mov ah,4Eh; int 21h
    v.extend_from_slice(&[0x72, 0x04]); // jc L
    v.extend_from_slice(&[0xb8, 0x00, 0x00]); // mov ax, 0
    v.push(0xcb); // retf
    v.push(0xcb); // L: retf
    v
}

fn run(fx: &mut Fixture, code: &[u8]) -> Outcome<mbbs::abi::Wg16> {
    let module = fx.minimal_module();
    fx.machine.load_code(code).expect("module fits");
    let entry = fx.machine.code_ptr(0);
    fx.host.run(&mut fx.machine, &module, entry, &[], None).expect("ran")
}

#[test]
fn get_default_drive_answers_c_and_resumes() {
    let mut fx = Fixture::new();
    match run(&mut fx, &get_drive()) {
        Outcome::Returned { lo, .. } => assert_eq!(lo & 0xff, 2, "C: is drive 2"),
        Outcome::Stopped(p) => panic!("stopped: {p}"),
    }
}

#[test]
fn find_first_fills_the_dta_for_a_file_in_the_root() {
    let root = scratch("int21-find");
    std::fs::write(root.join("RCIROSE.DLL"), b"x").expect("a file to find");
    let mut fx = Fixture::rooted(root);
    let dta = fx.buffer(43);
    let spec = fx.text("rcirose.dll");
    // DS is pinned by the test's own prologue (`find_first`'s `mov
    // ax,ds_sel; mov ds,ax`), so DS:DX addresses the scratch buffers
    // regardless of what DS the module's own DGROUP would otherwise be.
    match run(&mut fx, &find_first(dta.selector, dta.offset, spec.offset)) {
        Outcome::Returned { lo, .. } => assert_eq!(lo & 0xffff, 0, "found"),
        Outcome::Stopped(p) => panic!("stopped: {p}"),
    }
    let name = fx.machine.read_cstr(mbbs_machine::m16::FarPtr { selector: dta.selector, offset: dta.offset + 0x1e })
        .expect("the record's name field is NUL-terminated");
    assert_eq!(name, b"RCIROSE.DLL");
}

#[test]
fn find_first_reports_file_not_found_with_carry() {
    let root = scratch("int21-find-missing");
    let mut fx = Fixture::rooted(root);
    let dta = fx.buffer(43);
    let spec = fx.text("nothere.dll");
    match run(&mut fx, &find_first(dta.selector, dta.offset, spec.offset)) {
        Outcome::Returned { lo, .. } => assert_eq!(lo & 0xffff, 2, "DOS error 2, file not found"),
        Outcome::Stopped(p) => panic!("stopped: {p}"),
    }
}

#[test]
fn a_service_this_host_lacks_is_a_named_refusal() {
    let mut fx = Fixture::new();
    match run(&mut fx, &disk_free_space()) {
        Outcome::Stopped(p) => {
            let text = p.to_string();
            assert!(text.contains("int 21h") && text.contains("0x36"), "{text}");
        }
        Outcome::Returned { .. } => panic!("an unserviced AH must not be fabricated"),
    }
    assert!(fx.machine.poisoned().is_some());
}
