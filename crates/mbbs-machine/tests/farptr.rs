//! Far pointers: resolving `seg:off` the way the module means it.
//!
//! Galacticomm built these modules in Borland's **huge** model with `DS != SS`,
//! so every pointer is a 4-byte `seg:off` and the segment can be any of the
//! module's, including its stack. There is no case where a pointer is
//! implicitly in `DS`, which means the host can never resolve one by adding a
//! fixed base -- it has to go through the descriptor table it built.
//!
//! The module here passes two pointers into two different segments to the same
//! import. Resolving both correctly is only possible by selector.

use mbbs_machine::m16::{Exit, FarPtr, Machine, Ret};

/// The import the module calls: something `strlen`-shaped, which is the shape
/// most of the real API has.
const STRLEN_THUNK: u16 = 3;

/// Where the host plants the two strings, in two different segments.
const STACK_STRING_AT: u16 = 0x0200;
const CODE_STRING_AT: u16 = 0x0300;

const STACK_STRING: &[u8] = b"hello\0";
const CODE_STRING: &[u8] = b"worldly\0";

/// 16-bit module code, as Borland's cdecl emits a call taking `char far *`:
///
/// ```text
///  0: 16              push  %ss            far pointer, segment first...
///  1: 68 00 02        push  $0x200         ...then offset, so offset ends up lower
///  4: 9a <far ptr>    lcall $CS, $strlen
///  9: 83 c4 04        add   $4, %sp        cdecl: the caller cleans
///  c: 89 c7           mov   %ax, %di       keep the first length
///  e: 0e              push  %cs            now a pointer into a DIFFERENT segment
///  f: 68 00 03        push  $0x300
/// 12: 9a <far ptr>    lcall $CS, $strlen
/// 17: 83 c4 04        add   $4, %sp
/// 1a: 01 f8           add   %di, %ax
/// 1c: 89 c6           mov   %ax, %si       total, somewhere callee-saved
/// 1e: cb              lret
/// ```
fn test_module() -> Vec<u8> {
    let mut code = vec![0x16]; // push %ss
    code.push(0x68);
    code.extend_from_slice(&STACK_STRING_AT.to_le_bytes());
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x83, 0xc4, 0x04]);
    code.extend_from_slice(&[0x89, 0xc7]);
    code.push(0x0e); // push %cs
    code.push(0x68);
    code.extend_from_slice(&CODE_STRING_AT.to_le_bytes());
    code.extend_from_slice(&[0x9a, 0, 0, 0, 0]);
    code.extend_from_slice(&[0x83, 0xc4, 0x04]);
    code.extend_from_slice(&[0x01, 0xf8]);
    code.extend_from_slice(&[0x89, 0xc6]);
    code.push(0xcb); // lret
    code
}

const CALL1_SITE: usize = 5;
const CALL2_SITE: usize = 19;

fn loaded_machine() -> Machine {
    let mut machine = Machine::new().expect("16-bit machine");

    let mut code = test_module();
    let strlen = machine.thunk_address(STRLEN_THUNK).to_bytes();
    code[CALL1_SITE..CALL1_SITE + 4].copy_from_slice(&strlen);
    code[CALL2_SITE..CALL2_SITE + 4].copy_from_slice(&strlen);
    machine.load_code(&code).expect("module fits");

    // Plant one string in the stack segment and one in the code segment. The
    // stack one is the interesting case: it is what `DS != SS` is about.
    let stack_ptr = FarPtr {
        offset: STACK_STRING_AT,
        selector: machine.stack_selector(),
    };
    let code_ptr = FarPtr {
        offset: CODE_STRING_AT,
        selector: machine.code_selector(),
    };
    machine
        .write(stack_ptr, STACK_STRING)
        .expect("stack string");
    machine.write(code_ptr, CODE_STRING).expect("code string");

    machine
}

#[test]
fn a_far_pointer_argument_resolves_through_the_segment_it_names() {
    let mut machine = loaded_machine();
    let stack_sel = machine.stack_selector();
    let code_sel = machine.code_selector();

    let mut exit = machine
        .call(machine.code_ptr(0), &[])
        .expect("called the module");
    let mut seen: Vec<Vec<u8>> = Vec::new();

    loop {
        match exit {
            Exit::Call {
                index: STRLEN_THUNK,
            } => {
                let ptr = machine.arg_far(0);
                let s = machine.read_cstr(ptr).expect("resolved").to_vec();

                // The two calls name different segments, so a host resolving by
                // a fixed base would get at most one of them right.
                let expected = match seen.len() {
                    0 => (stack_sel, STACK_STRING_AT),
                    _ => (code_sel, CODE_STRING_AT),
                };
                assert_eq!((ptr.selector, ptr.offset), expected, "which segment");

                let len = s.len() as u16;
                seen.push(s);
                exit = machine.resume(Ret::U16(len)).expect("resumed");
            }
            Exit::Returned { .. } => break,
            Exit::Call { index } => panic!("unexpected thunk {index}"),
            Exit::Fault { signo, cs, ip } => {
                panic!("module faulted with signal {signo} at {cs:#06x}:{ip:#06x}")
            }
            Exit::Timeout { cs, ip } => panic!("module timed out at {cs:#06x}:{ip:#06x}"),
            Exit::Interrupt { vector, cs, ip } => {
                panic!("module executed int {vector:#04x} at {cs:#06x}:{ip:#06x}")
            }
        }
    }

    assert_eq!(seen, vec![b"hello".to_vec(), b"worldly".to_vec()]);
    assert_eq!(machine.si(), 5 + 7, "module summed both lengths");
}

#[test]
fn a_far_pointer_naming_no_segment_is_refused() {
    let machine = Machine::new().expect("16-bit machine");

    // A selector with the LDT bit set but no descriptor behind it.
    let bogus = FarPtr {
        offset: 0,
        selector: 0xfff7,
    };
    assert!(machine.read_cstr(bogus).is_err(), "unknown LDT entry");

    // The null selector, which modules use as a null pointer.
    let null = FarPtr {
        offset: 0,
        selector: 0,
    };
    assert!(machine.read_cstr(null).is_err(), "null selector");

    // A GDT selector: real, but not one of ours.
    let gdt = FarPtr {
        offset: 0,
        selector: 0x33,
    };
    assert!(machine.read_cstr(gdt).is_err(), "not an LDT selector");
}

#[test]
fn a_far_pointer_past_the_end_of_its_segment_is_refused() {
    let mut machine = Machine::new().expect("16-bit machine");
    let stack = machine.stack_selector();

    // The last byte of the segment is addressable...
    let last = FarPtr {
        offset: 0xffff,
        selector: stack,
    };
    assert!(machine.resolve(last, 1).is_ok(), "final byte is in bounds");

    // ...but one more is not, and neither is a run that straddles the end.
    assert!(machine.resolve(last, 2).is_err(), "runs off the end");

    // An unterminated string must be refused rather than read off the end.
    machine
        .write(
            FarPtr {
                offset: 0xfffc,
                selector: stack,
            },
            b"abcd",
        )
        .expect("fills the last four bytes");
    let unterminated = FarPtr {
        offset: 0xfffc,
        selector: stack,
    };
    assert!(
        machine.read_cstr(unterminated).is_err(),
        "no NUL before the segment ends"
    );
}

#[test]
fn resolve_reads_from_the_segment_the_selector_names() {
    let mut machine = Machine::new().expect("16-bit machine");
    let stack = machine.stack_selector();
    let code = machine.code_selector();

    // The same offset in two different segments, holding different bytes. A
    // host that resolved by adding some fixed base -- or that quietly always
    // used one segment -- would return the same answer twice.
    const AT: u16 = 0x0400;
    machine
        .write(
            FarPtr {
                offset: AT,
                selector: stack,
            },
            b"in-stack",
        )
        .expect("stack write");
    machine
        .write(
            FarPtr {
                offset: AT,
                selector: code,
            },
            b"in-code!",
        )
        .expect("code write");

    let from_stack = machine
        .resolve(
            FarPtr {
                offset: AT,
                selector: stack,
            },
            8,
        )
        .expect("stack resolve");
    assert_eq!(from_stack, b"in-stack");

    let from_code = machine
        .resolve(
            FarPtr {
                offset: AT,
                selector: code,
            },
            8,
        )
        .expect("code resolve");
    assert_eq!(from_code, b"in-code!");
}
