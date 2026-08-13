//! The mirror of `fault_16_after_32.rs`: construct a 16-bit machine FIRST,
//! then a 32-bit machine, and fault the **32-bit** module this time. The
//! sibling test proved the arbiter recovers a 16-bit fault with a 32-bit
//! machine already alive; it says nothing about the other direction, and a
//! claim predicate is exactly the kind of thing that can be right for one
//! ABI and backwards for the other (`cs == 0x23` and `cs & 0x4 != 0` are not
//! symmetric checks). This is the test that would catch that.
//!
//! Its own binary, and hence its own process: see `fault_16_alone.rs`'s
//! module comment for why sharing one with any sibling makes every result in
//! it meaningless.

use mbbs_machine::m32::{Exit, Mapping};

/// `mov eax, [0]` -- an ordinary, unprefixed dereference of address zero.
/// Byte-for-byte `crates/mbbs32/src/fault.rs`'s own `null_deref_code` fixture,
/// minus the `ljmp` back to a trampoline: `mbbs_machine::m32::Machine::call` already
/// builds a proper cdecl return frame on the module's own stack, and this
/// code is never meant to reach it.
fn null_deref() -> [u8; 5] {
    [0xa1, 0x00, 0x00, 0x00, 0x00] // mov eax, moffs32(0)
}

#[test]
fn a_32_bit_fault_is_recovered_after_mbbs16_has_also_armed() {
    // The clobber, constructed and held alive first -- the opposite
    // construction order from `fault_16_after_32.rs`, and the whole point of
    // this test: whichever ABI arms the process's signal disposition second
    // must not break recovery for the *other* one either.
    let _sixteen = mbbs_machine::m16::Machine::new().expect("a 16-bit machine");

    let mut mapping = Mapping::new(4096).expect("a low mapping for the fault code");
    let entry = mapping.base() as usize as u32;
    mapping.as_mut_slice()[..5].copy_from_slice(&null_deref());

    let mut machine = mbbs_machine::m32::Machine::new().expect("a 32-bit machine");

    match machine.call(entry, &[]).expect("recovered, not fatal") {
        Exit::Fault { signo, eip } => {
            assert_eq!(signo, libc::SIGSEGV);
            assert_eq!(eip, entry, "EIP did not name the faulting instruction");
        }
        other => panic!("expected a recovered fault, got {other:?}"),
    }
}
