//! `int` shims that answer `-1` must answer it at `A`'s own width under
//! `Wg32`, not the zero-extended `0x0000ffff` a `u16` sentinel becomes.
//!
//! This is the sibling coverage of `tests/wg32_textvar.rs`: the same trap
//! (`A::Int::from(0xffffu16)` is `65535`, not `-1`, under a 4-byte `int`) that
//! crashed MajorMUD-NT through `findtvar` was latent in every other shim that
//! spelled its `-1` the same way. `access` is reached at init on every board;
//! `unlink` is a plain Borland `int` returning `-1` for a file that is not
//! there. Both now use `A::int_from_u32(u32::MAX)`.
//!
//! Its own `Wg32` integration binary for the reason `tests/wg32_dfa_shims.rs`'
//! module doc comment gives.

use mbbs::abi::{Ret, Wg32};
use mbbs::shims::stream::unlink;
use mbbs::shims::system::access;
use mbbs::testing::Fixture;

/// The `int` value a shim answered, unwrapped from `Ret<Wg32>`.
fn int_of(ret: Ret<Wg32>) -> u32 {
    match ret {
        Ret::Int(v) => v,
        other => panic!("expected an int return, got {other:?}"),
    }
}

/// `access` on a path this host will not find answers `-1` at 32 bits: all
/// ones, so a module's `if (access(...) == -1)` recognises it.
#[test]
fn access_of_a_missing_file_answers_all_ones_at_32_bits() {
    let mut f = Fixture::<Wg32>::new_wg32();
    let path = f.text_wg32("NOSUCH.DAT");
    // mode 0 -- "does it exist?"
    let ret = f.invoke_wg32(access, &[path.0, 0]).expect("access");
    assert_eq!(
        int_of(ret),
        0xFFFF_FFFF,
        "access answers -1 at the ABI's own width, not 0x0000ffff"
    );
}

/// `unlink` of a file that is not there answers `-1` the same way.
#[test]
fn unlink_of_a_missing_file_answers_all_ones_at_32_bits() {
    let mut f = Fixture::<Wg32>::new_wg32();
    let path = f.text_wg32("NOSUCH.DAT");
    let ret = f.invoke_wg32(unlink, &[path.0]).expect("unlink");
    assert_eq!(
        int_of(ret),
        0xFFFF_FFFF,
        "unlink answers -1 at the ABI's own width, not 0x0000ffff"
    );
}
