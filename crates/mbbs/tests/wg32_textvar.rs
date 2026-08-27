//! `findtvar` under `Wg32`, where its not-found sentinel is a real bug's
//! only witness.
//!
//! MajorMUD-NT crashed with `SIGSEGV at 0x00000000` the moment a player left
//! the Realm: the exit sequence expands the `PAUSE_FU`/`FU_PAUSE` text
//! variables, and the module's expander is
//!
//! ```text
//! call findtvar(name)
//! cmp  eax, 0xffffffff     ; "not found?"
//! je   done                ; -> return, calling nothing
//! ...
//! mov  eax, [txtvars + eax*20 + 0x10]   ; varrou
//! call eax                              ; no null check
//! ```
//!
//! `findtvar`'s not-found path used to answer `A::Int::from(NO)`, which
//! zero-extends the `u16` `0xffff` to `0x0000ffff` under a 4-byte `int`. That
//! is `65535`, not `-1`, so `cmp eax, 0xffffffff` missed, the module indexed
//! `txtvars[65535*20 + 0x10]` far past the table, read a null `varrou`, and
//! called it. `A::int_from_u32(u32::MAX)` answers all-ones at the ABI's own
//! width instead -- `-1` under both `Wg16` and `Wg32` -- so the guard fires.
//!
//! This lives in its own `Wg32` integration binary for the reason every
//! real-`Wg32Cpu` test in this crate does; see `tests/wg32_dfa_shims.rs`'s
//! module doc comment. The `Wg16` counterpart -- where the old code was
//! already correct, which is why the bug hid -- is
//! `findtvar_of_an_unregistered_name_answers_negative_one`, inline in
//! `src/shims/mudtext.rs`.

use mbbs::abi::{Ret, Wg32};
use mbbs::shims::mudtext::findtvar;
use mbbs::shims::system::register_textvar;
use mbbs::testing::Fixture;

/// A not-found lookup answers `-1` at the full 32-bit width, so the module's
/// `cmp eax, 0xffffffff` guard recognises it. `0x0000ffff` -- the pre-fix
/// answer -- would slip past that guard and call a null `varrou`.
#[test]
fn findtvar_of_an_unregistered_name_answers_all_ones_at_32_bits() {
    let mut f = Fixture::<Wg32>::new_wg32();

    // One registered variable, so the table exists and the search actually
    // walks it rather than short-circuiting on an empty table.
    let name = f.text_wg32("MUDCHARINFO");
    let varrou = f.text_wg32("routine stand-in"); // any non-null pointer
    f.invoke_wg32(register_textvar, &[name.0, varrou.0])
        .expect("registered");

    let query = f.text_wg32("NOSUCHVAR");
    let ret = f.invoke_wg32(findtvar, &[query.0]).expect("findtvar");
    let Ret::Int(value) = ret else {
        panic!("findtvar returns an int, got {ret:?}");
    };
    assert_eq!(
        value, 0xFFFF_FFFF,
        "not-found must be -1 at 32 bits, not the zero-extended 0x0000ffff \
         that let MajorMUD-NT call a null varrou on Realm exit"
    );
}

/// The found path is unchanged: a registered name still answers its index,
/// so the fix to the sentinel did not disturb a real match.
#[test]
fn findtvar_still_finds_a_registered_name_at_32_bits() {
    let mut f = Fixture::<Wg32>::new_wg32();

    let name = f.text_wg32("MUDCHARINFO");
    let varrou = f.text_wg32("routine stand-in");
    f.invoke_wg32(register_textvar, &[name.0, varrou.0])
        .expect("registered");

    let query = f.text_wg32("MUDCHARINFO");
    let ret = f.invoke_wg32(findtvar, &[query.0]).expect("findtvar");
    let Ret::Int(value) = ret else {
        panic!("findtvar returns an int, got {ret:?}");
    };
    assert_eq!(value, 0, "the first registered variable is index zero");
}
