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
    // The host's standard suite (`shims::txtvbl`) is already in the table;
    // a module's registration lands after it.
    let base = u32::from(f.host.textvars().len());

    let name = f.text_wg32("MUDCHARINFO");
    let varrou = f.text_wg32("routine stand-in");
    f.invoke_wg32(register_textvar, &[name.0, varrou.0])
        .expect("registered");

    let query = f.text_wg32("MUDCHARINFO");
    let ret = f.invoke_wg32(findtvar, &[query.0]).expect("findtvar");
    let Ret::Int(value) = ret else {
        panic!("findtvar returns an int, got {ret:?}");
    };
    assert_eq!(value, base, "a module's first variable follows the standard suite");
}

/// Byte-for-byte the same fixture `crates/mbbs/tests/wg32_abi.rs`'s
/// `minimal_with_one_section` builds -- duplicated per this crate family's
/// own convention rather than shared. Loaded only so `Host::run` has a
/// `Module` to be handed; nothing in it is executed.
fn minimal_with_one_section() -> Vec<u8> {
    const SIZE_OF_IMAGE: u32 = 0x0000_2000;
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes());
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());

    let opt = 0x98;
    v[opt + 16..opt + 20].copy_from_slice(&0x0000_1111u32.to_le_bytes());
    v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes());
    v[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
    v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes());
    v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

    let sec = opt + 0xe0;
    v.resize(sec + 40 + 0x200, 0);
    v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
    v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes());
    v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes());
    v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    v
}

/// The Rose 3.0NT's crash path, end to end at 32 bits: its real-time kick
/// does `txtvars[findtvar("SYSTEM_NAME")].varrou()` with no `-1` check --
/// correct on a real board, where `init__galtxv` registered the standard
/// suite before any module's init. This host used to register none, so the
/// lookup answered `-1`, the table was NULL, and the module faulted at
/// RVA `0x4c705` five times in sixty seconds. Now the lookup finds row 37
/// (the vendor's own order), the row's `varrou` is a host thunk, and
/// calling through it -- the module's own `call eax` -- answers `bbsttl`.
#[test]
fn system_name_is_registered_and_its_varrou_answers_the_board_title() {
    use mbbs::abi::Abi as _;
    use mbbs::testing::Fixture as F;
    use mbbs::Outcome;
    use mbbs_machine::m32::Flat32Ptr;
    use mbbs_machine::ptr::ModulePtr as _;

    let mut f = F::<Wg32>::new_wg32();
    let module = f.host.load(&mut f.machine, &minimal_with_one_section()).expect("inert module loads");

    let query = f.text_wg32("SYSTEM_NAME");
    let ret = f.invoke_wg32(findtvar, &[query.0]).expect("findtvar");
    let Ret::Int(index) = ret else {
        panic!("findtvar returns an int, got {ret:?}");
    };
    assert_eq!(index, 37, "SYSTEM_NAME is row 37, TXTVBL.C's own order");

    let row = f
        .host
        .textvars()
        .get_mem(mbbs::abi::Wg32::mem_ref(&f.machine), 37)
        .expect("readable")
        .expect("a row");
    assert_eq!(row.name, "SYSTEM_NAME");
    let varrou = row.varrou.expect("a registered routine");
    let thunk_base = f.machine.machine.thunk_addr(0);
    let thunk_end = f.machine.machine.thunk_addr(mbbs_machine::m32::MAX_THUNKS - 1);
    assert!(
        (thunk_base..=thunk_end).contains(&varrou.0),
        "varrou {varrou:?} must point into the thunk table [{thunk_base:#x}, {thunk_end:#x}]"
    );

    let outcome = f
        .host
        .run(&mut f.machine, &module, varrou, &[], None)
        .expect("the call goes through the thunk and back");
    let Outcome::Returned { lo, .. } = outcome else {
        panic!("tvar_sysnam answers through the vector, got {outcome:?}");
    };
    let bbsttl = f
        .host
        .globals()
        .pointer_mem(mbbs::abi::Wg32::mem_ref(&f.machine), "bbsttl")
        .expect("bbsttl is placed");
    assert_eq!(Flat32Ptr(lo), bbsttl, "the pointer itself, not a copy");
    let text = Flat32Ptr(lo)
        .read_cstr(mbbs::abi::Wg32::mem_ref(&f.machine))
        .expect("terminated");
    assert_eq!(text, b"Worldgroup");
}
