//! `bgnedt` under `Wg32`: the pointer global holds something callable, and
//! calling it reaches the editor rather than address zero.
//!
//! MajorMUD-NT's sysop menu (`B - Edit the sysop bulletin file`,
//! `E - Edit the wccmmud.ini file`) does `mov eax,[_bgnedt]; call [eax]` --
//! `bgnedt` is `FSD.H:54`'s `int (*bgnedt)(...)`, a function-pointer global
//! the real host's editor fills in at boot. This host served it as zeroed
//! memory, so both options faulted with `signal 11 at 0x00000000`. The fix
//! is a host-reserved thunk written into the global (`Host::vectors`) and a
//! port of the vendor's line editor behind it (`shims::editor`).
//!
//! This lives in its own `Wg32` integration binary for the reason every
//! real-`Wg32Cpu` test in this crate does; see `tests/wg32_dfa_shims.rs`'s
//! module doc comment. The `Wg16` side of the same guarantee is
//! `wg16_bgnedt_global_holds_the_reserved_vector`, inline in
//! `src/shims/editor.rs`, and the editor's behaviour is tested there too --
//! it is generic, and only the vector needed proving at 32 bits.

use mbbs::abi::{Abi, Arg, Wg32};
use mbbs::testing::Fixture;
use mbbs::users::Connection;
use mbbs::Outcome;
use mbbs_machine::m32::Flat32Ptr;
use mbbs_machine::ptr::ModulePtr as _;

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

#[test]
fn bgnedt_global_is_a_host_thunk_and_calling_it_starts_the_editor() {
    let mut f = Fixture::<Wg32>::new_wg32();
    let module = f.host.load(&mut f.machine, &minimal_with_one_section()).expect("inert module loads");

    // The global names one of this machine's own thunks -- not zero, not
    // module memory.
    let vector = f
        .host
        .globals()
        .pointer_mem(Wg32::mem_ref(&f.machine), "bgnedt")
        .expect("bgnedt is a placed global");
    assert_ne!(vector, Flat32Ptr(0), "bgnedt must not be a null call");
    let thunk_base = f.machine.machine.thunk_addr(0);
    let thunk_end = f.machine.machine.thunk_addr(mbbs_machine::m32::MAX_THUNKS - 1);
    assert!(
        (thunk_base..=thunk_end).contains(&vector.0),
        "bgnedt {vector:?} must point into the thunk table [{thunk_base:#x}, {thunk_end:#x}]"
    );

    // A channel to edit on, then the call MajorMUD's sysop menu makes:
    // `bgnedt(siz, buf, tsiz, topic, whndun, flags)`.
    let chan = f.host.users().terms().all().next().expect("a channel");
    f.host
        .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
        .expect("connected");
    let before = f.host.users().state_mem(Wg32::mem_ref(&f.machine), chan).expect("state");
    let buf = f.bytes_wg32(&{
        let mut b = b"\rline one\rline two".to_vec();
        b.resize(0x781, 0);
        b
    });
    let _ = f.host.gsbl_mut().drain_output(chan);

    let outcome = f
        .host
        .run(
            &mut f.machine,
            &module,
            vector,
            &[
                Arg::Int(0x781),
                Arg::Ptr(buf),
                Arg::Int(0x28),
                Arg::Ptr(Flat32Ptr(0)),
                Arg::Ptr(Flat32Ptr(0)),
                Arg::Int(0),
            ],
            Some(chan),
        )
        .expect("the call goes through the thunk and back");
    assert!(
        matches!(outcome, Outcome::Returned { lo: 1, .. }),
        "fse_bgnedt answers CONEDT through the vector, got {outcome:?}"
    );

    let after = f.host.users().state_mem(Wg32::mem_ref(&f.machine), chan).expect("state");
    assert_ne!(after, before, "the channel's state is the editor's now");
    let shown = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
    assert!(shown.contains("EDITOR COMMANDS:"), "the editor menu was shown: {shown:?}");
    assert!(shown.contains("Choose one of the commands above: "), "{shown:?}");

    // And the buffer is the module's own, untouched by the normalising pass
    // when it is already in the editor's form.
    let text = buf.resolve(Wg32::mem_ref(&f.machine), 18).expect("buffer").to_vec();
    assert_eq!(text, b"\rline one\rline two");
}
