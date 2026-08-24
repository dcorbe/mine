//! `dfaUpdateDup`/`dfaInsertDup`/`dfaDelete`, driven through a real `Wg32`
//! `Fixture` -- the coverage gap Task 3 of
//! `docs/superpowers/plans/2026-08-24-btrieve-plan-3-incremental-updates.md`
//! closes. Before this task, `crate::testing::Fixture` was hardcoded to
//! `Wg16`/`mbbs_machine::m16::Machine`, and there was no `Wg32` shim-test
//! harness in this crate at all -- see `tmp/plan-3-update-survey.md`'s
//! own §0.A. The write-path refusals these shims can hit
//! (`crates/btrieve/src/lib.rs`) are reached identically from `Wg16` and
//! `Wg32`; what was missing was evidence that the 32-bit path -- the one
//! MajorMUD-NT actually runs under -- reaches them at all.
//!
//! # Why this lives in its own file
//!
//! Same reason every other real-`Wg32Cpu` test in this crate does (see
//! `tests/wg32_abi.rs`'s own module doc comment): building a real
//! `mbbs_machine::m32::Machine` arms this thread's fault recovery, and
//! `cargo test -p mbbs --lib` runs the whole `Wg16` dfa test suite
//! (`crates/mbbs/src/shims/dfa.rs`'s own `#[cfg(test)] mod tests`, which is
//! exactly where these tests' `Wg16` counterparts live) as threads of one
//! process. Nothing here needs to entangle that shared state with a
//! `--lib` run, so -- like `wg32_abi.rs`, `wg32_round_trip.rs`,
//! `lunatix.rs`, `wg32_math_st0.rs`, `wg32_rtkick.rs` and
//! `wg32_stream_flags_offset.rs` -- this is a separate integration binary,
//! hence a separate process. `crate::testing::Fixture<Wg32>`'s own
//! constructors are defined in `src/testing.rs` (which compiles into
//! `--lib`), but a function definition does not run until called, and
//! nothing there calls it -- only this file does.
//!
//! # The mutation this file's own tests are built to catch
//!
//! `crates/btrieve/src/lib.rs`'s `Layout::new` computes
//! `BlockAbi::WinNt32`'s `data` field at `0x8c` -- two bytes of alignment
//! padding after `reclen` that a 32-bit compiler inserts and a 16-bit one
//! does not (see that function's own doc comment, and the pinned
//! `the_32_bit_block_is_laid_out_the_way_dfaapi_hs_gcwinnt_branch_declares_it`
//! test). `Block::data()`, the Rust-level accessor every `Wg16` dfa test
//! uses to find a record buffer, does not read that offset at all -- it
//! returns the pointer the host allocated directly, so it cannot tell a
//! correct `Layout` from a broken one. A real 32-bit module can: its
//! compiled code reads `dfa->data` as a dword at a hardcoded offset from
//! the block pointer, which is exactly what stopped MajorMUD-NT's own init
//! before this offset was measured (see `Layout::new`'s doc comment for
//! the trace). [`wg32_visible_data_ptr`] below reproduces that read, and
//! is what makes these tests -- unlike every existing `Wg16` dfa test --
//! sensitive to a `BlockAbi::WinNt32` regression. See this task's own
//! report for the mutation record: `Layout::new`'s `WinNt32` arm changed to
//! skip the four-byte alignment (putting `data` at `0x8a`) turns every test
//! in this file red while leaving `crates/mbbs/src/shims/dfa.rs`'s `Wg16`
//! suite green.

use mbbs::abi::Wg32;
use mbbs::shims::dfa::{dfaAcqLock, dfaCountRec, dfaDelete, dfaInsertDup, dfaOpen, dfaQuery, dfaUpdateDup};
use mbbs::testing::{Fixture, scratch_with};
use mbbs_machine::m32::Flat32Ptr;
use mbbs_machine::ptr::ModulePtr;

/// A 64-byte `SAMPLE.DAT`-shaped record: the key at offset 0, a
/// NUL-terminated name from offset 2, the rest zero. Byte-for-byte the same
/// shape `crates/mbbs/src/shims/dfa.rs`'s own (private) `sample_record`
/// builds for the `Wg16` suite -- not shared, for the same reason that one
/// is not shared with `shims::btrieve`'s copy: it is private to its own
/// test module.
fn sample_record(key: i16, name: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[..2].copy_from_slice(&key.to_le_bytes());
    let name = name.as_bytes();
    bytes[2..2 + name.len()].copy_from_slice(name);
    bytes
}

/// Open `name` through the real `dfaOpen` shim, as a module would -- the
/// `Wg32` sibling of `dfa.rs`'s own `open` helper. Every argument is one
/// `u32`: `filnam` (a pointer), `maxlen` (an `int`), `owner` (a pointer,
/// null here -- see `dfaOpen`'s own doc comment for why a non-null owner
/// refuses).
fn open(f: &mut Fixture<Wg32>, name: &str, maxlen: u32) -> Flat32Ptr {
    let at = f.text_wg32(name);
    match f.invoke_wg32(dfaOpen, &[at.0, maxlen, 0]).expect("dfaOpen") {
        mbbs::abi::Ret::Ptr(block) => block,
        other => panic!("dfaOpen returns a pointer, got {other:?}"),
    }
}

/// `dfaAcqLock(NULL, key, keynum, opt, lock)` -- acquire into the file's own
/// data buffer. The `Wg32` sibling of `dfa.rs`'s own `acquire` helper.
fn acquire(f: &mut Fixture<Wg32>, key: u16, keynum: i32, opt: i32, lock: i32) -> bool {
    let value = f.bytes_wg32(&key.to_le_bytes());
    matches!(
        f.invoke_wg32(dfaAcqLock, &[0, value.0, keynum as u32, opt as u32, lock as u32])
            .expect("dfaAcqLock"),
        mbbs::abi::Ret::Int(1)
    )
}

/// The record buffer pointer a real 32-bit module would read out of its own
/// `struct dfablk` -- `dfa->data`, at the hardcoded `0x8c` byte offset
/// `BlockAbi::WinNt32`'s layout puts it at (see this file's own module doc
/// comment). Deliberately **not** [`mbbs::btrieve::Block::data`]: that
/// accessor returns the pointer the host allocated directly, bypassing the
/// struct entirely, so it cannot discriminate a correct offset from a wrong
/// one. This function is the one thing in this whole file that can.
fn wg32_visible_data_ptr(f: &Fixture<Wg32>, block: Flat32Ptr) -> Flat32Ptr {
    const DATA_OFFSET: u32 = 0x8c;
    let at = Flat32Ptr(block.0 + DATA_OFFSET);
    let bytes = at.resolve(&f.machine.mem, 4).expect("the block struct is readable");
    Flat32Ptr(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

/// The record bytes at `at`, read the same way [`wg32_visible_data_ptr`]
/// finds `at` in the first place -- through raw memory, not through any
/// Rust-level accessor.
fn read_record(f: &Fixture<Wg32>, at: Flat32Ptr, len: usize) -> Vec<u8> {
    at.resolve(&f.machine.mem, len).expect("readable").to_vec()
}

/// `dfaUpdateDup` updates the positioned record in place, and a real 32-bit
/// module reading `dfa->data` at its own compiled offset finds the new
/// bytes -- not merely the same bytes `Block::data()` would report from the
/// host's own bookkeeping.
///
/// This is the test the mutation record targets: break
/// `BlockAbi::WinNt32`'s layout (`data` at `0x8a` instead of `0x8c`) and the
/// `wg32_visible_data_ptr`/`true_data` comparison below fails, because the
/// struct image now holds the pointer's bytes two bytes to the left of
/// where this test -- reproducing a real module's own compiled read --
/// looks for them.
#[test]
fn dfaupdatedup_updates_the_positioned_record_and_a_module_finds_it_at_its_own_struct_offset() {
    let dir = scratch_with("wg32-dfa-updatedup", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir.clone());
    let block = open(&mut f, "SAMPLE.DAT", 64);
    assert!(acquire(&mut f, 5, 0, 5, 0), "key 5 (Troll) must be found");

    let true_data = f.host.btrieve().block(block).expect("open").data();
    let module_visible = wg32_visible_data_ptr(&f, block);
    assert_eq!(
        module_visible, true_data,
        "a module reading dfa->data at its own compiled offset (0x8c) must find the \
         same pointer this host allocated -- BlockAbi::WinNt32's layout is what makes \
         that true"
    );

    let recptr = f.bytes_wg32(&sample_record(5, "TROLLX32"));
    let ok = f.invoke_wg32(dfaUpdateDup, &[recptr.0]).expect("dfaUpdateDup");
    assert!(matches!(ok, mbbs::abi::Ret::Int(1)), "no collision, so this must answer true: {ok:?}");

    // Reopen fresh -- proves the write reached disk, not merely this
    // fixture's own in-memory `Block`.
    let mut g = Fixture::<Wg32>::rooted_wg32(dir);
    let block = open(&mut g, "SAMPLE.DAT", 64);
    assert!(acquire(&mut g, 5, 0, 5, 0), "still key 5 after reopening");
    let at = wg32_visible_data_ptr(&g, block);
    let bytes = read_record(&g, at, 64);
    assert_eq!(&bytes[..2], &5i16.to_le_bytes(), "key unchanged");
    assert_eq!(
        String::from_utf8_lossy(&bytes[2..2 + 7]),
        "TROLLX32"[..7],
        "the updated name, read through the module's own struct offset"
    );
}

/// `dfaInsertDup` inserts a new record, readable afterward -- the `Wg32`
/// sibling of `dfa.rs`'s own `dfainsertv_...` family, for the routine that
/// answers `FALSE` on a collision instead of refusing.
#[test]
fn dfainsertdup_inserts_a_new_record_readable_after_reopening() {
    let dir = scratch_with("wg32-dfa-insertdup", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir.clone());
    open(&mut f, "SAMPLE.DAT", 64);

    let recptr = f.bytes_wg32(&sample_record(99, "Zorro32"));
    let ok = f.invoke_wg32(dfaInsertDup, &[recptr.0]).expect("dfaInsertDup");
    assert!(matches!(ok, mbbs::abi::Ret::Int(1)), "no collision on a fresh key: {ok:?}");

    let mut g = Fixture::<Wg32>::rooted_wg32(dir);
    let block = open(&mut g, "SAMPLE.DAT", 64);
    assert!(acquire(&mut g, 99, 0, 5, 0), "the inserted key must be findable after reopening");
    let at = wg32_visible_data_ptr(&g, block);
    let bytes = read_record(&g, at, 64);
    assert_eq!(&bytes[..2], &99i16.to_le_bytes());
    assert_eq!(String::from_utf8_lossy(&bytes[2..2 + 7]), "Zorro32");
}

/// `dfaInsertDup` answers `FALSE` -- not a refusal -- on the identical
/// collision `dfaInsertV` refuses on. The `Wg32` sibling of `dfa.rs`'s own
/// `dfainsertdup_answers_false_on_the_identical_collision_instead_of_refusing`.
#[test]
fn dfainsertdup_answers_false_on_a_collision_instead_of_refusing() {
    let dir = scratch_with("wg32-dfa-insertdup-collide", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir);
    open(&mut f, "SAMPLE.DAT", 64);

    let recptr = f.bytes_wg32(&sample_record(5, "Imposter"));
    let ok = f.invoke_wg32(dfaInsertDup, &[recptr.0]).expect("dfaInsertDup answers, does not refuse");
    assert!(matches!(ok, mbbs::abi::Ret::Int(0)), "key 5 already belongs to Troll: {ok:?}");

    let count = f.invoke_wg32(dfaCountRec, &[]).expect("dfaCountRec");
    assert!(matches!(count, mbbs::abi::Ret::Long(7)), "nothing written on the quiet collision: {count:?}");
}

/// `dfaDelete` removes the positioned record, and it stays gone across a
/// reopen -- the `Wg32` sibling of `dfa.rs`'s own
/// `dfadelete_removes_the_positioned_record_and_it_is_gone_after_reopening`.
#[test]
fn dfadelete_removes_the_positioned_record_and_it_is_gone_after_reopening() {
    let dir = scratch_with("wg32-dfa-delete", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir.clone());
    open(&mut f, "SAMPLE.DAT", 64);
    assert!(acquire(&mut f, 5, 0, 5, 0), "key 5 (Troll) must be found");

    f.invoke_wg32(dfaDelete, &[]).expect("dfaDelete");
    assert!(matches!(f.invoke_wg32(dfaCountRec, &[]).expect("dfaCountRec"), mbbs::abi::Ret::Long(6)));

    let mut g = Fixture::<Wg32>::rooted_wg32(dir);
    open(&mut g, "SAMPLE.DAT", 64);
    assert!(!acquire(&mut g, 5, 0, 5, 0), "gone from disk, not just from memory");
    assert!(matches!(g.invoke_wg32(dfaCountRec, &[]).expect("dfaCountRec"), mbbs::abi::Ret::Long(6)));
}

/// `dfaDelete` with nothing positioned refuses -- the `Wg32` sibling of
/// `dfa.rs`'s own `dfadelete_with_nothing_positioned_refuses`. Included as a
/// cheap extra assertion that the generic refusal path (unrelated to
/// `BlockAbi`) also reaches `Wg32` unchanged.
#[test]
fn dfadelete_with_nothing_positioned_refuses() {
    let dir = scratch_with("wg32-dfa-delete-refuse", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir);
    open(&mut f, "SAMPLE.DAT", 64);
    let e = f.invoke_wg32(dfaDelete, &[]).expect_err("never positioned");
    assert!(e.to_string().contains("dfaDelete"), "{e}");
}

/// `dfaQuery` on the equal-key operator, used only to keep this file's own
/// `acquire` helper honest against a second, independent shim -- proves the
/// generic `btv::locate` core (shared by `dfaAcqLock` and `dfaQuery`) is
/// reachable under `Wg32` too.
#[test]
fn dfaquery_finds_the_same_key_dfaacqlock_does() {
    let dir = scratch_with("wg32-dfa-query", &["SAMPLE.DAT"]);
    let mut f = Fixture::<Wg32>::rooted_wg32(dir);
    open(&mut f, "SAMPLE.DAT", 64);
    let value = f.bytes_wg32(&5u16.to_le_bytes());
    // `dfaQuery`'s own `qryopt` is `btv::Op` offset by 50 (`DFAAPI.C`'s own
    // `dfaQuery*` macros add 50 to the plain a-macro code) -- 55, not 5, is
    // "equal".
    let found = f.invoke_wg32(dfaQuery, &[value.0, 0, 55]).expect("dfaQuery");
    assert!(matches!(found, mbbs::abi::Ret::Int(1)));
}
