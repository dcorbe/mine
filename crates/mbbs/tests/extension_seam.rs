//! The extension seam, exercised with a Rust fake rather than Lua: the trait
//! is Lua-agnostic by design, so its dispatch contract is testable without an
//! interpreter in the loop.

use std::io;
use std::sync::{Arc, Mutex};

use mbbs::Chan;
use mbbs::Outcome;
use mbbs::abi::{Abi, ModuleMem, Wg16};
use mbbs::extension::{CommandCtx, Extension, Verdict};
use mbbs::testing::{Fixture, module_bytes_exporting, module_bytes_exporting_many};

/// Records every line it is shown and always passes.
#[derive(Default)]
struct Recorder {
    seen: Vec<String>,
}

impl Extension<Wg16> for Recorder {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        self.seen.push(ctx.line().to_owned());
        Verdict::Pass
    }
}

#[test]
fn a_host_with_no_extension_is_the_default() {
    let f = Fixture::new();
    assert!(f.host.extension().is_none());
}

#[test]
fn an_installed_extension_is_visible_to_the_host() {
    let mut f = Fixture::new();
    f.host.set_extension(Box::new(Recorder::default()));
    assert!(f.host.extension().is_some());
}

/// Swallows any line beginning with `!`, passes everything else. The log is
/// shared so the test can read it back after the host has taken ownership.
struct Swallow {
    seen: Arc<Mutex<Vec<String>>>,
}

impl Extension<Wg16> for Swallow {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        self.seen.lock().expect("lock").push(ctx.line().to_owned());
        if ctx.line().starts_with('!') {
            Verdict::Handled
        } else {
            Verdict::Pass
        }
    }
}

/// Whether dispatch resolution was reached for `chan`'s `CRSTG` entry (index
/// 1) among the notes recorded since `since`.
///
/// `Fixture::minimal_module` loads the smallest NE image the loader accepts
/// -- no code segment at all -- and is never registered with the module
/// shim, so channel 0's state names `Registration::AbsentBbs`
/// (`task-2-findings.md` traces this in full). Every dispatch that reaches
/// `Host::state_entry` for that state folds to `Dispatch::SessionOver`, which
/// `poll_with_chan` turns into `Serviced::SessionOver` and then this exact
/// note. A `Handled` verdict's `continue` skips `state_entry` entirely, so
/// the note never fires for that call.
///
/// This is deliberately not "the module ran" -- unwitnessable with a
/// code-less module -- it witnesses "dispatch resolution was reached", which
/// is exactly the contract this task proves: a `Handled` line must never get
/// that far, and a `Pass` line always must.
///
/// Filtered by `chan` rather than by a bare note-count diff: one `poll`
/// call drains every status queued on the channel, and the same note fires
/// for whichever status is being serviced. Verified empirically that with
/// the single `push_input` this fixture issues per poll, exactly one note
/// of any kind is added, and it is always this one.
///
/// The note no longer names an entry index -- a channel whose `state` names
/// the absent BBS never had an entry point to be missing, and saying it did
/// was the 2026-08-20 defect this wording replaced.
fn crstg_no_entry_noted(f: &Fixture, since: usize, chan: Chan) -> bool {
    f.host.notes()[since..]
        .iter()
        .any(|n| n.contains(&format!("channel {chan} is in no module")))
}

#[test]
fn a_passed_line_reaches_the_module() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    f.host.set_extension(Box::new(Swallow { seen: seen.clone() }));

    let before = f.host.notes().len();
    f.host.gsbl_mut().push_input(chan, b"look\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    assert_eq!(seen.lock().expect("lock").as_slice(), &["look".to_owned()]);
    assert!(
        crstg_no_entry_noted(&f, before, chan),
        "a passed line must still reach dispatch resolution -- see \
         crstg_no_entry_noted's doc comment for why this fixture cannot \
         witness anything stronger"
    );
}

#[test]
fn a_handled_line_never_reaches_the_module() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    f.host.set_extension(Box::new(Swallow { seen: seen.clone() }));

    let before = f.host.notes().len();
    f.host.gsbl_mut().push_input(chan, b"!mine\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    assert_eq!(seen.lock().expect("lock").as_slice(), &["!mine".to_owned()]);
    assert!(
        !crstg_no_entry_noted(&f, before, chan),
        "a handled line must cost NO dispatch resolution -- this is the \
         whole contract"
    );
}

#[test]
fn a_handled_line_leaves_the_channel_ready_for_the_next() {
    // The regression guard for spec open question 1: whatever `Handled` does
    // to channel state, the NEXT line must behave like an ordinary first line.
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    f.host.set_extension(Box::new(Swallow { seen: seen.clone() }));

    f.host.gsbl_mut().push_input(chan, b"!swallowed\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    let before = f.host.notes().len();
    f.host.gsbl_mut().push_input(chan, b"look\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    assert_eq!(
        seen.lock().expect("lock").as_slice(),
        &["!swallowed".to_owned(), "look".to_owned()],
        "the second line must arrive at the seam normally"
    );
    assert!(
        crstg_no_entry_noted(&f, before, chan),
        "the second line must reach dispatch resolution"
    );
}

struct Greeter;

impl Extension<Wg16> for Greeter {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        ctx.print(b"hello\r\n");
        Verdict::Handled
    }
}

#[test]
fn a_handler_can_write_to_the_channel() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    f.host.set_extension(Box::new(Greeter));

    f.host.gsbl_mut().push_input(chan, b"anything\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    let out = f.host.gsbl_mut().drain_output(chan);
    assert!(
        String::from_utf8_lossy(&out).contains("hello"),
        "handler output must reach the channel, got: {:?}",
        String::from_utf8_lossy(&out)
    );
}

/// Calls [`CommandCtx::call_export`] with a fixed name and no arguments when
/// dispatched, and records the result -- shared with the test through an
/// `Arc<Mutex<_>>` the same way [`Swallow`] shares its log, since
/// `Fixture::run_command` takes the extension by `&mut` and this test needs
/// to read the result back out afterward.
struct Caller {
    name: &'static str,
    result: Arc<Mutex<Option<io::Result<Outcome<Wg16>>>>>,
}

impl Extension<Wg16> for Caller {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        let result = ctx.call_export(self.name, &[]);
        *self.result.lock().expect("lock") = Some(result);
        Verdict::Handled
    }
}

#[test]
fn call_export_resolves_a_known_export_and_runs_it() {
    let mut f = Fixture::new();
    // `0xcb` is `retf`: the smallest real NE code segment that returns
    // cleanly to `Host::run`'s own caller -- see `module_bytes_exporting`'s
    // own doc comment for why a hand-built export, not `minimal_module`, is
    // what this test needs.
    let module = f.host.load(&mut f.machine, &module_bytes_exporting("SUMMONTEST", &[0xcb])).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = Caller { name: "SUMMONTEST", result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let outcome = result.lock().expect("lock").take().expect("command ran").expect("call_export ran");
    assert_eq!(
        outcome,
        Outcome::Returned { lo: 0, hi: 0 },
        "a resolved export that immediately retf's must come back Returned"
    );
}

#[test]
fn call_export_names_the_symbol_when_unresolvable() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = Caller { name: "NOSUCHTHING", result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let err = result.lock().expect("lock").take().expect("command ran").expect_err("must refuse an unknown export");
    assert!(err.to_string().contains("NOSUCHTHING"), "got: {err}");
}

/// One `write_scratch` result, as [`ScratchTwice`] and [`ScratchTooBig`]
/// share it -- named so clippy's `type_complexity` lint has nothing to say
/// about either struct's own `result` field.
type ScratchResult = io::Result<mbbs_machine::m16::FarPtr>;

/// Calls `write_scratch` twice with small, distinct payloads when
/// dispatched, and records both results -- proving reuse (the same pointer
/// both times) is what `CommandCtx::write_scratch`'s persistent buffer
/// promises, not a fresh `alloc_region`, and therefore a fresh LDT segment,
/// per call. See `task-6-report.md`'s fix-report addendum for why this
/// matters: `summon` is player-retypable, and `ModuleMem::alloc_region`'s
/// `Wg16` backing is a real, finite, shared descriptor other subsystems
/// (`Heap::reserve`, `Host::fsd_scratch`) also draw from.
struct ScratchTwice {
    result: Arc<Mutex<Option<(ScratchResult, ScratchResult)>>>,
}

impl Extension<Wg16> for ScratchTwice {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        let first = ctx.write_scratch(b"one");
        let second = ctx.write_scratch(b"two");
        *self.result.lock().expect("lock") = Some((first, second));
        Verdict::Handled
    }
}

#[test]
fn write_scratch_reuses_the_same_buffer_across_calls() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = ScratchTwice { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let (first, second) = result.lock().expect("lock").take().expect("command ran");
    let first = first.expect("first write_scratch call must succeed");
    let second = second.expect("second write_scratch call must succeed");
    assert_eq!(
        first, second,
        "a second call must reuse the first call's buffer, not allocate a fresh LDT segment"
    );
}

/// Calls `write_scratch` with a payload larger than the seam's own scratch
/// buffer -- refused, not silently truncated and not served by falling back
/// to a fresh, unbounded allocation (which would reopen the exhaustion the
/// fixed-size buffer exists to close).
struct ScratchTooBig {
    result: Arc<Mutex<Option<ScratchResult>>>,
}

impl Extension<Wg16> for ScratchTooBig {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        // Comfortably past extension.rs's own `COMMAND_SCRATCH_BYTES` (128,
        // at the time of writing) without hard-coding that private constant
        // in a test outside its crate module.
        *self.result.lock().expect("lock") = Some(ctx.write_scratch(&vec![0u8; 4096]));
        Verdict::Handled
    }
}

#[test]
fn write_scratch_refuses_a_payload_too_big_for_the_scratch_buffer() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = ScratchTooBig { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let err = result.lock().expect("lock").take().expect("command ran").expect_err("must refuse an oversized payload");
    assert!(err.to_string().contains("4096"), "got: {err}");
}

/// Writes through `write_at` at a pointer this test obtained from
/// `write_scratch` (the one way to get a real, resolvable pointer without
/// building a whole module), then reads it back through `read_at` -- proving
/// both work against an arbitrary already-known pointer, not only the
/// persistent scratch buffer's own address. `CommandCtx::player_record`
/// (Task 7) needs exactly this: a pointer *into the module*, not one this
/// seam allocated.
struct WriteThenReadAt {
    result: Arc<Mutex<Option<io::Result<Vec<u8>>>>>,
}

impl Extension<Wg16> for WriteThenReadAt {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        let outcome = (|| {
            let ptr = ctx.write_scratch(b"....")?;
            ctx.write_at(ptr, &[1, 2, 3, 4])?;
            ctx.read_at(ptr, 4)
        })();
        *self.result.lock().expect("lock") = Some(outcome);
        Verdict::Handled
    }
}

#[test]
fn write_at_then_read_at_round_trips_through_an_explicit_pointer() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = WriteThenReadAt { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let bytes = result.lock().expect("lock").take().expect("command ran").expect("write_at/read_at must both succeed");
    assert_eq!(bytes, vec![1, 2, 3, 4]);
}

/// Calls [`CommandCtx::player_record`] when dispatched and records the
/// result.
struct PlayerRecordCaller {
    result: Arc<Mutex<Option<io::Result<mbbs_machine::m16::FarPtr>>>>,
}

impl Extension<Wg16> for PlayerRecordCaller {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        *self.result.lock().expect("lock") = Some(ctx.player_record());
        Verdict::Handled
    }
}

#[test]
fn player_record_names_the_symbol_when_get_player_is_unresolvable() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = PlayerRecordCaller { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let err = result
        .lock()
        .expect("lock")
        .take()
        .expect("command ran")
        .expect_err("must refuse an unresolvable _GET_PLAYER");
    assert!(err.to_string().contains("_GET_PLAYER"), "got: {err}");
}

#[test]
fn player_record_returns_the_far_pointer_get_player_answers_with() {
    let mut f = Fixture::new();
    // AX=0x1234, DX=0x5678, retf -- deliberately ASYMMETRIC, so a decode
    // that swapped offset and selector would fail this assertion. A prior
    // review of Task 7 (AX=1,DX=1 here, AX=0,DX=0 for the null case below)
    // pointed out that symmetric register values cannot distinguish a lo/hi
    // swap bug: `FarPtr { offset: 1, selector: 1 }` looks identical either
    // way. `player_record` is exactly the primitive Task 8's four
    // experience writes depend on, so a swap here would silently corrupt
    // whatever byte a wrong address happened to name.
    // Real backing memory, so the loaded-flag byte at `+0x1e` can exist at all:
    // `get_player` now reads it, and an unmapped literal address has nothing to
    // read. Offset and selector still differ (the allocator hands back selector
    // != offset), so a decode that swapped them still fails this assertion.
    let record_ptr = Wg16::mem(&mut f.machine).alloc_region(2000).expect("alloc real backing memory");
    Wg16::mem(&mut f.machine).write(Wg16::ptr_offset(record_ptr, 0x1e), &[1]).expect("mark loaded");
    let code = get_player_code(record_ptr);
    let module = f.host.load(&mut f.machine, &module_bytes_exporting("_GET_PLAYER", &code)).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = PlayerRecordCaller { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let ptr = result.lock().expect("lock").take().expect("command ran").expect("player_record must resolve");
    assert_eq!(ptr, record_ptr, "player_record must hand back exactly the pointer _GET_PLAYER answered with");
}

#[test]
fn player_record_is_an_error_when_get_player_returns_null() {
    let mut f = Fixture::new();
    // AX=0, DX=0, retf -- the far-pointer encoding of "player not loaded."
    let code = [0xb8, 0x00, 0x00, 0xba, 0x00, 0x00, 0xcb];
    let module = f.host.load(&mut f.machine, &module_bytes_exporting("_GET_PLAYER", &code)).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = PlayerRecordCaller { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let err = result
        .lock()
        .expect("lock")
        .take()
        .expect("command ran")
        .expect_err("a null _GET_PLAYER return must be an error, never a silent no-op");
    assert!(err.to_string().contains("_GET_PLAYER"), "got: {err}");
}

/// Machine code for a `_GET_PLAYER`-shaped export that returns a specific,
/// real far pointer -- `mov ax, offset` / `mov dx, selector` / `retf`, the
/// same three-instruction shape [`player_record_returns_the_far_pointer_get_player_answers_with`]
/// already uses, parameterised on the pointer so [`setting_experience_writes_both_copies`]
/// can point it at real backing memory (obtained independently, via
/// [`ModuleMem::alloc_region`], before the module is even built) rather
/// than a fabricated value nothing ever reads through.
fn get_player_code(ptr: mbbs_machine::m16::FarPtr) -> Vec<u8> {
    let mut code = vec![0xb8];
    code.extend_from_slice(&ptr.offset.to_le_bytes());
    code.push(0xba);
    code.extend_from_slice(&ptr.selector.to_le_bytes());
    code.push(0xcb);
    code
}

/// [`SetExperienceCaller::result`]'s shape: whether `set_experience` itself
/// succeeded, and -- only when it did -- the six words read back afterward,
/// in the order `[0x3c, 0x3e, 0x46f, 0x471, 0x46b, 0x46d]`. Widened from
/// four to six words when the review of this task's first draft found that
/// `_RESTRUCTURE_EXPERIENCE` writes a THIRD field (`0x46b`/`0x46d`, the
/// billions count -- see `set_experience`'s own doc comment) that the
/// original draft never wrote and this reader never read. Named so
/// clippy's `type_complexity` lint (and a human reader) sees one name
/// instead of a nested `Option<(Result<...>, Option<...>)>` at the use
/// site.
type SetExperienceResult = (io::Result<()>, Option<[u16; 6]>);

/// Calls [`CommandCtx::set_experience`], then reads all six words the
/// module's own three-field invariant is supposed to leave behind --
/// `0x3c`/`0x3e` (the raw total), `0x46f`/`0x471` (the total modulo one
/// billion), `0x46b`/`0x46d` (the billions count) -- straight out of the
/// same record `_GET_PLAYER` hands back, through a second, independent
/// `player_record()` this struct's own `command` makes itself. Never
/// trusts `set_experience`'s own `Ok(())` alone -- that only proves it ran
/// to completion, not that it wrote what it claims.
struct SetExperienceCaller {
    exp: u32,
    result: Arc<Mutex<Option<SetExperienceResult>>>,
}

impl Extension<Wg16> for SetExperienceCaller {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        let outcome = ctx.set_experience(self.exp);
        let words = if outcome.is_ok() {
            let record = ctx.player_record().expect("player_record must resolve a second time");
            let word = |ctx: &mut CommandCtx<'_, Wg16>, delta: u16| -> u16 {
                let bytes = ctx.read_at(Wg16::ptr_offset(record, delta), 2).expect("read_at must resolve");
                u16::from_le_bytes([bytes[0], bytes[1]])
            };
            Some([
                word(ctx, 0x3c),
                word(ctx, 0x3e),
                word(ctx, 0x46f),
                word(ctx, 0x471),
                word(ctx, 0x46b),
                word(ctx, 0x46d),
            ])
        } else {
            None
        };
        *self.result.lock().expect("lock") = Some((outcome, words));
        Verdict::Handled
    }
}

/// Experience is stored TWICE in the character record, at `0x3c`/`0x3e` and
/// `0x46f`/`0x471` (both 32-bit, low word first -- see
/// `task-8-findings.md`'s reading of `_RESTRUCTURE_EXPERIENCE`). Writing one
/// pair and not the other leaves the character internally inconsistent:
/// this asserts BOTH read back as the new value, against a genuine
/// `_GET_PLAYER` returning real, resolvable backing memory (not a fixture
/// stub) and a genuine `_SAVE_PLAYER` call afterward. `exp` here is well
/// under one billion, so the third field (`0x46b`/`0x46d`, the billions
/// count) is expected to read back zero either way --
/// [`setting_experience_past_a_billion_writes_the_reduced_remainder_and_billions_count`]
/// is the test that actually exercises a nonzero billions count.
///
/// This is the test the plan's own mutation step exists to prove has real
/// teeth: deleting either pair of writes from `set_experience` must fail
/// this exact assertion (all three mutations this task now carries are run
/// and quoted in `task-8-report.md`, not merely described).
#[test]
fn setting_experience_writes_both_copies() {
    let mut f = Fixture::new();
    // Real backing memory, allocated independently of the module itself --
    // 2000 bytes is comfortably past 0x471+2=0x473, the same margin
    // `task-8-findings.md` measures against the real 1998-byte record.
    let record_ptr = Wg16::mem(&mut f.machine).alloc_region(2000).expect("alloc real backing memory");
    // Mark the slot LOADED. `_GET_PLAYER` is `ptrtile` -- an array index that
    // answers for every in-range channel -- so a non-null pointer alone never
    // meant "a character is here". The module gates on a flag byte at `+0x1e`
    // (`_ADDON_ADJUST_USER_WEALTH`, `WCCMMUD_named.c:73421`) and so do we; a
    // record of zeroes is an EMPTY slot, which is what this fixture was before.
    Wg16::mem(&mut f.machine).write(Wg16::ptr_offset(record_ptr, 0x1e), &[1]).expect("mark loaded");
    let get_player = get_player_code(record_ptr);
    let save_player = [0xcbu8]; // retf -- a no-op stub; set_experience discards its return.
    let module_bytes = module_bytes_exporting_many(&[("_GET_PLAYER", &get_player), ("_SAVE_PLAYER", &save_player)]);
    let module = f.host.load(&mut f.machine, &module_bytes).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = SetExperienceCaller { exp: 0x1234_5678, result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let (outcome, words) = result.lock().expect("lock").take().expect("command ran");
    outcome.expect("set_experience must succeed against a real _GET_PLAYER/_SAVE_PLAYER");
    let words = words.expect("must have read back all six words");
    assert_eq!(
        words,
        [0x5678, 0x1234, 0x5678, 0x1234, 0, 0],
        "both the 0x3c/0x3e copy and the 0x46f/0x471 copy must read back the new value, and \
         the billions count (0x3c/0x3e was under one billion) must read back zero; got {words:x?}"
    );
}

/// The reduction the review of this task's first draft found missing: past
/// one billion, `0x46f`/`0x471` must hold the REMAINDER (not the raw
/// total) and `0x46b`/`0x46d` must hold the billions count --
/// `_RESTRUCTURE_EXPERIENCE`'s own invariant
/// (`re/exports/WCCMMUD_named.c:72415-72442`; see `set_experience`'s own
/// doc comment for the full reading).
///
/// `exp = 3_141_592_653` is deliberately chosen so all three stored fields
/// are distinctive and none is zero or equal to another: `0x3c`/`0x3e` is
/// the full value, `0x46f`/`0x471` is the remainder `141_592_653`
/// (`0x0870884d`), `0x46b`/`0x46d` is the billions count `3`. A swap
/// between any two fields, or a dropped low/high half of any one, changes
/// the read-back in a way this exact assertion catches -- unlike a round
/// value (all zero high words, or a billions count of 0 or 1) which could
/// hide several of those bugs at once.
#[test]
fn setting_experience_past_a_billion_writes_the_reduced_remainder_and_billions_count() {
    let mut f = Fixture::new();
    let record_ptr = Wg16::mem(&mut f.machine).alloc_region(2000).expect("alloc real backing memory");
    // Mark the slot LOADED. `_GET_PLAYER` is `ptrtile` -- an array index that
    // answers for every in-range channel -- so a non-null pointer alone never
    // meant "a character is here". The module gates on a flag byte at `+0x1e`
    // (`_ADDON_ADJUST_USER_WEALTH`, `WCCMMUD_named.c:73421`) and so do we; a
    // record of zeroes is an EMPTY slot, which is what this fixture was before.
    Wg16::mem(&mut f.machine).write(Wg16::ptr_offset(record_ptr, 0x1e), &[1]).expect("mark loaded");
    let get_player = get_player_code(record_ptr);
    let save_player = [0xcbu8];
    let module_bytes = module_bytes_exporting_many(&[("_GET_PLAYER", &get_player), ("_SAVE_PLAYER", &save_player)]);
    let module = f.host.load(&mut f.machine, &module_bytes).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = SetExperienceCaller { exp: 3_141_592_653, result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let (outcome, words) = result.lock().expect("lock").take().expect("command ran");
    outcome.expect("set_experience must succeed against a real _GET_PLAYER/_SAVE_PLAYER");
    let words = words.expect("must have read back all six words");
    assert_eq!(
        words,
        [0xe64d, 0xbb40, 0x884d, 0x0870, 3, 0],
        "0x3c/0x3e must hold the raw total, 0x46f/0x471 must hold the total modulo one \
         billion, and 0x46b/0x46d must hold the billions count; got {words:x?}"
    );
}

/// A line with arguments arrives at the seam WHOLE, not cut at its first word.
///
/// The regression guard for a bug a live board found on 2026-08-20 and that
/// every test until now missed. `Host::get_input_mem` writes the line into the
/// `input` global and then runs `parsin`, which tokenises IN PLACE by
/// overwriting each separator with a NUL. The seam used to read the line back
/// out of `input` with a C-string read, which therefore stopped at the first
/// NUL and handed every handler the first word alone -- `summon` out of
/// `summon rusty sword`, with the arguments silently gone.
///
/// Nothing caught it because every other test here drives a SINGLE-WORD line
/// (`look`, `!mine`, `anything`), which has no separator for `parsin` to
/// overwrite, and the Lua-side tests build a `CommandCtx` directly through
/// `Fixture::run_command`, which never touches the `input` global at all.
/// A test of this specifically has to go through `poll`, with a space in it.
#[test]
fn a_line_with_arguments_reaches_the_seam_whole() {
    let mut f = Fixture::new();
    let module = f.minimal_module();
    let chan = f.console();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    f.host.set_extension(Box::new(Swallow { seen: seen.clone() }));

    f.host.gsbl_mut().push_input(chan, b"summon a rusty sword\r");
    f.host.poll(&mut f.machine, &module).expect("polled");

    assert_eq!(
        seen.lock().expect("lock").as_slice(),
        &["summon a rusty sword".to_owned()],
        "the seam must see the whole line; truncation at the first word is \
         `parsin`'s in-place tokenisation leaking through"
    );
}

/// An empty slot is "no character loaded", even though `_GET_PLAYER` answers
/// with a perfectly good pointer to it.
///
/// The regression guard for a bug a live board found on 2026-08-20. Typing
/// `exp 5000` at the "Enter your user ID:" prompt answered "done." and wrote
/// four words into an unloaded slot, because the only guard was a null-pointer
/// check and `_GET_PLAYER` never returns null for an in-range channel: it is
/// `ptrtile` into the module's own `alctile(nterms, 1998)` table
/// (`WCCMMUD_named.c:29982`), an array index that answers for every channel
/// whether or not anybody is playing on it. So the guard could not fire.
///
/// The module's own gate is a flag byte at record `+0x1e` --
/// `_ADDON_ADJUST_USER_WEALTH` (`WCCMMUD_named.c:73421`) tests it before it
/// will touch the record or save it -- and that is what is checked now.
#[test]
fn an_unloaded_slot_is_no_character_even_though_get_player_answers_with_a_pointer() {
    let mut f = Fixture::new();
    // Real backing memory, left entirely zeroed: a slot nobody is playing on.
    // Deliberately NOT marking `+0x1e`, which is the whole point.
    let record_ptr = Wg16::mem(&mut f.machine).alloc_region(2000).expect("alloc real backing memory");
    let code = get_player_code(record_ptr);
    let module = f.host.load(&mut f.machine, &module_bytes_exporting("_GET_PLAYER", &code)).expect("loads");
    let chan = f.console();
    let result = Arc::new(Mutex::new(None));
    let mut ext = PlayerRecordCaller { result: result.clone() };

    f.run_command(&mut ext, chan, "anything", &module);

    let err = result
        .lock()
        .expect("lock")
        .take()
        .expect("command ran")
        .expect_err("an unloaded slot must NOT be reported as a usable record");
    assert!(
        err.to_string().contains("no player loaded"),
        "the error must say the slot is empty rather than blaming the pointer; got: {err}"
    );
}
