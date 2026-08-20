//! The extension seam, exercised with a Rust fake rather than Lua: the trait
//! is Lua-agnostic by design, so its dispatch contract is testable without an
//! interpreter in the loop.

use std::io;
use std::sync::{Arc, Mutex};

use mbbs::Chan;
use mbbs::Outcome;
use mbbs::abi::Wg16;
use mbbs::extension::{CommandCtx, Extension, Verdict};
use mbbs::testing::{Fixture, module_bytes_exporting};

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
/// `poll_with_chan` turns into `entry = None` and then this exact note
/// (`lib.rs`'s `let Some(entry) = entry else { .. }` fallback). A `Handled`
/// verdict's `continue` skips `state_entry` entirely, so the note never
/// fires for that call.
///
/// This is deliberately not "the module ran" -- unwitnessable with a
/// code-less module -- it witnesses "dispatch resolution was reached", which
/// is exactly the contract this task proves: a `Handled` line must never get
/// that far, and a `Pass` line always must.
///
/// Filtered by `chan` and by entry index 1 rather than a bare note-count
/// diff: one `poll` call drains every status queued on the channel, and the
/// identical fallback also fires for entry index 2 (`INBLK`/`OUTMT`/`CYCLE`)
/// -- a length check alone cannot tell those apart from the `CRSTG` note
/// this test cares about. Verified empirically that with the single
/// `push_input` this fixture issues per poll, exactly one note of any kind
/// is added, and it is always this one.
fn crstg_no_entry_noted(f: &Fixture, since: usize, chan: Chan) -> bool {
    f.host.notes()[since..]
        .iter()
        .any(|n| n.contains(&format!("channel {chan} has no entry 1 registered")))
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
