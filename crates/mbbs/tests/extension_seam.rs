//! The extension seam, exercised with a Rust fake rather than Lua: the trait
//! is Lua-agnostic by design, so its dispatch contract is testable without an
//! interpreter in the loop.

use std::sync::{Arc, Mutex};

use mbbs::Chan;
use mbbs::abi::Wg16;
use mbbs::extension::{CommandCtx, Extension, Verdict};
use mbbs::testing::Fixture;

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
