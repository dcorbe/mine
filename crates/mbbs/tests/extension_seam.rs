//! The extension seam, exercised with a Rust fake rather than Lua: the trait
//! is Lua-agnostic by design, so its dispatch contract is testable without an
//! interpreter in the loop.

use mbbs::extension::{CommandCtx, Extension, Verdict};
use mbbs::testing::Fixture;
use mbbs::abi::Wg16;

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
