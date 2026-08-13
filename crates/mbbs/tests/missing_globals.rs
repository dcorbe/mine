//! `Host::load`'s refusal path: a module that addresses a host global the
//! host cannot honestly place must come back `Err(LoadError::Globals(_))`,
//! naming the symbol.
//!
//! This is not exercised anywhere else. `wccmmud.rs`'s `LoadError::Globals`
//! arm is a `panic!` that only fires if the real `WCCMMUD.DLL` has a miss --
//! it has none today, so that arm never runs, and the whole refusal
//! mechanism (`Resolver::resolve` in `crates/mbbs/src/lib.rs`) had no test
//! that could ever go red. See `docs/plans/2026-08-12-abi-border-
//! implementation.md` Task 9's own mutation note.

use mbbs::testing::{Fixture, module_bytes_importing};
use mbbs::{LoadError, Why};

/// A module addressing a symbol no shim table serves at all: `shims::entry`
/// answers [`mbbs::shims::Entry::Unimplemented`] (there is no `TESTHOST` DLL
/// anywhere in this crate's tables), which `Resolver::resolve` must turn
/// into `Why::NotPlaced`.
#[test]
fn refused_when_the_host_has_no_such_global() {
    let mut f = Fixture::new();
    let file = module_bytes_importing("TESTHOST", "nosuchglobal", 0);

    match f.host.load(&mut f.machine, &file) {
        Ok(_) => panic!("a module addressing an unplaced global must be refused"),
        Err(LoadError::Globals(missing)) => {
            assert_eq!(missing.len(), 1, "exactly the one symbol was addressed");
            let m = &missing[0];
            assert_eq!(m.module, "TESTHOST");
            assert_eq!(m.symbol, "nosuchglobal");
            assert_eq!(m.why, Why::NotPlaced);
        }
        Err(e) => panic!("wrong error: {e}"),
    }
}

/// A module reaching 100 bytes into `MAJORBBS.usrnum` -- a real, placed
/// global, but a 2-byte `int` (`crates/mbbs/src/globals.rs`'s `INT`). The
/// host places it honestly; the module's own fixup is what is dishonest,
/// and `Resolver::resolve` must catch that too, as `Why::TooSmall`.
///
/// This is the arm with real arithmetic in it (`reach.max >= size`), so it
/// gets its own test rather than riding along on the `NotPlaced` one.
#[test]
fn refused_when_a_datum_is_addressed_past_its_own_size() {
    let mut f = Fixture::new();
    let file = module_bytes_importing("MAJORBBS", "usrnum", 100);

    match f.host.load(&mut f.machine, &file) {
        Ok(_) => panic!("a module reaching past a global's placed size must be refused"),
        Err(LoadError::Globals(missing)) => {
            assert_eq!(missing.len(), 1, "exactly the one symbol was addressed");
            let m = &missing[0];
            assert_eq!(m.module, "MAJORBBS");
            assert_eq!(m.symbol, "usrnum");
            assert_eq!(m.why, Why::TooSmall { addend: 100, size: 2 });
        }
        Err(e) => panic!("wrong error: {e}"),
    }
}

/// The same fixture that trips [`refused_when_the_host_has_no_such_global`],
/// with an addend so small it stays inside a real global's placed size --
/// proof the builder itself is not what refuses the load: an honestly
/// addressed datum must still load clean. `usrnum` is 2 bytes; addend `1`
/// stays inside it (`reach.max=1 < size=2`).
#[test]
fn not_refused_when_a_datum_is_addressed_within_its_own_size() {
    let mut f = Fixture::new();
    let file = module_bytes_importing("MAJORBBS", "usrnum", 1);

    f.host
        .load(&mut f.machine, &file)
        .expect("a module addressing a real, correctly-sized global loads");
}
