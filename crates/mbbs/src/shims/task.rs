//! The system-task table: `initask` and `prctask`.
//!
//! A *task* is a system-wide routine the host runs once per system cycle,
//! registered by a module at init. `GCOMM.H:493`:
//!
//!
//! **Why this matters, and why it went missing.** `MAJORBBS.C:323` is the
//! whole story in one line:
//!
//!
//! The `syscyc` vector's *initial value is the task runner*. A module that
//! chains onto that vector saves the previous value and calls it at its own
//! tail, so on the original every chained module ends by running the task
//! table. This host initialised `syscyc` to null, which is precisely why
//! MajorMUD's chain guard -- `if (DAT_1118_0568 != 0) (*DAT_1118_0568)()` at
//! `WCCMMUD_named.c:9821` -- mattered: it was guarding against *our* null,
//! not against the vendor's `prctask`.
//!
//! So a host that implemented `initask` and left the vector null would accept
//! every registration and run none of them. [`Host::prctask`] is therefore
//! called from [`Host::cycle`] directly, immediately after the vector, rather
//! than relying on a module to chain correctly -- a deviation recorded at that
//! call site. It reaches the same place the original does and does not depend
//! on the module's own bookkeeping being right.
//!
//! **Who needs it.** MajorMUD does not: it registers no task. `The Rose 2.0`
//! (`RCIROSE.DLL`) imports `initask`, and the vendor's own libraries do --
//! `GALMHS.C:707` (`mhstsk=initask(mhsproc)`) and `GALFILU.C:2141,2146`
//! (`initask(copyaut)`, `initask(keywdaut)`). The `syscyc` fix's own comment
//! used to claim "nothing this host loads registers a task"; surveying The
//! Rose made that false, which is why this exists.

use crate::abi::{self, Abi};
use crate::shims::{Call, ShimError};
use crate::Host;

/// `INT initask(VOID (*tskaddr)(INT taskid))` -- `GCOMM.H:493`, "start up a
/// new task".
///
/// Appends the routine to the host's table and answers its **index**, which is
/// the task id: the original hands that number back to the caller and passes
/// it to the routine on every run, so a routine registered more than once can
/// tell its registrations apart. `GALMHS.C:707` keeps the returned id in a
/// global for exactly that reason.
///
/// A null `tskaddr` is refused rather than registered. The original would
/// accept it and jump to address zero on the next cycle; this host prefers a
/// clear refusal at the registration to an unexplained fault a second later,
/// which is the same trade [`crate::shims::system::rtkick`] makes for a
/// negative delay.
pub fn initask<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let tskaddr = call.ptr();
    if tskaddr == A::null_ptr() {
        return Err(ShimError::Failed(
            "initask: a null task routine, which would fault on the next system cycle".to_string(),
        ));
    }
    let id = host.tasks.len();
    let Ok(id) = u16::try_from(id) else {
        return Err(ShimError::Failed(format!(
            "initask: {id} tasks registered; the id is an int and this cannot be one"
        )));
    };
    host.tasks.push(tskaddr);
    Ok(abi::Ret::Int(A::Int::from(id)))
}

// Tests live beside `Host::prctask` in `crates/mbbs/src/lib.rs`, not here:
// registering a task is only half the contract, and the half worth asserting
// is that a registered routine actually RUNS, which needs the `polling_fixture`
// machinery (a real module with a callable stub) that only that module has.
// Two tests that pushed straight into `host.tasks` and asserted the table had
// entries used to live here; they exercised `Vec::push`, not `initask`.
