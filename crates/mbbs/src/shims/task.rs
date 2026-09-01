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

/// `VOID mfytask(INT taskid, VOID (*tskaddr)(INT taskid))` -- `GCOMM.H:494`,
/// "modify an existing task's routine".
///
/// The split half of [`initask`]'s pair: three sites in The Rose call
/// `initask` to register a task and later call `mfytask` on the id it got
/// back, to point the same slot at a different routine. Before this, that
/// second call failed -- `initask` alone left a module that registers a
/// task and then tries to change it with no way to.
///
/// **Consistency with `initask`'s answer to the callback problem.** `initask`
/// does not refuse to store `tskaddr` -- it cannot invoke it either
/// (`shims::misc`'s module doc: `Call` holds only `cpu`, `Host` never stores
/// a loaded module's selector map), but it does not need to: it *appends the
/// address to `host.tasks`* and leaves invocation to [`Host::prctask`],
/// called from [`Host::cycle`] in `crates/mbbs/src/lib.rs`, which runs with
/// `machine` and `module` both in scope and can call out for real. `mfytask`
/// hits the identical non-problem for the identical reason: it only ever
/// *replaces* the address at an existing slot in that same `host.tasks`
/// table, so the same driver-thread invocation path serves the modified
/// routine on the next cycle with no change of its own. There is nothing
/// here to refuse in the callback's terms at all -- unlike `btuchi`
/// (Task 3), which must invoke synchronously, inside the call, with no
/// driver thread to defer to.
///
/// A null `tskaddr` is refused for the same reason [`initask`] refuses one:
/// the original would jump to address zero on the next cycle, and this host
/// would rather say so now than fault silently later.
///
/// An unknown `taskid` -- one `initask` never issued, or past the end of the
/// table -- is refused rather than silently ignored or grown into a new
/// slot: a module that races ahead of its own bookkeeping (or was never
/// tested against a host that implemented `initask` at all) gets a clear
/// stop instead of quietly acquiring a task it never registered.
///
/// # Mutation caught while implementing this
///
/// Appending the new address to `host.tasks` rather than overwriting the
/// existing slot passes every test that only checks the call succeeded --
/// `mfytask` is declared `void`, so a module reading its return value was
/// never going to catch it, and every other assertion here checks
/// `host.tasks.len()`. `mfytask_replaces_the_routine_initask_registered`
/// checks `len()` stayed at 1 and that the *original* slot changed, which
/// an append fails on both counts.
pub fn mfytask<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let taskid: u32 = call.int().into();
    let tskaddr = call.ptr();

    // A null `tskaddr` *disables* the slot; it is not a fault. Genuine
    // `mfytask` (`GCOMMLIB/TASKS.C`) `catastro`s only on a bad `taskid` and
    // stores whatever address it is handed, NULL included -- and `prctask`
    // skips a NULL slot rather than jumping to zero. The Rose disables its
    // tasks exactly this way (`mfytask(id, NULL)`), and refusing it stopped
    // the module.
    let idx = taskid as usize;
    let Some(slot) = host.tasks.get_mut(idx) else {
        return Err(ShimError::Failed(format!(
            "mfytask({taskid}, ..): no such task -- initask never issued id {taskid}, or it is past the {} task(s) actually registered",
            host.tasks.len()
        )));
    };
    *slot = tskaddr;
    Ok(abi::Ret::Void)
}

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
    // Reuse the first freed (NULL) slot before growing the table, and answer
    // its id -- genuine `initask` (`GCOMMLIB/TASKS.C`) does exactly this, so a
    // task disabled with `mfytask(id, NULL)` frees id `id` for the next
    // `initask`. A module that disables then re-registers (The Rose) counts
    // on the same id coming back; appending instead would drift its
    // bookkeeping and leave it modifying the wrong slot later. NULL is a valid
    // address to register -- a slot that starts disabled -- and `prctask`
    // skips it, so no null check is needed.
    if let Some(idx) = host.tasks.iter().position(|&t| t == A::null_ptr()) {
        host.tasks[idx] = tskaddr;
        // `idx < tasks.len()`, and the length fit an `id` when that slot was
        // first pushed, so this cast cannot lose.
        return Ok(abi::Ret::Int(A::Int::from(idx as u16)));
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

// `initask`'s own behavioural tests live beside `Host::prctask` in
// `crates/mbbs/src/lib.rs`, not here: registering a task is only half the
// contract, and the half worth asserting is that a registered routine
// actually RUNS, which needs the `polling_fixture` machinery (a real module
// with a callable stub) that only that module has. Two tests that pushed
// straight into `host.tasks` and asserted the table had entries used to live
// here; they exercised `Vec::push`, not `initask`.
//
// `mfytask` needs no such machinery: everything it does is answered by
// `host.tasks`'s own state, which `Fixture` reaches directly, so its tests
// live here beside it.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs_machine::m16::{FarPtr, Ret};

    /// `f.invoke` answers `mbbs_machine::m16::Ret`; `initask`/`mfytask` both
    /// return a plain `int`, which crosses as `Ret::U16`.
    fn word(ret: Ret) -> u16 {
        match ret {
            Ret::U16(v) => v,
            other => panic!("expected Ret::U16 (a task id), got {other:?}"),
        }
    }

    #[test]
    fn mfytask_replaces_the_routine_initask_registered() {
        let mut f = Fixture::new();
        let id = word(f.invoke(initask, &[0x0010, 0x1234]).expect("initask"));

        f.invoke(mfytask, &[id, 0x0020, 0x5678])
            .expect("mfytask on a taskid initask just issued");

        assert_eq!(
            f.host.tasks.len(),
            1,
            "mfytask must replace the existing slot, not grow the table"
        );
        assert_eq!(
            f.host.tasks[usize::from(id)],
            FarPtr {
                offset: 0x0020,
                selector: 0x5678
            },
            "the slot initask created must now hold mfytask's routine"
        );
    }

    #[test]
    fn mfytask_on_a_taskid_initask_never_issued_is_refused() {
        let mut f = Fixture::new();
        // No initask call at all: task 99 does not exist in an empty table.
        let e = f
            .invoke(mfytask, &[99, 0x0020, 0x5678])
            .expect_err("a refusal, not a silently grown table");
        assert!(e.to_string().contains("99"), "{e}");
        assert_eq!(f.host.tasks.len(), 0, "a refusal must not register anything");
    }

    #[test]
    fn mfytask_refuses_past_the_end_of_a_nonempty_table_too() {
        let mut f = Fixture::new();
        let id = word(f.invoke(initask, &[0x0010, 0x1234]).expect("initask"));
        let bogus = id + 1;

        let e = f
            .invoke(mfytask, &[bogus, 0x0020, 0x5678])
            .expect_err("a refusal");
        assert!(e.to_string().contains(&bogus.to_string()), "{e}");
        assert_eq!(
            f.host.tasks[usize::from(id)],
            FarPtr {
                offset: 0x0010,
                selector: 0x1234
            },
            "the real task's slot must be untouched by a refused call on a different id"
        );
    }

    #[test]
    fn mfytask_null_disables_the_task_rather_than_being_refused() {
        let mut f = Fixture::new();
        let id = word(f.invoke(initask, &[0x0010, 0x1234]).expect("initask"));

        // `mfytask(id, NULL)` disables the slot -- genuine `TASKS.C` stores
        // the address it is handed, NULL included, and `prctask` skips a NULL
        // slot. The Rose relies on this; refusing it stopped the module.
        f.invoke(mfytask, &[id, 0, 0])
            .expect("mfytask(id, null) disables the slot -- it is not a fault");
        assert_eq!(
            f.host.tasks[usize::from(id)],
            FarPtr { offset: 0, selector: 0 },
            "the slot is now the null (disabled) routine"
        );
    }

    /// Genuine `initask` (`TASKS.C`) reuses the first freed (NULL) slot before
    /// growing, so a task disabled with `mfytask(id, NULL)` frees id `id` for
    /// the next `initask`. A module that disables then re-registers counts on
    /// the same id coming back.
    #[test]
    fn initask_reuses_a_slot_a_null_mfytask_freed() {
        let mut f = Fixture::new();
        let id = word(f.invoke(initask, &[0x0010, 0x1234]).expect("initask"));
        f.invoke(mfytask, &[id, 0, 0]).expect("disable the slot");

        let id2 = word(f.invoke(initask, &[0x0020, 0x5678]).expect("initask"));
        assert_eq!(id2, id, "the freed slot is reused, its id handed back again");
        assert_eq!(f.host.tasks.len(), 1, "no new slot grew");
        assert_eq!(
            f.host.tasks[usize::from(id)],
            FarPtr { offset: 0x0020, selector: 0x5678 },
            "and it now holds the new routine"
        );
    }

    #[test]
    fn mfytask_leaves_other_tasks_alone() {
        // Channel-scoped tests elsewhere in this crate check exactly this
        // shape for a different subsystem (btuche on two channels); the
        // task table has the same hazard -- a routine that finds "the"
        // slot instead of "this" slot.
        let mut f = Fixture::new();
        let first = word(f.invoke(initask, &[0x0010, 0x1234]).expect("initask 1"));
        let second = word(f.invoke(initask, &[0x0030, 0x2222]).expect("initask 2"));

        f.invoke(mfytask, &[second, 0x0040, 0x3333])
            .expect("mfytask on the second task");

        assert_eq!(
            f.host.tasks[usize::from(first)],
            FarPtr {
                offset: 0x0010,
                selector: 0x1234
            },
            "the first task must be untouched by a mfytask call naming the second"
        );
        assert_eq!(
            f.host.tasks[usize::from(second)],
            FarPtr {
                offset: 0x0040,
                selector: 0x3333
            },
        );
    }
}
