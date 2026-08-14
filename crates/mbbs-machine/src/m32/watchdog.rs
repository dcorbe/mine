//! Interrupting a 32-bit module that never returns.
//!
//! The mirror of [`crate::m16::watchdog`] -- read that module's doc comment
//! first; this one only documents where the 32-bit side differs, and every
//! difference is a measurement or a direct consequence of `m32`'s own
//! execution substrate (`crate::m32::asm`), not a fresh design.
//!
//! # Why this is safe to build at all: the `!Send` argument, unchanged
//!
//! `crate::m16::watchdog::Watched`'s own doc comment settles the soundness
//! argument for a timer that targets one specific thread by TID
//! (`SIGEV_THREAD_ID`): the binding is sound only because the `Machine` that
//! owns the timer cannot move between threads, and it cannot move between
//! threads because it holds raw pointers into memory a specific thread's
//! segment/descriptor state depends on. `crate::m32::Machine` is the same
//! shape for the same reason -- it owns a [`crate::m32::map::Mapping`] (the
//! bridge: thunk table plus trampoline) and a
//! [`crate::m32::tib::Tib`] (the module's stack and Win32 TIB), both raw,
//! and its excursions run through `crate::m32::asm::enter`'s `arch_prctl`
//! dance, which is itself a per-thread `FS_BASE` save/restore. Nothing about
//! `m32::Machine` is `Send`, and this module does nothing to change that:
//! [`Watched`] is built, armed and read entirely from the one thread that
//! owns the [`crate::m32::Machine`] it lives inside. The timer this module
//! creates is bound to that thread's TID at construction and stays bound
//! for its whole life -- the same load-bearing property `m16`'s own module
//! comment names, carried over unchanged.
//!
//! # What differs from `crate::m16::watchdog`
//!
//! **The CPU-time clock, the interval-vs-one-shot reasoning, and the
//! "armed per entry point" rule are all identical** -- see `m16`'s module
//! doc comment for the full argument; nothing about 32-bit compatibility
//! mode changes any of it.
//!
//! **The signal is the SAME real-time signal `m16` already claims, not a
//! second one.** [`signo`] computes `libc::SIGRTMIN()` independently --
//! `m32` cannot import `crate::m16` at all (the cross-import guard), so it
//! cannot call `m16`'s function directly -- but `SIGRTMIN()` is a pure,
//! deterministic read of a process-wide constant, so both ABIs land on the
//! identical number by construction. `crate::fault`'s module doc comment
//! explains why sharing is deliberate rather than a coincidence to route
//! around, and how the arbiter's registry tells the two apart: every
//! `sigval` this module hands `timer_create` is tagged with this ABI's own
//! registered slot (`crate::fault::tag`, `crate::m32::fault::owner`), and
//! [`crate::m32::fault::recover_watchdog`] checks that tag before treating
//! the rest of the payload as an `m32::asm::Ctx` at all.
//!
//! **`Ctx` carries `expired: u32`, not `u64`.** `m32::asm::Ctx` is already
//! built from 32-bit-register-width fields throughout (unlike `m16`'s,
//! which widens everything to `u64` for `movq`); one register narrower
//! costs nothing here since, exactly as in `m16`, the assembly never reads
//! or writes this field at all -- only the signal handler and [`Watched`]
//! ever touch it.

use std::io;
use std::ptr;
use std::time::Duration;

use crate::m32::asm::Ctx;

/// The signal a watchdog timer raises. The SAME real-time signal
/// `crate::m16::watchdog::signo` computes -- see this module's doc comment
/// ("What differs") for why that is deliberate, not a collision to avoid.
pub(crate) fn signo() -> i32 {
    libc::SIGRTMIN()
}

/// How the budget divides into ticks. Mirrors `crate::m16::watchdog`'s own
/// constant exactly; see that module's doc comment for the reasoning.
const INTERVAL_DIVISOR: u32 = 4;

/// A module's execution context, and the CPU-time timer that watches it.
/// Mirrors `crate::m16::watchdog::Watched` field-for-field; see that type's
/// own doc comment for why the two live in one object and why [`Drop`]
/// deletes the timer before the fields are dropped.
pub(crate) struct Watched {
    timer: libc::timer_t,

    /// Boxed for its address, not for indirection -- see
    /// `crate::m16::watchdog::Watched::ctx`'s own doc comment.
    ctx: Box<Ctx>,
}

impl Watched {
    /// Build a context with a disarmed timer watching it.
    pub(crate) fn new() -> io::Result<Self> {
        let mut ctx = Box::new(Ctx::default());
        let target: *mut Ctx = &raw mut *ctx;

        // SAFETY: zeroed is a valid starting point for sigevent, whose padding
        // is private and must stay zero; every meaningful field is set below.
        let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = signo();
        // Tagged with this ABI's registered slot -- see this module's doc
        // comment ("What differs") and `crate::m32::fault::recover_watchdog`,
        // the other half of this contract.
        sev.sigev_value = crate::fault::tag(target, crate::m32::fault::owner());
        // SAFETY: gettid has no preconditions.
        sev.sigev_notify_thread_id = unsafe { libc::gettid() };

        let mut timer: libc::timer_t = ptr::null_mut();
        // SAFETY: both pointers name locals that outlive the call, which copies
        // what it needs from them.
        let rc = unsafe {
            libc::timer_create(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut sev, &raw mut timer)
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { timer, ctx })
    }

    /// Start the clock, and forget any overrun the previous entry point left
    /// behind. `budget` is CPU time, and must not be zero -- a zero `it_value`
    /// is how `timer_settime` spells "disarmed".
    pub(crate) fn arm(&mut self, budget: Duration) -> io::Result<()> {
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a watchdog budget of zero would disarm the timer, not fire it",
            ));
        }
        self.ctx.expired = 0;
        let interval = (budget / INTERVAL_DIVISOR).max(Duration::from_nanos(1));
        self.set(budget, interval)
    }

    /// Stop the clock. Idempotent.
    pub(crate) fn disarm(&self) -> io::Result<()> {
        self.set(Duration::ZERO, Duration::ZERO)
    }

    /// Is the timer currently counting down?
    ///
    /// Asks the kernel with `timer_gettime` rather than tracking a flag,
    /// because a flag would agree with whatever `arm`/`disarm` believed they
    /// did rather than with what actually happened.
    ///
    /// # Why this exists
    ///
    /// [`Watchdog::disarm`] had no observer at all. Deleting its body passed
    /// the entire suite: every test that cared armed the timer again first,
    /// and `arm` sets the interval unconditionally, so it papered over a
    /// missing disarm every time. The path with no `arm` after it is exactly
    /// the one that matters -- a poisoned machine is never re-entered, so a
    /// timer left ticking on it goes on delivering signals for the life of
    /// the process.
    ///
    /// # Errors
    ///
    /// If `timer_gettime` fails, which for a timer this type owns and has
    /// not deleted should not happen.
    pub(crate) fn armed(&self) -> io::Result<bool> {
        let mut spec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        };
        // SAFETY: `self.timer` is a live timer this value owns, and `spec` is
        // a local the kernel only writes.
        let rc = unsafe { libc::timer_gettime(self.timer, &raw mut spec) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // `it_value` all-zero is how `timer_gettime` spells "disarmed" --
        // the same encoding `set` uses in the other direction.
        Ok(spec.it_value.tv_sec != 0 || spec.it_value.tv_nsec != 0)
    }

    /// Has a tick been recorded against this context since it was armed?
    /// Volatile for the same reason `crate::m16::watchdog::Watched::expired`
    /// is -- see that method's own doc comment.
    pub(crate) fn expired(&self) -> bool {
        // SAFETY: an ordinary read of a live, aligned field we own.
        unsafe { ptr::read_volatile(&raw const self.ctx.expired) != 0 }
    }

    /// The context, for the assembly to enter through.
    pub(crate) fn as_ptr(&mut self) -> *mut Ctx {
        &raw mut *self.ctx
    }

    fn set(&self, value: Duration, interval: Duration) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: to_timespec(interval),
            it_value: to_timespec(value),
        };
        // SAFETY: our own timer, and `spec` outlives a call that copies it.
        let rc = unsafe { libc::timer_settime(self.timer, 0, &raw const spec, ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl std::ops::Deref for Watched {
    type Target = Ctx;

    fn deref(&self) -> &Ctx {
        &self.ctx
    }
}

impl std::ops::DerefMut for Watched {
    fn deref_mut(&mut self) -> &mut Ctx {
        &mut self.ctx
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        // Before the box below it goes away -- see
        // `crate::m16::watchdog::Watched`'s own `Drop` for why this ordering
        // is structural, not incidental.
        //
        // SAFETY: our own timer, deleted exactly once.
        unsafe { libc::timer_delete(self.timer) };
    }
}

fn to_timespec(d: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: libc::c_long::from(d.subsec_nanos()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// `disarm` really stops the kernel timer, and `armed` can tell.
    ///
    /// # The hole this closes
    ///
    /// `disarm` had no observer, so deleting its body passed the whole
    /// suite. Every test that cared armed the timer again first, and `arm`
    /// sets the interval unconditionally -- so an absent disarm was healed
    /// before anything looked. The path that matters has no `arm` after it:
    /// `Machine::poison` disarms and the machine is never re-entered, so a
    /// timer left running there keeps delivering signals for the life of the
    /// process.
    ///
    /// Asserted against `timer_gettime`, not a flag this module maintains --
    /// a flag would agree with whatever `arm`/`disarm` believed rather than
    /// with the kernel.
    #[test]
    fn disarm_stops_the_kernel_timer_and_arming_starts_it_again() {
        let mut w = Watched::new().expect("a watchdog");
        assert!(!w.armed().expect("gettime"), "a fresh watchdog is not running");

        // Long enough that it cannot plausibly expire inside this test.
        w.arm(Duration::from_secs(3600)).expect("arm");
        assert!(w.armed().expect("gettime"), "arm must start the timer");

        w.disarm().expect("disarm");
        assert!(!w.armed().expect("gettime"), "disarm must stop the timer");

        // Idempotent, as its own doc comment claims -- and still stopped.
        w.disarm().expect("second disarm");
        assert!(!w.armed().expect("gettime"), "disarm twice is still stopped");

        // And the timer is reusable afterwards, so disarming is not deletion.
        w.arm(Duration::from_secs(3600)).expect("re-arm");
        assert!(w.armed().expect("gettime"), "a disarmed timer can be armed again");
        w.disarm().expect("tidy up");
    }
}
