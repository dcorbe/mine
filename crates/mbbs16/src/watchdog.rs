//! Interrupting a module that never returns.
//!
//! A module that faults is survivable -- see [`crate::fault`]. A module that
//! loops forever was not, and for a host serving many users a wedged module is
//! as bad as a crashing one. MajorBBS is cooperatively scheduled: `struct
//! module` is nothing but a table of callbacks, and `rtkick`/`rtihdlr` exist
//! precisely because there is no preemption. Nothing takes the CPU back from a
//! module that will not give it up.
//!
//! Without this, that is not "the board fails" or "the module fails" -- it is
//! **the board hangs**, which is worse than either, and there is no way to
//! choose otherwise. This crate's job is to turn the hang into a fact
//! ([`crate::Exit::Timeout`]) and refuse to re-enter; deciding what to do about
//! it belongs to the host.
//!
//! # CPU time, not wall clock
//!
//! `CLOCK_THREAD_CPUTIME_ID`, so that a loaded machine or a descheduled process
//! cannot false-positive a module that is behaving. `ITIMER_VIRTUAL` is the
//! older equivalent but is process-wide, which stops being usable the moment
//! the host is multi-threaded.
//!
//! **The cost of that choice, stated plainly: a call blocked in a syscall is
//! invisible to this watchdog.** A Btrieve read on a stalled mount or a socket
//! read that never completes burns no CPU, so the timer never expires and the
//! host waits forever. Catching that needs a wall-clock deadline, and it
//! belongs in the host loop -- which has to notice a wedged *host* anyway, and
//! which this crate cannot see.
//!
//! # Armed per entry point, not per crossing
//!
//! The budget spans an entire [`crate::Machine::call`], including the time Rust
//! spends servicing the module's imports. Disarming on the way out to a shim
//! and re-arming on resume looks tidier and is wrong: it resets the budget
//! every iteration, so `for(;;) shim();` would never expire.
//!
//! Charging host time to the module is also the honest accounting. CPU burned
//! in a shim is CPU burned on that module's behalf, and a shim that blocks
//! rather than spins burns none of it.
//!
//! # A tick that lands in host code is evidence, not noise
//!
//! Most of a module's CPU is not spent in 16-bit mode. A module looping on an
//! import spends the bulk of each iteration inside the host servicing it --
//! measured at roughly fourteen to one on this crate's own test workload. If a
//! tick arriving in host code were simply discarded, detection would be a
//! coin-flip repeated until it came up right, and the effective timeout would
//! be some large multiple of the budget.
//!
//! It need not be. A tick means the budget is gone, wherever it landed. So the
//! handler records it on the machine it concerns and the host **refuses the
//! next re-entry**, which makes an overrun cost at most one more crossing to
//! notice however the module divides its time.
//!
//! Recording it needs somewhere stable to write, since a tick can arrive when
//! no excursion is in progress and `R14` therefore means nothing. That is why
//! [`Watched`] owns the context on the heap and hands the timer its address:
//! the handler always has a valid target, and it is always the right one.
//!
//! # An interval, not a one-shot
//!
//! A tick arriving in host code must not be passed through to the default
//! disposition (see [`crate::fault`] for why that would be a delayed disaster),
//! and a module wedged entirely inside 16-bit code has to be caught there. A
//! one-shot that had already been spent on the host would never come back for
//! it. A repeating timer covers both, at the price of up to one interval of
//! slack on when a timeout is noticed.

use std::io;
use std::ptr;
use std::time::Duration;

use crate::asm::Ctx;

/// The signal a watchdog timer raises.
///
/// A real-time signal, so it cannot collide with anything the host or its
/// libraries use for their own purposes, and `SIGRTMIN()` rather than the
/// constant because glibc reserves the first few for itself and reports the
/// first usable one here.
pub(crate) fn signo() -> i32 {
    libc::SIGRTMIN()
}

/// How the budget divides into ticks. Four gives a timeout noticed within 25%
/// of the budget while keeping the signal rate irrelevant.
const INTERVAL_DIVISOR: u32 = 4;

/// A module's execution context, and the CPU-time timer that watches it.
///
/// The two are one object because the timer holds the context's address and the
/// signal handler dereferences it. Dropping them separately would leave a window
/// in which a tick could write to freed memory; [`Drop`] here deletes the timer
/// *before* the fields are dropped, which closes it structurally rather than by
/// convention.
///
/// The timer is delivered with `SIGEV_THREAD_ID`. Process-directed delivery
/// would let a tick land on whichever thread happened to be running, and the
/// recovery the handler performs is only meaningful on the thread actually
/// inside 16-bit mode. The binding is sound because a [`crate::Machine`] owns
/// raw pointers and so cannot move between threads.
pub(crate) struct Watched {
    timer: libc::timer_t,

    /// Boxed for its address, not for indirection: the handler is given this
    /// pointer at `timer_create` time and must still find the context wherever
    /// the owning `Machine` has been moved to since.
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
        sev.sigev_value = libc::sigval {
            sival_ptr: target.cast(),
        };
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
        // Never zero, or the timer would be a one-shot: a tick spent on host
        // code would then be the only one there was.
        let interval = (budget / INTERVAL_DIVISOR).max(Duration::from_nanos(1));
        self.set(budget, interval)
    }

    /// Stop the clock. Idempotent.
    pub(crate) fn disarm(&self) -> io::Result<()> {
        self.set(Duration::ZERO, Duration::ZERO)
    }

    /// Has a tick been recorded against this context since it was armed?
    ///
    /// Volatile because the writer is a signal handler on this same thread: the
    /// two never run concurrently, so there is no data race to synchronise, but
    /// the compiler must not be allowed to assume nothing changed it.
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
        // Before the box below it goes away. `Drop::drop` runs ahead of field
        // drops, which is the whole reason these two live in one struct: after
        // this returns no tick can arrive, so nothing can write to the freed
        // context. A pending signal is discarded with the timer, which is what
        // we want -- the machine is going away.
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
