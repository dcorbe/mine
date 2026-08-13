//! The one arbiter for a process hosting more than one ABI at once.
//!
//! `mbbs16` and `mbbs32` each used to install their own process-wide handler
//! for SIGSEGV/SIGILL/SIGBUS/SIGFPE, behind their own `static INSTALL: Once`.
//! There is exactly one disposition per signal per process, so whichever
//! `Machine::new` ran second silently took the first one's handler away --
//! and its handler decided ownership with a *negative* test ("not host code,
//! so it must be mine"), which does not merely miss the other ABI's faults,
//! it actively **misclaims** them: a 16-bit fault reaching m32's old
//! handler had its `R14` read as a `crate::m32::asm::Ctx*` when it was really a
//! `crate::m16::asm::Ctx*`, and the process died.
//!
//! This module is the fix: one process-wide handler, shared by every ABI,
//! dispatching on a **positive** claim instead. Each ABI registers a
//! claim predicate over the faulting `CS` -- a plain `fn(u16) -> bool` with no
//! captures -- and a recovery function of its own. The handler walks the
//! registry and asks each one in turn; the first to say yes performs
//! recovery. If none claims a synchronous fault, the default disposition is
//! restored and the instruction re-executed, exactly as every ABI's own
//! handler used to do for host faults -- dying is still the correct outcome
//! when nobody recognises the code that faulted.
//!
//! # The registry is fixed-capacity atomics, not a `Vec` or a `Mutex`
//!
//! The handler runs on a signal's own stack with the module's data segments
//! (and, for `m32`, `FS_BASE`) in whatever state the fault left them. It
//! must stay async-signal-safe: no allocation, no locks, no library calls on
//! the path a module fault actually takes. A `Vec<Claim>` would allocate to
//! grow; a `Mutex` could already be held by the very thread the signal
//! interrupted, which is an instant deadlock. So the registry is a fixed
//! array of slots -- a claim predicate and a recovery function pointer for
//! the synchronous fault signals, plus (for a slot whose ABI has a
//! watchdog) a signal number and a second recovery pointer for its async
//! signal -- published with `Release` and read with `Acquire` so the
//! handler never sees a half-written slot -- and if it does
//! catch one still being written (the claim word not yet stored), it treats
//! that slot as "not yet claiming anything" rather than guessing, which is
//! the same bias toward dying over misclaiming that motivated this module.
//!
//! Two ABIs exist today; [`MAX_CLAIMS`] leaves room for more without another
//! rewrite.
//!
//! # Two signal classes, because one of them cannot use a CS claim at all
//!
//! Every registered *fault* signal is synchronous: it arrives at the
//! instruction that caused it, so the faulting `CS` is meaningful and a claim
//! predicate over it is exactly the right question to ask.
//!
//! `m16` and `m32` each also ride a watchdog timer signal over this same
//! handler (see `crate::m16::watchdog`, `crate::m32::watchdog`), and that
//! signal is **asynchronous** -- it can land anywhere, including in host
//! code that has nothing to do with any module, or while a *different*
//! module's excursion is in progress. A CS claim cannot express "this
//! concerns me" for a signal like that; only the timer's own payload (the
//! context address it was told to watch, carried in `siginfo_t`) can.
//!
//! **Both watchdogs share the same real-time signal** -- `SIGRTMIN()`,
//! computed independently by each ABI's own `watchdog::signo`, rather than
//! each minting its own. Real-time signals are a scarce, process-wide
//! resource, and there is no reason to spend a second one on a mechanism
//! that already has a payload to disambiguate with. So a delivery of that
//! signal is **offered to every registered async claim whose signal number
//! matches** -- today that is all of them, since they agree -- and each
//! one's own recovery function decides, from the payload alone, whether
//! this particular delivery is its own. See [`AsyncClaim`] and [`tag`]/
//! [`untag`] for how a recovery function makes that determination safely:
//! `sival_ptr` is not, on its own, enough to say *which ABI's* `Ctx` it
//! addresses, so each ABI's timer folds its own registration slot into the
//! low bits of the address it hands `timer_create`, and each recovery
//! function checks that tag before treating the rest of the value as its
//! own `Ctx` type. A tag mismatch is treated exactly like a CS claim that
//! answers no: not mine, touch nothing, let the delivery pass through
//! unclaimed by this slot.
//!
//! # What is deliberately NOT shared
//!
//! The actual register rewrite -- which fields move where, and why -- differs
//! per ABI and stays that way: `crate::m16::fault` and `crate::m32::fault` keep their
//! own recovery bodies, each measured against its own real recovery
//! experiments (`crates/mbbs-machine/src/m16/fault.rs`,
//! `crates/mbbs-machine/src/m32/fault.rs`).
//! This module owns only the parts that were pure duplication: the one
//! `sigaction` install, the one per-thread alternate signal stack, and the
//! dispatch that decides *which* recovery function runs.

use std::cell::Cell;
use std::io;
use std::sync::Once;
use std::sync::atomic::{AtomicI32, AtomicU16, AtomicUsize, Ordering};

/// Signals a module can raise by misbehaving. `SIGTRAP` is deliberately
/// absent: it belongs to debuggers, and a module executing `int3` is
/// pathological rather than routine. Every signal in this list is
/// synchronous -- see the module doc comment for why that is exactly what
/// makes a CS-based claim meaningful for these and not for the async slot.
const FAULT_SIGNALS: [i32; 4] = [libc::SIGSEGV, libc::SIGILL, libc::SIGBUS, libc::SIGFPE];

/// Size of the alternate signal stack. A handler that only edits registers
/// needs very little, but `SIGSTKSZ` worth costs nothing.
const ALTSTACK_BYTES: usize = 64 * 1024;

/// How many ABIs can register a synchronous claim. Two exist today
/// (`m16`, `m32`); this leaves room for a third without another
/// rewrite of the registry shape.
const MAX_CLAIMS: usize = 4;

/// Bit position of `CS` inside the packed `REG_CSGSFS` greg. Both ABIs
/// agreed on this independently before this module existed; it is simply
/// where the kernel puts it.
const CS_SHIFT: u32 = 0;

/// A claim predicate over a faulting `CS`, with no captures -- see the
/// module doc comment for why the registry demands a plain function pointer
/// rather than a closure.
pub(crate) type ClaimFn = fn(faulting_cs: u16) -> bool;

/// The context rewrite for a synchronous fault this ABI has just claimed.
///
/// # Safety
///
/// Called only from the signal handler, on its alternate stack, with `ctx`
/// pointing at the live `ucontext_t` the kernel built for this delivery.
/// Must be async-signal-safe: no allocation, no locks, no library calls
/// other than the specific ones each ABI has already measured as safe on
/// this path (see each ABI's own module comment for what those are and
/// why).
pub(crate) type RecoverFn = unsafe fn(signo: libc::c_int, ctx: *mut libc::c_void, host_cs: u16);

/// The recovery for an asynchronous signal -- see [`AsyncClaim`].
///
/// # Safety
///
/// Same obligations as [`RecoverFn`], plus: called for *every* delivery of
/// the registered signal, whatever `CS` happens to be at the time, so the
/// function must decide for itself (from `info`, `ctx`, or both) whether
/// there is anything to do.
pub(crate) type AsyncRecoverFn =
    unsafe fn(signo: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void, host_cs: u16);

/// One ABI's positive claim over the synchronous fault signals.
pub(crate) struct FaultClaim {
    /// Does this ABI's module code run under this `CS`? Measured, not
    /// assumed -- see each ABI's own claim function for how its value
    /// was obtained.
    pub(crate) claims: ClaimFn,
    /// Perform this ABI's context rewrite. Called only once `claims` has
    /// returned `true` for this exact fault.
    pub(crate) recover: RecoverFn,
}

/// One ABI's registration for an asynchronous signal, bypassing the
/// CS-claim dispatch entirely: every delivery of `signo` reaches `recover`,
/// whatever `CS` happens to be, and `recover` decides for itself (from the
/// payload -- see [`tag`]/[`untag`]) whether a given delivery is its own.
///
/// More than one of these can be active at once now -- both `m16` and
/// `m32`'s watchdogs register one, and today both choose the *same*
/// `signo` (see the module doc comment). [`register`] returns the slot
/// index this claim landed in, which the caller must fold into every
/// `sigval` it hands `timer_create` from then on (via [`tag`]) so that
/// [`untag`] can tell its own deliveries apart from another ABI's.
pub(crate) struct AsyncClaim {
    /// The signal number this ABI's timer raises.
    pub(crate) signo: libc::c_int,
    /// Handle every delivery whose payload names this ABI's own `Ctx`.
    pub(crate) recover: AsyncRecoverFn,
}

struct Slot {
    claims: AtomicUsize,
    recover: AtomicUsize,
    /// `0` means this slot has no asynchronous claim. Real signal numbers
    /// are always positive, so `0` is a safe sentinel.
    async_signo: AtomicI32,
    async_recover: AtomicUsize,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            claims: AtomicUsize::new(0),
            recover: AtomicUsize::new(0),
            async_signo: AtomicI32::new(0),
            async_recover: AtomicUsize::new(0),
        }
    }
}

static SLOTS: [Slot; MAX_CLAIMS] = [
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
];
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Bits of an async claim's `sigval.sival_ptr` reserved to say which
/// registration slot -- and therefore which ABI -- owns the `Ctx` it
/// names. Two bits cover every index [`MAX_CLAIMS`] can hand out. Every
/// `Ctx` an ABI in this crate boxes for a watchdog carries a `u32`- or
/// wider-aligned field, so a live heap address always has at least this
/// many low bits free to borrow.
const ASYNC_TAG_BITS: u32 = 2;
const ASYNC_TAG_MASK: usize = (1 << ASYNC_TAG_BITS) - 1;

/// Build the `sigval` an async timer should carry: `ctx`'s address, tagged
/// with `owner` -- the slot index [`register`] returned for this ABI's
/// registration -- so [`untag`] can tell whose payload a delivery names.
///
/// # Panics
///
/// If `owner` does not fit [`ASYNC_TAG_MASK`], or `ctx`'s address is not
/// aligned enough to carry the tag. Both are construction-time programmer
/// errors -- neither can be provoked by a module -- so this runs as an
/// ordinary `assert!`, not a `debug_assert!`: a silently mistagged context
/// is exactly the kind of bug this crate exists to make loud.
pub(crate) fn tag<T>(ctx: *mut T, owner: usize) -> libc::sigval {
    assert!(
        owner <= ASYNC_TAG_MASK,
        "owner slot {owner} does not fit the async tag"
    );
    assert_eq!(
        ctx as usize & ASYNC_TAG_MASK,
        0,
        "Ctx is not aligned enough to carry the async ownership tag"
    );
    libc::sigval {
        sival_ptr: ((ctx as usize) | owner) as *mut libc::c_void,
    }
}

/// The inverse of [`tag`]: given a delivery's raw `sival_ptr` and `owner`
/// (this ABI's own registered slot index), the untagged `Ctx` address if
/// `owner` matches the tag, or `None` if this delivery names some other
/// ABI's context -- the positive claim an async recovery function makes
/// over its own payload, mirroring [`ClaimFn`]'s positive claim over `CS`.
/// Never guess by ruling the other ABI out; a tag mismatch means "not
/// mine," full stop.
///
/// # Safety
///
/// The caller must supply the same `T` [`tag`] was built with for this
/// exact `sival_ptr` -- this function has no way to check that itself.
pub(crate) unsafe fn untag<T>(sival_ptr: *mut libc::c_void, owner: usize) -> Option<*mut T> {
    let raw = sival_ptr as usize;
    if raw & ASYNC_TAG_MASK == owner {
        Some((raw & !ASYNC_TAG_MASK) as *mut T)
    } else {
        None
    }
}

/// The 64-bit code selector host code runs under, recorded when the first
/// ABI registers. Every ABI in this process reads the same value at
/// startup (Linux's `__USER_CS`), so it does not matter which registration
/// wins the race to store it.
static HOST_CS: AtomicU16 = AtomicU16::new(0);

/// Guards the *first* `sigaction` install for [`FAULT_SIGNALS`]. Not a guard
/// on registration itself -- see [`register`]'s doc comment for why it
/// cannot be, and why each ABI still keeps a small `Once` of its own.
static INSTALL: Once = Once::new();

thread_local! {
    /// This thread's alternate signal stack, mapped once and kept.
    static ALTSTACK: Cell<*mut libc::c_void> = const { Cell::new(std::ptr::null_mut()) };
}

/// Make module faults survivable on this thread.
///
/// Every ABI's `Machine::new` must call this, every time -- the alternate
/// stack is per-thread, not process-wide, so a fresh thread has none until
/// this runs on it. Idempotent per thread: a second call on the same thread
/// finds its mapping already made and only reinstalls the `sigaltstack`
/// pointer, which costs one syscall.
pub(crate) fn install_altstack() -> io::Result<()> {
    ALTSTACK.with(|slot| {
        if slot.get().is_null() {
            // SAFETY: an ordinary anonymous mapping. MAP_32BIT does not
            // change whether recovery works -- m16's own module comment
            // settles that with a three-arm test -- but it costs nothing and
            // rules out a whole class of surprise for free, so it is applied
            // uniformly here rather than per-ABI.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ALTSTACK_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            slot.set(base);
        }

        let stack = libc::stack_t {
            ss_sp: slot.get(),
            ss_size: ALTSTACK_BYTES,
            ss_flags: 0,
        };
        // SAFETY: `stack` describes a live mapping owned by this thread for
        // the rest of its life.
        if unsafe { libc::sigaltstack(&stack, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// Register one ABI's claim over the process's fault signals, and its
/// asynchronous signal if it has one.
///
/// # Why this cannot be gated by a single `Once`
///
/// Two distinct ABIs each need their own registration to run exactly once
/// -- not "the first registration in the process wins and every later one
/// is silently dropped", which is what a single `Once` guarding this whole
/// function would produce, and is precisely the bug this module exists to
/// fix. So each ABI keeps a small `Once` of its own around its call
/// to this function; what lives here is [`INSTALL`], which only avoids a
/// redundant `sigaction` call for [`FAULT_SIGNALS`] on the common path
/// where a second ABI registers with no asynchronous signal of its own to
/// add. Calling `sigaction` again is not unsafe, just wasted -- the
/// registry write is what has to happen exactly once per ABI, and that is
/// enforced by the fixed-slot claim below, not by [`INSTALL`].
///
/// # Errors
///
/// If [`MAX_CLAIMS`] ABIs have already registered, or if any underlying
/// `sigaction` call fails.
///
/// # Returns
///
/// The slot index this registration landed in. A caller that also passed
/// `async_claim` must fold this into every `sigval` it builds afterward
/// (via [`tag`]) -- see the module doc comment's "Two signal classes"
/// section.
pub(crate) fn register(
    host_cs: u16,
    claim: FaultClaim,
    async_claim: Option<AsyncClaim>,
) -> io::Result<usize> {
    // Whichever registration gets here first wins; every ABI in this process
    // reads the same value, so it does not matter which.
    HOST_CS.store(host_cs, Ordering::Relaxed);

    let i = NEXT.fetch_add(1, Ordering::SeqCst);
    if i >= MAX_CLAIMS {
        return Err(io::Error::other("mbbs-machine::fault: claim registry is full"));
    }
    // Recovery first (Relaxed -- ordering is established below), then the
    // claim predicate with Release: the handler's matching Acquire load of
    // `claims` makes both writes visible together, or neither.
    SLOTS[i].recover.store(claim.recover as usize, Ordering::Relaxed);
    SLOTS[i].claims.store(claim.claims as usize, Ordering::Release);

    let mut result = Ok(());
    INSTALL.call_once(|| {
        result = install_fault_signals();
    });
    result?;

    if let Some(a) = async_claim {
        register_async(i, a)?;
    }
    Ok(i)
}

fn register_async(i: usize, claim: AsyncClaim) -> io::Result<()> {
    // Recovery first (Relaxed), signo with Release -- same pairing as the
    // fault claim above, and for the same reason: the handler's Acquire
    // load of `async_signo` must see a fully-written `async_recover`
    // alongside it. No signal of `claim.signo` can be delivered before
    // `install_async_signal` below runs, so there is no window in which a
    // partially-published slot could be observed as claiming a signal it
    // is not yet ready to service.
    SLOTS[i].async_recover.store(claim.recover as usize, Ordering::Relaxed);
    SLOTS[i].async_signo.store(claim.signo, Ordering::Release);
    install_async_signal(claim.signo)
}

fn install_async_signal(async_signo: libc::c_int) -> io::Result<()> {
    let mut action = fresh_action();
    // SAFETY: emptying a freshly zeroed set, then blocking one signal in it.
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        // A tick landing partway through a context rewrite would be
        // harmless on its own -- see the recovering ABI's own handling of
        // that case -- but a timer that cannot interrupt this handler at
        // all is one fewer thing to reason about, and it costs nothing.
        // Faults are left unmasked: a handler that faults should die, not
        // deadlock.
        libc::sigaddset(&mut action.sa_mask, async_signo);
    }
    for signo in FAULT_SIGNALS.into_iter().chain([async_signo]) {
        // SAFETY: `action` is fully initialised and outlives the call.
        if unsafe { libc::sigaction(signo, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn install_fault_signals() -> io::Result<()> {
    let mut action = fresh_action();
    // SAFETY: emptying a freshly zeroed set.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signo in FAULT_SIGNALS {
        // SAFETY: `action` is fully initialised and outlives the call.
        if unsafe { libc::sigaction(signo, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn fresh_action() -> libc::sigaction {
    // SAFETY: zeroed sigaction is a valid starting point; every field used
    // by a caller is set immediately after this returns.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
    action
}

/// The shared handler every registered ABI's faults, and the one registered
/// asynchronous signal, are delivered to.
///
/// Async-signal-safe: it reads a handful of atomics, dispatches to at most
/// one recovery function, and returns. No allocation, no locks, no library
/// calls of its own. (The `Once` above is not on this path -- it fires once,
/// long before any signal can be delivered on the signals it installs.)
extern "C" fn handler(signo: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let host_cs = HOST_CS.load(Ordering::Relaxed);
    let n = NEXT.load(Ordering::Acquire).min(MAX_CLAIMS);

    // Offer this delivery to every slot whose async signal matches. Today
    // that is every registered slot with a watchdog at all -- both ABIs
    // choose the same `signo` -- so more than one recovery function can run
    // for a single delivery, and each decides for itself (via `untag`,
    // inside its own `recover`) whether the payload is really its own. A
    // tag mismatch there is a fast, harmless no-op, so trying every match
    // costs nothing a single dispatch would not have.
    let mut delivered_async = false;
    for slot in &SLOTS[..n] {
        let async_signo = slot.async_signo.load(Ordering::Acquire);
        if async_signo != 0 && async_signo == signo {
            delivered_async = true;
            let recover = slot.async_recover.load(Ordering::Relaxed);
            if recover != 0 {
                // SAFETY: `recover` was stored before `async_signo` in
                // `register_async`, and observed here only after the
                // Acquire load above saw the Release-published signal
                // number, so the function pointer is valid. The kernel
                // guarantees `info` and `ctx` for an SA_SIGINFO handler.
                let f: AsyncRecoverFn = unsafe { std::mem::transmute(recover) };
                unsafe { f(signo, info, ctx, host_cs) };
            }
        }
    }
    if delivered_async {
        return;
    }

    // SAFETY: the kernel hands a real `ucontext_t` to an SA_SIGINFO handler
    // for every signal `install_fault_signals`/`install_async_signal` install.
    let uc = unsafe { &*ctx.cast::<libc::ucontext_t>() };
    let packed = uc.uc_mcontext.gregs[libc::REG_CSGSFS as usize] as u64;
    let faulting_cs = (packed >> CS_SHIFT) as u16;

    for slot in &SLOTS[..n] {
        let claims_addr = slot.claims.load(Ordering::Acquire);
        if claims_addr == 0 {
            // This slot's registration has not finished publishing yet.
            // Treating it as "claims nothing" rather than guessing is the
            // same bias toward dying over misclaiming the module doc
            // comment describes -- and this window only exists during
            // process startup, before any module has run.
            continue;
        }
        // SAFETY: published via the Release store in `register`, observed
        // here via the Acquire load above.
        let claims: ClaimFn = unsafe { std::mem::transmute(claims_addr) };
        if claims(faulting_cs) {
            let recover_addr = slot.recover.load(Ordering::Relaxed);
            // SAFETY: written before `claims` in program order in
            // `register`; the Acquire load of `claims` above already
            // established that this write is visible.
            let recover: RecoverFn = unsafe { std::mem::transmute(recover_addr) };
            unsafe { recover(signo, ctx, host_cs) };
            return;
        }
    }

    // Nobody claims it -- host code, or something else entirely. Put the
    // default disposition back and return, so the faulting instruction runs
    // again and kills us the way it would have without us here. Quietly
    // swallowing another subsystem's fault would be much worse than dying.
    //
    // Correct only because every signal reaching this branch is synchronous
    // -- see the module doc comment's "Two signal classes" section. Nothing
    // asynchronous may fall through to here, which is exactly why the async
    // signal is intercepted above, unconditionally, before this point.
    //
    // SAFETY: restoring the default disposition of a signal.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(signo, &dfl, std::ptr::null_mut());
    }
}
