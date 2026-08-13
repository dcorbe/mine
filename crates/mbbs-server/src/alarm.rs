//! The bell. Deadlines are owned by the host; this task only renders the
//! nearest one back as a message. See design doc
//! `docs/plans/2026-08-12-abi-border-design.md` §7 ("The event loop: one
//! spine") for the model this implements.
//!
//! **Sloppy on purpose.** [`crate::msg::In::Alarm`] carries no payload and no
//! identity: because `Host::cycle`'s catch-up (`tcklst`) fires whatever came
//! due off elapsed wall time rather than off *why* it was woken, a stale or
//! duplicate `Alarm` is harmless -- the host thread wakes, catch-up finds
//! nothing due, and the driver re-arms the true next deadline. So there is no
//! cancellation protocol here: the `watch::Receiver` always holds the LATEST
//! request, and a new one simply replaces whatever sleep was in progress.
//! Keep one outstanding alarm; tolerate extras.
//!
//! **On `std::sync::mpsc`, not `tokio::sync::mpsc`.** The host thread is a
//! plain `std::thread` (`Machine` is `!Send`; see `host.rs`'s module doc), so
//! the channel every socket event already arrives on is
//! `std::sync::mpsc::Sender<In>` -- a synchronous, non-blocking `send` on an
//! unbounded channel, safe to call from inside a tokio task. This task is the
//! ONLY thing on the async side that needs to reach into the host thread's
//! world at all, and it does so through that same, single channel: "the
//! point is ONE receiver" (the design doc's words), not a second one this
//! task would otherwise invent for itself.

use std::sync::mpsc::Sender;
use std::time::Duration;

use tokio::sync::watch;

use crate::msg::In;

/// Watch `deadline` and send [`In::Alarm`] on `tx` each time the armed
/// duration elapses, re-arming from whatever the host thread requests next.
///
/// `None` means "no deadline armed" (the host is blocked on
/// [`crate::Wait::Blocked`] or has stopped): this task waits for the next
/// change rather than spinning or exiting, since the host thread is still
/// alive and may arm a real deadline later. The task itself exits only once
/// `deadline`'s sender side is dropped (the host thread ended) or `tx`'s
/// receiver is dropped (nobody is left to hear an `Alarm`) -- either one
/// means nothing further this task could do would matter.
pub fn spawn(mut deadline: watch::Receiver<Option<Duration>>, tx: Sender<In>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let requested = *deadline.borrow_and_update();
            match requested {
                None => {
                    if deadline.changed().await.is_err() {
                        return;
                    }
                }
                Some(d) => {
                    tokio::select! {
                        () = tokio::time::sleep(d) => {
                            if tx.send(In::Alarm).is_err() {
                                return;
                            }
                            if deadline.changed().await.is_err() {
                                return;
                            }
                        }
                        changed = deadline.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    //! `alarm::spawn` in isolation, with no `Host`/`Machine`/`Module` at
    //! all -- just the two channels a real driver hands it. The end-to-end
    //! proof that a *driver* using this task actually wakes for a kick, and
    //! that killing this task leaves the driver's own wake-age meter stale,
    //! is `crates/mbbs-server/tests/host_supervisor.rs` (it needs a real
    //! module and `host::run`'s own loop; this file cannot build either).
    //!
    //! **`flavor = "multi_thread"`, not the default.** `rx.recv_timeout` is a
    //! blocking, synchronous call -- exactly what the real host thread makes
    //! it (see this module's own doc for why `std::sync::mpsc`, not
    //! `tokio::sync::mpsc`) -- and a single-threaded runtime never polls a
    //! spawned task while the one thread it has is parked inside that call.
    //! Every test below found this the hard way first: on the default
    //! flavor, `spawn`'s task never got a turn to run at all, and the
    //! `assert!`s that expect *no* message arrived passed for that wrong
    //! reason.

    use std::sync::mpsc;
    use std::time::Duration;

    use tokio::sync::watch;

    use super::spawn;
    use crate::msg::In;

    /// Arming a deadline sends exactly one `Alarm` once it elapses, and
    /// nothing before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_armed_deadline_fires_once_it_elapses() {
        let (deadline_tx, deadline_rx) = watch::channel(None);
        let (tx, rx) = mpsc::channel::<In>();
        let handle = spawn(deadline_rx, tx);

        deadline_tx.send(Some(Duration::from_millis(30))).expect("the task is still alive");

        assert!(
            rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "the bell must not fire before its deadline"
        );
        assert!(
            matches!(rx.recv_timeout(Duration::from_millis(200)), Ok(In::Alarm)),
            "the bell must fire once the deadline elapses"
        );

        handle.abort();
    }

    /// `None` arms nothing: a driver that goes back to `Wait::Blocked` must
    /// not keep receiving alarms for a deadline it withdrew.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disarming_the_deadline_silences_the_bell() {
        let (deadline_tx, deadline_rx) = watch::channel(None);
        let (tx, rx) = mpsc::channel::<In>();
        let handle = spawn(deadline_rx, tx);

        deadline_tx.send(Some(Duration::from_millis(20))).expect("alive");
        deadline_tx.send(None).expect("alive");

        // Generous slack past the original (withdrawn) deadline -- if the
        // task ignored the second `send` and fired anyway, this would catch
        // it.
        assert!(
            rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "a withdrawn deadline must never fire"
        );

        handle.abort();
    }

    /// A second, shorter request supersedes the first rather than queuing
    /// behind it -- "the watch channel always holds the LATEST request".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_new_deadline_replaces_the_one_in_progress() {
        let (deadline_tx, deadline_rx) = watch::channel(None);
        let (tx, rx) = mpsc::channel::<In>();
        let handle = spawn(deadline_rx, tx);

        deadline_tx.send(Some(Duration::from_secs(5))).expect("alive");
        deadline_tx.send(Some(Duration::from_millis(20))).expect("alive");

        assert!(
            matches!(rx.recv_timeout(Duration::from_millis(200)), Ok(In::Alarm)),
            "the shorter, later request must win, not the stale five-second one"
        );

        handle.abort();
    }

    /// Killing the task (simulating the frozen-world failure this whole
    /// mechanism exists to make observable) leaves the receiver silent
    /// forever, even past a deadline that was already armed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_bell_never_fires_again() {
        let (deadline_tx, deadline_rx) = watch::channel(Some(Duration::from_millis(10)));
        let (tx, rx) = mpsc::channel::<In>();
        let handle = spawn(deadline_rx, tx);
        handle.abort();
        drop(deadline_tx);

        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "an aborted bell must not still ring"
        );
    }
}
