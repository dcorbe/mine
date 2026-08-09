//! The host thread: the only place `Machine::new` is ever called.
//!
//! `mbbs16::Machine` is `!Send` -- its segments are `Rc`s over `mmap`s, its
//! watchdog timer is bound with `SIGEV_THREAD_ID` to the `gettid()` of the
//! thread that created it, and the fault handler's alternate stack is a
//! `thread_local`. So the `Machine` is built *inside* this thread and never
//! crosses into it: [`Boot`] carries everything that is `Send` -- paths,
//! [`Terms`], numbers -- and [`run`] does the rest.
//!
//! [`Host::hangup`] is the answer to both a lost carrier and a client that
//! cannot keep up with its own output: the driver does not distinguish them,
//! because a socket that will not drain is indistinguishable from one that
//! is gone.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::time::Duration;

use mbbs::{Host, Terms, Wait};
use mbbs16::{Machine, Module};
use tokio::sync::mpsc::Sender;

use crate::msg::{In, Out};
use crate::pool::Pool;

/// Everything the host thread needs, all of it `Send`. The `Machine` is not
/// here and cannot be: it is `!Send`, and the thread builds its own.
pub struct Boot {
    /// The board directory the module's own files live in.
    pub root: PathBuf,
    /// The module to load, e.g. `re/WCCMMUD.DLL`.
    pub module: PathBuf,
    /// The fixed channel count. Sizes every per-channel table at `Host::new`.
    pub terms: Terms,
    /// Poll dispatches granted per driver wake. See [`Host::refill_polls`].
    pub polls_per_wake: usize,
    /// Passes made per [`Host::cycle`] call.
    pub passes: usize,
}

/// What one wake yielded.
enum Woke {
    /// A message arrived.
    Message(In),
    /// Nothing arrived, which is expected: a kick came due, or there was
    /// simply nothing to do yet.
    Nothing,
    /// Every `Sender<In>` is gone. The listener and every connection task
    /// have dropped theirs, so nobody can ever send again.
    Gone,
}

/// Block, sleep, or peek, according to what the last `cycle` asked for.
///
/// Separated from [`run`] so that it can be tested at all: `run` needs a
/// booted `Machine`, and this needs only a channel.
///
/// **`Gone` is the case worth having a name.** Once every sender is dropped,
/// `recv` stops blocking and returns an error immediately, every time. A
/// driver that treated that as "nothing arrived" -- which is what a bare
/// `.ok()` does -- would spin at full speed forever under `Wait::Blocked`,
/// which is precisely the busy-wait this crate exists to remove, arriving by
/// the back door at shutdown.
fn wake(wait: Wait, rx: &std::sync::mpsc::Receiver<In>) -> Woke {
    match wait {
        Wait::Blocked => match rx.recv() {
            Ok(msg) => Woke::Message(msg),
            Err(_) => Woke::Gone,
        },
        Wait::Until(secs) => match rx.recv_timeout(Duration::from_secs(secs.into())) {
            Ok(msg) => Woke::Message(msg),
            Err(RecvTimeoutError::Timeout) => Woke::Nothing,
            Err(RecvTimeoutError::Disconnected) => Woke::Gone,
        },
        Wait::Now => match rx.try_recv() {
            Ok(msg) => Woke::Message(msg),
            Err(TryRecvError::Empty) => Woke::Nothing,
            Err(TryRecvError::Disconnected) => Woke::Gone,
        },
        Wait::Stop => Woke::Gone,
    }
}

/// Build the machine, boot the module, and drive it until [`Wait::Stop`].
///
/// This is the whole life of the host thread. It never awaits and holds
/// `&mut Machine` throughout -- that is forced, not a style choice, by the
/// three reasons in the module doc.
///
/// # Errors
///
/// If the machine cannot be built, the module cannot be loaded or entered, or
/// the module stops (a poisoned machine ends the thread; see [`Wait::Stop`]).
pub fn run(boot: Boot, rx: std::sync::mpsc::Receiver<In>) -> io::Result<()> {
    // 1. Build the machine HERE. It is !Send; it cannot be handed in.
    let mut machine = Machine::new()?;
    let mut host = Host::new(&mut machine, boot.root, boot.terms)?;
    let file = std::fs::read(&boot.module)?;
    let module = host.load(&mut machine, &file).map_err(io::Error::other)?;
    let entry = module
        .entry(1)
        .ok_or_else(|| io::Error::other("module has no ordinal 1 (the init routine)"))?;
    host.run(&mut machine, &module, entry, &[])?;
    host.finish_init(&mut machine)?;

    let terms = boot.terms;
    let mut pool = Pool::new(terms);
    let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];
    let mut wait = Wait::Now;

    loop {
        // 1. Sleep according to what the previous cycle told us to do.
        let first = match wake(wait, &rx) {
            Woke::Message(msg) => Some(msg),
            Woke::Nothing => None,
            Woke::Gone => return Ok(()),
        };

        // 2. Drain every message available, not just the one that woke us --
        //    taking one per wake would make a ten-line paste cost ten wakes.
        for msg in first
            .into_iter()
            .chain(std::iter::from_fn(|| rx.try_recv().ok()))
        {
            apply(&mut host, &mut machine, &module, &mut pool, &mut conns, msg)?;
        }

        // 3. Arm every polling channel and grant this wake's budget.
        host.refill_polls(&machine, boot.polls_per_wake)?;

        // 4. Turn the world.
        let cycles = host.cycle(&mut machine, &module, boot.passes)?;

        // 5. Everything the channels queued goes out.
        flush(&mut host, &mut machine, &module, &mut pool, &mut conns, terms)?;

        wait = cycles.ended.wait();
        if let Wait::Stop = wait {
            for conn in conns.iter().flatten() {
                let _ = conn.try_send(Out::Close);
            }
            return Err(io::Error::other(format!(
                "the module stopped: {:?}",
                cycles.ended
            )));
        }
    }
}

/// Apply one boundary message to the host.
fn apply(
    host: &mut Host,
    machine: &mut Machine,
    module: &Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    msg: In,
) -> io::Result<()> {
    match msg {
        In::Connect { who, out, reply } => {
            let Some(chan) = pool.take() else {
                // All lines busy. Whoever is waiting on `reply` is the only
                // audience -- if they are already gone (the connection task
                // died before we got here) there is nobody left to tell.
                let _ = reply.send(None);
                return Ok(());
            };
            host.connect(machine, module, chan, &who)?;
            conns[chan.index()] = Some(out);
            let _ = reply.send(Some(chan));
            Ok(())
        }
        In::Input { chan, bytes } => {
            host.gsbl_mut().push_input(chan, &bytes);
            Ok(())
        }
        In::Disconnect { chan } => {
            host.hangup(machine, module, chan)?;
            pool.give_back(chan);
            conns[chan.index()] = None;
            Ok(())
        }
    }
}

/// Send everything every channel queued, and hang up on anyone who cannot
/// take it.
fn flush(
    host: &mut Host,
    machine: &mut Machine,
    module: &Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    terms: Terms,
) -> io::Result<()> {
    for chan in terms.all() {
        let bytes = host.gsbl_mut().drain_output(chan);
        if bytes.is_empty() {
            continue;
        }
        let Some(sender) = &conns[chan.index()] else {
            // Output queued for a channel nobody is connected to. GSBL
            // cannot produce this on its own -- a channel is only ever
            // dispatched into after `Host::connect` -- but there is nowhere
            // to send it, so it is dropped rather than held.
            continue;
        };
        if sender.try_send(Out::Bytes(bytes)).is_err() {
            // Full (a client that cannot keep up) or Closed (the connection
            // task is already gone): the same treatment either way, because
            // a socket that will not drain is indistinguishable from one
            // that is gone. This is already the lost-carrier path.
            host.hangup(machine, module, chan)?;
            pool.give_back(chan);
            conns[chan.index()] = None;
            eprintln!("mbbs-server: channel {chan} dropped (could not send output), hung up");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! What these tests cannot see: `host.users` and `host.kicks` are
    //! `pub(crate)` to `mbbs`, so nothing outside that crate can call
    //! `set_polrou` or push a `Kick` -- there is no way from here to build a
    //! channel that polls, or a `Boot` whose module is anything but a real
    //! `.DLL` on disk. That means `run`'s loop, `apply`'s `Connect` success
    //! path, and `flush`'s hangup-on-full-queue path are untested here. What
    //! *is* tested is the part of `apply` that does not need a live
    //! `Host`/`Module`/`Machine` triple: a `Pool` refusing a `Connect` when
    //! empty, and a `Disconnect` returning a channel. The real coverage for
    //! the driver loop is Task 12 (two real sockets) and Task 13 (the sleep
    //! meter), both of which run against `re/WCCMMUD.DLL`.

    use mbbs::Terms;
    use tokio::sync::oneshot;

    use crate::pool::Pool;

    use super::{Woke, wake};
    use crate::msg::In;
    use mbbs::Wait;


    /// A driver whose senders are all gone must stop, not spin.
    ///
    /// This is the one part of the loop that can be tested without a booted
    /// `Machine`, and it is worth having: the plan this was built from wrote
    /// the wait step as a bare `.ok()` on each recv, which turns a dropped
    /// sender into "nothing arrived" and spins at full speed forever under
    /// `Wait::Blocked`. That is the busy-wait this whole crate exists to
    /// remove, reached by the back door at shutdown -- and no socket test
    /// finds it, because a socket test never drops its senders.
    #[test]
    fn every_wait_stops_once_the_senders_are_gone() {
        for wait in [Wait::Blocked, Wait::Until(60), Wait::Now, Wait::Stop] {
            let (tx, rx) = std::sync::mpsc::channel::<In>();
            drop(tx);
            assert!(
                matches!(wake(wait, &rx), Woke::Gone),
                "{wait:?} must report Gone, not spin"
            );
        }
    }

    /// The two "nothing arrived" answers, which must NOT be `Gone` -- a
    /// driver that shut down on an idle tick would end the board the first
    /// second nobody typed.
    #[test]
    fn an_idle_wake_is_nothing_rather_than_gone() {
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        assert!(matches!(wake(Wait::Now, &rx), Woke::Nothing));
        assert!(matches!(wake(Wait::Until(1), &rx), Woke::Nothing));
        drop(tx);
    }

    /// `apply`'s `Connect` arm, stripped of the `Host`/`Module` it would
    /// otherwise need: a pool with nothing free must answer the reply
    /// channel with `None`; it must never build a `Chan` out of thin air.
    #[tokio::test]
    async fn a_connect_against_an_empty_pool_replies_none() {
        let terms = Terms::new(1);
        let mut pool = Pool::new(terms);
        let taken = pool.take().expect("the only channel");

        // Reproduce exactly the branch `apply` takes on `pool.take() ==
        // None`, since `apply` itself needs a live `Host`.
        let (reply_tx, reply_rx) = oneshot::channel::<Option<mbbs::Chan>>();
        match pool.take() {
            Some(_) => panic!("the pool had one channel and it is already out"),
            None => {
                let _ = reply_tx.send(None);
            }
        }
        assert_eq!(reply_rx.await, Ok(None), "all lines busy");

        pool.give_back(taken);
        assert!(pool.take().is_some(), "the channel is reusable again");
    }

    /// `apply`'s `Disconnect` arm's pool half: giving a channel back makes it
    /// takeable again. (The `Host::hangup` call itself needs a live module
    /// and is not reachable from this crate's tests -- see the module doc.)
    #[test]
    fn a_disconnect_returns_its_channel_to_the_pool() {
        let terms = Terms::new(2);
        let mut pool = Pool::new(terms);
        let a = pool.take().expect("first");
        let _b = pool.take().expect("second");
        assert!(pool.take().is_none(), "both lines busy");

        pool.give_back(a);
        assert_eq!(pool.take(), Some(a), "disconnect frees the line for reuse");
    }
}
