//! The connection task and the listener.
//!
//! One `tokio::spawn`ed task per socket, speaking raw bytes. Negotiation
//! claims `SGA` and `ECHO`; a local, throwaway line editor collects the user
//! ID because no [`mbbs::Chan`] exists yet to hand that job to GSBL; then the
//! task becomes a byte pump between the socket and the host thread until
//! either end goes away.
//!
//! **`IAC WILL ECHO` is not a mistake.** GSBL echoes every accepted byte
//! itself (`crates/mbbs/src/gsbl.rs::Channel::take`, step 11), so the client
//! must be told to stay quiet. This is also what makes `btuech` work for
//! free: when the module takes echo away for a password, this task keeps
//! claiming `WILL ECHO` and simply stops writing bytes back -- the client was
//! already silent.
//!
//! **Client translation happens here, and nowhere upstream of here.** GSBL's
//! word wrap counts bytes as columns, which is only true if the bytes it
//! sees are still CP437; adapting them any earlier would hand it UTF-8 and
//! break the column math. See [`crate::termcompat`] for the translation
//! itself -- `pump` below just picks a [`Stack`] and calls it per chunk, in
//! both directions: `outbound` on the way to the socket, `inbound` on the
//! way from it.
//!
//! **`Filter::feed` must run before `Stack::inbound`, never after.**
//! `cp437::encode` can synthesize a `0xFF` byte -- CP437's non-breaking
//! space -- out of an ordinary typed character; `0xFF` also happens to be
//! telnet's `IAC`. Feeding the IAC filter the client's real bytes first
//! means it only ever sees genuine telnet commands, never one this
//! translation layer invented downstream. `pump` below gets this right, but
//! by construction rather than by anything that would stop a refactor
//! getting it wrong -- see `iac_filter_runs_before_inbound_transcode` in
//! this module's tests.
//!
//! **One host thread per machine, however many listeners.** [`serve_on`] can
//! bind more than one address -- a modern port and a period port, or several
//! of either -- but every one of them feeds the *same* set of machines'
//! senders. `A::Cpu` is `!Send` (see the crate doc): the thread that builds
//! it is the one and only owner of its machine's channels, its loaded
//! module, its Btrieve files, for the process's whole life. A listener that
//! spawned its own host thread per machine would spawn a second `A::Cpu`,
//! load the module a second time, and mint a second set of channels no other
//! listener's connections could ever reach -- two boards quietly sharing one
//! `--root` on disk, not one board with two doors into it. So
//! [`spawn_machine`] is called exactly once per machine, before any listener
//! is bound, and [`spawn_listener`] -- the per-address half -- only ever
//! receives clones of the senders it already built.
//!
//! **One machine is one host thread, and a board can run several.**
//! [`spawn_machine`] is generic over [`mbbs::abi::Abi`] since Task 20 of
//! `docs/plans/2026-08-12-abi-border-implementation.md`, and every `Chan` a
//! machine hands out (`Pool::take`, inside `host::life`) is numbered from
//! zero *within that machine* -- see `crates/mbbs-server/src/pool.rs`'s own
//! module doc for why. A board that runs more than one machine at once (a
//! 16-bit `Wg16` board and a 32-bit `Wg32` board, say -- design doc §4a's
//! staged acceptance) calls [`spawn_machine`] once per machine and hands
//! every resulting [`Machine`] to one [`serve_on`] call, so a connection is
//! identified process-wide as *(which machine's sender it holds, `Chan`)*,
//! not `Chan` alone: two machines can both have a channel zero, and only the
//! first half of that pair says which one a given `Chan` means.
//!
//! **That pairing is [`Routed`], and it is built.**
//! `crate::pool::MachineId` is the first half -- whoever builds a [`Machine`]
//! assigns one per machine (`main.rs` today: `MachineId(0)` for the always-
//! present `Wg16` board, `MachineId(1)` for an optional `Wg32` one);
//! `Pool::take` hands back the pair, never a bare `Chan`, and every message
//! this task exchanges with a host thread (`In::Connect`'s reply,
//! `In::Input`/`In::Disconnect`'s `chan` field) carries the pair too -- see
//! `crate::msg`'s module doc. A connection's identity for its whole life,
//! from [`handle`]'s `reply_rx.await` onward, is therefore already the
//! process-wide key, not a value that only happens to be unique because
//! nothing multiplexes it yet.
//!
//! **The connect-time selector is [`select_machine`], and it is deliberately
//! not a menu.** With exactly one [`Machine`], [`handle`] asks nothing at
//! all -- see [`select_machine`]'s own doc for why that case must be
//! byte-identical to a board that predates the selector entirely. With more
//! than one, it writes a single line naming each machine by its `label` and
//! reads a single keystroke; anything that keystroke does not resolve to a
//! real choice re-prompts rather than guessing, because a wrong guess
//! silently drops a player into the wrong game. This is design doc §4 point
//! 4's named next step (`docs/plans/2026-08-12-abi-border-implementation.md`
//! Task 22), landed.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;

use mbbs::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

use crate::host::{self, Boot};
use crate::iac::Filter;
use crate::msg::{In, Out};
use crate::pool::{MachineId, Routed};
use crate::termcompat::Stack;

const IAC: u8 = 255;
const WILL: u8 = 251;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

/// How many [`Out`] messages a connection's outbound queue holds before the
/// host thread treats it as wedged.
///
/// Each message is at most `OUTSIZ` (8192, `gsbl.rs`) bytes -- GSBL's own
/// output buffer refuses to grow past that and queues `OVRFLW` instead, so a
/// flush can never hand this task more than one buffer's worth at a time.
/// 32 slots is a few flushes' worth of slack (up to 256KB worst case): enough
/// to ride out a scheduling hiccup or a slow but working client without
/// piling up unbounded memory behind one bad socket. A client that is
/// genuinely wedged -- not reading at all -- fills 32 slots fast, and
/// `host::flush`'s `try_send` treats the resulting `Full` exactly like a
/// closed channel: hang up. That is the design point of a bounded channel
/// here at all.
const OUT_CHANNEL_BOUND: usize = 32;

/// The keys `crates/mbbs/tests/wccmmud.rs:3623` uses for a player who reaches
/// the Realm. This is a *default*, not a policy: [`serve`]'s `keys` parameter
/// is the actual seam, because who gets what keys is a login-backend decision
/// this crate has no business making for its caller.
///
/// **`WCCSYSOP` is in here, and that grants the sysop command set to every
/// connection.** It is deliberate and it is not a permanent answer. This host
/// is headless -- there is no logon, no `bbsusr.dat` and no `bbsk.dat`, so
/// nothing upstream of a connection has an opinion about who anyone is yet
/// (see [`mbbs::Connection::with_keys`]'s own doc on that seam). Until
/// something does, a board with no sysop at all cannot reach MajorMUD's own
/// diagnostics -- `sys configure show`, `sys list active_monsters` -- which
/// are the only way to see the module's internal state from outside, and
/// which this repository needed the moment monsters stopped respawning.
///
/// The board this serves listens on loopback. A deployment that faces anyone
/// else must pass `--keys` and leave this out: the flag exists precisely so
/// that this default never has to be the policy.
pub fn default_keys() -> Vec<String> {
    ["DEMO", "NORMAL", "USER", "WCCSYSOP"]
        .into_iter()
        .map(String::from)
        .collect()
}

/// One address [`serve`]/[`serve_on`] binds, paired with the [`Stack`]
/// constructor every connection through it gets.
pub type Listener<'a> = (&'a str, fn() -> Stack);

/// One machine a listener can route a fresh connection to: its process-wide
/// [`MachineId`] (see `crate::pool`'s module doc), a human-readable `label`
/// [`select_machine`] shows a player choosing between more than one, and the
/// sender every accepted connection uses to reach its dedicated host thread.
///
/// Built from [`spawn_machine`]'s return value, since the `tx` here is only
/// meaningful paired with a host thread actually reading the other end.
#[derive(Clone)]
pub struct Machine {
    pub id: MachineId,
    pub label: String,
    pub tx: std_mpsc::Sender<In>,
}

/// Spawn one machine's dedicated host thread and its bell, and return the
/// sender every connection routed to it uses.
///
/// This is the half of what used to be [`serve`] that has nothing to do with
/// listening: build the channel, spawn [`alarm::spawn`]'s bell task, spawn
/// the host thread. Callers wanting more than one machine on one board
/// (design doc §4a's staged acceptance -- a `Wg16` board and a `Wg32` board
/// together) call this once per machine and hand the resulting senders,
/// wrapped in [`Machine`], to [`serve_on`].
///
/// Does not block, and does not touch the network: the host thread and the
/// bell are both spawned and this returns immediately.
///
/// **Also spawns the bell.** [`host::run`]'s driver has one blocking point
/// (`rx.recv()`); everything that can wake it, including a deadline coming
/// due, arrives as a message on the returned sender's channel.
/// [`alarm::spawn`] is the task on this (async) side that turns "sleep this
/// long" requests from the host thread into [`In::Alarm`] messages back on
/// that same channel -- see its own module doc for why one more channel of
/// its own would defeat the point. It is given its own clone of the sender,
/// which -- unlike every clone a connection gets -- lives for the process's
/// whole life rather than one connection's, so [`host::run`]'s `rx` never
/// naturally observes every sender gone while this task is alive. That is
/// fine for a real board (this process runs until something kills it, never
/// by `rx` going quiet -- see `main.rs`'s `std::future::pending`); a test
/// that wants to see `run` react to every sender dropping drives it
/// directly, with a channel of its own and no bell attached
/// (`crates/mbbs-server/tests/host_supervisor.rs`).
pub fn spawn_machine<A: mbbs::abi::Abi + 'static>(boot: Boot<A>) -> std_mpsc::Sender<In> {
    let (host_tx, host_rx) = std_mpsc::channel::<In>();
    let (deadline_tx, deadline_rx) = tokio::sync::watch::channel(None);
    crate::alarm::spawn(deadline_rx, host_tx.clone());

    // `A::Cpu` is `!Send` (see the crate doc): this thread has to build its
    // own, via `Boot::build`, so all `run` gets handed in is `Boot` (paths,
    // `Terms`, numbers, and that closure -- all `Send`, see `Boot::build`'s
    // own doc for why the closure being `Send` says nothing about the
    // `A::Cpu` it produces), the receiving half of the channel every
    // listener's sender feeds, and the sending half of the deadline watch
    // the bell task above is now reading.
    //
    // `A: 'static` (this function's own bound) is what lets this closure --
    // which owns `boot: Boot<A>` -- satisfy `std::thread::spawn`'s own
    // `'static` bound; it says nothing about `A::Cpu`'s `Send`-ness either,
    // since no value of that type is ever part of the closure's captured
    // environment (see `Boot::build`'s own doc, and the module doc above).
    std::thread::spawn(move || {
        if let Err(e) = host::run::<A>(boot, host_rx, deadline_tx) {
            eprintln!("mbbs-server: host thread ended: {e}");
        }
    });

    host_tx
}

/// Spawn one machine (see [`spawn_machine`]) and bind every address in
/// `listeners` to it. A thin wrapper over [`spawn_machine`] and
/// [`serve_on`], kept for the single-machine case that predates Task 22:
/// existing callers, and every test that only ever boots one module, keep
/// working unchanged. See [`select_machine`] for why this case must stay
/// byte-identical on the wire.
pub async fn serve<A: mbbs::abi::Abi + 'static>(
    boot: Boot<A>,
    keys: Vec<String>,
    listeners: &[Listener<'_>],
) -> io::Result<Vec<SocketAddr>> {
    let id = boot.machine;
    let tx = spawn_machine(boot);
    serve_on(vec![Machine { id, label: String::new(), tx }], keys, listeners).await
}

/// Bind every address in `listeners`, each with the [`Stack`] constructor it
/// was given, and route every connection among `machines` (via
/// [`select_machine`], see [`handle`]). Returns the bound addresses in
/// `listeners`' order -- a caller binding port 0 reads back where each one
/// landed.
///
/// Does not block: every accept loop runs in its own spawned task.
pub async fn serve_on(
    machines: Vec<Machine>,
    keys: Vec<String>,
    listeners: &[Listener<'_>],
) -> io::Result<Vec<SocketAddr>> {
    let mut bound = Vec::with_capacity(listeners.len());
    for &(addr, stack) in listeners {
        bound.push(spawn_listener(addr, stack, machines.clone(), keys.clone()).await?);
    }
    Ok(bound)
}

/// Bind one address and spawn its accept loop, which hands every accepted
/// socket to [`handle`] along with `stack` -- the [`Stack`] constructor
/// *this* listener was given -- and `machines`, the full set [`handle`]'s
/// [`select_machine`] chooses among. `machines` is a clone shared with every
/// other listener [`serve_on`] binds; see the module doc for why that
/// sharing, and not a thread of its own per listener, is the point.
async fn spawn_listener(
    addr: &str,
    stack: fn() -> Stack,
    machines: Vec<Machine>,
    keys: Vec<String>,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (socket, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("mbbs-server: accept failed: {e}");
                    continue;
                }
            };
            let machines = machines.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(socket, machines, &keys, stack).await {
                    eprintln!("mbbs-server: connection ended: {e}");
                }
            });
        }
    });

    Ok(local)
}

/// One connection's whole life: negotiate, choose a machine, prompt for a
/// user ID, connect, pump bytes until either side hangs up.
///
/// `stack` is this connection's [`Stack`] constructor -- fixed by which
/// listener accepted the socket ([`spawn_listener`]'s parameter of the same
/// name), never by anything the connection itself says or does. `machines`
/// is the same list on every listener [`serve_on`] bound -- see
/// [`select_machine`] for how a connection picks one.
async fn handle(
    socket: TcpStream,
    machines: Vec<Machine>,
    keys: &[String],
    stack: fn() -> Stack,
) -> io::Result<()> {
    let (mut reader, mut writer) = socket.into_split();

    // IAC WILL SGA, IAC WILL ECHO -- see the module doc for why WILL ECHO is
    // deliberate.
    writer
        .write_all(&[IAC, WILL, OPT_SGA, IAC, WILL, OPT_ECHO])
        .await?;
    writer.flush().await?;

    let Some(host_tx) = select_machine(&machines, &mut reader, &mut writer).await? else {
        return Ok(()); // gone during the machine prompt
    };

    let Some((userid, leftover)) = read_user_id(&mut reader, &mut writer).await? else {
        return Ok(()); // gone during login
    };

    let who = Connection::ansi(&userid).with_keys(keys.iter());

    let (out_tx, out_rx) = mpsc::channel::<Out>(OUT_CHANNEL_BOUND);
    let (reply_tx, reply_rx) = oneshot::channel();
    if host_tx
        .send(In::Connect {
            who,
            out: out_tx,
            reply: reply_tx,
        })
        .is_err()
    {
        // The host thread is gone. There is no channel this connection could
        // ever be given, so this is the one place a dead host thread surfaces
        // to someone who was not already connected.
        let _ = writer
            .write_all(b"Server error, try again later.\r\n")
            .await;
        return Ok(());
    }

    // This connection's process-wide identity for the rest of its life --
    // see the module doc's "That pairing is `Routed`, and it is built."
    let routed = match reply_rx.await {
        Ok(Some(routed)) => routed,
        Ok(None) => {
            writer.write_all(b"All lines are busy.\r\n").await?;
            return Ok(());
        }
        Err(_) => {
            // The host thread died between the send above and answering --
            // the same "nothing we can do" outcome as the send failing
            // outright, just discovered one message later.
            let _ = writer
                .write_all(b"Server error, try again later.\r\n")
                .await;
            return Ok(());
        }
    };

    // Bytes that arrived pipelined behind the user ID's terminator (the same
    // TCP segment carried more than one line) must not be dropped just
    // because they showed up before a channel existed to receive them.
    if !leftover.is_empty()
        && host_tx.send(In::Input { chan: routed, bytes: leftover }).is_err()
    {
        return Ok(());
    }

    pump(reader, writer, host_tx, routed, out_rx, stack).await
}

/// Build the one-line prompt [`select_machine`] shows when there is more
/// than one [`Machine`] to choose from, e.g. `"1) MajorMUD  2) LunatiX  ? "`.
/// A free function so its exact wording has one place to change and one
/// place a test can pin.
fn machine_prompt(machines: &[Machine]) -> String {
    let mut prompt = machines
        .iter()
        .enumerate()
        .map(|(i, m)| format!("{}) {}", i + 1, m.label))
        .collect::<Vec<_>>()
        .join("  ");
    prompt.push_str("  ? ");
    prompt
}

/// Choose which [`Machine`]'s sender a fresh connection uses, before it is
/// ever asked for a user ID.
///
/// **With exactly one machine, this asks nothing at all and writes nothing
/// at all.** That is not an optimisation -- it is the whole reason this
/// function exists as a gate in front of [`handle`]'s login flow rather than
/// a menu screen bolted on unconditionally: a board that has only ever run
/// one module must stay byte-identical on the wire to the board that existed
/// before Task 22, so every test written against a single `serve` call
/// keeps passing, and so does every real player's telnet client that has
/// never seen this prompt. See `single_machine_writes_no_prompt_bytes_at_all`
/// in this module's tests.
///
/// **With more than one, one line and one keystroke -- never a menu the
/// player has to navigate.** [`machine_prompt`] is written once; the very
/// next printable byte off the wire decides. A byte that is not a digit
/// naming one of `machines`' own 1-based positions does not guess -- it
/// re-prompts, because routing a player into the wrong game silently is
/// worse than asking again. Telnet negotiation noise (bytes [`Filter::feed`]
/// already stripped, plus any surviving control byte) is not a keystroke
/// either way and is skipped without counting as an attempt.
///
/// Returns `Ok(None)` on EOF or a read error during the prompt -- the same
/// "nothing left to do" outcome [`read_user_id`] reports for the very same
/// reason, just one step earlier in a connection's life.
async fn select_machine(
    machines: &[Machine],
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
) -> io::Result<Option<std_mpsc::Sender<In>>> {
    let [only] = machines else {
        return select_among_machines(machines, reader, writer).await;
    };
    Ok(Some(only.tx.clone()))
}

/// [`select_machine`]'s prompt-and-read loop for two or more machines,
/// split out so [`select_machine`] itself stays a one-branch gate a reader
/// can see does nothing in the single-machine case without wading through
/// the loop that only matters when there is a choice to make.
async fn select_among_machines(
    machines: &[Machine],
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
) -> io::Result<Option<std_mpsc::Sender<In>>> {
    let prompt = machine_prompt(machines);

    loop {
        writer.write_all(prompt.as_bytes()).await?;
        writer.flush().await?;

        let mut filter = Filter::default();
        let mut buf = [0u8; 512];

        // `Ok(index)` is a recognised, 0-based choice; `Err(())` is a real
        // keystroke that named nothing valid. `None` means "still waiting on
        // one" and is never what this inner loop exits with -- it only ever
        // breaks once `decision` is `Some`, so the match after it has
        // nothing left to do for `None`.
        let mut decision: Option<Result<usize, ()>> = None;
        while decision.is_none() {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(None); // gone during the prompt
            }
            let bytes = filter.feed(&buf[..n]);
            for &b in &bytes {
                if !(0x20..=0x7e).contains(&b) {
                    continue; // telnet/control noise, not a keystroke
                }
                writer.write_all(&[b]).await?; // echo the one keystroke
                decision = Some(
                    (b.is_ascii_digit())
                        .then(|| (b - b'0') as usize)
                        .filter(|&n| n >= 1 && n <= machines.len())
                        .map(|n| n - 1)
                        .ok_or(()),
                );
                break;
            }
            writer.flush().await?;
        }

        writer.write_all(b"\r\n").await?;
        writer.flush().await?;

        match decision.expect("the loop above only exits once a decision is made") {
            Ok(index) => return Ok(Some(machines[index].tx.clone())),
            Err(()) => continue, // unrecognised -- re-prompt
        }
    }
}

/// The tiny line editor behind the user ID prompt.
///
/// A miniature, deliberate duplicate of one fragment of
/// `gsbl::Channel::take`: backspace/DEL erase, CR or LF terminates, printable
/// ASCII is kept, everything else is dropped. **This must not be unified with
/// `gsbl::Channel::take.`** The duplication exists only because no
/// [`mbbs::Chan`] exists yet at this point in a connection's life -- GSBL is
/// unreachable before `Host::connect` -- and it ends the instant one does:
/// [`pump`] below hands every later byte straight to the host and never edits
/// a line again.
///
/// Bytes above `0x7e` are dropped rather than reproducing GSBL's high-bit
/// strip (`gsbl.rs::translate`) byte-for-byte; a user ID is not a place a
/// stray high-bit character needs to survive, and this code is deleted the
/// moment a channel exists to do the job properly.
#[derive(Default)]
struct LineEditor {
    line: Vec<u8>,
}

/// What one already-IAC-filtered byte did to the line in progress.
enum Edit {
    /// A dropped control byte, or a backspace/DEL with nothing to erase.
    None,
    /// Echo this byte back.
    Echo(u8),
    /// A backspace erased a character; echo `\x08 \x08` to erase it visually.
    Erase,
    /// The line terminated. Everything accumulated, as lossy UTF-8 -- a user
    /// ID is compared and stored as a `String` from here on, and a login
    /// prompt is not the place to introduce a `Vec<u8>` identity that the
    /// rest of this host does not have.
    Done(String),
}

impl LineEditor {
    /// Feed one byte. Once this returns `Done`, build a fresh editor for the
    /// next line -- it does not reset itself.
    fn feed(&mut self, byte: u8) -> Edit {
        match byte {
            b'\r' | b'\n' => Edit::Done(String::from_utf8_lossy(&self.line).into_owned()),
            0x08 | 0x7f => {
                if self.line.pop().is_some() {
                    Edit::Erase
                } else {
                    Edit::None
                }
            }
            b @ 0x20..=0x7e => {
                self.line.push(b);
                Edit::Echo(b)
            }
            _ => Edit::None,
        }
    }
}

/// Prompt for a user ID and read one line, editing it locally (see
/// [`LineEditor`]).
///
/// An empty line re-prompts rather than closing the connection: a bare Enter
/// is far more likely to be a stray keystroke or leftover negotiation noise
/// than a deliberate refusal to log in, and hanging up on it would refuse
/// service to someone who has not actually done anything yet.
///
/// Returns `Ok(None)` on EOF or a read error -- there is nothing left to
/// prompt. On success, also returns whatever bytes were filtered but arrived
/// after the line's terminator in the same read, so pipelined input is not
/// silently dropped.
async fn read_user_id(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
) -> io::Result<Option<(String, Vec<u8>)>> {
    loop {
        writer.write_all(b"Enter your user ID: ").await?;
        writer.flush().await?;

        let mut filter = Filter::default();
        let mut editor = LineEditor::default();
        let mut buf = [0u8; 512];

        let (userid, leftover) = loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(None);
            }

            let bytes = filter.feed(&buf[..n]);
            let mut done = None;
            for (i, &byte) in bytes.iter().enumerate() {
                match editor.feed(byte) {
                    Edit::None => {}
                    Edit::Echo(b) => writer.write_all(&[b]).await?,
                    Edit::Erase => writer.write_all(b"\x08 \x08").await?,
                    Edit::Done(line) => {
                        writer.write_all(b"\r\n").await?;
                        done = Some((line, bytes[i + 1..].to_vec()));
                        break;
                    }
                }
            }
            writer.flush().await?;
            if let Some(result) = done {
                break result;
            }
        };

        if !userid.is_empty() {
            return Ok(Some((userid, leftover)));
        }
        // Empty: loop back and prompt again. Any bytes that were pipelined
        // behind a bare Enter are discarded along with it -- this is the one
        // corner this task does not chase, since it requires a user to type
        // nothing and something in the same breath.
    }
}

/// The byte pump: socket in one direction, [`Out`] messages in the other,
/// until either side ends.
///
/// `stack` was fixed at accept time by which listener this connection came
/// in on ([`handle`]'s parameter of the same name) -- calling it here, once,
/// is the one place a connection's transport translation is decided.
async fn pump(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    host_tx: std_mpsc::Sender<In>,
    routed: Routed,
    mut out_rx: mpsc::Receiver<Out>,
    stack: fn() -> Stack,
) -> io::Result<()> {
    let mut filter = Filter::default();
    let mut buf = [0u8; 4096];
    let mut termcompat = stack();

    loop {
        tokio::select! {
            out = out_rx.recv() => match out {
                Some(Out::Bytes(bytes)) => {
                    let text = termcompat.outbound(&bytes);
                    if writer.write_all(&text).await.is_err()
                        || writer.flush().await.is_err()
                    {
                        // The write failed -- treat it the same as a read
                        // failure: tell the host so the channel is freed
                        // promptly rather than waiting for a flush that may
                        // never come (a channel with nothing queued is never
                        // visited by `host::flush` at all).
                        let _ = host_tx.send(In::Disconnect { chan: routed });
                        return Ok(());
                    }
                }
                Some(Out::Close) | None => {
                    // The host is shutting down the whole board (`Out::Close`,
                    // sent to every connection on `Wait::Stop`) or has already
                    // dropped this channel's sender. Either way there is
                    // nobody left on the other end to tell.
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            },
            result = reader.read(&mut buf) => match result {
                Ok(0) | Err(_) => {
                    let _ = host_tx.send(In::Disconnect { chan: routed });
                    return Ok(());
                }
                Ok(n) => {
                    // Order matters: the IAC filter must see the client's
                    // real bytes before `inbound` transcodes them -- see
                    // the module doc.
                    let bytes = filter.feed(&buf[..n]);
                    let bytes = termcompat.inbound(&bytes);
                    if !bytes.is_empty()
                        && host_tx.send(In::Input { chan: routed, bytes }).is_err()
                    {
                        // The host thread is gone. Nobody will ever read
                        // another `Input` or send another `Out` -- there is
                        // nothing left for this task to do.
                        return Ok(());
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Edit, LineEditor, Machine, default_keys, pump, select_machine};

    /// A dead host thread must not leave a fresh connection hanging forever.
    ///
    /// The module here can never load (the path does not exist), so
    /// `host::run` returns before it ever reads the `In` channel. That races
    /// this test's `In::Connect` two ways -- either the send itself fails
    /// because the receiver is already dropped, or it succeeds into a queue
    /// that is then dropped, unread, along with the receiver -- and both
    /// races are exercised here (loopback is fast; which one wins is not
    /// controlled). They must converge on the same answer, because a caller
    /// cannot tell the two apart and should not have to: see `handle`'s two
    /// `Err` arms around `In::Connect`.
    #[tokio::test]
    async fn a_dead_host_thread_tells_a_fresh_connection_and_closes() {
        use std::path::PathBuf;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let root = mbbs::testing::scratch("mbbs-server-conn-dead-host");
        let boot: super::Boot<mbbs::abi::Wg16> = super::Boot {
            machine: crate::pool::MachineId(0),
            build: Box::new(mbbs_machine::m16::Machine::new),
            root,
            modules: vec![PathBuf::from("/nonexistent/NOPE.DLL")],
            terms: mbbs::Terms::new(1),
            bturno: None,
            polls_per_second: 1,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: None,
            extension: None,
        };

        let bound = super::serve(boot, default_keys(), &[("127.0.0.1:0", super::Stack::modern)])
            .await
            .expect("bind");
        let addr = bound[0];

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"nobody\r").await.expect("write userid");

        let mut received = Vec::new();
        sock.read_to_end(&mut received)
            .await
            .expect("read until the server closes the socket");
        let text = String::from_utf8_lossy(&received);

        assert!(
            text.contains("Enter your user ID: "),
            "the prompt must still appear -- the module hasn't even been asked \
             for yet when this is written: {text:?}"
        );
        assert!(
            text.contains("Server error, try again later."),
            "a host thread that died loading its module must tell a fresh \
             connection something instead of silently vanishing: {text:?}"
        );
    }

    /// Two separate invariants, because the list has two separate reasons.
    ///
    /// `DEMO`/`NORMAL`/`USER` are what a player needs to reach the Realm and
    /// come from `crates/mbbs/tests/wccmmud.rs:2450`, which is the source of
    /// truth; they are checked by containment so that this test fails if the
    /// fixture and the default ever drift apart. `WCCSYSOP` is an addition on
    /// top, checked separately because it is a deliberate local-board choice
    /// rather than anything the fixture says -- see [`default_keys`].
    ///
    /// The length check is the third invariant: without it, containment would
    /// let a fifth key in unnoticed, and a key nobody meant to grant is
    /// exactly the thing this test exists to catch.
    #[test]
    fn default_keys_holds_the_realm_fixture_plus_the_sysop_key_and_nothing_else() {
        let keys = default_keys();

        for needed in ["DEMO", "NORMAL", "USER"] {
            assert!(
                keys.iter().any(|k| k == needed),
                "crates/mbbs/tests/wccmmud.rs:2450 is the source of truth for the \
                 Realm keys, and {needed} is missing from {keys:?}"
            );
        }
        assert!(
            keys.iter().any(|k| k == "WCCSYSOP"),
            "the sysop key is deliberate -- MajorMUD's own diagnostics are \
             unreachable without it on a headless host: {keys:?}"
        );
        assert_eq!(keys.len(), 4, "no key nobody meant to grant: {keys:?}");
    }

    /// Typing builds the line and echoes every printable byte back.
    #[test]
    fn printable_bytes_are_kept_and_echoed() {
        let mut editor = LineEditor::default();
        for &b in b"rangerdan" {
            assert!(matches!(editor.feed(b), Edit::Echo(echoed) if echoed == b));
        }
        match editor.feed(b'\r') {
            Edit::Done(line) => assert_eq!(line, "rangerdan"),
            _ => panic!("CR must terminate the line"),
        }
    }

    /// LF terminates too, so a bare `\n` (no `\r`) still finishes the line.
    #[test]
    fn lf_also_terminates() {
        let mut editor = LineEditor::default();
        editor.feed(b'x');
        match editor.feed(b'\n') {
            Edit::Done(line) => assert_eq!(line, "x"),
            _ => panic!("LF must terminate the line"),
        }
    }

    /// An empty line is a legal, if useless, terminated line -- rejecting it
    /// is `read_user_id`'s job, not the editor's.
    #[test]
    fn an_empty_line_still_terminates() {
        let mut editor = LineEditor::default();
        match editor.feed(b'\r') {
            Edit::Done(line) => assert_eq!(line, ""),
            _ => panic!("CR on an empty line must still terminate"),
        }
    }

    /// Backspace erases the last byte and asks for the visual erase; at
    /// column zero there is nothing to erase and nothing to echo.
    #[test]
    fn backspace_erases_and_bottoms_out() {
        let mut editor = LineEditor::default();
        editor.feed(b'a');
        editor.feed(b'b');
        assert!(matches!(editor.feed(0x08), Edit::Erase));
        assert!(matches!(editor.feed(0x08), Edit::Erase));
        assert!(matches!(editor.feed(0x08), Edit::None), "nothing left to erase");

        match editor.feed(b'\r') {
            Edit::Done(line) => assert_eq!(line, "", "both typed bytes were erased"),
            _ => panic!(),
        }
    }

    /// DEL (0x7f) is a second spelling of backspace, exactly as GSBL's own
    /// translate table treats it.
    #[test]
    fn del_is_also_backspace() {
        let mut editor = LineEditor::default();
        editor.feed(b'z');
        assert!(matches!(editor.feed(0x7f), Edit::Erase));
        match editor.feed(b'\r') {
            Edit::Done(line) => assert_eq!(line, ""),
            _ => panic!(),
        }
    }

    /// Control bytes outside backspace/CR/LF are dropped, not stored and not
    /// echoed -- the same outcome GSBL's default translate table produces for
    /// them.
    #[test]
    fn other_control_bytes_are_dropped() {
        let mut editor = LineEditor::default();
        editor.feed(b'a');
        assert!(matches!(editor.feed(0x01), Edit::None));
        assert!(matches!(editor.feed(0x1b), Edit::None));
        match editor.feed(b'\r') {
            Edit::Done(line) => assert_eq!(line, "a", "the control bytes contributed nothing"),
            _ => panic!(),
        }
    }

    /// Bytes with the high bit set are dropped too -- see the struct doc for
    /// why this editor does not reproduce GSBL's high-bit strip byte for
    /// byte.
    #[test]
    fn high_bit_bytes_are_dropped() {
        let mut editor = LineEditor::default();
        assert!(matches!(editor.feed(0xe9), Edit::None));
    }

    /// `pump` actually applies whichever [`crate::termcompat::Stack`]
    /// constructor it is handed to every `Out::Bytes` chunk, not merely
    /// that `Stack` exists somewhere in the crate.
    ///
    /// This is the gap every `termcompat` unit test leaves open: they prove
    /// `Stack::modern()` transcodes correctly in isolation, but nothing
    /// proves `pump` is the one calling it. This test sends a high-bit CP437
    /// chunk (box drawing, plus 0x82 = 'é') straight through a real loopback
    /// `TcpStream` and `pump`, with no host thread and no module involved,
    /// and asserts the client sees the UTF-8 `Stack::modern` produces -- not
    /// the raw CP437 bytes.
    ///
    /// Since Task 5, `pump` no longer has a hardcoded default to get wrong
    /// here -- its caller decides. That wiring risk (does the raw-labelled
    /// listener actually hand `pump` `Stack::raw`?) moved up a layer, to
    /// [`serve`] and [`spawn_listener`]; see
    /// `each_port_gets_its_own_stack` below for the test that covers it.
    #[tokio::test]
    async fn pump_applies_modern_transcoding_to_every_chunk() {
        use crate::msg::{In, Out};
        use crate::termcompat::Stack;
        use textscreen::cp437;
        use std::sync::mpsc as std_mpsc;
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (reader, writer) = server.into_split();

        let (host_tx, _host_rx) = std_mpsc::channel::<In>();
        let (out_tx, out_rx) = mpsc::channel::<Out>(4);
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero of one");
        let routed = crate::pool::Routed { machine: crate::pool::MachineId(0), chan };

        let pump_task = tokio::spawn(pump(reader, writer, host_tx, routed, out_rx, Stack::modern));

        let cp437_bytes: Vec<u8> = vec![0xC9, 0xCD, 0xCD, 0xBB, 0x82, 0xBA];
        out_tx
            .send(Out::Bytes(cp437_bytes.clone()))
            .await
            .expect("queue one chunk");
        drop(out_tx); // no more chunks -- lets pump (and the client read) end

        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("read until pump closes the socket");
        pump_task.await.expect("pump task did not panic").expect("pump exited cleanly");

        let want = cp437::decode_wire(&cp437_bytes).into_bytes();
        assert_eq!(
            received, want,
            "pump must hand every Out::Bytes chunk to Stack::modern() before \
             writing it, not send the host's raw CP437 bytes unchanged"
        );
    }

    /// Task 7's pin: `pump`'s read arm must call `Filter::feed` before
    /// `Stack::inbound`, never the other way around.
    ///
    /// `cp437::encode` can synthesize a `0xFF` byte from an ordinary typed
    /// character: U+00A0 (non-breaking space), typed as UTF-8 `0xC2 0xA0`,
    /// encodes to CP437's single-byte `0xFF` -- the exact value telnet
    /// reserves for `IAC` (RFC 854). If `inbound` ran before the IAC
    /// filter, that synthesized `0xFF` would reach the filter looking
    /// exactly like the start of a genuine three-byte telnet command
    /// (`IAC WILL/WONT/DO/DONT <opt>`), and the filter would silently
    /// consume the very next byte -- the client's `X` -- as that command's
    /// option byte instead of forwarding it. This test drives the real
    /// `pump`, not `Stack::inbound` or `Filter::feed` in isolation: a
    /// primitive-level test would keep passing even if `pump`'s call order
    /// were swapped, because neither primitive enforces the other runs
    /// first -- only their order in `pump` does.
    #[tokio::test]
    async fn iac_filter_runs_before_inbound_transcode() {
        use crate::msg::{In, Out};
        use crate::termcompat::Stack;
        use std::sync::mpsc as std_mpsc;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (reader, writer) = server.into_split();

        let (host_tx, host_rx) = std_mpsc::channel::<In>();
        let (_out_tx, out_rx) = mpsc::channel::<Out>(4);
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero of one");
        let routed = crate::pool::Routed { machine: crate::pool::MachineId(0), chan };

        let _pump_task = tokio::spawn(pump(reader, writer, host_tx, routed, out_rx, Stack::modern));

        // U+00A0 (non-breaking space) as UTF-8, then a plain 'X'. Neither
        // byte is telnet's real IAC (255) -- the filter must let both
        // through untouched, and only `inbound` afterwards turns the first
        // two bytes into the single CP437 0xFF.
        client.write_all(&[0xC2, 0xA0, b'X']).await.expect("write");

        // Blocking recv (with a bound -- a pipeline that drops the bytes
        // silently, as a wrongly-ordered one does, must fail this test
        // loudly rather than hang it forever) on a std::sync::mpsc::Receiver,
        // off the async runtime thread: this test's own task must yield
        // (via `.await`) for `pump`, running as a separate tokio task on
        // the same current-thread runtime, to ever get polled and send
        // anything.
        let received = tokio::task::spawn_blocking(move || host_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("spawn_blocking did not panic")
            .expect("pump forwarded no In::Input within 5s -- the bytes were dropped");

        match received {
            In::Input { bytes, .. } => assert_eq!(
                bytes,
                vec![0xFF, b'X'],
                "the non-breaking space must encode to 0xFF and 'X' must survive \
                 intact -- if inbound ran before the IAC filter, this 0xFF would \
                 be read as IAC and 'X' would be eaten as a bogus telnet command's \
                 option byte"
            ),
            _ => panic!("expected In::Input, got a different In variant instead"),
        }
    }

    /// The wiring risk Task 5 adds: a listener started with `Stack::raw`
    /// must hand its connections `Stack::raw`, and one started with
    /// `Stack::modern` must hand its connections `Stack::modern` -- not,
    /// say, both wired to whichever constructor happened to be bound last.
    ///
    /// This is the same shared-shape trap as
    /// `pump_applies_modern_transcoding_to_every_chunk` above, one layer
    /// higher. Every test in `termcompat.rs` proves `Stack::raw()` and
    /// `Stack::modern()` transcode correctly in isolation; the test above
    /// proves `pump` applies whatever `Stack` it is *handed*. Nothing yet
    /// proves that `spawn_listener`, called once per address inside
    /// `serve_on`'s loop, actually threads listener `i`'s constructor through
    /// to listener `i`'s connections rather than, say, always the first one,
    /// or the two swapped. A mutant that ignored `stack` and always used
    /// `Stack::modern()` -- or one that zipped `listeners` against `bound`
    /// backwards -- would pass every test above and still ship the wrong
    /// stack on a live raw port.
    ///
    /// A fake host thread stands in for `host::run`: booting the real DLL
    /// module is unrelated to what this test checks (it is exercised by the
    /// `--ignored` integration tests instead). Critically, this drives
    /// `serve_on`'s *actual* zip-and-bind loop rather than hand-calling
    /// `spawn_listener` twice: an earlier version of this test did exactly
    /// that, and it would have missed a `serve_on` that hardcoded
    /// `Stack::modern()` for every entry or zipped `listeners` against
    /// `bound` off by one, because the test itself would have been doing the
    /// zipping. The fake host answers `In::Connect` with a channel and
    /// immediately pushes the *same* high-bit CP437 chunk down every
    /// connection -- the two clients seeing different bytes back can then
    /// only be explained by the transport, not the host.
    #[tokio::test]
    async fn each_port_gets_its_own_stack() {
        use crate::msg::{In, Out};
        use crate::termcompat::Stack;
        use textscreen::cp437;
        use std::sync::mpsc as std_mpsc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let (host_tx, host_rx) = std_mpsc::channel::<In>();
        let terms = mbbs::Terms::new(2);

        // The chunk every connection is sent, regardless of which port it
        // came in on: box drawing, plus 0x82 ('é'), plus a lone 0xFF -- the
        // exact byte telnet's IAC coincides with (see termcompat.rs).
        let chunk: Vec<u8> = vec![0xC9, 0xCD, 0xBB, 0x82, 0xFF, 0xBA];
        let host_chunk = chunk.clone();

        std::thread::spawn(move || {
            let mut next = 0i16;
            while let Ok(msg) = host_rx.recv() {
                if let In::Connect { out, reply, .. } = msg {
                    let chan = terms.chan(next).expect("channel in range");
                    next += 1;
                    let routed = crate::pool::Routed { machine: crate::pool::MachineId(0), chan };
                    let _ = reply.send(Some(routed));
                    // blocking_send: this is a plain std::thread, not a
                    // tokio task, so there is no async context to violate.
                    let _ = out.blocking_send(Out::Bytes(host_chunk.clone()));
                    // `out` drops here, closing the channel -- pump reads
                    // that as `Out::Close` and shuts the socket down, which
                    // is what lets each `read_to_end` below terminate.
                }
            }
        });

        let machines = vec![Machine {
            id: crate::pool::MachineId(0),
            label: String::new(),
            tx: host_tx.clone(),
        }];
        let bound = super::serve_on(
            machines,
            default_keys(),
            &[("127.0.0.1:0", Stack::modern as fn() -> Stack), ("127.0.0.1:0", Stack::raw)],
        )
        .await
        .expect("bind both listeners");
        drop(host_tx);
        let [modern_addr, raw_addr]: [std::net::SocketAddr; 2] =
            bound.try_into().expect("serve_on must return one SocketAddr per listener given");

        async fn login_and_drain(addr: std::net::SocketAddr) -> Vec<u8> {
            let mut sock = TcpStream::connect(addr).await.expect("connect");
            sock.write_all(b"tester\r").await.expect("write userid");
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.expect("read until pump closes the socket");
            received
        }

        let modern_bytes = login_and_drain(modern_addr).await;
        let raw_bytes = login_and_drain(raw_addr).await;

        // Note: both streams' *preambles* legitimately contain raw 0xFF --
        // `IAC WILL SGA`/`IAC WILL ECHO` (`handle`'s telnet negotiation) go
        // out before either `Stack` ever sees a byte, identically on both
        // ports. The chunk this test cares about is the suffix, after login.
        let modern_want = cp437::decode_wire(&chunk).into_bytes();
        assert!(
            modern_bytes.ends_with(&modern_want),
            "the modern-stack listener must hand its client Stack::modern's UTF-8, \
             not raw CP437: {modern_bytes:?}"
        );
        assert!(
            !modern_want.contains(&0xFF),
            "sanity check on the expected value itself: UTF-8 cannot contain a raw \
             0xFF byte, so cp437::decode_wire's output here never should either"
        );

        let mut raw_want = Vec::new();
        for &b in &chunk {
            raw_want.push(b);
            if b == 0xFF {
                raw_want.push(b); // IAC doubling, see termcompat.rs
            }
        }
        assert!(
            raw_bytes.ends_with(&raw_want),
            "the raw-stack listener must hand its client the host's own CP437 \
             bytes (IAC doubled), not the modern listener's UTF-8: {raw_bytes:?}"
        );

        assert_ne!(
            modern_bytes, raw_bytes,
            "the two ports fed the same host chunk but must not produce the same bytes"
        );
    }

    /// `serve` binds every listener it is given, in order: three addresses
    /// in, three distinct, live `SocketAddr`s out, each one reachable.
    ///
    /// This is the structural half of the coverage `each_port_gets_its_own_stack`
    /// leaves open -- that test proves index-to-behaviour correctness for
    /// two listeners; this one proves `serve` itself (not `spawn_listener`
    /// called by hand) binds an arbitrary count, including more than one of
    /// the same kind, and returns one address per listener rather than,
    /// say, silently dropping a duplicate address request or losing one to
    /// an off-by-one in the accumulating `Vec`.
    #[tokio::test]
    async fn serve_binds_every_listener_and_returns_addresses_in_order() {
        use crate::termcompat::Stack;
        use std::path::PathBuf;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let root = mbbs::testing::scratch("mbbs-server-conn-multi-listen");
        let boot: super::Boot<mbbs::abi::Wg16> = super::Boot {
            machine: crate::pool::MachineId(0),
            build: Box::new(mbbs_machine::m16::Machine::new),
            root,
            modules: vec![PathBuf::from("/nonexistent/NOPE.DLL")],
            terms: mbbs::Terms::new(1),
            bturno: None,
            polls_per_second: 1,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: None,
            extension: None,
        };

        let bound = super::serve(
            boot,
            default_keys(),
            &[
                ("127.0.0.1:0", Stack::modern as fn() -> Stack),
                ("127.0.0.1:0", Stack::modern),
                ("127.0.0.1:0", Stack::raw),
            ],
        )
        .await
        .expect("bind three listeners");

        assert_eq!(bound.len(), 3, "one SocketAddr back per listener given");
        assert_ne!(bound[0], bound[1], "two independently bound port-0 listeners must differ");
        assert_ne!(bound[1], bound[2]);
        assert_ne!(bound[0], bound[2]);

        // Every returned address is genuinely live: connecting and reading
        // the login prompt confirms `bound[i]` really is listener `i`'s own
        // socket, not a stale or unbound placeholder.
        for addr in &bound {
            let mut sock = TcpStream::connect(addr).await.expect("connect");
            let mut buf = [0u8; 128];
            let n = sock.read(&mut buf).await.expect("read greeting");
            assert!(n > 0, "listener at {addr} accepted but sent nothing");
        }
    }

    /// Build a throwaway [`Machine`] wrapping a fresh `std::sync::mpsc`
    /// channel, so a test can inspect exactly what [`In::Connect`] a
    /// selection routed to, without a real host thread.
    fn fake_machine(
        id: u16,
        label: &str,
    ) -> (Machine, std::sync::mpsc::Receiver<crate::msg::In>) {
        let (tx, rx) = std::sync::mpsc::channel::<crate::msg::In>();
        (Machine { id: crate::pool::MachineId(id), label: label.to_string(), tx }, rx)
    }

    /// Task 22's central guarantee: with exactly one [`Machine`], the
    /// connect-time selector writes *nothing at all* to the wire before the
    /// user ID prompt -- not even a suppressed prompt, not a blank line.
    ///
    /// This is checked byte-exactly against a real loopback socket driving
    /// [`select_machine`] directly, so a mutation that always printed
    /// `machine_prompt`'s line (even for one machine) or that echoed
    /// anything at all on this path would fail here even though every other
    /// test in this file only ever exercises the one-machine case through
    /// `handle`, where a prompt's absence is easy to miss inside a longer
    /// transcript.
    #[tokio::test]
    async fn single_machine_writes_no_prompt_bytes_at_all() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (mut reader, mut writer) = server.into_split();

        let (machine, _rx) = fake_machine(0, "MajorMUD");
        let machines = vec![machine];

        let selected = select_machine(&machines, &mut reader, &mut writer)
            .await
            .expect("no I/O error")
            .expect("the only machine is chosen without any read at all");

        // Nothing was ever written server-side before this point returned,
        // and nothing needs to be read from the client either -- prove it by
        // writing a sentinel from the client and confirming the server's
        // `writer` produced zero bytes for `select_machine` to have raced
        // against: shut the write half down and read the client's own
        // socket to end-of-stream immediately.
        drop(writer);
        drop(selected);
        client.write_all(b"anything\r").await.expect("client write");
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.expect("read to EOF");
        assert!(
            received.is_empty(),
            "the single-machine path must write no prompt bytes at all: {received:?}"
        );
    }

    /// Two machines: selecting `"1"` routes to the first machine's sender
    /// and never the second's.
    #[tokio::test]
    async fn selecting_one_routes_to_the_first_machine() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (mut reader, mut writer) = server.into_split();

        let (machine_a, _rx_a) = fake_machine(0, "MajorMUD");
        let (machine_b, _rx_b) = fake_machine(1, "LunatiX");
        let machines = vec![machine_a, machine_b];

        let select_task =
            tokio::spawn(async move { select_machine(&machines, &mut reader, &mut writer).await });

        let mut prompt_buf = [0u8; 128];
        let n = client.read(&mut prompt_buf).await.expect("read the prompt");
        assert_eq!(
            &prompt_buf[..n],
            b"1) MajorMUD  2) LunatiX  ? ",
            "the prompt must name both machines, in order, before any keystroke"
        );

        client.write_all(b"1").await.expect("select the first machine");

        let chosen = select_task
            .await
            .expect("select_machine task did not panic")
            .expect("no I/O error")
            .expect("a recognised selection must return a sender");

        // Send an In::Connect down the sender select_machine returned and
        // confirm it lands on machine 0's receiver, not machine 1's.
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let who = mbbs::Connection::ansi("tester");
        chosen
            .send(crate::msg::In::Connect { who, out: out_tx, reply: reply_tx })
            .expect("machine 0's receiver is still alive");

        let received = _rx_a.try_recv().expect("machine 0's receiver got the Connect");
        assert!(matches!(received, crate::msg::In::Connect { .. }));
        assert!(
            _rx_b.try_recv().is_err(),
            "machine 1's receiver must not have seen anything at all"
        );
    }

    /// The mirror of the test above: selecting `"2"` routes to the second
    /// machine's sender and never the first's.
    ///
    /// Together, these two tests are what a mutation swapping the routing
    /// lookup (making selection `"2"` pick index 0, say) would fail --
    /// exactly the mutation this task's brief calls out.
    #[tokio::test]
    async fn selecting_two_routes_to_the_second_machine() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (mut reader, mut writer) = server.into_split();

        let (machine_a, _rx_a) = fake_machine(0, "MajorMUD");
        let (machine_b, _rx_b) = fake_machine(1, "LunatiX");
        let machines = vec![machine_a, machine_b];

        let select_task =
            tokio::spawn(async move { select_machine(&machines, &mut reader, &mut writer).await });

        client.write_all(b"2").await.expect("select the second machine");

        let chosen = select_task
            .await
            .expect("select_machine task did not panic")
            .expect("no I/O error")
            .expect("a recognised selection must return a sender");

        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let who = mbbs::Connection::ansi("tester");
        chosen
            .send(crate::msg::In::Connect { who, out: out_tx, reply: reply_tx })
            .expect("machine 1's receiver is still alive");

        let received = _rx_b.try_recv().expect("machine 1's receiver got the Connect");
        assert!(matches!(received, crate::msg::In::Connect { .. }));
        assert!(
            _rx_a.try_recv().is_err(),
            "machine 0's receiver must not have seen anything at all"
        );
    }

    /// A selection that names nothing valid -- here, `"9"` with only two
    /// machines on offer -- re-prompts rather than routing anywhere; only
    /// the second, valid keystroke actually picks a machine.
    #[tokio::test]
    async fn an_unrecognised_selection_reprompts_instead_of_guessing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (mut reader, mut writer) = server.into_split();

        let (machine_a, _rx_a) = fake_machine(0, "MajorMUD");
        let (machine_b, _rx_b) = fake_machine(1, "LunatiX");
        let machines = vec![machine_a, machine_b];

        let select_task =
            tokio::spawn(async move { select_machine(&machines, &mut reader, &mut writer).await });

        let mut buf = [0u8; 128];
        let n = client.read(&mut buf).await.expect("read the first prompt");
        assert_eq!(&buf[..n], b"1) MajorMUD  2) LunatiX  ? ");

        // "9" names nothing -- neither machine 1 nor machine 2. The echo,
        // the CRLF, and the re-printed prompt are three separate writer
        // calls (see `select_among_machines`), so they can arrive as more
        // than one TCP segment -- read until exactly as many bytes as
        // expected have shown up rather than assuming one `read` gets all
        // of them.
        client.write_all(b"9").await.expect("send an out-of-range digit");
        let want = b"9\r\n1) MajorMUD  2) LunatiX  ? ";
        let mut got = Vec::new();
        while got.len() < want.len() {
            let n = client.read(&mut buf).await.expect("read the echoed digit, CRLF, and re-prompt");
            assert!(n > 0, "the connection closed before the re-prompt finished arriving");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            got, want,
            "an unrecognised selection must echo, terminate the line, and show \
             the exact same prompt again -- not silently guess a machine"
        );

        // Now send a real selection and confirm the connection still
        // resolves correctly -- the bad keystroke must not have wedged
        // anything.
        client.write_all(b"2").await.expect("select the second machine this time");
        let chosen = select_task
            .await
            .expect("select_machine task did not panic")
            .expect("no I/O error")
            .expect("the second attempt must succeed");

        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(1);
        let who = mbbs::Connection::ansi("tester");
        chosen
            .send(crate::msg::In::Connect { who, out: out_tx, reply: reply_tx })
            .expect("machine 1's receiver is still alive");
        assert!(_rx_b.try_recv().is_ok(), "the eventual valid selection must still route correctly");
        assert!(_rx_a.try_recv().is_err());
    }

    /// A disconnect mid-prompt (EOF before any keystroke arrives) must
    /// return `Ok(None)`, not panic and not hang -- the same contract
    /// `read_user_id` gives `handle` one step later.
    #[tokio::test]
    async fn a_disconnect_during_the_prompt_is_handled_cleanly() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _peer) = listener.accept().await.expect("accept");
        let (mut reader, mut writer) = server.into_split();

        let (machine_a, _rx_a) = fake_machine(0, "MajorMUD");
        let (machine_b, _rx_b) = fake_machine(1, "LunatiX");
        let machines = vec![machine_a, machine_b];

        drop(client); // disconnect before typing anything

        let result = select_machine(&machines, &mut reader, &mut writer).await;
        assert!(matches!(result, Ok(None)), "a disconnect mid-prompt must be Ok(None), not an error: {result:?}");
    }
}
