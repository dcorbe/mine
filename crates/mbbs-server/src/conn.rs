//! The connection task and the listener.
//!
//! One `tokio::spawn`ed task per socket, speaking raw bytes. Negotiation
//! claims `SGA` and `ECHO`; a local, throwaway line editor collects the
//! login dialogue's lines because no [`mbbs::Chan`] exists yet to hand that
//! job to GSBL; then the task becomes a byte pump between the socket and
//! the host thread until either end goes away.
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
//! **Telnet framing is a property of the wire, so `Stack` owns it, not
//! `pump`.** `cp437::encode` can synthesize a `0xFF` byte -- CP437's
//! non-breaking space -- out of an ordinary typed character; `0xFF` also
//! happens to be telnet's `IAC`. `Stack::inbound` runs its own telnet
//! filter before any transcoding for exactly this reason, so `pump` has no
//! ordering to get wrong -- see `iac_filter_runs_before_inbound_transcode`
//! in this module's tests and `termcompat::Stack::inbound`'s doc comment.
//!
//! **One host thread, however many listeners.** [`serve_on`] can bind more
//! than one address -- a modern port and a period port, or several of either
//! -- but every one of them feeds the *same* machine's sender. `A::Cpu` is
//! `!Send` (see the crate doc): the thread that builds it is the one and
//! only owner of its machine's channels, its loaded module, its Btrieve
//! files, for the process's whole life. A listener that spawned its own host
//! thread would spawn a second `A::Cpu`, load the module a second time, and
//! mint a second set of channels no other listener's connections could ever
//! reach -- two boards quietly sharing one `--root` on disk, not one board
//! with two doors into it. So [`spawn_machine`] is called exactly once, before
//! any listener is bound, and [`spawn_listener`] -- the per-address half --
//! only ever receives clones of the sender it already built.
//!
//! **One machine is one host thread, one process.** [`spawn_machine`] is
//! generic over [`mbbs::abi::Abi`] since Task 20 of
//! `docs/plans/2026-08-12-abi-border-implementation.md`, and every `Chan` a
//! machine hands out (`Pool::take`, inside `host::life`) is numbered from
//! zero -- see `crates/mbbs-server/src/pool.rs`'s own module doc for why.
//!
//! **One `serve_on` call serves one machine.** A connection goes from telnet
//! negotiation straight to the user-ID prompt -- nothing in between. What
//! follows that prompt is [`login_dialogue`]: a password, and, for a name
//! the board has never seen, the offer to create the account.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;

use mbbs::{Chan, Login, Terminal};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

use crate::host::{self, Boot};
use crate::iac::Filter;
use crate::msg::{In, Out};
use crate::termcompat::Stack;

const IAC: u8 = 255;
const WILL: u8 = 251;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

/// How many [`Out`] messages a connection's outbound queue holds before the
/// host thread stops handing it more and holds output in GSBL instead.
///
/// Each message is at most `OUTSIZ` (8192, `gsbl.rs`) bytes -- GSBL's own
/// output buffer refuses to grow past that and queues `OVRFLW` instead, so a
/// flush can never hand this task more than one buffer's worth at a time.
/// 32 slots is a few flushes' worth of slack (up to 256KB worst case): enough
/// to ride out a scheduling hiccup or a slow but working client without
/// piling up unbounded memory behind one bad socket.
///
/// A full queue is **backpressure, not a hangup**: `host::offer` leaves the
/// channel's output in GSBL -- where it coalesces with whatever the module
/// queues next, and where `OVRFLW` backpressures the module itself, exactly
/// the real host's own flow control -- and only a `Closed` queue (the
/// socket really gone) hangs the channel up. It used to be a hangup
/// (`Full` treated like `Closed`), which made a burst of tiny writes
/// lethal: see `host::offer`'s own doc comment for the measured
/// character-creation drop that retired that rule.
pub(crate) const OUT_CHANNEL_BOUND: usize = 32;

/// How many refusals a caller earns before the connection ends. Spec
/// section 2.
pub(crate) const MAX_REFUSALS: usize = 3;

/// The login dialogue, word for word. Spec section 2.
///
/// Constants rather than literals at their one call site each, so the whole
/// script can be read (and diffed) in one place: a caller's screen is a
/// contract, and a prompt that quietly loses its trailing space is not the
/// kind of change anybody notices in a diff of `login_dialogue`.
const USERID_PROMPT: &[u8] = b"Enter your user ID: ";
const PASSWORD_PROMPT: &[u8] = b"Enter your password: ";
const CREATE_PROMPT: &[u8] = b"No account by that name. Create one? [y/n] ";
const CHOOSE_PROMPT: &[u8] = b"Choose a password (1 to 9 characters): ";
const AGAIN_PROMPT: &[u8] = b"Enter it again: ";
const MISMATCH_LINE: &[u8] = b"Passwords do not match.\r\n";
const TOO_MANY_LINE: &[u8] = b"Too many tries.\r\n";

/// The one thing a listener says that is not about the caller at all: the
/// host thread this process is built around is gone, so there is no board
/// to be let onto.
pub(crate) const SERVER_ERROR_LINE: &[u8] = b"Server error, try again later.\r\n";

/// What a telnet caller's terminal is taken to be: what the wire says, not
/// what the account remembers -- `Host::login` applies these on top of the
/// record it loads. Nothing in the telnet dialogue negotiates size or
/// colour, so this is the 80x24 ANSI screen the modules assume.
const TELNET_TERMINAL: Terminal = Terminal { ansi: true, width: 80, height: 24 };

/// What a caller is told while maintenance is running.
pub(crate) const MAINTENANCE_LINE: &[u8] = b"The system is down for daily maintenance. Try again in a few minutes.\r\n";

/// The ring a new account is written with: what a player needs to reach the
/// Realm and nothing more (`crates/mbbs/tests/wccmmud.rs:2450`).
///
/// This is not what a connection holds. It reaches [`mbbs::Host`] as
/// [`crate::host::Boot::default_ring`] and is read exactly once per
/// account, when a claim provisions one that does not exist yet; every
/// later login for that account reads its ring out of the key file, where
/// the sysop's own edits live. So changing this changes nothing for anyone
/// who has logged in before.
///
/// `SYSOP` and `WCCSYSOP` used to be here, because a headless host with no
/// accounts had no other way to reach MajorMUD's own diagnostics. There is
/// a logon now: `Host::resolve_login` adds the sysop keys to a
/// `Login::Trusted { sysop: true }` claim, which is what the BBS in front
/// of the door says about its own sysop, and the `mbbs-user` CLI grants
/// them to an account for good. Handing them to every caller is no longer
/// the only way, so it is no longer the default.
pub fn default_keys() -> Vec<String> {
    ["DEMO", "NORMAL", "USER"].into_iter().map(String::from).collect()
}

/// One line per refusal, for every listener -- telnet, the door, and
/// rlogin. Spec section 5.
///
/// The whole vocabulary is here rather than at each call site so the three
/// listeners cannot drift into three different wordings for the same
/// answer, and so a new [`mbbs::Refusal`] cannot be added without this
/// match refusing to compile.
///
/// `Cow`, because [`mbbs::Refusal::Invalid`] carries the reason the account
/// layer wrote -- "a user ID is at most 29 characters", say -- and that is
/// the only one that has to be built rather than pointed at.
#[must_use]
pub fn refusal_line(r: mbbs::Refusal) -> Cow<'static, [u8]> {
    use mbbs::Refusal as R;
    match r {
        R::Unknown => Cow::Borrowed(b"No account by that name.\r\n"),
        R::BadPassword => Cow::Borrowed(b"Invalid password.\r\n"),
        R::NoPassword => {
            Cow::Borrowed(b"That account has no password yet. Ask the sysop to set one.\r\n")
        }
        R::Exists => Cow::Borrowed(b"That user ID is taken.\r\n"),
        R::Deleted => Cow::Borrowed(b"That account has been deleted.\r\n"),
        R::Suspended => Cow::Borrowed(b"That account is suspended.\r\n"),
        R::Full => Cow::Borrowed(b"All lines are busy.\r\n"),
        R::Maintenance => Cow::Borrowed(MAINTENANCE_LINE),
        R::Invalid(why) => Cow::Owned(format!("{why}\r\n").into_bytes()),
    }
}

/// One address [`serve`]/[`serve_on`] binds, paired with the [`Stack`]
/// constructor every connection through it gets.
pub type Listener<'a> = (&'a str, fn() -> Stack);

/// Spawn one machine's dedicated host thread and its bell, and return the
/// sender every connection routed to it uses.
///
/// This is the half of what used to be [`serve`] that has nothing to do with
/// listening: build the channel, spawn [`alarm::spawn`]'s bell task, spawn
/// the host thread.
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
/// [`serve_on`], kept for callers that build their own `Boot` -- every
/// integration test does.
pub async fn serve<A: mbbs::abi::Abi + 'static>(
    boot: Boot<A>,
    listeners: &[Listener<'_>],
) -> io::Result<Vec<SocketAddr>> {
    let serving = boot.serving.clone();
    serve_on(spawn_machine(boot), listeners, serving).await
}

/// Bind every listener in front of the one machine `host_tx` reaches.
/// Returns the bound addresses in `listeners`' order -- a caller binding
/// port 0 reads back where each one landed.
///
/// Does not block: every accept loop runs in its own spawned task.
pub async fn serve_on(
    host_tx: std_mpsc::Sender<In>,
    listeners: &[Listener<'_>],
    serving: crate::host::Serving,
) -> io::Result<Vec<SocketAddr>> {
    let mut bound = Vec::with_capacity(listeners.len());
    for &(addr, stack) in listeners {
        bound.push(spawn_listener(addr, stack, host_tx.clone(), serving.clone()).await?);
    }
    Ok(bound)
}

/// Bind one address and spawn its accept loop, which hands every accepted
/// socket to [`handle`] along with `stack` -- the [`Stack`] constructor
/// *this* listener was given -- and a clone of `host_tx`, the sender every
/// connection through this listener uses to reach the one machine.
async fn spawn_listener(
    addr: &str,
    stack: fn() -> Stack,
    host_tx: std_mpsc::Sender<In>,
    serving: crate::host::Serving,
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
            let host_tx = host_tx.clone();
            let serving = serving.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(socket, host_tx, stack, serving).await {
                    eprintln!("mbbs-server: connection ended: {e}");
                }
            });
        }
    });

    Ok(local)
}

/// One connection's whole life: negotiate, take the caller through the
/// login dialogue, pump bytes until either side hangs up.
///
/// `stack` is this connection's [`Stack`] constructor -- fixed by which
/// listener accepted the socket ([`spawn_listener`]'s parameter of the same
/// name), never by anything the connection itself says or does. `host_tx` is
/// the same sender on every listener [`serve_on`] bound.
async fn handle(
    socket: TcpStream,
    host_tx: std_mpsc::Sender<In>,
    stack: fn() -> Stack,
    serving: crate::host::Serving,
) -> io::Result<()> {
    let (mut socket_reader, mut writer) = socket.into_split();

    // IAC WILL SGA, IAC WILL ECHO -- see the module doc for why WILL ECHO is
    // deliberate.
    writer.write_all(&[IAC, WILL, OPT_SGA, IAC, WILL, OPT_ECHO]).await?;
    writer.flush().await?;

    if !serving.load(std::sync::atomic::Ordering::Relaxed) {
        writer.write_all(&refusal_line(mbbs::Refusal::Maintenance)).await?;
        return Ok(());
    }

    let mut reader = Reader::new(&mut socket_reader);
    let Some((chan, out_rx, leftover)) =
        login_dialogue(&mut reader, &mut writer, &host_tx).await?
    else {
        // Refused, out of tries, or gone. Whoever is still on the other end
        // has already been told which.
        return Ok(());
    };

    // Bytes that arrived pipelined behind the accepted line's terminator
    // (the same TCP segment carried more than one line) must not be dropped
    // just because they showed up before a channel existed to receive them.
    if !leftover.is_empty()
        && host_tx.send(In::Input { chan, bytes: leftover }).is_err()
    {
        return Ok(());
    }

    pump(socket_reader, writer, host_tx, chan, out_rx, stack).await
}

/// The whole login dialogue, from the first prompt to a channel. Spec
/// section 2.
///
/// `Ok(None)` means this connection is over: the caller ran out of tries,
/// hit a refusal there is no point retrying, or went away. Whoever is still
/// listening has already been told which. `Ok(Some(..))` is a live channel,
/// the queue the host thread will write to, and whatever bytes arrived
/// pipelined behind the line that won it.
///
/// The steps below are the dialogue in order. Two rules hold across all of
/// them:
///
/// - **What counts.** `refusals` is the only thing that stops a caller
///   guessing forever. Every refusal the board answers with counts, a line
///   the account record cannot hold counts, and a signup whose two
///   passwords differ counts. Two things do not: an unknown name, which
///   becomes the offer below rather than a refusal, and declining that
///   offer, where nothing was refused and the caller simply changed their
///   mind. The [`MAX_REFUSALS`]th counted try ends the connection.
/// - **`Full` and `Maintenance` end it instead of counting.** Neither is
///   anything the caller could have typed differently, so a retry would
///   only invite them to fail again -- and spending a caller's tries on the
///   board's own state would close the connection on someone who had done
///   nothing wrong.
async fn login_dialogue(
    reader: &mut Reader<'_>,
    writer: &mut OwnedWriteHalf,
    host_tx: &std_mpsc::Sender<In>,
) -> io::Result<Option<(Chan, mpsc::Receiver<Out>, Vec<u8>)>> {
    use mbbs::Refusal as R;
    use mbbs::accounts::{PSWSIZ, UIDSIZ, validate_password, validate_userid};

    let mut refusals = 0usize;

    loop {
        // Step 1: who is this?
        let Some(userid) = read_line(reader, writer, USERID_PROMPT, true).await? else {
            return Ok(None);
        };
        if let Some(refusal) = too_long(&userid, UIDSIZ - 1, validate_userid) {
            if refuse(reader, writer, &mut refusals, &refusal_line(refusal)).await? {
                return Ok(None);
            }
            continue;
        }

        // Step 2: prove it. Not echoed -- see `read_line`'s `echo`.
        let Some(password) = read_line(reader, writer, PASSWORD_PROMPT, false).await? else {
            return Ok(None);
        };
        if let Some(refusal) = too_long(&password, PSWSIZ - 1, validate_password) {
            if refuse(reader, writer, &mut refusals, &refusal_line(refusal)).await? {
                return Ok(None);
            }
            continue;
        }

        // Step 3: ask the board. It owns the account file, so it -- not
        // this listener -- decides whether this is anybody.
        let claim = Login::Password { userid: userid.clone(), password };
        match claim_channel(host_tx, claim, TELNET_TERMINAL, writer).await? {
            None => return Ok(None),
            Some(Ok((chan, out_rx))) => {
                return Ok(Some((chan, out_rx, std::mem::take(&mut reader.pending))));
            }
            // Not a refusal on the wire: an unknown name is the one answer
            // this listener turns into an offer, so the caller sees the
            // create prompt below instead of a goodbye.
            Some(Err(R::Unknown)) => {}
            Some(Err(refusal @ (R::Full | R::Maintenance))) => {
                writer.write_all(&refusal_line(refusal)).await?;
                writer.flush().await?;
                return Ok(None);
            }
            Some(Err(refusal)) => {
                if refuse(reader, writer, &mut refusals, &refusal_line(refusal)).await? {
                    return Ok(None);
                }
                continue;
            }
        }

        // Step 4: the offer. Anything but `y` starts over, uncounted -- and
        // an empty line is an answer here, which is why this is the one
        // prompt that does not re-ask on one (see `read_line`). Nothing was
        // refused, so nothing pipelined behind the answer is dropped
        // either: a caller who typed a whole second login behind their `n`
        // meant it for the prompt they are about to see.
        let Some(answer) = prompt_once(reader, writer, CREATE_PROMPT, true).await? else {
            return Ok(None);
        };
        if !matches!(answer.as_str(), "y" | "Y") {
            continue;
        }

        // Step 5: a new password, twice, neither echoed.
        let Some(chosen) = read_line(reader, writer, CHOOSE_PROMPT, false).await? else {
            return Ok(None);
        };
        if let Some(refusal) = too_long(&chosen, PSWSIZ - 1, validate_password) {
            if refuse(reader, writer, &mut refusals, &refusal_line(refusal)).await? {
                return Ok(None);
            }
            continue;
        }
        let Some(again) = read_line(reader, writer, AGAIN_PROMPT, false).await? else {
            return Ok(None);
        };
        if again != chosen {
            if refuse(reader, writer, &mut refusals, MISMATCH_LINE).await? {
                return Ok(None);
            }
            continue;
        }

        // Step 6: claim the new account. The board still has the last word
        // -- the name may be reserved, or somebody may have taken it
        // between step 3 and here.
        let claim = Login::Signup { userid, password: chosen };
        match claim_channel(host_tx, claim, TELNET_TERMINAL, writer).await? {
            None => return Ok(None),
            Some(Ok((chan, out_rx))) => {
                return Ok(Some((chan, out_rx, std::mem::take(&mut reader.pending))));
            }
            Some(Err(refusal @ (R::Full | R::Maintenance))) => {
                writer.write_all(&refusal_line(refusal)).await?;
                writer.flush().await?;
                return Ok(None);
            }
            Some(Err(refusal)) => {
                if refuse(reader, writer, &mut refusals, &refusal_line(refusal)).await? {
                    return Ok(None);
                }
                continue;
            }
        }
    }
}

/// One counted refusal: say which one it was, drop anything pipelined
/// behind the line that earned it, and answer whether that was the last
/// try.
///
/// **The pipelined bytes go.** A caller who typed ahead was typing ahead of
/// a dialogue that has just restarted; feeding those bytes to the fresh
/// user ID prompt would spend their remaining tries on lines they meant for
/// prompts that are no longer on screen. This is the same rule an empty
/// line has always had (see [`read_line`]).
///
/// `line` rather than a [`mbbs::Refusal`] because not every counted
/// refusal has one: two signup passwords that differ are refused here, in
/// this listener's own words, and never reach the board at all.
async fn refuse(
    reader: &mut Reader<'_>,
    writer: &mut OwnedWriteHalf,
    refusals: &mut usize,
    line: &[u8],
) -> io::Result<bool> {
    writer.write_all(line).await?;
    writer.flush().await?;
    reader.pending.clear();

    *refusals += 1;
    if *refusals >= MAX_REFUSALS {
        writer.write_all(TOO_MANY_LINE).await?;
        writer.flush().await?;
        return Ok(true);
    }
    Ok(false)
}

/// The one refusal a listener makes on its own: a line longer than the
/// field the account record keeps it in.
///
/// There is nothing to ask the board about -- the record cannot hold it,
/// whoever it names -- and asking would spend a channel (`Pool::take`, then
/// `give_back`) to be told so. The *words*, though, are the account
/// layer's: `validate` is called for them rather than a string being
/// spelled out here, so this listener can never tell a caller something
/// different from what the same line would have been refused with one layer
/// down.
fn too_long(
    line: &str,
    limit: usize,
    validate: fn(&str) -> Result<(), mbbs::Refusal>,
) -> Option<mbbs::Refusal> {
    if line.len() <= limit {
        return None;
    }
    validate(line).err()
}

/// Send one claim to the host thread and wait for the board's answer.
///
/// Every listener -- telnet, the door, and Task 13's rlogin -- makes this
/// same round trip, and the two ways it can end badly are the same for all
/// of them, which is why they are here rather than at each call site:
///
/// - `Ok(None)`: the host thread is gone, either before the message was
///   taken or between that and the answer. The caller cannot tell those two
///   apart and there is nothing either of them could do differently, so
///   both write `Server error, try again later.` and end the connection.
/// - `Ok(Some(Err(refusal)))`: the board said no. **The wire line is not
///   written here.** Telnet turns [`mbbs::Refusal::Unknown`] into a signup
///   offer rather than a goodbye, and counts some refusals and not others,
///   so which refusals become a line -- and which become a prompt -- is the
///   listener's decision. [`refusal_line`] is the shared vocabulary it
///   makes that decision with.
///
/// The `Sender<Out>` half of the queue goes to the host with the claim; the
/// `Receiver` comes back beside the channel, for [`pump`].
pub(crate) async fn claim_channel<W: AsyncWrite + Unpin>(
    host_tx: &std_mpsc::Sender<In>,
    login: Login,
    terminal: Terminal,
    writer: &mut W,
) -> io::Result<Option<Result<(Chan, mpsc::Receiver<Out>), mbbs::Refusal>>> {
    let (out_tx, out_rx) = mpsc::channel::<Out>(OUT_CHANNEL_BOUND);
    let (reply_tx, reply_rx) = oneshot::channel();

    if host_tx
        .send(In::Connect { login, terminal, out: out_tx, reply: reply_tx })
        .is_err()
    {
        let _ = writer.write_all(SERVER_ERROR_LINE).await;
        return Ok(None);
    }

    match reply_rx.await {
        Ok(Ok(chan)) => Ok(Some(Ok((chan, out_rx)))),
        Ok(Err(refusal)) => Ok(Some(Err(refusal))),
        Err(_) => {
            // The host thread died between the send above and answering --
            // the same "nothing we can do" outcome as the send failing
            // outright, just discovered one message later.
            let _ = writer.write_all(SERVER_ERROR_LINE).await;
            Ok(None)
        }
    }
}

/// The tiny line editor behind every prompt in the login dialogue.
///
/// A miniature, deliberate duplicate of one fragment of
/// `gsbl::Channel::take`: backspace/DEL erase, CR or LF terminates, printable
/// ASCII is kept, everything else is dropped. **This must not be unified with
/// `gsbl::Channel::take.`** The duplication exists only because no
/// [`mbbs::Chan`] exists yet at this point in a connection's life -- GSBL is
/// unreachable before a channel is claimed -- and it ends the instant one
/// exists: [`pump`] below hands every later byte straight to the host and
/// never edits a line again.
///
/// Bytes above `0x7e` are dropped rather than reproducing GSBL's high-bit
/// strip (`gsbl.rs::translate`) byte-for-byte; neither a user ID nor a
/// password is a place a stray high-bit character needs to survive (the
/// account layer's own `validate_password` refuses one anyway), and this
/// code is deleted the moment a channel exists to do the job properly.
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

/// The reading half of the login dialogue.
///
/// Three things have to live longer than one prompt, which is why they are
/// a struct rather than three locals inside a read:
///
/// - the socket, obviously;
/// - the telnet [`Filter`], because an `IAC` sequence can straddle the byte
///   that ends a line, and a filter rebuilt per prompt would forget the
///   half it was holding;
/// - `pending`, the bytes that arrived in the same `read()` as the last
///   line's terminator. A caller who sends `Dan\rhunter2\r` in one write
///   has already answered the password prompt before it was printed, and
///   those bytes have to feed it rather than be dropped or waited on.
struct Reader<'a> {
    socket: &'a mut OwnedReadHalf,
    filter: Filter,
    /// Filtered bytes left over from the last line. Consumed by the next
    /// prompt, cleared by anything that refuses a line (see [`refuse`]).
    pending: Vec<u8>,
}

impl<'a> Reader<'a> {
    fn new(socket: &'a mut OwnedReadHalf) -> Self {
        Self { socket, filter: Filter::default(), pending: Vec::new() }
    }
}

/// Print `prompt` and read one line, editing it locally (see
/// [`LineEditor`]), re-asking until the line is not empty.
///
/// An empty line re-prompts rather than closing the connection: a bare
/// Enter is far more likely to be a stray keystroke or leftover negotiation
/// noise than a deliberate refusal to log in, and hanging up on it would
/// refuse service to someone who has not actually done anything yet. Any
/// bytes pipelined behind a bare Enter are discarded along with it -- this
/// is the one corner this task does not chase, since it requires a user to
/// type nothing and something in the same breath.
///
/// The one prompt that must not re-ask is the offer to create an account,
/// where an empty line is an answer ("no"); it calls [`prompt_once`]
/// directly.
///
/// `echo` is what makes a password prompt a password prompt: with it off,
/// nothing typed is written back -- not the characters ([`Edit::Echo`]) and
/// not a backspace's visual erase ([`Edit::Erase`]), since there is nothing
/// on screen to erase. The line's own `\r\n` is still written either way,
/// so the next prompt starts on a fresh line.
///
/// Returns `Ok(None)` on EOF or a read error -- there is nothing left to
/// prompt.
async fn read_line(
    reader: &mut Reader<'_>,
    writer: &mut OwnedWriteHalf,
    prompt: &[u8],
    echo: bool,
) -> io::Result<Option<String>> {
    loop {
        match prompt_once(reader, writer, prompt, echo).await? {
            None => return Ok(None),
            Some(line) if line.is_empty() => reader.pending.clear(),
            Some(line) => return Ok(Some(line)),
        }
    }
}

/// [`read_line`] without the re-ask: print `prompt`, read exactly one line,
/// and answer it even if it is empty.
///
/// Whatever arrived pipelined behind the previous line is consumed first
/// and edited exactly as freshly read bytes are, echo and all -- a client
/// that types ahead sees the same screen as one that waits.
async fn prompt_once(
    reader: &mut Reader<'_>,
    writer: &mut OwnedWriteHalf,
    prompt: &[u8],
    echo: bool,
) -> io::Result<Option<String>> {
    writer.write_all(prompt).await?;
    writer.flush().await?;

    let mut editor = LineEditor::default();
    let mut buf = [0u8; 512];

    loop {
        let bytes = if reader.pending.is_empty() {
            let n = reader.socket.read(&mut buf).await?;
            if n == 0 {
                return Ok(None);
            }
            reader.filter.feed(&buf[..n])
        } else {
            std::mem::take(&mut reader.pending)
        };

        let mut done = None;
        for (i, &byte) in bytes.iter().enumerate() {
            match editor.feed(byte) {
                Edit::None => {}
                Edit::Echo(b) => {
                    if echo {
                        writer.write_all(&[b]).await?;
                    }
                }
                Edit::Erase => {
                    if echo {
                        writer.write_all(b"\x08 \x08").await?;
                    }
                }
                Edit::Done(line) => {
                    writer.write_all(b"\r\n").await?;
                    done = Some((line, bytes[i + 1..].to_vec()));
                    break;
                }
            }
        }
        writer.flush().await?;

        if let Some((line, leftover)) = done {
            reader.pending = leftover;
            return Ok(Some(line));
        }
    }
}

/// The byte pump: socket in one direction, [`Out`] messages in the other,
/// until either side ends.
///
/// `stack` was fixed at accept time by which listener this connection came
/// in on ([`handle`]'s parameter of the same name) -- calling it here, once,
/// is the one place a connection's transport translation is decided.
pub(crate) async fn pump(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    host_tx: std_mpsc::Sender<In>,
    chan: Chan,
    mut out_rx: mpsc::Receiver<Out>,
    stack: fn() -> Stack,
) -> io::Result<()> {
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
                        let _ = host_tx.send(In::Disconnect { chan });
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
                    let _ = host_tx.send(In::Disconnect { chan });
                    return Ok(());
                }
                Ok(n) => {
                    // Telnet framing and transcoding are both `Stack`'s
                    // job now, in the right order internally -- see the
                    // module doc and `termcompat::Stack::inbound`.
                    let bytes = termcompat.inbound(&buf[..n]);
                    if !bytes.is_empty()
                        && host_tx.send(In::Input { chan, bytes }).is_err()
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
    use super::{Edit, IAC, LineEditor, OPT_ECHO, OPT_SGA, WILL, default_keys, handle, pump, refusal_line};

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
            build: Box::new(mbbs_machine::m16::Machine::new),
            root,
            modules: vec![PathBuf::from("/nonexistent/NOPE.DLL")],
            terms: mbbs::Terms::new(1),
            bturno: None,
            polls_per_second: 1,
            syscyc_hz: 1,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: None,
            extension: None,
            maintenance_interval: crate::host::MAINTENANCE_INTERVAL,
            serving: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            default_ring: default_keys(),
        };

        let bound = super::serve(boot, &[("127.0.0.1:0", super::Stack::modern)])
            .await
            .expect("bind");
        let addr = bound[0];

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        // A whole login, not just the user ID: nothing reaches the host
        // thread until the password prompt has been answered too.
        sock.write_all(b"nobody\rpw\r").await.expect("write the login");

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

    /// While `serving` is false a caller is told and closed before any user
    /// ID is asked for, and nothing reaches the host thread.
    #[tokio::test]
    async fn a_caller_during_maintenance_is_told_and_no_connect_is_sent() {
        use crate::msg::In;
        use std::sync::mpsc as std_mpsc;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let (tx, rx) = std_mpsc::channel::<In>();
        let serving: crate::host::Serving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bound = super::serve_on(tx, &[("127.0.0.1:0", super::Stack::modern)], serving)
            .await
            .expect("bind");

        let mut sock = TcpStream::connect(bound[0]).await.expect("connect");
        let mut received = Vec::new();
        sock.read_to_end(&mut received).await.expect("the server closes the socket");
        let text = String::from_utf8_lossy(&received);

        assert!(text.contains("The system is down for daily maintenance."), "{text:?}");
        assert!(!text.contains("Enter your user ID: "), "no prompt during maintenance: {text:?}");
        assert!(
            matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)),
            "no In::Connect may reach the host during maintenance"
        );
    }

    /// A refused claim reaches the caller as its own line, and the
    /// dialogue starts over.
    ///
    /// The refusal is chosen for what only this path can prove: a fake host
    /// answers `Err(Refusal::Suspended)`, so the bytes on the wire can only
    /// have come from `login_dialogue` mapping the reply through
    /// [`refusal_line`]. `Full` would not discriminate -- it is the one
    /// refusal the old code wrote from a hardcoded string, and it is now
    /// also the one that ends the dialogue instead of counting
    /// (`a_full_board_ends_the_dialogue_without_counting`).
    #[tokio::test]
    async fn a_refused_login_prints_the_line_and_prompts_again() {
        use tokio::io::AsyncWriteExt;

        let (host_tx, _claims, _rest) = fake_host(vec![Err(mbbs::Refusal::Suspended)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(b"tester\rpw\r").await.expect("write the login");

        let mut got = Vec::new();
        read_until_nth(&mut client, &mut got, "Enter your user ID: ", 2).await;

        assert!(
            String::from_utf8_lossy(&got)
                .contains("That account is suspended.\r\nEnter your user ID: "),
            "a refused caller is told which refusal it was, then asked again: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// `DEMO`/`NORMAL`/`USER` are what a player needs to reach the Realm and
    /// come from `crates/mbbs/tests/wccmmud.rs:2450`, which is the source of
    /// truth; they are checked by containment so that this test fails if the
    /// fixture and the default ever drift apart.
    ///
    /// The sysop keys are checked for by name and must be absent. A ring is
    /// written into a brand-new account and kept, so a sysop key that
    /// slipped back into this list would not merely be granted to one
    /// session -- it would be on the account's ring in `bbsk.dat`
    /// afterwards, for every later login, whatever this function then said.
    ///
    /// The length check is the third invariant: without it, containment
    /// would let a fourth key in unnoticed.
    #[test]
    fn default_keys_is_the_realm_ring_and_grants_no_sysop_key() {
        let keys = default_keys();

        for needed in ["DEMO", "NORMAL", "USER"] {
            assert!(
                keys.iter().any(|k| k == needed),
                "crates/mbbs/tests/wccmmud.rs:2450 is the source of truth for the \
                 Realm keys, and {needed} is missing from {keys:?}"
            );
        }
        for sysop in ["SYSOP", "WCCSYSOP"] {
            assert!(
                !keys.iter().any(|k| k == sysop),
                "a new account's ring is written to the key file and kept: {sysop} \
                 in {keys:?} would grant it to that account for good"
            );
        }
        assert_eq!(keys.len(), 3, "no key nobody meant to grant: {keys:?}");
    }

    /// One line per refusal, all distinct, all CRLF-terminated, and
    /// `Invalid` carrying the account layer's own words.
    ///
    /// Distinctness is the assertion that matters: nine arms mapping to a
    /// shared "Login failed." would be a listener that cannot tell a caller
    /// which of nine things went wrong, and a copy-paste in the middle of
    /// the match is exactly how that happens.
    #[test]
    fn every_refusal_has_its_own_line() {
        use mbbs::Refusal as R;
        let all = [
            R::Unknown,
            R::BadPassword,
            R::NoPassword,
            R::Exists,
            R::Deleted,
            R::Suspended,
            R::Full,
            R::Maintenance,
            R::Invalid("a user ID is required"),
        ];
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for refusal in all {
            let line = refusal_line(refusal).into_owned();
            assert!(line.ends_with(b"\r\n"), "{refusal:?} is not a wire line: {line:?}");
            assert!(!seen.contains(&line), "{refusal:?} repeats another refusal's line: {line:?}");
            seen.push(line);
        }
        assert_eq!(refusal_line(R::Full).as_ref(), b"All lines are busy.\r\n");
        assert_eq!(refusal_line(R::Maintenance).as_ref(), super::MAINTENANCE_LINE);
        assert_eq!(
            refusal_line(R::Invalid("that user ID is reserved")).as_ref(),
            b"that user ID is reserved\r\n",
            "Invalid says the account layer's own reason, not a generic line"
        );
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

        let pump_task = tokio::spawn(pump(reader, writer, host_tx, chan, out_rx, Stack::modern));

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

    /// Task 7's pin: telnet filtering must run before CP437 transcoding,
    /// never the other way around -- now enforced inside `Stack::inbound`
    /// rather than by `pump`'s call order.
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
    /// `pump`, not `Stack::inbound` in isolation, so it still proves the
    /// end-to-end order even though the ordering itself now lives one
    /// layer down.
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

        let _pump_task = tokio::spawn(pump(reader, writer, host_tx, chan, out_rx, Stack::modern));

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
                    let _ = reply.send(Ok(chan));
                    // blocking_send: this is a plain std::thread, not a
                    // tokio task, so there is no async context to violate.
                    let _ = out.blocking_send(Out::Bytes(host_chunk.clone()));
                    // `out` drops here, closing the channel -- pump reads
                    // that as `Out::Close` and shuts the socket down, which
                    // is what lets each `read_to_end` below terminate.
                }
            }
        });

        let bound = super::serve_on(
            host_tx.clone(),
            &[("127.0.0.1:0", Stack::modern as fn() -> Stack), ("127.0.0.1:0", Stack::raw)],
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await
        .expect("bind both listeners");
        drop(host_tx);
        let [modern_addr, raw_addr]: [std::net::SocketAddr; 2] =
            bound.try_into().expect("serve_on must return one SocketAddr per listener given");

        async fn login_and_drain(addr: std::net::SocketAddr) -> Vec<u8> {
            let mut sock = TcpStream::connect(addr).await.expect("connect");
            sock.write_all(b"tester\rpw\r").await.expect("write the login");
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
            build: Box::new(mbbs_machine::m16::Machine::new),
            root,
            modules: vec![PathBuf::from("/nonexistent/NOPE.DLL")],
            terms: mbbs::Terms::new(1),
            bturno: None,
            polls_per_second: 1,
            syscyc_hz: 1,
            clock_reads: None,
            wake_age_ms: None,
            dispatched_total: None,
            calls_total: None,
            survey: None,
            extension: None,
            maintenance_interval: crate::host::MAINTENANCE_INTERVAL,
            serving: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            default_ring: default_keys(),
        };

        let bound = super::serve(
            boot,
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

    /// Nothing precedes the user-ID prompt on the wire: telnet negotiation,
    /// then `Enter your user ID: `. There is no machine to choose.
    #[tokio::test]
    async fn the_first_prompt_is_the_user_id() {
        use crate::termcompat::Stack;
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (host_tx, _host_rx) = std::sync::mpsc::channel::<crate::msg::In>();
        tokio::spawn(async move {
            let (server, _peer) = listener.accept().await.expect("accept");
            let serving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let _ = handle(server, host_tx, Stack::modern, serving).await;
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while !got.ends_with(b"Enter your user ID: ") {
            let n = client.read(&mut buf).await.expect("read");
            assert!(n > 0, "closed before the prompt: {got:?}");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            got,
            [IAC, WILL, OPT_SGA, IAC, WILL, OPT_ECHO].iter().copied().chain(b"Enter your user ID: ".iter().copied()).collect::<Vec<u8>>()
        );
    }

    // ---- the login dialogue ------------------------------------------

    /// How long one read in a dialogue test may block before the test calls
    /// it a hang. Every one of these runs over loopback against a fake host
    /// with no module behind it, so a wait this long is never legitimate.
    const DIALOGUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Read from `client` into `acc` until `acc` holds at least `count`
    /// occurrences of `needle`. Panics on EOF or on the timeout rather than
    /// hanging the run.
    ///
    /// The count is what makes a retry loop testable: `Enter your user ID: `
    /// appears once per try, so "the second prompt" is `count == 2` and
    /// nothing weaker.
    async fn read_until_nth(
        client: &mut tokio::net::TcpStream,
        acc: &mut Vec<u8>,
        needle: &str,
        count: usize,
    ) {
        use tokio::io::AsyncReadExt;
        loop {
            if String::from_utf8_lossy(acc).matches(needle).count() >= count {
                return;
            }
            let mut buf = [0u8; 512];
            let n = match tokio::time::timeout(DIALOGUE_TIMEOUT, client.read(&mut buf)).await {
                Ok(Ok(0)) => panic!(
                    "the socket closed before {needle:?} appeared {count} time(s); saw {:?}",
                    String::from_utf8_lossy(acc)
                ),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => panic!("read error waiting for {needle:?}: {e}"),
                Err(_) => panic!(
                    "timed out waiting for {needle:?} x{count}; saw {:?}",
                    String::from_utf8_lossy(acc)
                ),
            };
            acc.extend_from_slice(&buf[..n]);
        }
    }

    /// Read to EOF, appending to `acc`, with a timeout instead of a hang.
    async fn read_to_close(client: &mut tokio::net::TcpStream, acc: &mut Vec<u8>) {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(DIALOGUE_TIMEOUT, client.read_to_end(acc))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the server never closed the socket; saw {:?}",
                    String::from_utf8_lossy(acc)
                )
            })
            .expect("read until the server closes the socket");
    }

    /// A fake host thread for the dialogue tests: it answers each
    /// `In::Connect` from `replies`, in order, and hands the test the claim
    /// it saw on one channel and every other message on another.
    ///
    /// The `Sender<Out>` is dropped as soon as a claim is answered, which
    /// [`pump`] reads as a closed output channel and turns into a socket
    /// shutdown. That is what lets a test that expects a *successful* login
    /// read to EOF rather than waiting on a board that will never say
    /// anything on its own.
    ///
    /// A claim beyond the end of `replies` is answered `Err(Full)`: a
    /// dialogue that sends more claims than the test set up should end
    /// loudly, on a line the test never asked for, rather than block.
    fn fake_host(
        replies: Vec<Result<mbbs::Chan, mbbs::Refusal>>,
    ) -> (
        std::sync::mpsc::Sender<crate::msg::In>,
        std::sync::mpsc::Receiver<mbbs::Login>,
        std::sync::mpsc::Receiver<crate::msg::In>,
    ) {
        use crate::msg::In;
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        let (claims_tx, claims_rx) = std::sync::mpsc::channel();
        let (rest_tx, rest_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for msg in rx {
                match msg {
                    In::Connect { login, out, reply, .. } => {
                        let _ = claims_tx.send(login);
                        let _ = reply.send(replies.next().unwrap_or(Err(mbbs::Refusal::Full)));
                        drop(out);
                    }
                    other => {
                        let _ = rest_tx.send(other);
                    }
                }
            }
        });
        (tx, claims_rx, rest_rx)
    }

    /// Bind one telnet listener in front of a [`fake_host`] sender.
    async fn bind_dialogue(host_tx: std::sync::mpsc::Sender<crate::msg::In>) -> std::net::SocketAddr {
        use crate::termcompat::Stack;
        super::serve_on(
            host_tx,
            &[("127.0.0.1:0", Stack::modern as fn() -> Stack)],
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await
        .expect("bind the telnet listener")[0]
    }

    /// The next claim the fake host saw, or a panic naming what was waited
    /// for.
    fn next_claim(claims: &std::sync::mpsc::Receiver<mbbs::Login>, what: &str) -> mbbs::Login {
        claims
            .recv_timeout(DIALOGUE_TIMEOUT)
            .unwrap_or_else(|e| panic!("no claim reached the host for {what}: {e}"))
    }

    /// A telnet caller is asked for a password, and not one byte of it is
    /// echoed back.
    ///
    /// The two halves are one test on purpose: a listener that never echoed
    /// anything would pass the second assertion and fail the first, and one
    /// that echoed the whole line would pass the first and fail the second.
    /// What must hold is that the user ID comes back and the password does
    /// not, with both prompts in that order.
    #[tokio::test]
    async fn a_password_is_asked_for_and_not_echoed() {
        use tokio::io::AsyncWriteExt;

        let terms = mbbs::Terms::new(1);
        let chan = terms.chan(0).expect("channel 0");
        let (host_tx, claims, _rest) = fake_host(vec![Ok(chan)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(b"Dan\rhunter2\r").await.expect("write the login");

        let mut got = Vec::new();
        read_to_close(&mut client, &mut got).await;
        let text = String::from_utf8_lossy(&got);

        assert!(
            text.contains("Enter your user ID: Dan\r\nEnter your password: \r\n"),
            "both prompts, in order, with the user ID echoed and the password not: {text:?}"
        );
        assert!(
            !text.contains("hunter2"),
            "the password must never reach the wire: {text:?}"
        );
        assert_eq!(
            next_claim(&claims, "the password login"),
            mbbs::Login::Password { userid: "Dan".into(), password: "hunter2".into() },
            "the claim carries the password the caller typed, not an empty one"
        );
    }

    /// An unknown user ID becomes an offer, not a goodbye: the caller is
    /// asked whether to create the account, and answering `y` sends a
    /// `Signup` claim with the password they chose twice.
    ///
    /// The whole dialogue is written in one `write_all`, which also pins
    /// the pipelining rule through four prompts: every line after the user
    /// ID arrives in the same `read()` the user ID did, and the last one
    /// (`look\r`) has to survive as `In::Input` once a channel exists.
    #[tokio::test]
    async fn an_unknown_name_offers_signup_and_sends_the_signup_claim() {
        use crate::msg::In;
        use tokio::io::AsyncWriteExt;

        let terms = mbbs::Terms::new(1);
        let chan = terms.chan(0).expect("channel 0");
        let (host_tx, claims, rest) = fake_host(vec![Err(mbbs::Refusal::Unknown), Ok(chan)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"Dan\rx\ry\rhunter2\rhunter2\rlook\r")
            .await
            .expect("write the whole dialogue at once");

        let mut got = Vec::new();
        read_to_close(&mut client, &mut got).await;
        let text = String::from_utf8_lossy(&got);

        assert!(
            text.contains(
                "Enter your password: \r\n\
                 No account by that name. Create one? [y/n] y\r\n\
                 Choose a password (1 to 9 characters): \r\n\
                 Enter it again: \r\n"
            ),
            "the offer replaces the refusal line rather than following it, and \
             neither chosen password is echoed: {text:?}"
        );

        assert_eq!(
            next_claim(&claims, "the first, unknown login"),
            mbbs::Login::Password { userid: "Dan".into(), password: "x".into() }
        );
        assert_eq!(
            next_claim(&claims, "the signup"),
            mbbs::Login::Signup { userid: "Dan".into(), password: "hunter2".into() }
        );

        match rest.recv_timeout(DIALOGUE_TIMEOUT).expect("the pipelined line reached the host") {
            In::Input { chan: got_chan, bytes } => {
                assert_eq!(got_chan, chan);
                assert_eq!(
                    bytes, b"look\r",
                    "the bytes behind the accepted line survive the whole dialogue"
                );
            }
            _ => panic!("expected In::Input carrying the pipelined line"),
        }
    }

    /// Two different passwords at signup are refused on the spot, with no
    /// claim sent, and the dialogue starts over at the user ID prompt.
    #[tokio::test]
    async fn mismatched_signup_passwords_return_to_the_user_id_prompt() {
        use tokio::io::AsyncWriteExt;

        let (host_tx, claims, _rest) = fake_host(vec![Err(mbbs::Refusal::Unknown)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"Dan\rx\ry\rone\rtwo\r")
            .await
            .expect("write the whole dialogue at once");

        let mut got = Vec::new();
        read_until_nth(&mut client, &mut got, "Enter your user ID: ", 2).await;
        let text = String::from_utf8_lossy(&got);

        assert!(
            text.contains("Enter it again: \r\nPasswords do not match.\r\nEnter your user ID: "),
            "a mismatch says so and starts over: {text:?}"
        );
        assert_eq!(
            next_claim(&claims, "the first, unknown login"),
            mbbs::Login::Password { userid: "Dan".into(), password: "x".into() }
        );
        assert!(
            claims.try_recv().is_err(),
            "a mismatch is refused here -- no Signup claim may reach the host"
        );
    }

    /// Three counted refusals end the connection. The board answers
    /// `BadPassword` every time, so nothing but the count can stop the
    /// caller trying again.
    ///
    /// Each try is written only after its prompt has been read: bytes
    /// pipelined behind a refused line are deliberately dropped, so three
    /// tries in one `write_all` would be one try and two discarded lines.
    #[tokio::test]
    async fn three_refusals_close_the_connection() {
        use tokio::io::AsyncWriteExt;

        let (host_tx, claims, _rest) =
            fake_host(vec![Err(mbbs::Refusal::BadPassword), Err(mbbs::Refusal::BadPassword), Err(mbbs::Refusal::BadPassword)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut got = Vec::new();
        for try_number in 1..=super::MAX_REFUSALS {
            read_until_nth(&mut client, &mut got, "Enter your user ID: ", try_number).await;
            client.write_all(b"Dan\rbad\r").await.expect("write one try");
            read_until_nth(&mut client, &mut got, "Invalid password.\r\n", try_number).await;
        }
        read_to_close(&mut client, &mut got).await;

        let text = String::from_utf8_lossy(&got);
        assert!(got.ends_with(b"Too many tries.\r\n"), "{text:?}");
        assert_eq!(
            text.matches("Enter your user ID: ").count(),
            super::MAX_REFUSALS,
            "there is no fourth try: {text:?}"
        );
        for round in 1..=super::MAX_REFUSALS {
            assert_eq!(
                next_claim(&claims, &format!("try {round}")),
                mbbs::Login::Password { userid: "Dan".into(), password: "bad".into() }
            );
        }
        assert!(claims.try_recv().is_err(), "exactly {} claims", super::MAX_REFUSALS);
    }

    /// A user ID that cannot fit the account file's field is refused here,
    /// in the account layer's own words, without asking the board.
    ///
    /// The "without a round trip" half is the point: a 30-byte user ID is
    /// one the record cannot hold, and sending it would spend a channel
    /// (`Pool::take`, then `give_back`) to be told what this listener
    /// already knows.
    #[tokio::test]
    async fn an_overlong_user_id_is_refused_without_a_round_trip() {
        use tokio::io::AsyncWriteExt;

        let (host_tx, claims, _rest) = fake_host(Vec::new());
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let overlong = "x".repeat(mbbs::accounts::UIDSIZ);
        client
            .write_all(format!("{overlong}\r").as_bytes())
            .await
            .expect("write an overlong user ID");

        let mut got = Vec::new();
        read_until_nth(&mut client, &mut got, "Enter your user ID: ", 2).await;
        let text = String::from_utf8_lossy(&got);

        assert!(
            text.contains("a user ID is at most 29 characters\r\n"),
            "the wire text is the account layer's own: {text:?}"
        );
        assert!(
            !text.contains("Enter your password: "),
            "a user ID the record cannot hold is refused before the password prompt: {text:?}"
        );
        assert!(
            claims.try_recv().is_err(),
            "nothing may reach the host: this refusal costs no channel"
        );
    }

    /// The user ID and the password in one `write_all`, and the line behind
    /// them delivered as input once the channel exists.
    ///
    /// Both lines have to land in the same `read()` for this to prove
    /// anything: bytes left over from the user ID's line have to feed the
    /// password prompt rather than being dropped or waited on, and what is
    /// left after *that* is what `In::Input` carries. Split across two
    /// reads, the socket would drive each prompt on its own and the test
    /// would pass without exercising either hand-off.
    #[tokio::test]
    async fn userid_and_password_pipelined_in_one_read_both_land() {
        use crate::msg::In;
        use tokio::io::AsyncWriteExt;

        let terms = mbbs::Terms::new(1);
        let chan = terms.chan(0).expect("channel 0");
        let (host_tx, claims, rest) = fake_host(vec![Ok(chan)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"Dan\rhunter2\rlook\r")
            .await
            .expect("write both lines and the leftover together");

        let mut got = Vec::new();
        read_to_close(&mut client, &mut got).await;

        assert_eq!(
            next_claim(&claims, "the pipelined login"),
            mbbs::Login::Password { userid: "Dan".into(), password: "hunter2".into() }
        );
        match rest.recv_timeout(DIALOGUE_TIMEOUT).expect("the pipelined line reached the host") {
            In::Input { chan: got_chan, bytes } => {
                assert_eq!(
                    got_chan, chan,
                    "the leftover is tagged with the Chan the reply carried"
                );
                assert_eq!(bytes, b"look\r");
            }
            _ => panic!("expected In::Input carrying the pipelined line"),
        }
        assert!(
            !String::from_utf8_lossy(&got).contains("hunter2"),
            "a pipelined password is still a password: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// A backspace at a password prompt erases the byte and writes nothing
    /// back -- not even the `\x08 \x08` an echoing prompt uses.
    ///
    /// With echo off there is nothing on screen to erase, so the visual
    /// erase would be three stray bytes walking the client's cursor back
    /// over the prompt itself. This is the half of `read_line`'s `echo`
    /// rule that `a_password_is_asked_for_and_not_echoed` cannot see: a
    /// listener that suppressed `Edit::Echo` and forgot `Edit::Erase`
    /// passes that test and fails this one.
    #[tokio::test]
    async fn a_backspace_in_a_password_erases_nothing_on_the_wire() {
        use tokio::io::AsyncWriteExt;

        let terms = mbbs::Terms::new(1);
        let chan = terms.chan(0).expect("channel 0");
        let (host_tx, claims, _rest) = fake_host(vec![Ok(chan)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        // "hunterX", backspace, "2" -- the editor still has to build
        // "hunter2" out of it.
        client.write_all(b"Dan\rhunterX\x082\r").await.expect("write the login");

        let mut got = Vec::new();
        read_to_close(&mut client, &mut got).await;

        assert_eq!(
            next_claim(&claims, "the edited password"),
            mbbs::Login::Password { userid: "Dan".into(), password: "hunter2".into() },
            "the backspace must still edit the line it is not echoing"
        );
        assert!(
            !got.contains(&0x08u8),
            "a password prompt has nothing on screen to erase: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// Bytes pipelined behind a line that was refused are dropped, not fed
    /// to the prompt the dialogue restarts at.
    ///
    /// A caller who typed a whole second login behind the first was typing
    /// ahead of a dialogue that has just gone back to its start; replaying
    /// those bytes into the fresh prompts would spend their remaining tries
    /// on lines meant for prompts that are no longer on screen. The fake
    /// host would happily serve the second login here -- the only reason it
    /// never sees it is that `refuse` cleared the buffer.
    #[tokio::test]
    async fn bytes_pipelined_behind_a_refused_line_are_dropped() {
        use tokio::io::AsyncWriteExt;

        let terms = mbbs::Terms::new(1);
        let chan = terms.chan(0).expect("channel 0");
        let (host_tx, claims, _rest) = fake_host(vec![Err(mbbs::Refusal::BadPassword), Ok(chan)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"Dan\rbad\rBob\rgood\r")
            .await
            .expect("write two logins at once");

        let mut got = Vec::new();
        read_until_nth(&mut client, &mut got, "Enter your user ID: ", 2).await;

        assert_eq!(
            next_claim(&claims, "the first, refused login"),
            mbbs::Login::Password { userid: "Dan".into(), password: "bad".into() }
        );
        assert!(
            claims.try_recv().is_err(),
            "the second login was typed behind a refused line and must not reach \
             the host: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(
            !String::from_utf8_lossy(&got).contains("Bob"),
            "nothing behind the refused line is echoed either: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    /// A full board ends the dialogue rather than counting a try: there is
    /// nothing the caller could type differently, so there is nothing to
    /// retry.
    #[tokio::test]
    async fn a_full_board_ends_the_dialogue_without_counting() {
        use tokio::io::AsyncWriteExt;

        let (host_tx, _claims, _rest) = fake_host(vec![Err(mbbs::Refusal::Full)]);
        let addr = bind_dialogue(host_tx).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(b"Dan\rhunter2\r").await.expect("write the login");

        let mut got = Vec::new();
        read_to_close(&mut client, &mut got).await;
        let text = String::from_utf8_lossy(&got);

        assert!(got.ends_with(b"All lines are busy.\r\n"), "{text:?}");
        assert_eq!(
            text.matches("Enter your user ID: ").count(),
            1,
            "a full board is not the caller's mistake: there is no second prompt: {text:?}"
        );
    }
}
