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
//! itself -- `pump` below just picks a [`Stack`] and calls it per chunk.
//! Inbound bytes are never translated at all -- GSBL's own default translate
//! table (`gsbl.rs::translate`) strips the high bit, which is what a real
//! CP437 terminal would already have done to a multi-byte character typed at
//! it.
//!
//! **One host thread, however many listeners.** [`serve`] can bind more than
//! one address -- a modern port and a period port, or several of either --
//! but every one of them feeds the *same* host thread through the same
//! `host_tx`. `Machine` is `!Send` (see the crate doc): the thread that
//! builds it is the one and only owner of this board's channels, its loaded
//! module, its Btrieve files, for the process's whole life. A listener that
//! spawned its own host thread would spawn its own `Machine`, load the
//! module a second time, and mint a second set of channels no other
//! listener's connections could ever reach -- two boards quietly sharing one
//! `--root` on disk, not one board with two doors into it. So [`serve`]
//! spawns the host thread exactly once, before it binds anything, and
//! [`spawn_listener`] -- the per-address half -- only ever receives a clone
//! of that one thread's sender.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;

use mbbs::{Chan, Connection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
pub fn default_keys() -> Vec<String> {
    ["DEMO", "NORMAL", "USER"]
        .into_iter()
        .map(String::from)
        .collect()
}

/// One address [`serve`] binds, paired with the [`Stack`] constructor every
/// connection through it gets.
pub type Listener<'a> = (&'a str, fn() -> Stack);

/// Spawn the host thread once, then bind every address in `listeners`, each
/// with the [`Stack`] constructor it was given. Returns the bound addresses
/// in `listeners`' order -- a caller binding port 0 reads back where each
/// one landed, same as before this took more than one address.
///
/// Does not block: every accept loop runs in its own spawned task. See the
/// module doc for why the host thread is spawned exactly once, here, before
/// any listener is bound.
pub async fn serve(
    boot: Boot,
    keys: Vec<String>,
    listeners: &[Listener<'_>],
) -> io::Result<Vec<SocketAddr>> {
    let (host_tx, host_rx) = std_mpsc::channel::<In>();

    // `Machine` is `!Send` (see the crate doc): this thread has to build its
    // own, so all `run` gets handed in is `Boot` (paths, `Terms`, numbers --
    // all `Send`) and the receiving half of the channel every listener's
    // sender feeds.
    std::thread::spawn(move || {
        if let Err(e) = host::run(boot, host_rx) {
            eprintln!("mbbs-server: host thread ended: {e}");
        }
    });

    bind_all(listeners, host_tx, keys).await
}

/// [`serve`]'s per-listener half, split out so a test can drive the exact
/// same zip-and-bind loop against a `host_tx` it controls, without paying
/// for a real module load. `listeners[i]`'s constructor becomes `bound[i]`'s
/// connections' [`Stack`] -- this is the one place that pairing happens, so
/// it is the one place a mutation swapping, reversing, or dropping it would
/// hide.
async fn bind_all(
    listeners: &[Listener<'_>],
    host_tx: std_mpsc::Sender<In>,
    keys: Vec<String>,
) -> io::Result<Vec<SocketAddr>> {
    let mut bound = Vec::with_capacity(listeners.len());
    for &(addr, stack) in listeners {
        bound.push(spawn_listener(addr, stack, host_tx.clone(), keys.clone()).await?);
    }
    Ok(bound)
}

/// Bind one address and spawn its accept loop, which hands every accepted
/// socket to [`handle`] along with `stack` -- the [`Stack`] constructor
/// *this* listener was given. `host_tx` is a clone shared with every other
/// listener [`serve`] binds; see the module doc for why that sharing, and
/// not a thread of its own per listener, is the point.
async fn spawn_listener(
    addr: &str,
    stack: fn() -> Stack,
    host_tx: std_mpsc::Sender<In>,
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
            let host_tx = host_tx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(socket, host_tx, &keys, stack).await {
                    eprintln!("mbbs-server: connection ended: {e}");
                }
            });
        }
    });

    Ok(local)
}

/// One connection's whole life: negotiate, prompt for a user ID, connect,
/// pump bytes until either side hangs up.
///
/// `stack` is this connection's [`Stack`] constructor -- fixed by which
/// listener accepted the socket ([`spawn_listener`]'s parameter of the same
/// name), never by anything the connection itself says or does.
async fn handle(
    socket: TcpStream,
    host_tx: std_mpsc::Sender<In>,
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

    let chan = match reply_rx.await {
        Ok(Some(chan)) => chan,
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
    if !leftover.is_empty() && host_tx.send(In::Input { chan, bytes: leftover }).is_err() {
        return Ok(());
    }

    pump(reader, writer, host_tx, chan, out_rx, stack).await
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
    chan: Chan,
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
                    let bytes = filter.feed(&buf[..n]);
                    if !bytes.is_empty() && host_tx.send(In::Input { chan, bytes }).is_err() {
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
    use super::{Edit, LineEditor, default_keys, pump};

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
        let boot = super::Boot {
            root,
            module: PathBuf::from("/nonexistent/NOPE.DLL"),
            terms: mbbs::Terms::new(1),
            polls_per_wake: 1,
            passes: 1,
            clock_reads: None,
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

    #[test]
    fn default_keys_matches_the_realm_fixture() {
        assert_eq!(
            default_keys(),
            vec!["DEMO".to_string(), "NORMAL".to_string(), "USER".to_string()],
            "crates/mbbs/tests/wccmmud.rs:3623 is the source of truth for this list"
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
        use mud_core::cp437;
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

        let want = cp437::decode(&cp437_bytes).into_bytes();
        assert_eq!(
            received, want,
            "pump must hand every Out::Bytes chunk to Stack::modern() before \
             writing it, not send the host's raw CP437 bytes unchanged"
        );
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
    /// `serve`'s loop, actually threads listener `i`'s constructor through
    /// to listener `i`'s connections rather than, say, always the first one,
    /// or the two swapped. A mutant that ignored `stack` and always used
    /// `Stack::modern()` -- or one that zipped `listeners` against `bound`
    /// backwards -- would pass every test above and still ship the wrong
    /// stack on a live raw port.
    ///
    /// A fake host thread stands in for `host::run`: booting the real DLL
    /// module is unrelated to what this test checks (it is exercised by the
    /// `--ignored` integration tests instead). Critically, this drives
    /// `serve`'s *actual* zip-and-bind loop -- `bind_all`, called once with
    /// both listeners -- rather than hand-calling `spawn_listener` twice: an
    /// earlier version of this test did exactly that, and it would have
    /// missed a `bind_all` that hardcoded `Stack::modern()` for every entry
    /// or zipped `listeners` against `bound` off by one, because the test
    /// itself would have been doing the zipping. The fake host answers
    /// `In::Connect` with a channel and immediately pushes the *same*
    /// high-bit CP437 chunk down every connection -- the two clients seeing
    /// different bytes back can then only be explained by the transport,
    /// not the host.
    #[tokio::test]
    async fn each_port_gets_its_own_stack() {
        use crate::msg::{In, Out};
        use crate::termcompat::Stack;
        use mud_core::cp437;
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
                    let _ = reply.send(Some(chan));
                    // blocking_send: this is a plain std::thread, not a
                    // tokio task, so there is no async context to violate.
                    let _ = out.blocking_send(Out::Bytes(host_chunk.clone()));
                    // `out` drops here, closing the channel -- pump reads
                    // that as `Out::Close` and shuts the socket down, which
                    // is what lets each `read_to_end` below terminate.
                }
            }
        });

        let bound = super::bind_all(
            &[("127.0.0.1:0", Stack::modern as fn() -> Stack), ("127.0.0.1:0", Stack::raw)],
            host_tx.clone(),
            default_keys(),
        )
        .await
        .expect("bind both listeners");
        drop(host_tx);
        let [modern_addr, raw_addr]: [std::net::SocketAddr; 2] =
            bound.try_into().expect("bind_all must return one SocketAddr per listener given");

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
        let modern_want = cp437::decode(&chunk).into_bytes();
        assert!(
            modern_bytes.ends_with(&modern_want),
            "the modern-stack listener must hand its client Stack::modern's UTF-8, \
             not raw CP437: {modern_bytes:?}"
        );
        assert!(
            !modern_want.contains(&0xFF),
            "sanity check on the expected value itself: UTF-8 cannot contain a raw \
             0xFF byte, so cp437::decode's output here never should either"
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
        let boot = super::Boot {
            root,
            module: PathBuf::from("/nonexistent/NOPE.DLL"),
            terms: mbbs::Terms::new(1),
            polls_per_wake: 1,
            passes: 1,
            clock_reads: None,
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
}
