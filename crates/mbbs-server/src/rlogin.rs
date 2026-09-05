//! The rlogin listener: a TCP port a fronting board's gateway connects to
//! on a caller's behalf.
//!
//! The protocol is RFC 1282's, and it is tiny. The client opens with one
//! NUL byte and three NUL-terminated strings -- the client user name, the
//! server user name, and the terminal type with a speed after a slash
//! (`ansi/115200`) -- the server answers one NUL byte, and everything after
//! that is the session's raw bytes. Nothing else is framed, in either
//! direction: this host never asks for the window-size report, so no
//! in-band control sequence can arrive, and the session runs on
//! [`Stack::door`] -- no telnet framing, no transcoding, because a gateway
//! hands its caller's bytes on raw.
//!
//! **There is no password field, and this listener asks for none.** RFC
//! 1282 has nowhere to put one: rlogin was a trusted-host protocol, and the
//! two names are all a caller ever sends. Synchronet's gateway
//! (`telgate.cpp:318-322`, the fronting board on this machine) puts the
//! caller's alias in the first string and their real name in the second,
//! swappable by a board flag -- which is what [`NameField`] chooses
//! between, `--rlogin-name first` matching that flag. The convention where
//! a terminal program puts a password in the client user name is a
//! different caller on the same port and is out of scope.
//!
//! **So the address must be one only trusted callers can reach.** The name
//! that arrives becomes a [`mbbs::Login::Trusted`] claim and the host
//! provisions an account for it the first time it is seen: anything that
//! can open this port can be anybody. `sysop` is always false -- the
//! handshake has no field that could say otherwise -- so an rlogin caller
//! cannot claim the sysop keys the door's `sysop=1` grants. This is the
//! same trust boundary [`crate::door`] draws with a `0600` socket file;
//! rlogin is a TCP port instead, so drawing it is the sysop's job: bind it
//! to loopback or a private network, never a public interface.
//!
//! See `docs/superpowers/specs/2026-09-04-auth-rlogin-design.md`, section 2.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;

use crate::conn;
use crate::msg::In;
use crate::termcompat::Stack;

/// The longest any one of the handshake's three strings may be. RFC 1282
/// sets no limit; this one is here so a client that opens the socket and
/// pours bytes in without ever sending a NUL is refused instead of buffered.
/// 256 is far more than a user name or a terminal type needs.
pub const MAX_FIELD: usize = 256;

/// How long the whole handshake has to arrive. A gateway sends it in one
/// write the moment it connects, so five seconds is a network hiccup's worth
/// of slack rather than a budget anything legitimate spends.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// Terminal types that mean "no ANSI": everything else is taken to be a
/// screen the modules can paint. Compared without regard to case, against
/// the type alone -- what precedes the `/speed` (see [`terminal`]).
const DUMB_TERMINALS: [&str; 4] = ["dumb", "ascii", "tty", "none"];

/// The screen an rlogin caller is taken to have. The host never requests
/// the window-size report, so nothing on this wire can say otherwise, and
/// 80x24 is what the modules assume.
const RLOGIN_TERMINAL: mbbs::Terminal = mbbs::Terminal { ansi: true, width: 80, height: 24 };

/// Which of the handshake's two names this listener claims.
///
/// Synchronet sends the alias first and the real name second, and a board
/// flag swaps them (`telgate.cpp:318-322`); [`NameField::Second`] is the
/// default because that is what an unswapped gateway puts the account name
/// in. Whichever is chosen is taken on trust -- see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NameField {
    First,
    Second,
}

/// The three strings a client opens with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub client_user: String,
    pub server_user: String,
    pub terminal: String,
}

/// The outcome of looking at what has arrived so far. `Incomplete` asks the
/// caller to read more; `Invalid` is final and names why, in words a caller
/// can be shown.
#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
    Complete { handshake: Handshake, consumed: usize },
    Incomplete,
    Invalid(&'static str),
}

/// Parse a handshake from the front of `buf` -- RFC 1282's connection
/// establishment: one NUL, then three NUL-terminated strings.
///
/// `consumed` is the NUL and the three strings with their terminators, so
/// the caller can hand whatever follows to the session as its first bytes:
/// a caller who types ahead of the server's answer has their line in the
/// same segment as the handshake.
///
/// The [`MAX_FIELD`] cap is checked against what has arrived, not only
/// against a terminated string, so a client that never sends a NUL is
/// refused at the cap rather than buffered forever.
///
/// The strings are decoded lossily: a name is a `String` everywhere else in
/// this host, and a handshake is not the place to introduce a `Vec<u8>`
/// identity the account layer does not have.
#[must_use]
pub fn parse(buf: &[u8]) -> Parse {
    match buf.first() {
        None => return Parse::Incomplete,
        Some(0) => {}
        Some(_) => return Parse::Invalid("not an rlogin handshake"),
    }

    let mut cursor = 1;
    let mut fields = Vec::with_capacity(3);
    for _ in 0..3 {
        let rest = &buf[cursor..];
        match rest.iter().position(|&b| b == 0) {
            Some(end) if end > MAX_FIELD => return Parse::Invalid("field too long"),
            Some(end) => {
                fields.push(String::from_utf8_lossy(&rest[..end]).into_owned());
                cursor += end + 1;
            }
            None if rest.len() > MAX_FIELD => return Parse::Invalid("field too long"),
            None => return Parse::Incomplete,
        }
    }

    let mut fields = fields.into_iter();
    Parse::Complete {
        handshake: Handshake {
            client_user: fields.next().expect("three fields were parsed"),
            server_user: fields.next().expect("three fields were parsed"),
            terminal: fields.next().expect("three fields were parsed"),
        },
        consumed: cursor,
    }
}

/// What the handshake says the caller's screen is. Spec section 2.
///
/// The type is what precedes the first `/` -- `ansi/115200` is an `ansi`
/// terminal at a speed this host has no use for -- and it is ANSI unless it
/// names one of [`DUMB_TERMINALS`]. The size is [`RLOGIN_TERMINAL`]'s fixed
/// 80x24.
#[must_use]
pub fn terminal(handshake: &Handshake) -> mbbs::Terminal {
    let kind = handshake.terminal.split('/').next().unwrap_or_default();
    let ansi = !DUMB_TERMINALS.iter().any(|dumb| kind.eq_ignore_ascii_case(dumb));
    mbbs::Terminal { ansi, ..RLOGIN_TERMINAL }
}

/// The claim the handshake makes: the chosen name, on trust.
///
/// [`mbbs::Login::Trusted`] because the board in front of this port has
/// already authenticated the caller -- that is the whole point of a gateway
/// -- so there is no password here to check and none to ask for. `sysop` is
/// false because the handshake has no field that could say otherwise; a
/// sysop who wants the keys grants them to the account with `mbbs-user`.
#[must_use]
pub fn login(handshake: &Handshake, name: NameField) -> mbbs::Login {
    mbbs::Login::Trusted { userid: chosen(handshake, name).to_string(), sysop: false }
}

/// The one of the two names this listener is reading. Shared by [`login`]
/// and the session's empty-name check, so the name that is refused is
/// always the name that would have been claimed.
fn chosen(handshake: &Handshake, name: NameField) -> &str {
    match name {
        NameField::First => &handshake.client_user,
        NameField::Second => &handshake.server_user,
    }
}

/// What this listener says about the handshake itself. The board's own
/// answers are [`conn::refusal_line`]'s; these are the ones that never
/// reach it, so they are prefixed with who is speaking -- whatever is on
/// the other end of a bad handshake is a program, not a person reading a
/// screen.
fn handshake_refusal(reason: &str) -> String {
    format!("mbbs-server: {reason}\r\n")
}

/// Bind `addr` and spawn its accept loop; returns the bound address as soon
/// as it is listening, so a caller binding port 0 reads back where it
/// landed.
pub async fn serve(
    addr: &str,
    name: NameField,
    tx: std_mpsc::Sender<In>,
    serving: crate::host::Serving,
) -> io::Result<SocketAddr> {
    serve_with_deadline(addr, name, tx, serving, HANDSHAKE_DEADLINE).await
}

/// [`serve`] with the handshake deadline injected, for the test that has to
/// watch it expire without waiting [`HANDSHAKE_DEADLINE`] to do it.
pub(crate) async fn serve_with_deadline(
    addr: &str,
    name: NameField,
    tx: std_mpsc::Sender<In>,
    serving: crate::host::Serving,
    deadline: Duration,
) -> io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let tx = tx.clone();
                    let serving = serving.clone();
                    tokio::spawn(async move {
                        if let Err(e) = session(stream, peer, name, tx, serving, deadline).await {
                            eprintln!("mbbs-server: rlogin session ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("mbbs-server: rlogin accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(local)
}

/// One rlogin session: handshake, the answering NUL, connect, pump.
async fn session(
    stream: TcpStream,
    peer: SocketAddr,
    name: NameField,
    tx: std_mpsc::Sender<In>,
    serving: crate::host::Serving,
    deadline: Duration,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    // One deadline for the whole handshake rather than one per read: a
    // client dribbling a byte at a time would reset a per-read timeout
    // forever, which is the shape of hang this bound exists to prevent.
    let mut buf = Vec::with_capacity(MAX_FIELD);
    let Ok(parsed) = tokio::time::timeout(deadline, read_handshake(&mut reader, &mut buf)).await else {
        // Nothing was agreed and nothing is owed: a client that never
        // finished the handshake is not owed an explanation of one, and
        // anything listening at that end is a program that has not been
        // told a session started.
        return Ok(());
    };
    let (handshake, consumed) = match parsed? {
        Parse::Complete { handshake, consumed } => (handshake, consumed),
        Parse::Invalid(reason) => {
            writer.write_all(handshake_refusal(reason).as_bytes()).await?;
            return Ok(());
        }
        // `read_handshake` only returns this at EOF: gone before the
        // handshake ended, with nobody left to tell.
        Parse::Incomplete => return Ok(()),
    };
    let leftover = buf.split_off(consumed);

    // The answering NUL comes before anything else this listener might have
    // to say. It is what tells the client the session has begun -- until it
    // arrives, a gateway is still in its handshake and may not be showing
    // its caller anything -- so even a refusal is written after it.
    writer.write_all(&[0u8]).await?;
    writer.flush().await?;

    // Before the maintenance check, because an empty name is the gateway's
    // own misconfiguration (it is sending the field this listener is not
    // reading) and saying so is worth more to whoever has to fix it than
    // the board's current state is.
    let userid = chosen(&handshake, name);
    if userid.is_empty() {
        writer.write_all(handshake_refusal("no user name").as_bytes()).await?;
        return Ok(());
    }
    eprintln!("mbbs-server: rlogin session for {userid:?} from {peer}");

    if !serving.load(std::sync::atomic::Ordering::Relaxed) {
        writer.write_all(&conn::refusal_line(mbbs::Refusal::Maintenance)).await?;
        return Ok(());
    }

    // The round trip and both of its "the host thread is gone" endings are
    // `conn`'s, shared with the telnet listener and the door. What is left
    // here is the door's decision for the same reason: a refused gateway is
    // told which refusal it was and closed, with no retry -- there is
    // nobody at that end of the socket to type anything different.
    let (chan, out_rx) =
        match conn::claim_channel(&tx, login(&handshake, name), terminal(&handshake), &mut writer).await? {
            Some(Ok(pair)) => pair,
            Some(Err(refusal)) => {
                writer.write_all(&conn::refusal_line(refusal)).await?;
                return Ok(());
            }
            None => return Ok(()),
        };

    // Bytes that arrived pipelined behind the handshake (a caller who typed
    // ahead of the answering NUL) must not be dropped just because they
    // showed up before a channel existed to receive them.
    if !leftover.is_empty() && tx.send(In::Input { chan, bytes: leftover }).is_err() {
        return Ok(());
    }

    conn::pump(reader, writer, tx, chan, out_rx, Stack::door).await
}

/// Read until the handshake is complete or refused.
///
/// [`Parse::Incomplete`] as a *return* value means the peer went away
/// before the handshake ended -- the only way out of this loop other than a
/// complete or invalid handshake is EOF.
async fn read_handshake(reader: &mut OwnedReadHalf, buf: &mut Vec<u8>) -> io::Result<Parse> {
    loop {
        match parse(buf) {
            Parse::Incomplete => {}
            done => return Ok(done),
        }
        let mut chunk = [0u8; 256];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Parse::Incomplete);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::msg::{In, Out};

    /// The handshake Synchronet's gateway sends (`telgate.cpp:318-322`):
    /// alias, real name, terminal type with a speed after the slash. The
    /// `look\r` behind it is a caller who typed ahead.
    const SYNCHRONET: &[u8] = b"\0Dan\0Dan Corbe\0ansi/115200\0look\r";

    #[test]
    fn a_handshake_parses_and_the_second_field_is_the_user_by_default() {
        let Parse::Complete { handshake, consumed } = parse(SYNCHRONET) else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, 1 + 4 + 10 + 12, "the NUL and the three strings, not the typed-ahead line");
        assert_eq!(
            handshake,
            Handshake {
                client_user: "Dan".into(),
                server_user: "Dan Corbe".into(),
                terminal: "ansi/115200".into(),
            }
        );
        assert_eq!(
            login(&handshake, NameField::Second),
            mbbs::Login::Trusted { userid: "Dan Corbe".into(), sysop: false }
        );
        assert_eq!(
            login(&handshake, NameField::First),
            mbbs::Login::Trusted { userid: "Dan".into(), sysop: false }
        );
        assert!(terminal(&handshake).ansi);
    }

    /// The type is what precedes the slash, matched without regard to case,
    /// and only the four names in [`DUMB_TERMINALS`] turn colour off.
    #[test]
    fn a_dumb_terminal_type_is_line_mode() {
        let dumb = |t: &[u8]| {
            let Parse::Complete { handshake, .. } = parse(t) else { panic!("expected Complete") };
            terminal(&handshake)
        };
        assert!(!dumb(b"\0a\0b\0DUMB/9600\0").ansi);
        assert!(!dumb(b"\0a\0b\0tty\0").ansi);
        assert!(!dumb(b"\0a\0b\0None/38400\0").ansi);
        assert!(!dumb(b"\0a\0b\0ascii\0").ansi);
        assert!(dumb(b"\0a\0b\0xterm\0").ansi);
        assert!(dumb(b"\0a\0b\0ansi-bbs/115200\0").ansi, "a type that merely starts with a dumb name is not one");

        let screen = dumb(b"\0a\0b\0xterm/38400\0");
        assert_eq!((screen.width, screen.height), (80, 24), "the host never asks for the window size");
    }

    #[test]
    fn a_missing_leading_nul_is_invalid_and_a_short_read_is_incomplete() {
        assert_eq!(parse(b"Dan\0"), Parse::Invalid("not an rlogin handshake"));
        assert_eq!(parse(b"GET / HTTP/1.0\r\n"), Parse::Invalid("not an rlogin handshake"));
        assert_eq!(parse(b"\0Dan\0Dan\0"), Parse::Incomplete, "two of the three strings have arrived");
        assert_eq!(parse(b""), Parse::Incomplete, "nothing has arrived yet");
        assert_eq!(parse(b"\0"), Parse::Incomplete);
    }

    /// The cap is enforced on what has arrived, not only on a terminated
    /// string: a client that never sends a NUL must be refused rather than
    /// buffered until it runs the host out of memory.
    #[test]
    fn a_field_past_256_bytes_is_invalid() {
        let long = "x".repeat(MAX_FIELD + 1);
        let mut terminated = vec![0u8];
        terminated.extend_from_slice(long.as_bytes());
        terminated.extend_from_slice(b"\0b\0ansi\0");
        assert_eq!(parse(&terminated), Parse::Invalid("field too long"));

        let mut unterminated = vec![0u8];
        unterminated.extend_from_slice(long.as_bytes());
        assert_eq!(parse(&unterminated), Parse::Invalid("field too long"));

        let mut third = b"\0a\0b\0".to_vec();
        third.extend_from_slice(long.as_bytes());
        third.push(0);
        assert_eq!(parse(&third), Parse::Invalid("field too long"), "every field is capped, not just the first");

        let mut exact = vec![0u8];
        exact.extend_from_slice("x".repeat(MAX_FIELD).as_bytes());
        exact.extend_from_slice(b"\0b\0ansi\0");
        assert!(matches!(parse(&exact), Parse::Complete { .. }), "256 is the limit, not one under it");
    }

    fn serving(on: bool) -> crate::host::Serving {
        Arc::new(AtomicBool::new(on))
    }

    /// What the fake host below captures off every `In::Connect` it
    /// answers: the claim, the terminal, and the sender it was handed.
    type Claimed = (mbbs::Login, mbbs::Terminal, tokio::sync::mpsc::Sender<Out>);

    /// A fake host thread: answers every `Connect` as told, then hands the
    /// test the claim it saw, the `Out` sender it was given, and every
    /// later message.
    fn fake_host(
        reply_with: Result<mbbs::Chan, mbbs::Refusal>,
    ) -> (std_mpsc::Sender<In>, std_mpsc::Receiver<Claimed>, std_mpsc::Receiver<In>) {
        let (tx, rx) = std_mpsc::channel::<In>();
        let (connected_tx, connected_rx) = std_mpsc::channel();
        let (rest_tx, rest_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            for msg in rx {
                match msg {
                    In::Connect { login, terminal, out, reply } => {
                        let _ = reply.send(reply_with);
                        let _ = connected_tx.send((login, terminal, out));
                    }
                    other => {
                        let _ = rest_tx.send(other);
                    }
                }
            }
        });
        (tx, connected_rx, rest_rx)
    }

    /// `std_mpsc::Receiver` is not `Sync`, so it cannot be borrowed into
    /// `spawn_blocking`; every blocking wait below moves a clone of an
    /// `Arc<Mutex<_>>` in instead.
    async fn next<T: Send + 'static>(rx: &Arc<std::sync::Mutex<std_mpsc::Receiver<T>>>) -> T {
        let rx = rx.clone();
        tokio::task::spawn_blocking(move || rx.lock().expect("lock").recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join")
            .expect("the host received a message")
    }

    async fn read_to_end(sock: &mut TcpStream) -> Vec<u8> {
        let mut acc = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut acc))
            .await
            .expect("the server closes the socket within 5s")
            .expect("read");
        acc
    }

    async fn read_exact<const N: usize>(sock: &mut TcpStream) -> [u8; N] {
        let mut got = [0u8; N];
        tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut got))
            .await
            .expect("bytes within 5s")
            .expect("read");
        got
    }

    /// The whole prelude and then the wire: one NUL answers the handshake,
    /// the host sees the second name as a `Trusted` claim, bytes typed
    /// ahead of the answer are the session's first input, and the session
    /// is raw -- `Stack::door` doubles no `IAC` and transcodes nothing.
    #[tokio::test]
    async fn a_session_answers_one_nul_then_pumps_raw_bytes() {
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero");
        let (tx, connected, rest) = fake_host(Ok(chan));
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(SYNCHRONET).await.expect("write");

        assert_eq!(read_exact::<1>(&mut sock).await, [0], "RFC 1282: the server's answer is one NUL");

        let connected = Arc::new(std::sync::Mutex::new(connected));
        let (claim, terminal, out) = next(&connected).await;
        assert_eq!(
            claim,
            mbbs::Login::Trusted { userid: "Dan Corbe".into(), sysop: false },
            "the board in front has already authenticated the caller, and rlogin carries no sysop level"
        );
        assert!(terminal.ansi);

        let rest = Arc::new(std::sync::Mutex::new(rest));
        match next(&rest).await {
            In::Input { bytes, .. } => assert_eq!(bytes, b"look\r"),
            _ => panic!("expected the typed-ahead bytes as the first Input"),
        }

        out.send(Out::Bytes(vec![b'A', 0xFF])).await.expect("send");
        assert_eq!(read_exact::<2>(&mut sock).await, [b'A', 0xFF], "no IAC doubling on an rlogin session");

        sock.write_all(&[0xFF, b'X']).await.expect("write");
        match next(&rest).await {
            In::Input { bytes, .. } => assert_eq!(bytes, vec![0xFF, b'X'], "no IAC stripping either"),
            _ => panic!("expected Input"),
        }
    }

    /// A client that opens the socket and then says nothing must not hold a
    /// task forever. The deadline here is 100ms, and the read below is
    /// bounded at 2s: a listener that ignored the injected deadline and used
    /// [`HANDSHAKE_DEADLINE`] fails this rather than passing slowly.
    #[tokio::test]
    async fn a_stalled_handshake_is_closed_after_the_deadline() {
        let (tx, rx) = std_mpsc::channel::<In>();
        let addr = serve_with_deadline(
            "127.0.0.1:0",
            NameField::Second,
            tx,
            serving(true),
            Duration::from_millis(100),
        )
        .await
        .expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan").await.expect("write");

        let mut acc = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), sock.read_to_end(&mut acc))
            .await
            .expect("the deadline closes the socket")
            .expect("read");
        assert!(acc.is_empty(), "a deadline is not something to announce: no NUL, no line");
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)), "nothing reached the host");
    }

    /// A refused session is told which refusal it was and closed -- there is
    /// nobody at that end of the socket to type anything different.
    /// `Suspended` rather than `Full` because it can only have come from
    /// [`conn::refusal_line`]'s shared table.
    #[tokio::test]
    async fn a_refusal_writes_its_line_and_closes() {
        let (tx, _connected, _rest) = fake_host(Err(mbbs::Refusal::Suspended));
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan\0Dan Corbe\0ansi/115200\0").await.expect("write");

        let mut want = vec![0u8];
        want.extend_from_slice(b"That account is suspended.\r\n");
        assert_eq!(read_to_end(&mut sock).await, want, "the NUL first, then the one line, then the close");
    }

    /// Something that is not an rlogin client at all: refused with the
    /// reason, and without the NUL that would tell it a session had begun.
    #[tokio::test]
    async fn an_invalid_handshake_is_refused_with_its_reason() {
        let (tx, rx) = std_mpsc::channel::<In>();
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"GET / HTTP/1.0\r\n\r\n").await.expect("write");
        assert_eq!(read_to_end(&mut sock).await, b"mbbs-server: not an rlogin handshake\r\n");
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)));
    }

    /// A gateway configured to send the field this listener is not reading
    /// leaves it empty. There is no name to claim and none to invent, so the
    /// session is refused with a line saying exactly that.
    #[tokio::test]
    async fn an_empty_chosen_name_is_refused() {
        let (tx, rx) = std_mpsc::channel::<In>();
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan\0\0ansi/115200\0").await.expect("write");

        let mut want = vec![0u8];
        want.extend_from_slice(b"mbbs-server: no user name\r\n");
        assert_eq!(read_to_end(&mut sock).await, want);
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)), "nothing reached the host");
    }

    /// The same handshake under `--rlogin-name first` claims the other
    /// string, which is also what makes the empty-name test above about the
    /// *chosen* field rather than about the second one.
    #[tokio::test]
    async fn the_first_field_is_claimed_when_asked_for() {
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero");
        let (tx, connected, _rest) = fake_host(Ok(chan));
        let addr = serve("127.0.0.1:0", NameField::First, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan\0Dan Corbe\0dumb/9600\0").await.expect("write");
        assert_eq!(read_exact::<1>(&mut sock).await, [0]);

        let connected = Arc::new(std::sync::Mutex::new(connected));
        let (claim, terminal, _out) = next(&connected).await;
        assert_eq!(claim, mbbs::Login::Trusted { userid: "Dan".into(), sysop: false });
        assert!(!terminal.ansi, "the terminal the handshake named reaches the host too");
    }

    #[tokio::test]
    async fn a_caller_during_maintenance_is_told_and_no_connect_is_sent() {
        let (tx, rx) = std_mpsc::channel::<In>();
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(false)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan\0Dan Corbe\0ansi/115200\0").await.expect("write");

        let mut want = vec![0u8];
        want.extend_from_slice(crate::conn::MAINTENANCE_LINE);
        assert_eq!(read_to_end(&mut sock).await, want);
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)));
    }

    /// A host thread that died leaves nobody to answer `In::Connect`.
    #[tokio::test]
    async fn a_dead_host_thread_tells_the_gateway_and_closes() {
        let (tx, rx) = std_mpsc::channel::<In>();
        drop(rx);
        let addr = serve("127.0.0.1:0", NameField::Second, tx, serving(true)).await.expect("bind");

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"\0Dan\0Dan Corbe\0ansi/115200\0").await.expect("write");

        let mut want = vec![0u8];
        want.extend_from_slice(b"Server error, try again later.\r\n");
        assert_eq!(read_to_end(&mut sock).await, want);
    }
}
