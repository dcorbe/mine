//! The door: a Unix-domain socket a BBS's relay (`mbbs-door`) connects to
//! on a caller's behalf.
//!
//! A session opens with one header -- `mbbs-door 1`, then `key=value`
//! lines, then a blank line -- and everything after the blank line is the
//! session's bytes, raw CP437 with no telnet framing (`Stack::door`). The
//! header carries who the caller is and what the BBS decided about them;
//! this host holds no accounts and no security levels, only keys, and the
//! relay has already reduced the BBS's level to `sysop=0|1`.
//!
//! See `docs/superpowers/specs/2026-08-29-sbbs-door-design.md`.

use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;

use mbbs::Connection;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::conn::{self, OUT_CHANNEL_BOUND};
use crate::msg::{In, Out};
use crate::termcompat::Stack;

/// The header's first line. The `1` is the protocol version; a relay that
/// speaks a later one is refused rather than half-understood.
pub const PROTOCOL: &str = "mbbs-door 1";

/// The most header a session may send before its blank line. A relay is a
/// few short lines; anything longer is not a relay.
pub const MAX_HEADER: usize = 1024;

/// What a player needs to run MajorMUD at all (`crates/mbbs/tests/wccmmud.rs:2450`).
pub const PLAYER_KEYS: [&str; 3] = ["DEMO", "NORMAL", "USER"];

/// What a sysop can do inside it. Granted only when the BBS says the
/// caller is a sysop -- the relay decides that from the BBS's own level
/// scale, which this host never sees.
pub const SYSOP_KEYS: [&str; 2] = ["SYSOP", "WCCSYSOP"];

/// The header, parsed. `node` is informational: logged, never acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub user: String,
    pub sysop: bool,
    pub ansi: bool,
    pub node: Option<u16>,
    pub rows: u8,
    pub cols: u8,
}

/// The outcome of looking at what has arrived so far. `Incomplete` asks
/// the caller to read more; `Invalid` is final and names why, in words a
/// caller can be shown.
#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
    Complete { handshake: Handshake, consumed: usize },
    Incomplete,
    Invalid(&'static str),
}

/// Parse a header from the front of `buf`. Complete when the blank line
/// (`\n\n`) has arrived; `consumed` is the header's length including it,
/// so the caller can hand the remainder to the session as its first bytes.
pub fn parse(buf: &[u8]) -> Parse {
    // Find and check the protocol line first, before waiting for the full header
    let first_newline = match buf.iter().position(|&b| b == b'\n') {
        Some(i) => i,
        None => {
            if buf.len() >= MAX_HEADER {
                return Parse::Invalid("header too long");
            }
            return Parse::Incomplete;
        }
    };

    let Ok(first_line) = std::str::from_utf8(&buf[..first_newline]) else {
        return Parse::Invalid("header is not UTF-8");
    };

    if first_line != PROTOCOL {
        return Parse::Invalid("not an mbbs-door 1 header");
    }

    // LF-only, deliberately: a CRLF header would never match this
    // terminator (`mbbs-door.rs`'s `header()` sends bare LF, and the
    // protocol check above already refused anything else with a `\r`
    // before its first `\n`), so it fails fast above rather than
    // spinning here until `MAX_HEADER`.
    let end = match buf.windows(2).position(|w| w == b"\n\n") {
        Some(i) => i + 2,
        None if buf.len() >= MAX_HEADER => return Parse::Invalid("header too long"),
        None => return Parse::Incomplete,
    };
    if end > MAX_HEADER {
        return Parse::Invalid("header too long");
    }
    let Ok(text) = std::str::from_utf8(&buf[..end]) else {
        return Parse::Invalid("header is not UTF-8");
    };
    let mut lines = text.lines();
    let _ = lines.next(); // Skip the protocol line we already checked

    let mut handshake = Handshake {
        user: String::new(),
        sysop: false,
        ansi: true,
        node: None,
        rows: 24,
        cols: 80,
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Parse::Invalid("bad line");
        };
        match key {
            "user" => handshake.user = value.to_string(),
            "sysop" => handshake.sysop = match flag(value) {
                Some(b) => b,
                None => return Parse::Invalid("bad value"),
            },
            "ansi" => handshake.ansi = match flag(value) {
                Some(b) => b,
                None => return Parse::Invalid("bad value"),
            },
            "node" => handshake.node = match value.parse::<u16>() {
                Ok(n) => Some(n),
                Err(_) => return Parse::Invalid("bad value"),
            },
            "rows" => handshake.rows = match dimension(value) {
                Some(n) => n,
                None => return Parse::Invalid("bad value"),
            },
            "cols" => handshake.cols = match dimension(value) {
                Some(n) => n,
                None => return Parse::Invalid("bad value"),
            },
            _ => {} // a newer relay's key: ignored, by design
        }
    }
    if handshake.user.is_empty() {
        return Parse::Invalid("no user");
    }
    Parse::Complete { handshake, consumed: end }
}

/// `0` or `1`, nothing else.
fn flag(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// A screen dimension: 1..=255. Zero is not a screen.
fn dimension(value: &str) -> Option<u8> {
    value.parse::<u8>().ok().filter(|&n| n > 0)
}

/// The keys a door session holds. Fixed, and independent of `--keys`.
pub fn keys(sysop: bool) -> Vec<&'static str> {
    let mut keys = PLAYER_KEYS.to_vec();
    if sysop {
        keys.extend(SYSOP_KEYS);
    }
    keys
}

/// The `Connection` a header describes. `Connection` truncates `userid` to
/// `UIDSIZ` itself.
pub fn connection(h: &Handshake) -> Connection {
    let mut c = if h.ansi { Connection::ansi(&h.user) } else { Connection::line_mode(&h.user) };
    c.width = h.cols;
    c.height = h.rows;
    c.with_keys(keys(h.sysop))
}

/// Bind `path` and spawn its accept loop; returns as soon as it is bound.
///
/// A socket file left by a previous process is not proof that nothing is
/// listening on it -- a crashed process's socket file outlives it, but a
/// live one's does too, and `bind` refuses either alike with
/// `AddrInUse`, giving no way to tell them apart from that error. So a
/// socket at `path` is probed first with a real connect: if that
/// succeeds, another process is actually serving it and this call is
/// refused rather than stealing the path out from under it; if it fails
/// (`ConnectionRefused` or otherwise), nothing is listening and the file
/// is stale, so it is unlinked before `bind`. Anything at `path` that is
/// *not* a socket is refused outright: that is a misconfiguration, not a
/// stale socket.
///
/// The socket is created `0600` (owner-only) immediately after `bind`:
/// this door has no authentication of its own -- see the module doc
/// comment and the spec's trust-boundary paragraph -- so anything that
/// can connect can claim any `user=` and `sysop=1`. The directory `path`
/// lives in must be traversable only by the serving user (`/run/user/<uid>`
/// is `0700`) to close the window between `bind` and this call.
pub async fn serve(path: PathBuf, tx: std_mpsc::Sender<In>, serving: crate::host::Serving) -> io::Result<()> {
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} is already served by another process", path.display()),
                ));
            }
            std::fs::remove_file(&path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    let serving = serving.clone();
                    tokio::spawn(async move {
                        if let Err(e) = session(stream, tx, serving).await {
                            eprintln!("mbbs-server: door session ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("mbbs-server: door accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

/// One door session: header, connect, pump.
async fn session(stream: UnixStream, tx: std_mpsc::Sender<In>, serving: crate::host::Serving) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    let mut buf = Vec::with_capacity(256);
    let (handshake, leftover) = loop {
        match parse(&buf) {
            Parse::Complete { handshake, consumed } => break (handshake, buf.split_off(consumed)),
            Parse::Invalid(reason) => {
                writer.write_all(format!("mbbs-door: {reason}\r\n").as_bytes()).await?;
                return Ok(());
            }
            Parse::Incomplete => {
                let mut chunk = [0u8; 256];
                let n = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk).await?;
                if n == 0 {
                    return Ok(()); // gone before the header ended
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    };
    eprintln!(
        "mbbs-server: door session for {:?} (sysop={}, node={:?})",
        handshake.user, handshake.sysop, handshake.node
    );

    if !serving.load(std::sync::atomic::Ordering::Relaxed) {
        writer.write_all(conn::MAINTENANCE_LINE).await?;
        return Ok(());
    }

    let (out_tx, out_rx) = mpsc::channel::<Out>(OUT_CHANNEL_BOUND);
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(In::Connect { who: connection(&handshake), out: out_tx, reply: reply_tx })
        .is_err()
    {
        writer.write_all(b"Server error, try again later.\r\n").await?;
        return Ok(());
    }
    let chan = match reply_rx.await {
        Ok(Some(chan)) => chan,
        Ok(None) => {
            writer.write_all(b"All lines are busy.\r\n").await?;
            return Ok(());
        }
        Err(_) => {
            writer.write_all(b"Server error, try again later.\r\n").await?;
            return Ok(());
        }
    };

    if !leftover.is_empty() && tx.send(In::Input { chan, bytes: leftover }).is_err() {
        return Ok(());
    }

    conn::pump(reader, writer, tx, chan, out_rx, Stack::door).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &[u8] = b"mbbs-door 1\nuser=Dan\nsysop=1\nansi=0\nnode=3\nrows=25\ncols=132\n\n";

    #[test]
    fn a_complete_header_parses_every_field_and_reports_its_length() {
        let Parse::Complete { handshake, consumed } = parse(FULL) else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, FULL.len());
        assert_eq!(
            handshake,
            Handshake { user: "Dan".into(), sysop: true, ansi: false, node: Some(3), rows: 25, cols: 132 }
        );
    }

    #[test]
    fn session_bytes_after_the_blank_line_are_not_consumed() {
        let mut buf = FULL.to_vec();
        buf.extend_from_slice(b"look\r");
        let Parse::Complete { consumed, .. } = parse(&buf) else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, FULL.len());
    }

    #[test]
    fn absent_keys_take_their_defaults() {
        let Parse::Complete { handshake, .. } = parse(b"mbbs-door 1\nuser=Dan\n\n") else {
            panic!("expected Complete");
        };
        assert_eq!(
            handshake,
            Handshake { user: "Dan".into(), sysop: false, ansi: true, node: None, rows: 24, cols: 80 }
        );
    }

    #[test]
    fn user_is_mandatory() {
        assert_eq!(parse(b"mbbs-door 1\nsysop=0\n\n"), Parse::Invalid("no user"));
        assert_eq!(parse(b"mbbs-door 1\nuser=\n\n"), Parse::Invalid("no user"));
    }

    #[test]
    fn a_header_without_its_blank_line_yet_is_incomplete() {
        assert_eq!(parse(b"mbbs-door 1\nuser=Dan\n"), Parse::Incomplete);
        assert_eq!(parse(b""), Parse::Incomplete);
    }

    #[test]
    fn the_wrong_protocol_line_is_refused() {
        assert_eq!(parse(b"mbbs-door 2\nuser=Dan\n\n"), Parse::Invalid("not an mbbs-door 1 header"));
        assert_eq!(parse(b"GET / HTTP/1.0\r\n\r\n"), Parse::Invalid("not an mbbs-door 1 header"));
    }

    /// CRLF is refused, not half-accepted: a `\r` before the first `\n`
    /// makes the protocol line not match `PROTOCOL` (which has none), so
    /// a CRLF relay is refused at once instead of spinning until
    /// `MAX_HEADER` looking for a `\n\n` it can never find.
    #[test]
    fn a_crlf_header_is_refused_at_once() {
        assert_eq!(
            parse(b"mbbs-door 1\r\nuser=Dan\r\n\r\n"),
            Parse::Invalid("not an mbbs-door 1 header")
        );
        assert_eq!(parse(b"mbbs-door 1\r\n"), Parse::Invalid("not an mbbs-door 1 header"));
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let Parse::Complete { handshake, .. } = parse(b"mbbs-door 1\nuser=Dan\ncolour=blue\n\n") else {
            panic!("expected Complete");
        };
        assert_eq!(handshake.user, "Dan");
    }

    #[test]
    fn a_malformed_value_is_refused_not_defaulted() {
        assert_eq!(parse(b"mbbs-door 1\nuser=Dan\nsysop=yes\n\n"), Parse::Invalid("bad value"));
        assert_eq!(parse(b"mbbs-door 1\nuser=Dan\nrows=0\n\n"), Parse::Invalid("bad value"));
        assert_eq!(parse(b"mbbs-door 1\nuser=Dan\nrows=300\n\n"), Parse::Invalid("bad value"));
        assert_eq!(parse(b"mbbs-door 1\nuser=Dan\nnope\n\n"), Parse::Invalid("bad line"));
    }

    #[test]
    fn a_header_over_the_cap_with_no_blank_line_is_refused_not_held() {
        let mut buf = b"mbbs-door 1\nuser=Dan\n".to_vec();
        buf.extend(std::iter::repeat(b'x').take(MAX_HEADER));
        assert_eq!(parse(&buf), Parse::Invalid("header too long"));
    }

    #[test]
    fn the_key_rule_is_exactly_the_spec() {
        assert_eq!(keys(false), vec!["DEMO", "NORMAL", "USER"]);
        assert_eq!(keys(true), vec!["DEMO", "NORMAL", "USER", "SYSOP", "WCCSYSOP"]);
    }

    #[test]
    fn a_connection_carries_the_handshake_into_the_host() {
        let h = Handshake { user: "Dan".into(), sysop: false, ansi: false, node: None, rows: 25, cols: 132 };
        let c = connection(&h);
        assert_eq!(c.userid, "Dan");
        assert!(!c.ansi);
        assert_eq!((c.width, c.height), (132, 25));
        assert!(c.keys.evaluate("USER"));
        assert!(!c.keys.evaluate("SYSOP"));

        let c = connection(&Handshake { sysop: true, ansi: true, ..h });
        assert!(c.ansi);
        assert!(c.keys.evaluate("SYSOP") && c.keys.evaluate("WCCSYSOP"));
    }

    use crate::msg::{In, Out};
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn socket_path(name: &str) -> std::path::PathBuf {
        mbbs::testing::scratch(name).canonicalize().expect("scratch dir exists").join("door.sock")
    }

    async fn read_to_end(sock: &mut UnixStream) -> Vec<u8> {
        let mut acc = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut acc))
            .await
            .expect("the server closes the socket within 5s")
            .expect("read");
        acc
    }

    /// A host thread that died leaves nobody to answer `In::Connect`.
    #[tokio::test]
    async fn a_dead_host_thread_tells_the_relay_and_closes() {
        let path = socket_path("door-dead-host");
        let (tx, rx) = std_mpsc::channel::<In>();
        drop(rx);
        serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("bind");

        let mut sock = UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"mbbs-door 1\nuser=Dan\n\n").await.expect("write");
        let got = read_to_end(&mut sock).await;
        assert_eq!(got, b"Server error, try again later.\r\n");
    }

    #[tokio::test]
    async fn a_bad_header_is_refused_with_its_reason() {
        let path = socket_path("door-bad-header");
        let (tx, _rx) = std_mpsc::channel::<In>();
        serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("bind");

        let mut sock = UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"HELLO\n\n").await.expect("write");
        let got = read_to_end(&mut sock).await;
        assert_eq!(got, b"mbbs-door: not an mbbs-door 1 header\r\n");
    }

    /// A fake host thread: answers the first `Connect` as told, then hands
    /// the test the `Out` sender it was given and every later message.
    fn fake_host(
        reply_with: Option<mbbs::Chan>,
    ) -> (std_mpsc::Sender<In>, std_mpsc::Receiver<(mbbs::Connection, tokio::sync::mpsc::Sender<Out>)>, std_mpsc::Receiver<In>) {
        let (tx, rx) = std_mpsc::channel::<In>();
        let (connected_tx, connected_rx) = std_mpsc::channel();
        let (rest_tx, rest_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            for msg in rx {
                match msg {
                    In::Connect { who, out, reply } => {
                        let _ = reply.send(reply_with);
                        let _ = connected_tx.send((who, out));
                    }
                    other => {
                        let _ = rest_tx.send(other);
                    }
                }
            }
        });
        (tx, connected_rx, rest_rx)
    }

    #[tokio::test]
    async fn a_full_board_tells_the_relay_and_closes() {
        let path = socket_path("door-full");
        let (tx, _connected, _rest) = fake_host(None);
        serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("bind");

        let mut sock = UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"mbbs-door 1\nuser=Dan\n\n").await.expect("write");
        assert_eq!(read_to_end(&mut sock).await, b"All lines are busy.\r\n");
    }

    #[tokio::test]
    async fn a_relay_during_maintenance_is_told_and_closes() {
        let path = socket_path("door-maintenance");
        let (tx, rx) = std_mpsc::channel::<In>();
        let serving: crate::host::Serving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        serve(path.clone(), tx, serving).await.expect("bind");

        let mut sock = UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"mbbs-door 1\nuser=Dan\n\n").await.expect("write");
        assert_eq!(read_to_end(&mut sock).await, crate::conn::MAINTENANCE_LINE);
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)));
    }

    /// The whole prelude, then the wire: the host sees the handshake's
    /// `Connection`; the session's bytes flow both ways with no telnet
    /// framing and no transcoding; bytes pipelined behind the header are
    /// the session's first input.
    #[tokio::test]
    async fn a_session_connects_with_the_handshake_and_pumps_raw_cp437() {
        let path = socket_path("door-session");
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero");
        let (tx, connected, rest) = fake_host(Some(chan));
        serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("bind");

        let mut sock = UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"mbbs-door 1\nuser=Dan\nsysop=1\nrows=25\ncols=132\n\nlook\r")
            .await
            .expect("write");

        let (who, out) = tokio::task::spawn_blocking(move || connected.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join")
            .expect("the host saw a Connect");
        assert_eq!(who.userid, "Dan");
        assert_eq!((who.width, who.height), (132, 25));
        assert!(who.keys.evaluate("SYSOP"));

        // `std_mpsc::Receiver` is not `Sync`, so it cannot be borrowed into
        // `spawn_blocking`; share it behind a mutex and move clones in.
        let rest = std::sync::Arc::new(std::sync::Mutex::new(rest));
        let next = |rest: std::sync::Arc<std::sync::Mutex<std_mpsc::Receiver<In>>>| async move {
            tokio::task::spawn_blocking(move || rest.lock().expect("lock").recv_timeout(Duration::from_secs(5)))
                .await
                .expect("join")
                .expect("the host received a message")
        };

        match next(rest.clone()).await {
            In::Input { bytes, .. } => assert_eq!(bytes, b"look\r"),
            _ => panic!("expected the pipelined bytes as the first Input"),
        }

        out.send(Out::Bytes(vec![b'A', 0xFF, b'B'])).await.expect("send");
        let mut got = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut got))
            .await
            .expect("bytes within 5s")
            .expect("read");
        assert_eq!(got, [b'A', 0xFF, b'B'], "no IAC doubling on a door");

        sock.write_all(&[0xFF, b'X']).await.expect("write");
        match next(rest.clone()).await {
            In::Input { bytes, .. } => assert_eq!(bytes, vec![0xFF, b'X'], "no IAC stripping on a door"),
            _ => panic!("expected Input"),
        }

        out.send(Out::Close).await.expect("send");
        assert!(read_to_end(&mut sock).await.is_empty(), "Close ends the session with nothing more");
    }

    #[tokio::test]
    async fn a_stale_socket_file_is_replaced_and_a_regular_file_is_not() {
        let path = socket_path("door-stale");
        std::os::unix::net::UnixListener::bind(&path).expect("a stale socket file");
        let (tx, _rx) = std_mpsc::channel::<In>();
        serve(path.clone(), tx.clone(), std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("rebinds over a stale socket");

        let regular = mbbs::testing::scratch("door-regular")
            .canonicalize()
            .expect("scratch dir exists")
            .join("door.sock");
        std::fs::write(&regular, b"not a socket").expect("write");
        let err = serve(regular, tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect_err("refuses a regular file");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    /// A socket file with a live listener behind it is not stale: `serve`
    /// must refuse rather than unlink and steal the path, and the
    /// original listener must still be answering afterward.
    #[tokio::test]
    async fn a_live_socket_is_refused_not_stolen() {
        let path = socket_path("door-live");
        let live = std::os::unix::net::UnixListener::bind(&path).expect("a live socket");
        let (tx, _rx) = std_mpsc::channel::<In>();

        let err = serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect_err("refuses a live socket");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);

        std::os::unix::net::UnixStream::connect(&path).expect("the original listener still accepts");
        drop(live);
    }

    /// The door has no authentication of its own -- see the module doc
    /// comment -- so the socket file must be reachable only by the
    /// serving user.
    #[tokio::test]
    async fn the_door_socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = socket_path("door-perms");
        let (tx, _rx) = std_mpsc::channel::<In>();
        serve(path.clone(), tx, std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .await
            .expect("bind");

        let mode = std::fs::symlink_metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
