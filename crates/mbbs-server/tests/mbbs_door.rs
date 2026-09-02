//! The relay binary, end to end, against an in-test door socket.
//!
//! `cargo test -p mbbs-server --test mbbs_door`

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const SBBS: &str = "0\n-1\n38400\nSynchronet 3.22a\n7\nDan Corbe\nDan\n90\n55\n1\n3\n";

fn relay() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mbbs-door"))
}

/// A scratch dir holding a DOOR32.SYS and a socket path nobody listens on
/// yet.
///
/// Canonicalized: `mbbs::testing::scratch` builds its path through a
/// `../..` it never resolves, and a Unix socket path has no room to spare
/// -- `SUN_LEN` is 108 bytes, and the unresolved form blows past it from
/// inside a worktree checkout.
fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let dir = mbbs::testing::scratch(name).canonicalize().expect("scratch dir exists");
    let drop_file = dir.join("DOOR32.SYS");
    std::fs::write(&drop_file, SBBS).expect("write DOOR32.SYS");
    (drop_file, dir.join("door.sock"))
}

fn read_header(sock: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut byte = [0u8; 1];
    while !acc.ends_with(b"\n\n") {
        assert_eq!(sock.read(&mut byte).expect("read"), 1, "EOF before the header ended: {acc:?}");
        acc.push(byte[0]);
    }
    acc
}

#[test]
fn the_relay_sends_the_header_then_copies_bytes_both_ways_unaltered() {
    let (drop_file, path) = fixture("mbbs-door-relay");
    let listener = UnixListener::bind(&path).expect("bind");

    let mut child = relay()
        .arg(&drop_file)
        .arg("--socket")
        .arg(&path)
        .args(["--rows", "25", "--cols", "132"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mbbs-door");

    let (mut sock, _) = listener.accept().expect("accept");
    assert_eq!(
        read_header(&mut sock),
        b"mbbs-door 1\nuser=Dan\nsysop=1\nansi=1\nnode=3\nrows=25\ncols=132\n\n"
    );

    // Server -> caller: 0xFF and CR must arrive as themselves.
    sock.write_all(&[b'A', 0xFF, b'\r']).expect("write to relay");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut got = [0u8; 3];
    stdout.read_exact(&mut got).expect("read relay stdout");
    assert_eq!(got, [b'A', 0xFF, b'\r']);

    // Caller -> server, same rule.
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(&[0xFF, b'X', b'\r']).expect("write to relay stdin");
    let mut got = [0u8; 3];
    sock.read_exact(&mut got).expect("read from relay");
    assert_eq!(got, [0xFF, b'X', b'\r']);

    // The server ends the session: the relay exits 0.
    drop(sock);
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn no_server_tells_the_caller_and_exits_1() {
    let (drop_file, path) = fixture("mbbs-door-no-server");
    let out = relay()
        .arg(&drop_file)
        .arg("--socket")
        .arg(&path)
        .output()
        .expect("run mbbs-door");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("The game is not available right now."),
        "stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_short_drop_file_exits_2_with_the_reason() {
    let (drop_file, path) = fixture("mbbs-door-short");
    let ten: String = SBBS.lines().take(10).map(|l| format!("{l}\n")).collect();
    std::fs::write(&drop_file, ten).expect("rewrite DOOR32.SYS");
    let out = relay()
        .arg(&drop_file)
        .arg("--socket")
        .arg(&path)
        .output()
        .expect("run mbbs-door");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("10 lines, not 11"));
}

#[test]
fn a_caller_hangup_closes_the_relays_write_half_toward_the_server() {
    let (drop_file, path) = fixture("mbbs-door-hangup");
    let listener = UnixListener::bind(&path).expect("bind");
    let mut child = relay()
        .arg(&drop_file)
        .arg("--socket")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mbbs-door");
    let (mut sock, _) = listener.accept().expect("accept");
    read_header(&mut sock);

    drop(child.stdin.take()); // the BBS hung up: stdin EOF
    let mut rest = Vec::new();
    sock.read_to_end(&mut rest).expect("the relay shut its write half");
    assert!(rest.is_empty());

    drop(sock);
    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn a_transport_error_mid_session_exits_3_with_a_stderr_line() {
    let (drop_file, path) = fixture("mbbs-door-transport-error");
    let listener = UnixListener::bind(&path).expect("bind");
    let mut child = relay()
        .arg(&drop_file)
        .arg("--socket")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mbbs-door");
    let (mut sock, _) = listener.accept().expect("accept");
    read_header(&mut sock);

    // Close the relay's stdout: its next write to the caller fails with
    // EPIPE (Rust ignores SIGPIPE by default, so the write returns `Err`
    // rather than killing the process).
    drop(child.stdout.take());
    sock.write_all(b"more bytes than the caller will ever read").expect("write to relay");

    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("mbbs-door: writing to the caller"),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
