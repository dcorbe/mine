//! Account administration: the commands `mbbs-user` runs, applied by
//! whichever process has the account files open.
//!
//! Spec: `docs/superpowers/specs/2026-09-05-live-account-admin-design.md`.
//!
//! Two processes can have the pair open, never at once: a running
//! `mbbs-server`, or `mbbs-user` against a stopped board. Both call
//! [`apply`] with the same [`Request`] and get the same [`Reply`], so a
//! sysop types one command and gets one answer whichever it was. What
//! differs is only how the request reaches the files: over the socket
//! [`serve`] binds under the board root, or by `mbbs-user` opening the
//! pair itself.

use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use mbbs::abi::Abi;
use mbbs::accounts::{self, flags, Refusal};
use mbbs::Host;

use crate::msg::In;

/// One `mbbs-user` command, parsed and with every default already applied.
///
/// `Add::keys` is the ring to write: the caller resolves the board's
/// default, so a new account's ring reaches the file through one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Add { userid: String, password: String, keys: Vec<String> },
    Passwd { userid: String, password: String },
    Keys { userid: String, add: Vec<String>, remove: Vec<String> },
    Master { userid: String, on: bool },
    List,
    Delete { userid: String },
}

/// One account as `list` reports it: the name, the whole flags word, and
/// the ring as the key file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub userid: String,
    pub flags: u16,
    pub ring: Vec<String>,
}

/// What a [`Request`] came to.
///
/// `Refused` is the sysop's mistake, worded for a sysop (exit 1 at the
/// CLI). `Faulted` is the engine or the files (exit 2). `Listed` answers
/// `List`; `Ring` answers `Keys` with the ring read back from the file, so
/// what the sysop is shown is what the next login will load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Done,
    Refused(String),
    Faulted(String),
    Listed(Vec<Row>),
    Ring(Vec<String>),
}

/// The frame's first line. The `1` is the protocol version: a peer that
/// speaks a later one is refused rather than half-understood.
pub const PROTOCOL: &str = "mbbs-user 1";

/// The most a request may send before its blank line. A request is a
/// handful of short lines, so one bigger than this is a mistake or an
/// attack, not a legitimate one that grew. A reply is not bounded by this:
/// it lists a whole board, at about fifty bytes a row, and the sysop who
/// asked for the listing is entitled to all of it.
pub const MAX_FRAME: usize = 65536;

/// What looking at the bytes so far came to. `Incomplete` asks for more;
/// `Invalid` is final and names why, in words a caller can be shown.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<T> {
    Complete(T),
    Incomplete,
    Invalid(String),
}

/// Split one frame into its `key=value` lines. The shared half of
/// [`parse_request`] and [`parse_reply`].
///
/// `cap` bounds how large the frame may grow before its blank line arrives;
/// `None` means unbounded. [`parse_request`] passes [`MAX_FRAME`], since a
/// request is a handful of short lines. [`parse_reply`] passes `None`: a
/// reply lists a whole board, and the client reads it to EOF before it is
/// ever parsed, so there is nothing left here to bound.
fn lines(buf: &[u8], cap: Option<usize>) -> Parsed<Vec<(&str, &str)>> {
    let too_long = |len: usize| cap.is_some_and(|cap| len >= cap);
    let Some(first_newline) = buf.iter().position(|&b| b == b'\n') else {
        return if too_long(buf.len()) {
            Parsed::Invalid("frame too long".into())
        } else {
            Parsed::Incomplete
        };
    };
    if std::str::from_utf8(&buf[..first_newline]) != Ok(PROTOCOL) {
        return Parsed::Invalid("not an mbbs-user 1 frame".into());
    }
    let end = match buf.windows(2).position(|w| w == b"\n\n") {
        Some(i) => i + 2,
        None if too_long(buf.len()) => return Parsed::Invalid("frame too long".into()),
        None => return Parsed::Incomplete,
    };
    if too_long(end) {
        return Parsed::Invalid("frame too long".into());
    }
    let Ok(text) = std::str::from_utf8(&buf[..end]) else {
        return Parsed::Invalid("frame is not UTF-8".into());
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some(pair) = line.split_once('=') else {
            return Parsed::Invalid("bad line".into());
        };
        out.push(pair);
    }
    Parsed::Complete(out)
}

/// A frame from `lines`: the protocol line, each pair, the blank line.
/// `Err` names a value that cannot be one line.
///
/// `row` is the one value this file builds itself, with a literal tab
/// between its three fields: that tab is a separator, not a stray control
/// character passed through from a sysop, so it is let through here and
/// nowhere else.
fn frame(pairs: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let mut out = format!("{PROTOCOL}\n");
    for (key, value) in pairs {
        if value.chars().any(|c| c.is_control() && !(*key == "row" && c == '\t')) {
            return Err(format!("{key} contains a control character and cannot be sent"));
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
    Ok(out.into_bytes())
}

/// Encode a request. `Err` for a value with a control character in it: a
/// newline would end the line early and a tab is a row separator on the
/// way back, so neither is sent.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, String> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    match request {
        Request::Add { userid, password, keys } => {
            pairs.push(("command", "add"));
            pairs.push(("userid", userid));
            pairs.push(("password", password));
            pairs.extend(keys.iter().map(|k| ("keys", k.as_str())));
        }
        Request::Passwd { userid, password } => {
            pairs.push(("command", "passwd"));
            pairs.push(("userid", userid));
            pairs.push(("password", password));
        }
        Request::Keys { userid, add, remove } => {
            pairs.push(("command", "keys"));
            pairs.push(("userid", userid));
            pairs.extend(add.iter().map(|k| ("add", k.as_str())));
            pairs.extend(remove.iter().map(|k| ("remove", k.as_str())));
        }
        Request::Master { userid, on } => {
            pairs.push(("command", "master"));
            pairs.push(("userid", userid));
            pairs.push(("on", if *on { "1" } else { "0" }));
        }
        Request::List => pairs.push(("command", "list")),
        Request::Delete { userid } => {
            pairs.push(("command", "delete"));
            pairs.push(("userid", userid));
        }
    }
    frame(&pairs)
}

/// Parse a request from the front of `buf`.
pub fn parse_request(buf: &[u8]) -> Parsed<Request> {
    let pairs = match lines(buf, Some(MAX_FRAME)) {
        Parsed::Complete(pairs) => pairs,
        Parsed::Incomplete => return Parsed::Incomplete,
        Parsed::Invalid(why) => return Parsed::Invalid(why),
    };
    let one = |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string());
    let many = |key: &str| -> Vec<String> {
        pairs.iter().filter(|(k, _)| *k == key).map(|(_, v)| v.to_string()).collect()
    };
    let Some(command) = one("command") else {
        return Parsed::Invalid("no command".into());
    };
    let userid = || one("userid").ok_or_else(|| "no userid".to_string());
    let password = || one("password").ok_or_else(|| "no password".to_string());
    let request = match command.as_str() {
        "list" => Ok(Request::List),
        "add" => userid().and_then(|userid| {
            password().map(|password| Request::Add { userid, password, keys: many("keys") })
        }),
        "passwd" => userid().and_then(|userid| password().map(|password| Request::Passwd { userid, password })),
        "keys" => userid().map(|userid| Request::Keys { userid, add: many("add"), remove: many("remove") }),
        "master" => userid().and_then(|userid| match one("on").as_deref() {
            Some("1") => Ok(Request::Master { userid, on: true }),
            Some("0") => Ok(Request::Master { userid, on: false }),
            Some(_) => Err("bad on".to_string()),
            None => Err("no on".to_string()),
        }),
        "delete" => userid().map(|userid| Request::Delete { userid }),
        _ => Err("unknown command".to_string()),
    };
    match request {
        Ok(request) => Parsed::Complete(request),
        Err(why) => Parsed::Invalid(why),
    }
}

/// Encode a reply. Infallible: every value a reply carries was either
/// validated on the way into the file or is this program's own sentence.
/// A userid may hold a space and a key name may not hold whitespace, so a
/// tab separates a row's fields.
pub fn encode_reply(reply: &Reply) -> Vec<u8> {
    let owned: Vec<(&str, String)> = match reply {
        Reply::Done => vec![("status", "ok".into())],
        Reply::Refused(message) => vec![("status", "refused".into()), ("message", message.clone())],
        Reply::Faulted(message) => vec![("status", "faulted".into()), ("message", message.clone())],
        Reply::Listed(rows) => {
            let mut out = vec![("status", "ok".into()), ("rows", rows.len().to_string())];
            out.extend(rows.iter().map(|row| {
                ("row", format!("{}\t{}\t{}", row.userid, row.flags, row.ring.join(" ")))
            }));
            out
        }
        Reply::Ring(ring) => vec![("status", "ok".into()), ("ring", ring.join(" "))],
    };
    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    frame(&pairs).unwrap_or_else(|why| {
        // A message with a control character in it came from the engine or
        // the files. Say that instead of sending a frame that will not parse.
        let fallback = [("status", "faulted"), ("message", why.as_str())];
        frame(&fallback).expect("two plain sentences encode")
    })
}

/// Parse a reply from the front of `buf`.
pub fn parse_reply(buf: &[u8]) -> Parsed<Reply> {
    let pairs = match lines(buf, None) {
        Parsed::Complete(pairs) => pairs,
        Parsed::Incomplete => return Parsed::Incomplete,
        Parsed::Invalid(why) => return Parsed::Invalid(why),
    };
    let one = |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    let message = || one("message").unwrap_or("").to_string();
    match one("status") {
        Some("refused") => Parsed::Complete(Reply::Refused(message())),
        Some("faulted") => Parsed::Complete(Reply::Faulted(message())),
        Some("ok") => {
            if let Some(ring) = one("ring") {
                return Parsed::Complete(Reply::Ring(split_ring(ring)));
            }
            let listing = one("rows").is_some() || pairs.iter().any(|(k, _)| *k == "row");
            if !listing {
                return Parsed::Complete(Reply::Done);
            }
            let mut rows = Vec::new();
            for (_, value) in pairs.iter().filter(|(k, _)| *k == "row") {
                let mut fields = value.splitn(3, '\t');
                let (Some(userid), Some(flags), Some(ring)) = (fields.next(), fields.next(), fields.next()) else {
                    return Parsed::Invalid("bad row".into());
                };
                let Ok(flags) = flags.parse::<u16>() else {
                    return Parsed::Invalid("bad row".into());
                };
                rows.push(Row { userid: userid.to_string(), flags, ring: split_ring(ring) });
            }
            Parsed::Complete(Reply::Listed(rows))
        }
        _ => Parsed::Invalid("bad status".into()),
    }
}

/// A space-separated ring back into keys. Empty is no keys, not one empty key.
fn split_ring(ring: &str) -> Vec<String> {
    ring.split(' ').filter(|k| !k.is_empty()).map(str::to_string).collect()
}

/// The admin socket's name under the board root. Both programs derive it
/// from `--root`, so neither needs a flag for it.
pub const SOCKET_NAME: &str = "mbbs-user.sock";

/// Where the admin socket for the board at `root` lives.
pub fn socket_path(root: &Path) -> PathBuf {
    root.join(SOCKET_NAME)
}

/// Bind the admin socket at `path` and serve one request per connection.
///
/// Anyone who can connect can administer the board's accounts, so the
/// socket is `0600` and lives in the board root, which the serving user
/// owns. A socket file already there is a dead server's leftover if nothing
/// answers on it, and is removed; one that answers is another live server
/// on the same root, and this one refuses to start rather than steal it.
///
/// `bind` and `set_permissions` cannot be one atomic step, and the board
/// root is typically `0755`, so a plain bind-then-chmod at `path` itself
/// would leave the well-known name `mbbs-user.sock` briefly reachable at
/// whatever mode the listening process's ordinary umask gives it. Instead
/// this binds under a name in the same directory that nothing else is told
/// about, narrows that file to `0600`, and only then renames it onto
/// `path` -- a rename keeps the file's mode, so nothing ever appears at the
/// name a client would connect to before it is already `0600`.
///
/// This does not touch the process umask. `umask` is one setting shared by
/// every thread in the process, not scoped to this call, and narrowing it
/// around the bind raced this very crate's own test binary: a concurrent
/// test's scratch directory, created by an unrelated thread mid-window,
/// came out with the narrowed mode baked in and unreadable ever after. A
/// rename needs no such process-wide state.
///
/// Does not block: the accept loop runs in its own spawned task.
pub async fn serve(path: PathBuf, tx: std_mpsc::Sender<In>, serving: crate::host::Serving) -> io::Result<()> {
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} is already served by another mbbs-server", path.display()),
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
    // `AF_UNIX` paths are capped at `sockaddr_un::sun_path`'s length --
    // 108 bytes on Linux, null included -- so the temporary name stays as
    // close to `path`'s own length as it can: no process ID, just enough of
    // a change that it cannot collide with a real socket name. A `path`
    // already near the limit is what a deeply nested test scratch directory
    // looks like, and this fix must not be the reason one stops binding.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(".{SOCKET_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp); // a leftover from a killed process
    let listener = match UnixListener::bind(&tmp) {
        Ok(listener) => listener,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    let serving = serving.clone();
                    tokio::spawn(async move {
                        if let Err(e) = session(stream, tx, serving).await {
                            eprintln!("mbbs-server: mbbs-user session ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("mbbs-server: mbbs-user accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(())
}

/// One session: read a request, answer it, close.
async fn session(stream: UnixStream, tx: std_mpsc::Sender<In>, serving: crate::host::Serving) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    let mut buf = Vec::with_capacity(256);
    let request = loop {
        match parse_request(&buf) {
            Parsed::Complete(request) => break request,
            Parsed::Invalid(why) => {
                writer.write_all(&encode_reply(&Reply::Faulted(why))).await?;
                return Ok(());
            }
            Parsed::Incomplete => {
                let mut chunk = [0u8; 256];
                let n = reader.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(()); // gone before the frame ended
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    };

    let reply = if !serving.load(std::sync::atomic::Ordering::Relaxed) {
        Reply::Refused(sentence(crate::conn::MAINTENANCE_LINE))
    } else {
        let (reply_tx, reply_rx) = oneshot::channel();
        if tx.send(In::Admin { request, reply: reply_tx }).is_err() {
            Reply::Faulted(sentence(crate::conn::SERVER_ERROR_LINE))
        } else {
            match reply_rx.await {
                Ok(reply) => reply,
                // The host thread died between taking the message and
                // answering: the same outcome as the send failing.
                Err(_) => Reply::Faulted(sentence(crate::conn::SERVER_ERROR_LINE)),
            }
        }
    };
    writer.write_all(&encode_reply(&reply)).await?;
    Ok(())
}

/// The client half: hand `request` to the server behind `path`, if there is
/// one.
///
/// `Ok(None)` is "no server here": no file, a file that is not a socket, or
/// a socket file nothing answers on (a dead server's leftover). The caller
/// then opens the files itself. `Err` is a server that was there and could
/// not be talked to: a value that cannot be sent, a write that failed, a
/// reply that ended early or did not parse.
pub fn send(path: &Path, request: &Request) -> Result<Option<Reply>, String> {
    use std::io::{Read, Write};

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("looking at {}: {e}", path.display())),
    }
    let mut sock = match std::os::unix::net::UnixStream::connect(path) {
        Ok(sock) => sock,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(None),
        Err(e) => return Err(format!("connecting to {}: {e}", path.display())),
    };
    let bytes = encode_request(request)?;
    sock.write_all(&bytes).map_err(|e| format!("sending to mbbs-server: {e}"))?;

    // The server answers with exactly one frame and then closes (`session`
    // returns after its one write), so the whole reply is read to EOF
    // before any of it is parsed. A reply is not capped the way a request
    // is: `list` against a large board is exactly the case this is for.
    let mut got = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = sock.read(&mut chunk).map_err(|e| format!("reading mbbs-server's reply: {e}"))?;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    match parse_reply(&got) {
        Parsed::Complete(reply) => Ok(Some(reply)),
        Parsed::Invalid(why) => Err(format!("mbbs-server answered something this mbbs-user cannot read: {why}")),
        Parsed::Incomplete => Err("mbbs-server closed the socket before it answered".into()),
    }
}

/// A listener's wire line as a sentence: the `\r\n` off the end.
fn sentence(line: &[u8]) -> String {
    String::from_utf8_lossy(line).trim_end_matches(['\r', '\n']).to_owned()
}

/// Apply one request to the host that has the account files open.
///
/// The one place the commands are implemented. `mbbs-user` calls this
/// directly against a stopped board, and the host thread calls it for a
/// request that arrived over the socket, so the two can never disagree.
///
/// `passwd`, `keys`, `master` and `delete` are refused while the account
/// has a session (`Host::account_online`): the logoff write-back would put
/// the in-memory record back over whatever was written here.
pub fn apply<A: Abi>(host: &mut Host<A>, machine: &mut A::Cpu, request: Request) -> Reply {
    match request {
        Request::List => match host.account_list() {
            Ok(listed) => Reply::Listed(
                listed
                    .into_iter()
                    .map(|(record, ring)| Row {
                        userid: record.userid().to_owned(),
                        flags: record.flags(),
                        ring,
                    })
                    .collect(),
            ),
            Err(why) => Reply::Faulted(why),
        },
        Request::Add { userid, password, keys } => {
            accept(&userid, host.account_add(machine, &userid, &password, &keys))
        }
        Request::Passwd { userid, password } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            accept(&userid, host.account_set_password(&userid, &password))
        }
        Request::Keys { userid, add, remove } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            keys(host, &userid, &add, &remove)
        }
        Request::Master { userid, on } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            master(host, &userid, on)
        }
        Request::Delete { userid } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            accept(&userid, host.account_tag_deleted(&userid))
        }
    }
}

/// The online refusal, or `None` when the edit may go ahead.
fn online<A: Abi>(host: &mut Host<A>, userid: &str) -> Option<Reply> {
    match host.account_online(userid) {
        Ok(true) => Some(Reply::Refused(format!("{userid} is online"))),
        Ok(false) => None,
        Err(why) => Some(Reply::Faulted(why)),
    }
}

/// Turn one account-layer answer into a reply.
fn accept(userid: &str, answer: Result<Result<(), Refusal>, String>) -> Reply {
    match answer {
        Ok(Ok(())) => Reply::Done,
        Ok(Err(refusal)) => Reply::Refused(refused(userid, refusal)),
        Err(why) => Reply::Faulted(why),
    }
}

/// What each refusal is called on a sysop's terminal.
///
/// The listeners have their own vocabulary for these
/// (`mbbs_server::conn::refusal_line`) and it is the wrong one here: a caller
/// is told "No account by that name.", where a sysop is told which name. The
/// last six arms cannot be reached from any command in this program -- they are a
/// listener's answers to a claim -- and are spelled out anyway because
/// `Refusal` is closed, so a new variant lands here as a compile error rather
/// than as a wrong sentence.
pub fn refused(userid: &str, refusal: Refusal) -> String {
    match refusal {
        Refusal::Unknown => format!("no account named {userid}"),
        Refusal::Exists => format!("{userid} already has an account"),
        Refusal::Invalid(why) => why.to_string(),
        Refusal::BadPassword => format!("{userid}'s password does not match"),
        Refusal::NoPassword => format!("{userid} has no password"),
        Refusal::Deleted => format!("{userid} is tagged for deletion"),
        Refusal::Suspended => format!("{userid} is suspended"),
        Refusal::Full => "the board is full".to_owned(),
        Refusal::Maintenance => "the board is in maintenance".to_owned(),
    }
}

/// `keys`: the removals first, then the additions, then the file.
///
/// Removals before additions so that `--remove SYSOP --add SYSOP` is a way to
/// move a key to the end of the ring rather than a way to lose it, and so
/// that the order does not depend on the order the two flags were typed in.
///
/// An added key has to be one word of at most `KEYSIZ - 1` characters, and
/// anything else is refused before the ring is touched -- see the check
/// itself for what a space or a long name would do to a stored ring.
fn keys<A: Abi>(host: &mut Host<A>, userid: &str, add: &[String], remove: &[String]) -> Reply {
    // Asked first: `account_ring` answers `None` both for an account with no
    // ring record and for no account at all, and those are different
    // sentences.
    match host.account_find(userid) {
        Ok(None) => return Reply::Refused(refused(userid, Refusal::Unknown)),
        Ok(Some(_)) => {}
        Err(why) => return Reply::Faulted(why),
    }

    // A key name is one word, short enough for `keys[KEYSIZ]`. A ring is
    // stored space-separated and split on spaces when it is loaded, so a key
    // with a space in it is two keys the moment it is read back, and one
    // longer than `KEYSIZ - 1` is silently cut short by whatever reads it
    // into that array. Both are refused here rather than written: the
    // removal side needs no such check, since a name that cannot be stored
    // cannot be on a ring to remove.
    for key in add {
        if key.is_empty()
            || key.chars().any(char::is_whitespace)
            || key.len() > accounts::KEYSIZ - 1
        {
            return Reply::Refused(format!(
                "a key name is one word of at most {} characters",
                accounts::KEYSIZ - 1
            ));
        }
    }

    // A `keys USERID` with neither flag is a question, and a question does
    // not rewrite the record it is asking about: writing a ring is a delete
    // and an insert (see `Accounts::write_ring`), which is not a thing to do
    // to a file for no reason.
    if !add.is_empty() || !remove.is_empty() {
        let mut ring = match ring_of(host, userid) {
            Ok(ring) => ring,
            Err(why) => return Reply::Faulted(why),
        };
        ring.retain(|key| !remove.iter().any(|gone| gone.eq_ignore_ascii_case(key)));
        ring.extend(add.iter().map(|key| key.to_ascii_uppercase()));
        if let reply @ (Reply::Refused(_) | Reply::Faulted(_)) =
            accept(userid, host.account_write_ring(userid, &ring))
        {
            return reply;
        }
    }

    // Read back out of the file rather than the ring just written: what
    // the sysop is shown is what the next login will load.
    match ring_of(host, userid) {
        Ok(now) => Reply::Ring(now),
        Err(why) => Reply::Faulted(why),
    }
}

fn ring_of<A: Abi>(host: &mut Host<A>, userid: &str) -> Result<Vec<String>, String> {
    Ok(host.account_ring(userid)?.map_or_else(Vec::new, |ring| ring.keys))
}

/// `master`: set or clear `HASMST`, leaving the other three bits alone.
fn master<A: Abi>(host: &mut Host<A>, userid: &str, on: bool) -> Reply {
    let record = match host.account_find(userid) {
        Ok(Some((_, record))) => record,
        Ok(None) => return Reply::Refused(refused(userid, Refusal::Unknown)),
        Err(why) => return Reply::Faulted(why),
    };
    // The whole word, with one bit changed: the other three are the sysop's
    // and this command has no business touching them.
    let word = if on { record.flags() | flags::HASMST } else { record.flags() & !flags::HASMST };
    accept(userid, host.account_set_flags(userid, word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs::accounts::{Login, Terminal};
    use mbbs::testing::{scratch, Fixture};

    fn opened(name: &str) -> Fixture {
        let mut f = Fixture::rooted_with_terms(scratch(name), mbbs::Terms::new(2));
        f.host
            .open_accounts(&mut f.machine, crate::conn::default_keys())
            .expect("opened");
        f
    }

    fn add(f: &mut Fixture, userid: &str, password: &str) {
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Add {
                userid: userid.into(),
                password: password.into(),
                keys: crate::conn::default_keys(),
            },
        );
        assert_eq!(reply, Reply::Done, "{userid} added");
    }

    fn rows(f: &mut Fixture) -> Vec<Row> {
        match apply(&mut f.host, &mut f.machine, Request::List) {
            Reply::Listed(rows) => rows,
            other => panic!("list answered {other:?}"),
        }
    }

    #[test]
    fn add_then_list_shows_the_ring_and_no_flags() {
        let mut f = opened("admin-add");
        add(&mut f, "Dan", "hunter2");
        assert_eq!(
            rows(&mut f),
            vec![Row {
                userid: "Dan".into(),
                flags: 0,
                ring: vec!["DEMO".into(), "NORMAL".into(), "USER".into()]
            }]
        );
    }

    #[test]
    fn add_refuses_a_taken_name_in_the_sysops_words() {
        let mut f = opened("admin-add-taken");
        add(&mut f, "Dan", "hunter2");
        let again = apply(
            &mut f.host,
            &mut f.machine,
            Request::Add { userid: "dan".into(), password: "x".into(), keys: vec![] },
        );
        assert_eq!(again, Reply::Refused("dan already has an account".into()));
    }

    #[test]
    fn passwd_changes_what_a_login_accepts() {
        let mut f = opened("admin-passwd");
        add(&mut f, "Dan", "hunter2");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Passwd { userid: "Dan".into(), password: "newpw".into() },
        );
        assert_eq!(reply, Reply::Done);
        let (_, record) = f.host.account_find("Dan").expect("no fault").expect("exists");
        assert_eq!(record.password(), "newpw");
    }

    #[test]
    fn keys_removes_then_adds_and_answers_the_ring_read_back() {
        let mut f = opened("admin-keys");
        add(&mut f, "Dan", "hunter2");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Dan".into(), add: vec!["sysop".into()], remove: vec!["DEMO".into()] },
        );
        assert_eq!(reply, Reply::Ring(vec!["NORMAL".into(), "USER".into(), "SYSOP".into()]));

        // Neither flag: a question, answered with the same ring.
        let asked = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Dan".into(), add: vec![], remove: vec![] },
        );
        assert_eq!(asked, Reply::Ring(vec!["NORMAL".into(), "USER".into(), "SYSOP".into()]));
    }

    #[test]
    fn keys_refuses_a_name_that_is_not_one_short_word() {
        let mut f = opened("admin-keys-bad");
        add(&mut f, "Dan", "hunter2");
        for bad in ["TWO WORDS", "SIXTEENCHARSXXXX", ""] {
            let reply = apply(
                &mut f.host,
                &mut f.machine,
                Request::Keys { userid: "Dan".into(), add: vec![bad.into()], remove: vec![] },
            );
            assert_eq!(
                reply,
                Reply::Refused("a key name is one word of at most 15 characters".into()),
                "{bad:?}"
            );
        }
        assert_eq!(rows(&mut f)[0].ring, vec!["DEMO", "NORMAL", "USER"], "the ring is untouched");
    }

    #[test]
    fn keys_for_an_unknown_account_says_which_name() {
        let mut f = opened("admin-keys-unknown");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Nobody".into(), add: vec![], remove: vec![] },
        );
        assert_eq!(reply, Reply::Refused("no account named Nobody".into()));
    }

    #[test]
    fn master_sets_and_clears_one_bit_and_leaves_the_others() {
        use mbbs::accounts::flags;
        let mut f = opened("admin-master");
        add(&mut f, "Dan", "hunter2");
        f.host.account_set_flags("Dan", flags::UNDAXS).expect("no fault").expect("exists");

        let on = apply(&mut f.host, &mut f.machine, Request::Master { userid: "Dan".into(), on: true });
        assert_eq!(on, Reply::Done);
        assert_eq!(rows(&mut f)[0].flags, flags::HASMST | flags::UNDAXS);

        let off = apply(&mut f.host, &mut f.machine, Request::Master { userid: "Dan".into(), on: false });
        assert_eq!(off, Reply::Done);
        assert_eq!(rows(&mut f)[0].flags, flags::UNDAXS, "the other bit survives");
    }

    #[test]
    fn delete_tags_and_refuses_an_unknown_account() {
        use mbbs::accounts::flags;
        let mut f = opened("admin-delete");
        add(&mut f, "Dan", "hunter2");
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Delete { userid: "Dan".into() }),
            Reply::Done
        );
        assert_eq!(rows(&mut f)[0].flags & flags::DELTAG, flags::DELTAG);
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Delete { userid: "Nobody".into() }),
            Reply::Refused("no account named Nobody".into())
        );
    }

    /// The logoff write-back puts the whole in-memory record back over the
    /// file, so an edit to an account somebody is logged in as would be
    /// undone at their logoff. All four editing commands are refused while
    /// the account has a session, and allowed again once it has gone.
    #[test]
    fn editing_an_online_account_is_refused_until_it_logs_off() {
        let mut f = opened("admin-online");
        add(&mut f, "Dan", "hunter2");
        let module = f.registered_module();
        let chan = f.host.users().terms().chan(0).expect("channel 0");
        f.host
            .login(
                &mut f.machine,
                &module,
                chan,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                Terminal { ansi: true, width: 80, height: 24 },
            )
            .expect("no io error")
            .expect("accepted");

        let edits = [
            Request::Passwd { userid: "dan".into(), password: "x".into() },
            Request::Keys { userid: "Dan".into(), add: vec!["SYSOP".into()], remove: vec![] },
            Request::Master { userid: "Dan".into(), on: true },
            Request::Delete { userid: "Dan".into() },
        ];
        for request in &edits {
            let reply = apply(&mut f.host, &mut f.machine, request.clone());
            assert_eq!(reply, Reply::Refused(format!("{} is online", request_userid(request))), "{request:?}");
        }
        let (_, record) = f.host.account_find("Dan").expect("no fault").expect("exists");
        assert_eq!(record.password(), "hunter2", "nothing was written");
        assert_eq!(rows(&mut f)[0].ring, vec!["DEMO", "NORMAL", "USER"]);

        // `list` and `add` are never refused for this reason.
        assert_eq!(rows(&mut f).len(), 1);
        add(&mut f, "Beef", "beef1");

        f.host.hangup(&mut f.machine, &module, chan).expect("hung up");
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Passwd { userid: "Dan".into(), password: "x".into() }),
            Reply::Done,
            "logged off, so the edit lands"
        );
    }

    fn request_userid(request: &Request) -> &str {
        match request {
            Request::Passwd { userid, .. }
            | Request::Keys { userid, .. }
            | Request::Master { userid, .. }
            | Request::Delete { userid }
            | Request::Add { userid, .. } => userid,
            Request::List => "",
        }
    }

    fn every_request() -> Vec<Request> {
        vec![
            Request::Add {
                userid: "Dan Corbe".into(),
                password: "hunter2".into(),
                keys: vec!["DEMO".into(), "NORMAL".into()],
            },
            Request::Add { userid: "Beef".into(), password: "b".into(), keys: vec![] },
            Request::Passwd { userid: "Dan".into(), password: "x=y".into() },
            Request::Keys {
                userid: "Dan".into(),
                add: vec!["SYSOP".into(), "WCCSYSOP".into()],
                remove: vec!["DEMO".into()],
            },
            Request::Keys { userid: "Dan".into(), add: vec![], remove: vec![] },
            Request::Master { userid: "Dan".into(), on: true },
            Request::Master { userid: "Dan".into(), on: false },
            Request::List,
            Request::Delete { userid: "Dan".into() },
        ]
    }

    fn every_reply() -> Vec<Reply> {
        vec![
            Reply::Done,
            Reply::Refused("Dan is online".into()),
            Reply::Faulted("writing the account Dan: status 2".into()),
            Reply::Listed(vec![]),
            Reply::Listed(vec![
                Row { userid: "Dan Corbe".into(), flags: 0, ring: vec!["DEMO".into(), "NORMAL".into()] },
                Row { userid: "Beef".into(), flags: 0x8003, ring: vec![] },
            ]),
            Reply::Ring(vec![]),
            Reply::Ring(vec!["NORMAL".into(), "USER".into()]),
        ]
    }

    #[test]
    fn every_request_round_trips() {
        for request in every_request() {
            let bytes = encode_request(&request).expect("encodes");
            assert!(bytes.starts_with(b"mbbs-user 1\n"), "{request:?}: {bytes:?}");
            assert!(bytes.ends_with(b"\n\n"), "{request:?}: {bytes:?}");
            match parse_request(&bytes) {
                Parsed::Complete(back) => assert_eq!(back, request),
                other => panic!("{request:?} parsed as {other:?}"),
            }
        }
    }

    #[test]
    fn every_reply_round_trips() {
        for reply in every_reply() {
            let bytes = encode_reply(&reply);
            match parse_reply(&bytes) {
                Parsed::Complete(back) => assert_eq!(back, reply),
                other => panic!("{reply:?} parsed as {other:?}"),
            }
        }
    }

    #[test]
    fn a_value_with_a_control_character_is_not_sent() {
        for bad in ["a\nb", "a\rb", "a\tb", "a\x7fb", "\x1b[2J"] {
            let request = Request::Passwd { userid: "Dan".into(), password: bad.into() };
            assert!(encode_request(&request).is_err(), "{bad:?} must be refused before it is sent");
        }
    }

    #[test]
    fn a_frame_is_incomplete_until_its_blank_line_and_too_long_past_the_cap() {
        assert!(matches!(parse_request(b""), Parsed::Incomplete));
        assert!(matches!(parse_request(b"mbbs-user 1\ncommand=list\n"), Parsed::Incomplete));
        assert!(matches!(parse_request(b"mbbs-user 1\ncommand=list\n\n"), Parsed::Complete(Request::List)));
        let long = vec![b'x'; MAX_FRAME];
        assert_eq!(parse_request(&long), Parsed::Invalid("frame too long".into()));
        let mut padded = b"mbbs-user 1\n".to_vec();
        padded.extend(std::iter::repeat_n(b'k', MAX_FRAME));
        padded.extend_from_slice(b"=v\n\n");
        assert_eq!(parse_request(&padded), Parsed::Invalid("frame too long".into()));
    }

    #[test]
    fn each_request_parse_refusal_is_named() {
        let cases: [(&[u8], &str); 8] = [
            (b"GET / HTTP/1.0\r\n\r\n", "not an mbbs-user 1 frame"),
            (b"mbbs-door 1\nuser=Dan\n\n", "not an mbbs-user 1 frame"),
            (b"mbbs-user 1\nnonsense\n\n", "bad line"),
            (b"mbbs-user 1\nuserid=Dan\n\n", "no command"),
            (b"mbbs-user 1\ncommand=purge\n\n", "unknown command"),
            (b"mbbs-user 1\ncommand=passwd\npassword=x\n\n", "no userid"),
            (b"mbbs-user 1\ncommand=add\nuserid=Dan\n\n", "no password"),
            (b"mbbs-user 1\ncommand=master\nuserid=Dan\non=yes\n\n", "bad on"),
        ];
        for (bytes, why) in cases {
            assert_eq!(parse_request(bytes), Parsed::Invalid(why.into()), "{:?}", String::from_utf8_lossy(bytes));
        }
        assert_eq!(
            parse_request(b"mbbs-user 1\ncommand=master\nuserid=Dan\n\n"),
            Parsed::Invalid("no on".into())
        );
    }

    #[test]
    fn each_reply_parse_refusal_is_named() {
        assert_eq!(parse_reply(b"mbbs-user 1\nstatus=maybe\n\n"), Parsed::Invalid("bad status".into()));
        assert_eq!(parse_reply(b"mbbs-user 1\nstatus=ok\nrow=Dan\t0\n\n"), Parsed::Invalid("bad row".into()));
        assert_eq!(parse_reply(b"mbbs-user 1\nstatus=ok\nrow=Dan\tlots\tDEMO\n\n"), Parsed::Invalid("bad row".into()));
        assert_eq!(parse_reply(b"mbbs-user 1\nstatus=ok\nrow=Dan\t0\tDEMO\n\n"), Parsed::Complete(Reply::Listed(vec![Row { userid: "Dan".into(), flags: 0, ring: vec!["DEMO".into()] }])));
    }

    /// `MAX_FRAME` bounds a request, not a reply: `list` against a board
    /// with thousands of accounts answers with a frame well past it, and
    /// the client side has to read the whole thing back.
    #[test]
    fn a_reply_larger_than_max_frame_round_trips() {
        let rows: Vec<Row> = (0..3000)
            .map(|i| Row { userid: format!("user{i}"), flags: 0, ring: vec!["DEMO".into(), "NORMAL".into()] })
            .collect();
        let reply = Reply::Listed(rows);
        let bytes = encode_reply(&reply);
        assert!(bytes.len() > MAX_FRAME, "this test needs a reply bigger than a request's cap, got {} bytes", bytes.len());
        assert_eq!(parse_reply(&bytes), Parsed::Complete(reply));
    }

    /// A stand-in host thread: answers every `In::Admin` with the next
    /// canned reply and hands everything else to `rest`.
    fn fake_host(
        replies: Vec<Reply>,
    ) -> (
        std::sync::mpsc::Sender<crate::msg::In>,
        std::sync::mpsc::Receiver<Request>,
        std::sync::mpsc::Receiver<crate::msg::In>,
    ) {
        use crate::msg::In;
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (rest_tx, rest_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for msg in rx {
                match msg {
                    In::Admin { request, reply } => {
                        let _ = seen_tx.send(request);
                        let _ = reply.send(replies.next().unwrap_or(Reply::Faulted("out of canned replies".into())));
                    }
                    other => {
                        let _ = rest_tx.send(other);
                    }
                }
            }
        });
        (tx, seen_rx, rest_rx)
    }

    fn serving(on: bool) -> crate::host::Serving {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(on))
    }

    /// Connect, send one request, read to close, parse the reply.
    async fn exchange(path: &std::path::Path, request: &Request) -> Reply {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut sock = tokio::net::UnixStream::connect(path).await.expect("connect");
        sock.write_all(&encode_request(request).expect("encodes")).await.expect("send");
        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), sock.read_to_end(&mut got))
            .await
            .expect("the server closes within 5s")
            .expect("read");
        match parse_reply(&got) {
            Parsed::Complete(reply) => reply,
            other => panic!("reply {other:?} from {:?}", String::from_utf8_lossy(&got)),
        }
    }

    #[tokio::test]
    async fn a_request_reaches_the_host_and_its_reply_comes_back() {
        let root = scratch("admin-socket-roundtrip").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        let (tx, seen, _rest) = fake_host(vec![Reply::Ring(vec!["SYSOP".into()])]);
        serve(path.clone(), tx, serving(true)).await.expect("bind");

        let request = Request::Keys { userid: "Dan".into(), add: vec!["SYSOP".into()], remove: vec![] };
        assert_eq!(exchange(&path, &request).await, Reply::Ring(vec!["SYSOP".into()]));
        assert_eq!(seen.recv_timeout(std::time::Duration::from_secs(5)).expect("seen"), request);

        let meta = std::fs::metadata(&path).expect("the socket file exists");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "owner-only");
    }

    #[tokio::test]
    async fn during_maintenance_the_request_is_refused_and_never_sent() {
        let root = scratch("admin-socket-maintenance").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        let (tx, seen, _rest) = fake_host(vec![Reply::Done]);
        serve(path.clone(), tx, serving(false)).await.expect("bind");

        let reply = exchange(&path, &Request::List).await;
        assert_eq!(
            reply,
            Reply::Refused("The system is down for daily maintenance. Try again in a few minutes.".into())
        );
        assert!(
            seen.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
            "nothing reached the host thread"
        );
    }

    #[tokio::test]
    async fn a_dead_host_thread_is_a_fault_the_client_can_read() {
        let root = scratch("admin-socket-dead-host").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        let (tx, rx) = std::sync::mpsc::channel::<crate::msg::In>();
        drop(rx);
        serve(path.clone(), tx, serving(true)).await.expect("bind");

        assert_eq!(
            exchange(&path, &Request::List).await,
            Reply::Faulted("Server error, try again later.".into())
        );
    }

    #[tokio::test]
    async fn a_frame_that_does_not_parse_is_a_fault_naming_why() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let root = scratch("admin-socket-bad-frame").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        let (tx, _seen, _rest) = fake_host(vec![]);
        serve(path.clone(), tx, serving(true)).await.expect("bind");

        let mut sock = tokio::net::UnixStream::connect(&path).await.expect("connect");
        sock.write_all(b"mbbs-user 1\ncommand=purge\n\n").await.expect("send");
        let mut got = Vec::new();
        sock.read_to_end(&mut got).await.expect("read");
        assert_eq!(parse_reply(&got), Parsed::Complete(Reply::Faulted("unknown command".into())));
    }

    #[tokio::test]
    async fn a_stale_socket_file_is_replaced_and_a_live_one_is_refused() {
        let root = scratch("admin-socket-stale").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        // Stale: a socket file nothing is listening on.
        drop(std::os::unix::net::UnixListener::bind(&path).expect("a listener to abandon"));
        assert!(path.exists(), "the abandoned socket file is still there");
        let (tx, _seen, _rest) = fake_host(vec![Reply::Done]);
        serve(path.clone(), tx.clone(), serving(true)).await.expect("a stale file is replaced");
        assert_eq!(exchange(&path, &Request::List).await, Reply::Done);

        // Live: a second server on the same root is refused.
        let err = serve(path.clone(), tx, serving(true)).await.expect_err("a live socket is another server's");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    // Multi-thread, for the same reason `mbbs_user.rs`'s live tests need it:
    // `send` is a blocking synchronous client, and a current-thread runtime
    // would never get to run the server's spawned accept and session tasks
    // while `send` sat inside `spawn_blocking` waiting on them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_returns_a_reply_larger_than_max_frame_intact() {
        let root = scratch("admin-socket-huge-reply").canonicalize().expect("scratch dir exists");
        let path = socket_path(&root);
        let rows: Vec<Row> = (0..3000)
            .map(|i| Row { userid: format!("user{i}"), flags: 0, ring: vec!["DEMO".into(), "NORMAL".into()] })
            .collect();
        let reply = Reply::Listed(rows);
        assert!(
            encode_reply(&reply).len() > MAX_FRAME,
            "this test needs a reply bigger than a request's cap, got {} bytes",
            encode_reply(&reply).len()
        );
        let (tx, _seen, _rest) = fake_host(vec![reply.clone()]);
        serve(path.clone(), tx, serving(true)).await.expect("bind");

        let got = tokio::task::spawn_blocking({
            let path = path.clone();
            move || send(&path, &Request::List)
        })
        .await
        .expect("the blocking send task did not panic")
        .expect("no transport error")
        .expect("a server answered");
        assert_eq!(got, reply);
    }
}
