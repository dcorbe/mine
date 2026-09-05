//! The `mbbs-user` CLI, end to end, against a real account pair.
//!
//! `cargo test -p mbbs-server --test mbbs_user`
//!
//! Every test here runs the shipped binary as a child process against a
//! scratch board, because the exit code and the one stderr line *are* the
//! contract a sysop and a script see. The pair itself is created the only
//! way this codebase creates one -- `Host::open_accounts` on a
//! [`mbbs::testing::Fixture`] -- and the fixture is then dropped, which
//! releases the advisory lock the host holds for its life. A live board
//! keeps that lock, and [`a_held_lock_refuses`] is the test that proves the
//! CLI refuses to edit under one.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mbbs::abi::Wg16;
use mbbs::accounts::{flags, Login, Terminal};
use mbbs::testing::{scratch, Fixture};
use mbbs_server::admin;
use mbbs_server::msg::{In, Out};

/// One test at a time.
///
/// Not for the files -- every test has its own scratch board -- but for the
/// advisory lock. A `Command` this file runs forks before it execs, and the
/// child inherits every descriptor the parent had open at the fork, including
/// the `flock`ed one a [`Fixture`] is holding on some *other* test's account
/// file. `O_CLOEXEC` closes it at the exec a moment later, but until then that
/// duplicate keeps the lock alive after the owning thread has dropped its own
/// copy -- so a test that drops a fixture and immediately takes the lock
/// itself ([`a_held_lock_refuses`]) saw `WouldBlock` from a lock nobody owned,
/// about once in eight runs. Running the tests one at a time closes the
/// window: no fixture is ever dropped while another test is forking.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold [`ONE_AT_A_TIME`] for the rest of the test. A poisoned mutex is a
/// test that already failed, and is no reason to fail the rest.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A scratch board with an empty `Wg16` pair and no accounts in it.
///
/// The fixture is dropped before this returns: its `Accounts` holds the
/// `flock` on `bbsusr.dat`, and every test below runs a binary that takes
/// the same lock.
fn board(name: &str) -> PathBuf {
    let root = scratch(name);
    let mut f = Fixture::rooted(root.clone());
    f.host
        .open_accounts(&mut f.machine, mbbs_server::conn::default_keys())
        .expect("a fresh board gets its pair created");
    drop(f);
    root
}

/// Run the CLI against `root`. Stdin is `/dev/null`, so a password prompt
/// cannot reach for the terminal `cargo test` was started from.
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mbbs-user"))
        .arg("--root")
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the CLI ran")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// One `list` row, whitespace collapsed: `"Dan - DEMO NORMAL USER"`.
///
/// The real row is column-aligned, and asserting on the padding would make
/// every test here a test of the column widths. The row is found by its
/// first field, which is why no userid in this file contains a space.
fn row(out: &Output, userid: &str) -> String {
    let text = stdout(out);
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some(userid))
        .unwrap_or_else(|| panic!("no row for {userid} in:\n{text}"));
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Set an account's whole flags word through the library, the way a test
/// arranges a state the CLI has no command for (`UNDAXS`).
fn set_flags(root: &Path, userid: &str, word: u16) {
    let mut f = Fixture::rooted(root.to_path_buf());
    f.host
        .open_accounts(&mut f.machine, mbbs_server::conn::default_keys())
        .expect("the pair opens");
    f.host
        .account_set_flags(userid, word)
        .expect("no engine fault")
        .expect("the account exists");
}

/// What the stand-in host thread did, so a test can wait for it.
#[derive(Debug, PartialEq, Eq)]
enum Happened {
    LoggedIn,
    Refused,
    HungUp,
    Applied,
}

/// A stand-in for `mbbs-server`'s host thread over a real account pair:
/// logs `In::Connect` callers in with `Host::login`, hangs them up on
/// `In::Disconnect`, and answers `In::Admin` with `admin::apply`. Built on
/// its own thread because a 16-bit machine cannot cross one.
fn live_board(root: PathBuf) -> (std::sync::mpsc::Sender<In>, std::sync::mpsc::Receiver<Happened>) {
    let (tx, rx) = std::sync::mpsc::channel::<In>();
    let (happened_tx, happened_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let terms = mbbs::Terms::new(2);
        let mut f = Fixture::<Wg16>::rooted_with_terms(root, terms);
        f.host
            .open_accounts(&mut f.machine, mbbs_server::conn::default_keys())
            .expect("the pair opens");
        let module = f.registered_module();
        let mut outs: Vec<Option<tokio::sync::mpsc::Sender<Out>>> = vec![None; 2];
        ready_tx.send(()).expect("the test is waiting");
        for msg in rx {
            match msg {
                In::Connect { login, terminal, out, reply } => {
                    let chan = terms.chan(0).expect("channel 0");
                    match f.host.login(&mut f.machine, &module, chan, &login, terminal).expect("no io error") {
                        Ok(_) => {
                            outs[0] = Some(out);
                            let _ = reply.send(Ok(chan));
                            let _ = happened_tx.send(Happened::LoggedIn);
                        }
                        Err(refusal) => {
                            let _ = reply.send(Err(refusal));
                            let _ = happened_tx.send(Happened::Refused);
                        }
                    }
                }
                In::Disconnect { chan } => {
                    if outs[chan.index()].take().is_some() {
                        f.host.hangup(&mut f.machine, &module, chan).expect("hung up");
                        let _ = happened_tx.send(Happened::HungUp);
                    }
                }
                In::Admin { request, reply } => {
                    let _ = reply.send(admin::apply(&mut f.host, &mut f.machine, request));
                    let _ = happened_tx.send(Happened::Applied);
                }
                In::Input { .. } | In::Alarm | In::Maintain => {}
                In::Shutdown { done } => {
                    drop(done);
                    break;
                }
            }
        }
    });
    ready_rx.recv().expect("the board came up");
    (tx, happened_rx)
}

fn expect(happened: &std::sync::mpsc::Receiver<Happened>, what: Happened) {
    assert_eq!(
        happened.recv_timeout(std::time::Duration::from_secs(10)).expect("the board did something"),
        what
    );
}

/// Run the CLI off the runtime's blocking pool, so the socket task keeps
/// being driven while the child runs.
async fn run_live(root: &Path, args: &[&str]) -> Output {
    let root = root.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&root, &args)
    })
    .await
    .expect("the CLI ran")
}

/// Connect to the telnet listener and answer the login dialogue.
async fn telnet_login(addr: std::net::SocketAddr, userid: &str, password: &str) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(format!("{userid}\r{password}\r").as_bytes()).await.expect("login");
    sock
}

// Multi-thread: `expect` blocks the calling OS thread on a std channel, and
// under a current-thread runtime that thread *is* the runtime, so the
// telnet accept loop and login dialogue this test waits on would never get
// to run. `run_live`'s `spawn_blocking` needs the same thing for the same
// reason. `_serial` is a std `MutexGuard` held across the awaits below, which
// is exactly what it is for: it serialises the whole test body, on this
// runtime's own worker threads, against every other test in the binary.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn against_a_running_board_add_goes_over_the_socket_and_the_account_can_log_in() {
    let _serial = serial();
    let root = scratch("mbbs-user-live-add").canonicalize().expect("scratch dir exists");
    let (tx, happened) = live_board(root.clone());
    let serving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    admin::serve(admin::socket_path(&root), tx.clone(), serving.clone()).await.expect("admin socket");
    let addr = mbbs_server::conn::serve_on(
        tx.clone(),
        &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern as fn() -> mbbs_server::termcompat::Stack)],
        serving,
    )
    .await
    .expect("telnet")[0];

    // The board holds the lock. The direct path would be refused, so a
    // success here is the socket path.
    let added = run_live(&root, &["add", "Dan", "--password", "hunter2"]).await;
    assert_eq!(added.status.code(), Some(0), "{}", stderr(&added));
    assert_eq!(stderr(&added), "");
    expect(&happened, Happened::Applied);

    let listed = run_live(&root, &["list"]).await;
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert_eq!(row(&listed, "Dan"), "Dan - DEMO NORMAL USER");
    expect(&happened, Happened::Applied);

    let sock = telnet_login(addr, "Dan", "hunter2").await;
    expect(&happened, Happened::LoggedIn);
    drop(sock);
    expect(&happened, Happened::HungUp);

    let bad = telnet_login(addr, "Dan", "wrong").await;
    expect(&happened, Happened::Refused);
    drop(bad);
    let _ = tx.send(In::Shutdown { done: tokio::sync::oneshot::channel().0 });
}

// See the comment on the previous test for why this needs a multi-thread
// runtime and holds `_serial` across its awaits.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passwd_for_an_online_account_is_refused_and_lands_after_logoff() {
    let _serial = serial();
    let root = scratch("mbbs-user-live-online").canonicalize().expect("scratch dir exists");
    let (tx, happened) = live_board(root.clone());
    let serving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    admin::serve(admin::socket_path(&root), tx.clone(), serving.clone()).await.expect("admin socket");
    let addr = mbbs_server::conn::serve_on(
        tx.clone(),
        &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern as fn() -> mbbs_server::termcompat::Stack)],
        serving,
    )
    .await
    .expect("telnet")[0];

    assert_eq!(run_live(&root, &["add", "Dan", "--password", "hunter2"]).await.status.code(), Some(0));
    expect(&happened, Happened::Applied);

    let sock = telnet_login(addr, "Dan", "hunter2").await;
    expect(&happened, Happened::LoggedIn);

    let refused = run_live(&root, &["passwd", "Dan", "--password", "newpw"]).await;
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert_eq!(stderr(&refused), "mbbs-user: Dan is online\n");
    expect(&happened, Happened::Applied);

    drop(sock);
    expect(&happened, Happened::HungUp);

    // The old password still works: nothing was written under the session.
    let old = telnet_login(addr, "Dan", "hunter2").await;
    expect(&happened, Happened::LoggedIn);
    drop(old);
    expect(&happened, Happened::HungUp);

    let landed = run_live(&root, &["passwd", "Dan", "--password", "newpw"]).await;
    assert_eq!(landed.status.code(), Some(0), "{}", stderr(&landed));
    expect(&happened, Happened::Applied);

    let new = telnet_login(addr, "Dan", "newpw").await;
    expect(&happened, Happened::LoggedIn);
    drop(new);
    expect(&happened, Happened::HungUp);
    let _ = tx.send(In::Shutdown { done: tokio::sync::oneshot::channel().0 });
}

/// A socket file nothing answers on is a dead server's. The CLI falls
/// through to the files, which are unlocked, and the command succeeds.
#[test]
fn a_stale_socket_falls_through_to_the_direct_path() {
    let _serial = serial();
    let root = board("mbbs-user-stale-socket").canonicalize().expect("scratch dir exists");
    drop(std::os::unix::net::UnixListener::bind(admin::socket_path(&root)).expect("a listener to abandon"));

    let added = run(&root, &["add", "Dan", "--password", "hunter2"]);
    assert_eq!(added.status.code(), Some(0), "{}", stderr(&added));
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan - DEMO NORMAL USER");
}

#[test]
fn add_then_list_shows_the_ring_and_no_flags() {
    let _serial = serial();
    let root = board("mbbs-user-add");

    let added = run(&root, &["add", "Dan", "--password", "hunter2"]);
    assert!(added.status.success(), "{}", stderr(&added));
    assert_eq!(stderr(&added), "", "a successful add says nothing");

    let listed = run(&root, &["list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert!(
        stdout(&listed).starts_with("USERID"),
        "the listing has a header:\n{}",
        stdout(&listed)
    );
    assert_eq!(row(&listed, "Dan"), "Dan - DEMO NORMAL USER");
}

#[test]
fn master_on_sets_the_flag_and_warns() {
    let _serial = serial();
    let root = board("mbbs-user-master");
    assert!(run(&root, &["add", "Dan", "--password", "hunter2"]).status.success());

    let on = run(&root, &["master", "Dan", "on"]);
    assert_eq!(on.status.code(), Some(0), "{}", stderr(&on));
    assert!(
        stderr(&on).contains("note: the master flag"),
        "the warning is said: {}",
        stderr(&on)
    );
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan MASTER DEMO NORMAL USER");

    let off = run(&root, &["master", "Dan", "off"]);
    assert_eq!(off.status.code(), Some(0), "{}", stderr(&off));
    assert_eq!(stderr(&off), "", "turning it off warns about nothing");
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan - DEMO NORMAL USER");
}

#[test]
fn keys_add_and_remove_rewrite_the_ring() {
    let _serial = serial();
    let root = board("mbbs-user-keys");
    assert!(run(&root, &["add", "Dan", "--password", "hunter2"]).status.success());

    let keyed = run(&root, &["keys", "Dan", "--add", "sysop", "--remove", "DEMO"]);
    assert_eq!(keyed.status.code(), Some(0), "{}", stderr(&keyed));
    assert!(
        stdout(&keyed).contains("NORMAL USER SYSOP"),
        "the resulting ring is printed: {}",
        stdout(&keyed)
    );

    // The file's own order, read back by a second process: removes first,
    // then the additions on the end, and a lower-case `--add` stored upper.
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan - NORMAL USER SYSOP");

    // With neither flag it is a question, and the answer is the same ring.
    let asked = run(&root, &["keys", "Dan"]);
    assert_eq!(asked.status.code(), Some(0), "{}", stderr(&asked));
    assert_eq!(stdout(&asked), "NORMAL USER SYSOP\n");
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan - NORMAL USER SYSOP");
}

/// A ring is stored space-separated and read back by splitting on spaces, so
/// a key with a space in it is two keys the next time it is loaded, and one
/// longer than `KEYSIZ - 1` is cut short by whatever reads it into that
/// array. Both are refused with exit 1, and the ring on disk is untouched.
#[test]
fn keys_add_refuses_a_name_that_is_not_one_short_word() {
    let _serial = serial();
    let root = board("mbbs-user-keys-bad");
    assert!(run(&root, &["add", "Dan", "--password", "hunter2"]).status.success());
    let before = row(&run(&root, &["list"]), "Dan");

    for bad in ["TWO WORDS", "SIXTEENCHARSXXXX"] {
        let out = run(&root, &["keys", "Dan", "--add", bad]);
        assert_eq!(out.status.code(), Some(1), "{bad}: {}", stderr(&out));
        assert_eq!(
            stderr(&out),
            "mbbs-user: a key name is one word of at most 15 characters\n",
            "{bad}"
        );
        assert_eq!(row(&run(&root, &["list"]), "Dan"), before, "{bad}: the ring is untouched");
    }

    // Fifteen is the longest that is allowed, so the boundary is a rule and
    // not an off-by-one.
    let ok = run(&root, &["keys", "Dan", "--add", "FIFTEENCHARSXXX"]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(stdout(&ok).contains("FIFTEENCHARSXXX"), "{}", stdout(&ok));
}

#[test]
fn delete_tags_and_refuses_undeletable() {
    let _serial = serial();
    let root = board("mbbs-user-delete");
    assert!(run(&root, &["add", "Dan", "--password", "hunter2"]).status.success());

    let deleted = run(&root, &["delete", "Dan"]);
    assert_eq!(deleted.status.code(), Some(0), "{}", stderr(&deleted));

    // Tagged, not gone: the maintenance purge is what removes the record.
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan DELETED DEMO NORMAL USER");

    set_flags(&root, "Dan", flags::UNDAXS);
    let refused = run(&root, &["delete", "Dan"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert_eq!(stderr(&refused), "mbbs-user: that account cannot be deleted\n");
    assert_eq!(row(&run(&root, &["list"]), "Dan"), "Dan UNDAXS DEMO NORMAL USER");
}

#[test]
fn passwd_changes_what_the_host_accepts() {
    let _serial = serial();
    let root = board("mbbs-user-passwd");
    assert!(run(&root, &["add", "Dan", "--password", "hunter2"]).status.success());

    let changed = run(&root, &["passwd", "Dan", "--password", "newpw"]);
    assert_eq!(changed.status.code(), Some(0), "{}", stderr(&changed));

    let mut f = Fixture::rooted(root.clone());
    f.host
        .open_accounts(&mut f.machine, mbbs_server::conn::default_keys())
        .expect("the pair opens");
    let terminal = Terminal { ansi: true, width: 80, height: 24 };

    let now = f
        .host
        .resolve_login(
            &mut f.machine,
            &Login::Password { userid: "Dan".into(), password: "newpw".into() },
            terminal,
        )
        .expect("no engine fault");
    assert!(now.is_ok(), "the new password logs in: {now:?}");

    let before = f
        .host
        .resolve_login(
            &mut f.machine,
            &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
            terminal,
        )
        .expect("no engine fault");
    assert_eq!(before.unwrap_err(), mbbs::Refusal::BadPassword);
}

#[test]
fn no_pair_and_two_pairs_refuse_with_the_named_lines() {
    let _serial = serial();
    let bare = scratch("mbbs-user-no-pair");
    let refused = run(&bare, &["list"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert_eq!(
        stderr(&refused),
        format!(
            "mbbs-user: no account files in {}; boot mbbs-server once to create them\n",
            bare.display()
        )
    );

    let both = board("mbbs-user-two-pairs");
    std::fs::write(both.join("wgsusr2.dat"), b"").expect("a second generation's account file");
    let confused = run(&both, &["list"]);
    assert_eq!(confused.status.code(), Some(1), "{}", stderr(&confused));
    assert_eq!(
        stderr(&confused),
        "mbbs-user: both bbsusr.dat and wgsusr2.dat are here; a board has one pair\n"
    );
}

#[test]
fn a_held_lock_refuses() {
    let _serial = serial();
    let root = board("mbbs-user-locked");
    let held = mbbs::accounts::lock_file(&root.join("bbsusr.dat")).expect("the lock is free");

    let refused = run(&root, &["list"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("stop it first"),
        "the running board is named: {}",
        stderr(&refused)
    );

    drop(held);
    assert_eq!(run(&root, &["list"]).status.code(), Some(0));
}

#[test]
fn a_password_cannot_be_prompted_for_without_a_terminal() {
    let _serial = serial();
    let root = board("mbbs-user-no-tty");

    let refused = run(&root, &["add", "Dan"]);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert_eq!(
        stderr(&refused),
        "mbbs-user: --password is required when stdin is not a terminal\n"
    );

    // And nothing was written on the way to refusing.
    assert_eq!(stdout(&run(&root, &["list"])).lines().count(), 1);
}

#[test]
fn an_unknown_user_is_refused_by_every_command_that_names_one() {
    let _serial = serial();
    let root = board("mbbs-user-unknown");

    for args in [
        vec!["passwd", "Nobody", "--password", "hunter2"],
        vec!["keys", "Nobody", "--add", "SYSOP"],
        vec!["master", "Nobody", "on"],
        vec!["delete", "Nobody"],
    ] {
        let refused = run(&root, &args);
        assert_eq!(refused.status.code(), Some(1), "{args:?}: {}", stderr(&refused));
        assert_eq!(stderr(&refused), "mbbs-user: no account named Nobody\n", "{args:?}");
    }

    let twice = run(&root, &["add", "Dan", "--password", "hunter2"]);
    assert!(twice.status.success(), "{}", stderr(&twice));
    let again = run(&root, &["add", "Dan", "--password", "hunter2"]);
    assert_eq!(again.status.code(), Some(1), "{}", stderr(&again));
    assert_eq!(stderr(&again), "mbbs-user: Dan already has an account\n");
}

#[test]
fn a_board_with_half_a_pair_gets_the_hosts_own_refusal() {
    let _serial = serial();

    // The account file alone, under the host that owns that name.
    let root = board("mbbs-user-half-wg16");
    std::fs::remove_file(root.join("bbsk.dat")).expect("the key file goes");
    let refused = run(&root, &["list"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert_eq!(
        stderr(&refused),
        "mbbs-user: bbsusr.dat exists but bbsk.dat does not; a board has both or neither\n",
        "the host's own sentence, not a second copy of it in the CLI"
    );
    assert!(!root.join("bbsk.dat").exists(), "and nothing was created to make the pair whole");

    // An empty `wgsusr2.dat` is enough to pick the other generation, which is
    // the only thing in this file that builds a 32-bit machine at all -- the
    // refusal proves `run::<Wg32>` runs, not just that it compiles.
    let other = scratch("mbbs-user-half-wg32");
    std::fs::write(other.join("wgsusr2.dat"), b"").expect("a lone Worldgroup 3 account file");
    let refused = run(&other, &["list"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert_eq!(
        stderr(&refused),
        "mbbs-user: wgsusr2.dat exists but wgskey2.dat does not; a board has both or neither\n"
    );
    assert_eq!(
        std::fs::read_dir(&other).expect("the board directory").count(),
        1,
        "and nothing was created there either"
    );
}
