//! `mbbs-user`: the sysop's account editor for a board this host serves.
//!
//! Spec section 4. The board's accounts live in two Btrieve files
//! (`bbsusr.dat`/`bbsk.dat` under a `Wg16` board, `wgsusr2.dat`/`wgskey2.dat`
//! under a `Wg32` one), and every rule about what may go in them --
//! `valuid`, the password bounds, the flags word, a ring's `RINGSZ` -- lives
//! in `mbbs`'s account layer with the login path. This binary is the sysop's
//! way in: it opens the same pair the server opens, through the same
//! `Host::open_accounts`, under the same advisory lock, and calls the same
//! `Host::account_*` methods a login calls into. It has no rules of its own.
//!
//! Three things it deliberately does not do:
//!
//! - **It never creates a pair.** A board gets its account files by booting
//!   `mbbs-server` once. A tool that created them would happily lay a second,
//!   empty database beside a board whose real one is a typo away in the path
//!   the sysop gave, and the sysop would find out at the first login.
//! - **It never edits a running board.** `Host::open_accounts` takes the
//!   `flock` the server holds for its whole life, so an edit while the board
//!   is up is refused before anything is read.
//! - **`delete` tags, it does not remove.** `DELTAG` is what the vendor's own
//!   account editor sets; the maintenance purge is what deletes the record and
//!   tells every module about it (`dlarou`), and only it can do that.
//!
//! ```text
//! mbbs-user --root DIR add USERID [--password PW] [--keys A,B]
//! mbbs-user --root DIR passwd USERID [--password PW]
//! mbbs-user --root DIR keys USERID [--add K]... [--remove K]...
//! mbbs-user --root DIR master USERID on|off
//! mbbs-user --root DIR list
//! mbbs-user --root DIR delete USERID
//! ```
//!
//! Exit 0 is done, exit 1 is a refusal (a userid nothing knows, a name
//! already taken, an account that may not be deleted, a board with no pair or
//! two, a board that is running), exit 2 is a mistake in the command line or
//! an I/O failure. Every refusal is one line on stderr starting `mbbs-user: `,
//! and nothing else is ever written there.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use mbbs::abi::{Abi, Wg16, Wg32};
use mbbs::accounts::{self, flags, Refusal};
use mbbs::{Host, Terms};
use mbbs_server::host::build_wg32_cpu;

/// What `master on` says every time, whatever the board.
///
/// `HASMST` is not "the sysop bit": `haskey` answers yes to *every* key for
/// an account that carries it, and MajorMUD's locks include ones a player
/// wants to fail -- `idiot` and `gidiot` gag the holder. A sysop who also
/// plays wants the two keys the door grants, not this flag.
const MASTER_WARNING: &str = "note: the master flag grants every lock, including MajorMUD's \
                              negative ones (idiot, gidiot); a sysop who plays should hold SYSOP \
                              and WCCSYSOP in the ring instead.";

#[derive(Parser)]
#[command(about = "Administer a board's accounts, keys and the master flag")]
struct Cli {
    /// The board directory, the same one `mbbs-server --root` names. Which
    /// generation's pair is in it decides which host this tool builds; there
    /// is no ABI flag to get wrong.
    #[arg(long)]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add an account with a password and a key ring.
    Add {
        userid: String,
        /// The password. Prompted for twice, without echo, if this is
        /// absent and stdin is a terminal.
        #[arg(long)]
        password: Option<String>,
        /// The ring the new account gets, comma separated. The board's
        /// default ring if absent.
        #[arg(long, value_delimiter = ',')]
        keys: Vec<String>,
    },
    /// Set an account's password.
    Passwd {
        userid: String,
        /// The new password. Prompted for twice, without echo, if this is
        /// absent and stdin is a terminal.
        #[arg(long)]
        password: Option<String>,
    },
    /// Add and remove keys on an account's ring.
    Keys {
        userid: String,
        /// A key to grant. Repeatable.
        #[arg(long = "add")]
        add: Vec<String>,
        /// A key to take away. Repeatable, and matched without regard to
        /// case, because a ring's names are compared with `sameas`.
        #[arg(long = "remove")]
        remove: Vec<String>,
    },
    /// Grant or revoke the master flag.
    Master { userid: String, switch: Switch },
    /// Print every account with its flags and its ring.
    List,
    /// Tag an account for deletion. The nightly purge removes it.
    Delete { userid: String },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Switch {
    On,
    Off,
}

/// One line and one exit code, which is the whole of what this program says.
///
/// Every path below produces one of these instead of printing as it goes, so
/// that `main` is the only place that writes a refusal and there is exactly
/// one `mbbs-user: ` prefix in the program.
struct Failure {
    code: u8,
    line: String,
}

impl Failure {
    /// The board said no: exit 1.
    fn refused(line: impl Into<String>) -> Self {
        Self { code: 1, line: line.into() }
    }

    /// The command line was wrong, or something underneath failed: exit 2.
    fn faulted(line: impl Into<String>) -> Self {
        Self { code: 2, line: line.into() }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli.root, &cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure { code, line }) => {
            eprintln!("mbbs-user: {line}");
            ExitCode::from(code)
        }
    }
}

/// Which host this board wants, then that host.
fn dispatch(root: &Path, command: &Command) -> Result<(), Failure> {
    match generation(root)? {
        Which::Wg16 => {
            let mut machine = mbbs_machine::m16::Machine::new()
                .map_err(|e| Failure::faulted(format!("building a 16-bit machine: {e}")))?;
            run::<Wg16>(&mut machine, root, command)
        }
        Which::Wg32 => {
            let mut machine = build_wg32_cpu()()
                .map_err(|e| Failure::faulted(format!("building a 32-bit machine: {e}")))?;
            run::<Wg32>(&mut machine, root, command)
        }
    }
}

enum Which {
    Wg16,
    Wg32,
}

/// Which generation's pair is under `root`.
///
/// The account file alone decides it, the same way
/// `Host::open_accounts`'s wrong-generation check does. A board holding one
/// of a pair is *not* diagnosed here: that is the host's own half-pair
/// refusal, and letting it come from there keeps one sentence about it in the
/// codebase instead of two.
fn generation(root: &Path) -> Result<Which, Failure> {
    let (wg16, _) = accounts::file_names::<Wg16>();
    let (wg32, _) = accounts::file_names::<Wg32>();
    match (present(root, wg16), present(root, wg32)) {
        (true, false) => Ok(Which::Wg16),
        (false, true) => Ok(Which::Wg32),
        (true, true) => Err(Failure::refused(format!(
            "both {wg16} and {wg32} are here; a board has one pair"
        ))),
        (false, false) => Err(Failure::refused(format!(
            "no account files in {}; boot mbbs-server once to create them",
            root.display()
        ))),
    }
}

/// Whether `root` holds a file called `name`, ignoring case.
///
/// `Host::find`'s rule, for one name in one directory: a board installed from
/// a DOS distribution has `BBSUSR.DAT` where this host writes `bbsusr.dat`,
/// and the host opens either. Inferring the generation case-sensitively would
/// tell such a sysop their board has no accounts.
fn present(root: &Path, name: &str) -> bool {
    if root.join(name).is_file() {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry.file_name().to_string_lossy().eq_ignore_ascii_case(name) && entry.path().is_file()
    })
}

/// One command against one board, whichever ABI it is.
///
/// The host is built the way `mbbs-server` builds one -- `Host::new`, then
/// `finish_init`, then `open_accounts` -- with one channel, because nothing
/// here connects one. No module is loaded: every method below reads and
/// writes the two files and touches no module memory.
fn run<A: Abi>(machine: &mut A::Cpu, root: &Path, command: &Command) -> Result<(), Failure> {
    let mut host = Host::<A>::new(machine, root.to_path_buf(), Terms::new(1))
        .map_err(|e| Failure::faulted(format!("opening the board at {}: {e}", root.display())))?;
    host.finish_init(machine)
        .map_err(|e| Failure::faulted(format!("starting the host: {e}")))?;

    // The default ring matters only to `Host::open_accounts`'s bookkeeping
    // here: `add` passes the ring it will use explicitly, so the board's
    // default reaches an account through one path and not two.
    host.open_accounts(machine, mbbs_server::conn::default_keys())
        .map_err(open_refusal)?;

    match command {
        Command::List => list(&mut host),
        Command::Add { userid, password, keys } => {
            let password = password_for(password.as_deref())?;
            let ring = if keys.is_empty() {
                mbbs_server::conn::default_keys()
            } else {
                keys.clone()
            };
            accept(userid, host.account_add(machine, userid, &password, &ring))
        }
        Command::Passwd { userid, password } => {
            let password = password_for(password.as_deref())?;
            accept(userid, host.account_set_password(userid, &password))
        }
        Command::Keys { userid, add, remove } => keys(&mut host, userid, add, remove),
        Command::Master { userid, switch } => master(&mut host, userid, *switch),
        Command::Delete { userid } => accept(userid, host.account_tag_deleted(userid)),
    }
}

/// What a board that will not open says.
///
/// A held lock is the one case worth its own sentence: the host's own text
/// names a path and an `flock`, where what the sysop needs to know is that
/// their board is up. Everything else -- half a pair, the wrong generation, a
/// record length that is not this host's -- is the host's own sentence,
/// unaltered, because it already names the file and the mismatch.
fn open_refusal(e: io::Error) -> Failure {
    if e.kind() == io::ErrorKind::WouldBlock {
        return Failure::refused("mbbs-server has this board's account file open, stop it first");
    }
    Failure::refused(e.to_string())
}

/// Turn one account-layer answer into an exit code.
///
/// `Ok(Err(refusal))` is the sysop's mistake and exits 1. `Err(fault)` is the
/// engine or the files, and exits 2.
fn accept(userid: &str, answer: Result<Result<(), Refusal>, String>) -> Result<(), Failure> {
    match answer {
        Ok(Ok(())) => Ok(()),
        Ok(Err(refusal)) => Err(Failure::refused(refused(userid, refusal))),
        Err(why) => Err(Failure::faulted(why)),
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
fn refused(userid: &str, refusal: Refusal) -> String {
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

/// `list`: the whole account file, one row each, in key order.
fn list<A: Abi>(host: &mut Host<A>) -> Result<(), Failure> {
    let listed = host.account_list().map_err(Failure::faulted)?;
    let mut out = io::stdout().lock();
    let mut row = |userid: &str, flags: &str, ring: &str| {
        let line = format!("{userid:<29} {flags:<9} {ring}");
        writeln!(out, "{}", line.trim_end())
    };
    row("USERID", "FLAGS", "RING").map_err(|e| Failure::faulted(e.to_string()))?;
    for (record, ring) in listed {
        row(record.userid(), &spelled(record.flags()), &ring.join(" "))
            .map_err(|e| Failure::faulted(e.to_string()))?;
    }
    Ok(())
}

/// A flags word as a sysop reads it. `USRACC.H:64-68`.
fn spelled(word: u16) -> String {
    let mut named = Vec::new();
    if word & flags::HASMST != 0 {
        named.push("MASTER");
    }
    if word & flags::UNDAXS != 0 {
        named.push("UNDAXS");
    }
    if word & flags::SUSPEN != 0 {
        named.push("SUSPENDED");
    }
    if word & flags::DELTAG != 0 {
        named.push("DELETED");
    }
    if named.is_empty() {
        "-".to_owned()
    } else {
        named.join(",")
    }
}

/// `keys`: the removals first, then the additions, then the file.
///
/// Removals before additions so that `--remove SYSOP --add SYSOP` is a way to
/// move a key to the end of the ring rather than a way to lose it, and so
/// that the order does not depend on the order the two flags were typed in.
fn keys<A: Abi>(
    host: &mut Host<A>,
    userid: &str,
    add: &[String],
    remove: &[String],
) -> Result<(), Failure> {
    // Asked first: `account_ring` answers `None` both for an account with no
    // ring record and for no account at all, and those are different
    // sentences.
    if host.account_find(userid).map_err(Failure::faulted)?.is_none() {
        return Err(Failure::refused(refused(userid, Refusal::Unknown)));
    }

    // A `keys USERID` with neither flag is a question, and a question does
    // not rewrite the record it is asking about: writing a ring is a delete
    // and an insert (see `Accounts::write_ring`), which is not a thing to do
    // to a file for no reason.
    if !add.is_empty() || !remove.is_empty() {
        let mut ring = ring_of(host, userid)?;
        ring.retain(|key| !remove.iter().any(|gone| gone.eq_ignore_ascii_case(key)));
        ring.extend(add.iter().map(|key| key.to_ascii_uppercase()));
        accept(userid, host.account_write_ring(userid, &ring))?;
    }

    // Read back out of the file rather than printed from the ring just
    // written: what the sysop is shown is what the next login will load.
    let now = ring_of(host, userid)?;
    println!("{}", if now.is_empty() { "-".to_owned() } else { now.join(" ") });
    Ok(())
}

fn ring_of<A: Abi>(host: &mut Host<A>, userid: &str) -> Result<Vec<String>, Failure> {
    Ok(host
        .account_ring(userid)
        .map_err(Failure::faulted)?
        .map_or_else(Vec::new, |ring| ring.keys))
}

/// `master`: set or clear `HASMST`, and say what setting it means.
fn master<A: Abi>(host: &mut Host<A>, userid: &str, switch: Switch) -> Result<(), Failure> {
    let Some((_, record)) = host.account_find(userid).map_err(Failure::faulted)? else {
        return Err(Failure::refused(refused(userid, Refusal::Unknown)));
    };
    // The whole word, with one bit changed: the other three are the sysop's
    // and this command has no business touching them.
    let word = match switch {
        Switch::On => record.flags() | flags::HASMST,
        Switch::Off => record.flags() & !flags::HASMST,
    };
    accept(userid, host.account_set_flags(userid, word))?;
    if switch == Switch::On {
        eprintln!("mbbs-user: {MASTER_WARNING}");
    }
    Ok(())
}

/// The password to write: the one given, or one typed twice at a terminal.
///
/// A script has no terminal, so `--password` is required there and the
/// refusal says so rather than hanging on a read that will never return.
fn password_for(given: Option<&str>) -> Result<String, Failure> {
    if let Some(password) = given {
        return Ok(password.to_owned());
    }

    let Some(_raw) = RawStdin::enter()
        .map_err(|e| Failure::faulted(format!("putting the terminal in raw mode: {e}")))?
    else {
        return Err(Failure::faulted(
            "--password is required when stdin is not a terminal",
        ));
    };

    let first = typed("Password: ")?;
    let again = typed("Again: ")?;
    if first != again {
        return Err(Failure::faulted("the two passwords do not match"));
    }
    Ok(first)
}

/// One password, read a byte at a time with the terminal in raw mode.
///
/// The prompt and the echo of the newline go to stderr, so that a command
/// whose output is being captured (`list`) and a command that asks a question
/// never share a stream. Bytes outside printable ASCII are dropped rather
/// than collected: an arrow key is three bytes the password field has no use
/// for, and `validate_password` would refuse them anyway.
fn typed(prompt: &str) -> Result<String, Failure> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();

    let mut stdin = io::stdin().lock();
    let mut password = String::new();
    let mut byte = [0u8; 1];
    loop {
        match stdin.read(&mut byte) {
            Ok(0) => return Err(Failure::faulted("stdin ended before the password did")),
            Ok(_) => {}
            Err(e) => return Err(Failure::faulted(format!("reading the password: {e}"))),
        }
        match byte[0] {
            b'\r' | b'\n' => {
                // CRLF, not LF: OPOST is off, so the carriage stays where the
                // prompt left it otherwise.
                eprint!("\r\n");
                return Ok(password);
            }
            // ^C and ^D. ISIG is off in raw mode, so both arrive as bytes and
            // this is the only thing that can stop the read.
            0x03 | 0x04 => {
                eprint!("\r\n");
                return Err(Failure::faulted("cancelled"));
            }
            0x08 | 0x7f => {
                password.pop();
            }
            b @ 0x20..=0x7e => password.push(char::from(b)),
            _ => {}
        }
    }
}

/// Raw mode on stdin for as long as this lives; restores on drop.
///
/// The same forty lines as `crates/mbbs-server/src/bin/mbbs-door.rs`'s, and
/// duplicated for the reason that one gives for duplicating
/// `crates/dos-runtime/src/terminal.rs`'s: a termios call is not worth a
/// shared module, and two bins each owning their own is the precedent this
/// crate already set.
struct RawStdin {
    saved: libc::termios,
}

impl RawStdin {
    /// `None` when stdin is not a terminal -- a pipe, a cron job, or a test.
    /// Nothing to set, nothing to restore, and nobody to prompt.
    fn enter() -> io::Result<Option<Self>> {
        // SAFETY: querying our own stdin.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
            return Ok(None);
        }
        // SAFETY: reading the current settings of our own stdin.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: applying settings to our own stdin.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { saved }))
    }
}

impl Drop for RawStdin {
    fn drop(&mut self) {
        // SAFETY: restoring settings we saved from our own stdin.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved) };
    }
}
