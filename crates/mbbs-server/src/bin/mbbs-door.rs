//! `mbbs-door`: what a BBS launches per caller to put them into a running
//! `mbbs-server`.
//!
//! The BBS wrote a DOOR32.SYS for this caller immediately before launching
//! us (Synchronet: `/sbbs/repo/src/sbbs3/xtrn_sec.cpp:1377`, path via
//! `%f`) and wired our stdin/stdout to the caller's terminal, usually a pty
//! left in cooked+echo mode (`xtrn.cpp:140,1642-1646`). We read the drop
//! file, reduce the BBS's security level to `sysop=0|1` against
//! `--sysop-level` (90 is Synchronet's `SYSOP_LEVEL`; Mystic and WWIV use
//! 255 -- the level scale is the BBS's, never the server's), put the pty
//! in raw mode, connect to the server's door socket, send the header, and
//! copy bytes both ways until the server closes the session.
//!
//! See `docs/superpowers/specs/2026-08-29-sbbs-door-design.md` §4.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mbbs_server::door::PROTOCOL;

/// Synchronet's `SYSOP_LEVEL` (`/sbbs/repo/src/sbbs3/sbbsdefs.h:865`).
const DEFAULT_SYSOP_LEVEL: u32 = 90;

#[derive(Parser)]
#[command(about = "Relay a BBS caller into a running mbbs-server")]
struct Cli {
    /// The DOOR32.SYS drop file the BBS wrote for this caller just before
    /// launching this relay (`%f` under Synchronet). It carries the caller's
    /// name, security level, node and ANSI capability.
    drop_file: PathBuf,
    /// The Unix socket of the server to relay into: the path that
    /// `mbbs-server --listen-door` is listening on.
    #[arg(long)]
    socket: PathBuf,
    /// Security level at or above which the caller is presented to the
    /// module as a sysop. The scale is the BBS's own: 90 is Synchronet's
    /// SYSOP_LEVEL, Mystic and WWIV use 255.
    #[arg(long, default_value_t = DEFAULT_SYSOP_LEVEL)]
    sysop_level: u32,
    /// The caller's terminal height in rows (`%R` under Synchronet). The
    /// module lays out full-screen forms against it.
    #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u8).range(1..))]
    rows: u8,
    /// The caller's terminal width in columns (`%W` under Synchronet). The
    /// module word-wraps against it.
    #[arg(long, default_value_t = 80, value_parser = clap::value_parser!(u8).range(1..))]
    cols: u8,
}

/// What we read from DOOR32.SYS. Lines 7, 8, 10 and 11 of eleven; the
/// socket handle on line 2 is ignored -- we talk to the caller through
/// stdio.
#[derive(Debug, PartialEq, Eq)]
struct Door32 {
    alias: String,
    level: u32,
    ansi: bool,
    node: u16,
}

/// Parse a DOOR32.SYS. `str::lines` accepts both bare LF (what Synchronet
/// writes for a native door, `xtrn_sec.cpp:101-110`) and CRLF.
fn parse_door32(text: &str) -> Result<Door32, String> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 11 {
        return Err(format!("DOOR32.SYS has {} lines, not 11", lines.len()));
    }
    let alias = lines[6].trim();
    if alias.is_empty() {
        return Err("DOOR32.SYS line 7 (alias) is empty".into());
    }
    let level = lines[7]
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("DOOR32.SYS line 8 (security level) is not a number: {:?}", lines[7]))?;
    // 0 = ASCII, 1 = ANSI, 2 = Avatar, ...: anything but plain ASCII can
    // take ANSI. Synchronet writes 0/1.
    let emulation = lines[9]
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("DOOR32.SYS line 10 (emulation) is not a number: {:?}", lines[9]))?;
    let node = lines[10]
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("DOOR32.SYS line 11 (node) is not a number: {:?}", lines[10]))?;
    Ok(Door32 { alias: alias.to_string(), level, ansi: emulation != 0, node })
}

/// The header, exactly as `mbbs_server::door::parse` reads it.
fn header(d: &Door32, sysop_level: u32, rows: u8, cols: u8) -> String {
    format!(
        "{PROTOCOL}\nuser={}\nsysop={}\nansi={}\nnode={}\nrows={rows}\ncols={cols}\n\n",
        d.alias,
        u8::from(d.level >= sysop_level),
        u8::from(d.ansi),
        d.node,
    )
}

/// Raw mode on stdin for as long as this lives; restores on drop. Modelled
/// on `crates/dos-runtime/src/terminal.rs`'s `RawStdin`; this one gates on
/// `isatty` and uses `VMIN=1` because its reads are blocking. Duplicated
/// rather than shared: pulling the DOS runtime in for a termios call would
/// be the larger wrong.
struct RawStdin {
    saved: libc::termios,
}

impl RawStdin {
    /// `None` when stdin is not a terminal (a pipe under test, or a BBS that
    /// launches doors on pipes): nothing to set, nothing to restore.
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

/// One line to the caller, CRLF-terminated because their terminal is raw.
fn tell(msg: &str) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(msg.as_bytes());
    let _ = out.write_all(b"\r\n");
    let _ = out.flush();
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let text = match std::fs::read(&cli.drop_file) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            tell(&format!("cannot read {}: {e}", cli.drop_file.display()));
            return ExitCode::from(2);
        }
    };
    let door32 = match parse_door32(&text) {
        Ok(d) => d,
        Err(reason) => {
            tell(&reason);
            return ExitCode::from(2);
        }
    };

    let mut sock = match UnixStream::connect(&cli.socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mbbs-door: {}: {e}", cli.socket.display());
            tell("The game is not available right now.");
            return ExitCode::from(1);
        }
    };

    let raw = match RawStdin::enter() {
        Ok(guard) => guard,
        Err(e) => {
            tell(&format!("cannot set the terminal to raw mode: {e}"));
            return ExitCode::from(2);
        }
    };

    if let Err(e) = sock.write_all(header(&door32, cli.sysop_level, cli.rows, cli.cols).as_bytes()) {
        drop(raw);
        tell(&format!("The game hung up before the session started: {e}"));
        return ExitCode::from(1);
    }

    // Caller -> server. Ends when the BBS hangs up (stdin EOF): shut our
    // write half so the server sees the disconnect, and let the other
    // thread run on until the server closes. A real error (as opposed to
    // clean EOF) is reported through `tx`, non-blocking on the receiving
    // end -- this thread is still blocked in `stdin.read` for as long as
    // the BBS holds its end of the pty open, so `main` must never join it.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let mut to_server = sock.try_clone().expect("clone the socket");
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Err(e) => {
                    let _ = tx.send(format!("reading from the caller: {e}"));
                    break;
                }
                Ok(n) => {
                    if let Err(e) = to_server.write_all(&buf[..n]) {
                        let _ = tx.send(format!("writing to the server: {e}"));
                        break;
                    }
                }
            }
        }
        let _ = to_server.shutdown(std::net::Shutdown::Write);
    });

    // Server -> caller. Ends when the server closes the session. A real
    // I/O error here (dead socket, broken stdout pipe) is not the same as
    // the server ending the session cleanly -- it is reported to stderr
    // (sbbs's log, never the caller's CP437 stream) and exits 3, so a
    // sysop can tell a transport fault from a logout.
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 4096];
    let mut error = None;
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Err(e) => {
                error = Some(format!("reading from the server: {e}"));
                break;
            }
            Ok(n) => {
                if let Err(e) = stdout.write_all(&buf[..n]).and_then(|()| stdout.flush()) {
                    error = Some(format!("writing to the caller: {e}"));
                    break;
                }
            }
        }
    }
    drop(stdout);
    drop(raw);

    // Non-blocking: the stdin thread may still be running (see above).
    let error = error.or_else(|| rx.try_recv().ok());
    if let Some(reason) = error {
        eprintln!("mbbs-door: {reason}");
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eleven lines as Synchronet writes them for a native door -- bare LF.
    const SBBS: &str = "0\n-1\n38400\nSynchronet 3.22a\n7\nDan Corbe\nDan\n90\n55\n1\n3\n";

    #[test]
    fn an_sbbs_door32_parses() {
        let d = parse_door32(SBBS).expect("parses");
        assert_eq!(d, Door32 { alias: "Dan".into(), level: 90, ansi: true, node: 3 });
    }

    #[test]
    fn crlf_line_endings_parse_the_same() {
        let crlf = SBBS.replace('\n', "\r\n");
        assert_eq!(parse_door32(&crlf), parse_door32(SBBS));
    }

    #[test]
    fn a_short_file_is_refused_with_the_line_count() {
        let ten: String = SBBS.lines().take(10).map(|l| format!("{l}\n")).collect();
        assert_eq!(parse_door32(&ten), Err("DOOR32.SYS has 10 lines, not 11".into()));
    }

    #[test]
    fn avatar_emulation_counts_as_ansi() {
        let avatar = SBBS.replace("\n1\n3\n", "\n2\n3\n");
        assert!(parse_door32(&avatar).expect("parses").ansi);
        let ascii = SBBS.replace("\n1\n3\n", "\n0\n3\n");
        assert!(!parse_door32(&ascii).expect("parses").ansi);
    }

    #[test]
    fn an_empty_alias_is_refused() {
        let blank = SBBS.replace("\nDan\n90\n", "\n\n90\n");
        assert_eq!(parse_door32(&blank), Err("DOOR32.SYS line 7 (alias) is empty".into()));
    }

    #[test]
    fn the_level_is_reduced_to_a_sysop_flag_at_the_threshold() {
        let d = |level| Door32 { alias: "Dan".into(), level, ansi: true, node: 1 };
        assert!(header(&d(89), 90, 24, 80).contains("\nsysop=0\n"));
        assert!(header(&d(90), 90, 24, 80).contains("\nsysop=1\n"));
        assert!(header(&d(254), 255, 24, 80).contains("\nsysop=0\n"));
        assert!(header(&d(255), 255, 24, 80).contains("\nsysop=1\n"));
    }

    #[test]
    fn the_header_is_exactly_the_protocol() {
        let d = Door32 { alias: "Dan".into(), level: 90, ansi: false, node: 3 };
        assert_eq!(
            header(&d, 90, 25, 132),
            "mbbs-door 1\nuser=Dan\nsysop=1\nansi=0\nnode=3\nrows=25\ncols=132\n\n"
        );
    }
}
