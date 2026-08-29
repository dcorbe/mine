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

use mbbs::Connection;

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

    let first_line_end = if first_newline > 0 && buf[first_newline - 1] == b'\r' {
        first_newline - 1
    } else {
        first_newline
    };

    let Ok(first_line) = std::str::from_utf8(&buf[..first_line_end]) else {
        return Parse::Invalid("header is not UTF-8");
    };

    if first_line != PROTOCOL {
        return Parse::Invalid("not an mbbs-door 1 header");
    }

    // Now find the blank line
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
}
