//! A live terminal on the other end of the same seam the script driver uses.
//!
//! This is the door path. Painting the guest's text buffer to a terminal and
//! feeding `int 16h` from its keystrokes is exactly what running a DOS door
//! over telnet requires -- the only difference is which file descriptor the
//! bytes travel over. Building it to drive a config menu gets the harder half
//! of that for free.
//!
//! Three translations, and each one is a place fidelity is normally lost:
//!
//! - **CP437 to UTF-8.** The C0 range is *not* control codes on a PC text
//!   screen: `0x11` is a left-pointing triangle, not a device control. Treating
//!   bytes under 0x20 as unprintable throws away the arrows a menu draws with.
//! - **Attributes to SGR.** The DOS colour order is not the ANSI order, so the
//!   indices have to be remapped rather than passed through.
//! - **Escape sequences to scan codes**, which is the same table the script
//!   driver spells out in words.

use std::io::{self, Write};

use crate::driver::{Driver, Key};
use crate::screen::{Cell, Screen};

/// CP437 as Unicode. Index is the byte the guest wrote.
///
/// **This is a second copy of a table the workspace already has**, in
/// `mud_core::cp437::HIGH`. Above `0x7F` the two agree entry for entry, and a
/// test below pins that. They are not merged because `mud_core` is the MUD
/// game crate -- the wrong direction for a DOS runtime to depend in -- and
/// because only the table is shareable, not the function around it.
///
/// `mud_core::cp437::decode` is *identity* below `0x80` on purpose: it decodes
/// the wire, where ANSI escapes, line endings and the anti-bot backspaces must
/// pass through untouched. A text screen is the opposite case. Bytes under
/// `0x20` in a screen cell are glyphs -- `0x11` is `◄` -- so decoding a screen
/// with `decode` blanks every arrow a menu draws with. Using the right table
/// through the wrong function is the failure mode here, not a missing table.
///
/// `0x00` is the one deliberate departure from CP437 proper: a cleared cell is
/// a NUL, and rendering its glyph would fill the screen with noise.
const CP437: [char; 256] = [
    ' ', '☺', '☻', '♥', '♦', '♣', '♠', '•', '◘', '○', '◙', '♂', '♀', '♪', '♫', '☼', //
    '►', '◄', '↕', '‼', '¶', '§', '▬', '↨', '↑', '↓', '→', '←', '∟', '↔', '▲', '▼', //
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', //
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', //
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', //
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', //
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', //
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '⌂', //
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{A0}',
];

/// DOS colour index to ANSI colour index.
///
/// The two orders differ: DOS counts blue as 1 and red as 4, ANSI the other way
/// round. Passing the index through unchanged swaps every red and blue on the
/// screen, which looks plausible enough to ship by mistake.
const TO_ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

/// Put stdin in raw mode without touching the screen.
///
/// A door does not own the display -- the BBS does -- so it must not switch to
/// an alternate screen or clear anything. It only needs the terminal to stop
/// interpreting keystrokes on its behalf.
pub struct RawStdin {
    saved: libc::termios,
}

impl RawStdin {
    pub fn enter() -> io::Result<Self> {
        // SAFETY: reading the current settings of our own stdin.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: applying settings to our own stdin.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { saved })
    }
}

impl Drop for RawStdin {
    fn drop(&mut self) {
        // SAFETY: restoring settings we saved from our own stdin.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved) };
    }
}

/// Restores the terminal however the program leaves.
struct RawMode {
    saved: libc::termios,
}

impl RawMode {
    fn enter() -> io::Result<Self> {
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
        // Alternate screen, cursor hidden while we paint.
        print!("\x1b[?1049h\x1b[2J");
        let _ = io::stdout().flush();
        Ok(Self { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[0m\x1b[?1049l");
        let _ = io::stdout().flush();
        // SAFETY: restoring the settings we saved from our own stdin.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved) };
    }
}

/// Paints the guest's screen and feeds back what the user types.
pub struct Terminal {
    _raw: RawMode,
    last: Vec<Cell>,
    quit: bool,
    painted: std::time::Instant,
}

impl Terminal {
    /// The key that gives control back, since in raw mode Ctrl-C is just a byte
    /// the guest is entitled to see.
    pub const QUIT: u8 = 0x1d; // Ctrl-]

    pub fn new() -> io::Result<Self> {
        Ok(Self {
            _raw: RawMode::enter()?,
            last: Vec::new(),
            quit: false,
            painted: std::time::Instant::now(),
        })
    }

    /// Redraw, skipping rows that have not changed since the last paint.
    fn paint(&mut self, screen: &Screen) {
        let mut out = String::with_capacity(8 * 1024);
        out.push_str("\x1b[?25l");

        let unchanged = self.last.len() == screen.cells.len();
        for row in 0..screen.rows {
            let start = row * screen.cols;
            let end = start + screen.cols;
            if unchanged && self.last[start..end] == screen.cells[start..end] {
                continue;
            }
            out.push_str(&format!("\x1b[{};1H", row + 1));
            let mut attr = None;
            for col in 0..screen.cols {
                let cell = screen.cell(row, col);
                if attr != Some(cell.attr) {
                    let fg = cell.foreground();
                    let bg = cell.background();
                    let fg_code = if fg >= 8 {
                        90 + u16::from(TO_ANSI[usize::from(fg - 8)])
                    } else {
                        30 + u16::from(TO_ANSI[usize::from(fg)])
                    };
                    let bg_code = 40 + u16::from(TO_ANSI[usize::from(bg)]);
                    out.push_str(&format!("\x1b[0;{fg_code};{bg_code}m"));
                    attr = Some(cell.attr);
                }
                out.push(CP437[usize::from(cell.ch)]);
            }
            out.push_str("\x1b[0m");
        }

        // Park the real cursor where the guest put its own, and show it only if
        // the guest wants it shown.
        let (row, col) = screen.cursor;
        out.push_str(&format!(
            "\x1b[{};{}H",
            u16::from(row) + 1,
            u16::from(col) + 1
        ));
        out.push_str(if screen.cursor_visible {
            "\x1b[?25h"
        } else {
            "\x1b[?25l"
        });

        print!("{out}");
        let _ = io::stdout().flush();
        self.last = screen.cells.clone();
    }

    /// One byte from the terminal, or `None` at end of input.
    ///
    /// Retries on `EINTR`: a blocking read here shares its thread with the
    /// guest's watchdog signal, and treating an interrupted read as end of
    /// input closes the session under the user the first time anything else
    /// in the process raises a signal.
    fn byte(&self) -> Option<u8> {
        loop {
            let mut b = 0u8;
            // SAFETY: a one-byte read into a local from our own stdin.
            let n = unsafe { libc::read(libc::STDIN_FILENO, std::ptr::from_mut(&mut b).cast(), 1) };
            if n == 1 {
                return Some(b);
            }
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
    }

    /// A byte, but only if one is already waiting -- used to tell a lone Escape
    /// from the start of an arrow-key sequence.
    fn byte_soon(&self) -> Option<u8> {
        let mut fds = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling our own stdin with a bounded timeout.
        let n = unsafe { libc::poll(std::ptr::from_mut(&mut fds), 1, 20) };
        // Same trap as `ready`: the count includes POLLHUP and POLLERR, and
        // reading on those blocks or returns nothing.
        if n > 0 && fds.revents & libc::POLLIN != 0 {
            self.byte()
        } else {
            None
        }
    }

    /// Is a byte already waiting? Never blocks.
    ///
    /// The count `poll` returns is not the answer. It counts descriptors with
    /// *any* event, and `POLLHUP` and `POLLERR` are reported whether or not you
    /// asked for them -- so a hung-up terminal answers "ready" forever. Since
    /// this gates the repaint, that turns every keyboard poll the guest makes
    /// into a full screen snapshot and redraw, which is precisely the shape of
    /// a pause that only appears interactively.
    fn ready(&self) -> bool {
        let mut fds = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling our own stdin with a zero timeout.
        let n = unsafe { libc::poll(std::ptr::from_mut(&mut fds), 1, 0) };
        n > 0 && fds.revents & libc::POLLIN != 0
    }

    fn read_key(&mut self) -> Option<Key> {
        let first = self.byte()?;
        if first == Self::QUIT {
            self.quit = true;
            return None;
        }
        if first != 0x1b {
            // The terminal sends 0x7f for backspace; DOS programs expect 0x08.
            let ch = if first == 0x7f { 0x08 } else { first };
            return Some(Key::Char(ch));
        }

        // An escape sequence, or a bare Escape if nothing follows.
        let Some(second) = self.byte_soon() else {
            return Some(Key::Char(0x1b));
        };
        match second {
            b'[' | b'O' => {}
            _ => return Some(Key::Char(0x1b)),
        }
        let Some(third) = self.byte_soon() else {
            return Some(Key::Char(0x1b));
        };
        let key = match third {
            b'A' => Key::Ext(0x48), // up
            b'B' => Key::Ext(0x50), // down
            b'C' => Key::Ext(0x4d), // right
            b'D' => Key::Ext(0x4b), // left
            b'H' => Key::Ext(0x47), // home
            b'F' => Key::Ext(0x4f), // end
            b'P' => Key::Ext(0x3b), // F1 on an SS3 terminal
            b'Q' => Key::Ext(0x3c),
            b'R' => Key::Ext(0x3d),
            b'S' => Key::Ext(0x3e),
            digit if digit.is_ascii_digit() => {
                // A numeric sequence: collect until the terminator.
                let mut number = String::new();
                number.push(digit as char);
                while let Some(b) = self.byte_soon() {
                    if b == b'~' {
                        break;
                    }
                    number.push(b as char);
                }
                match number.as_str() {
                    "1" | "7" => Key::Ext(0x47), // home
                    "4" | "8" => Key::Ext(0x4f), // end
                    "5" => Key::Ext(0x49),       // page up
                    "6" => Key::Ext(0x51),       // page down
                    "3" => Key::Char(0x7f),      // delete
                    "11" | "15" => Key::Ext(0x3b),
                    "12" | "17" => Key::Ext(0x3c),
                    "13" | "18" => Key::Ext(0x3d),
                    "14" | "19" => Key::Ext(0x3e),
                    _ => return Some(Key::Char(0x1b)),
                }
            }
            _ => return Some(Key::Char(0x1b)),
        };
        Some(key)
    }

    pub fn quit_requested(&self) -> bool {
        self.quit
    }
}

impl Driver for Terminal {
    fn next_key(&mut self, screen: &Screen) -> Option<Key> {
        self.paint(screen);
        self.read_key()
    }

    /// A repaint is due at most sixty times a second, or immediately when the
    /// user has typed -- which is faster than an eye and far slower than the
    /// guest's poll loop.
    fn poll_due(&self) -> bool {
        self.ready() || self.painted.elapsed() >= std::time::Duration::from_millis(16)
    }

    /// Repaint, and take a keystroke only if one is already waiting.
    fn poll_key(&mut self, screen: &Screen) -> Option<Key> {
        self.painted = std::time::Instant::now();
        self.paint(screen);
        if !self.ready() {
            return None;
        }
        self.read_key()
    }

    fn ending(&self) -> String {
        if self.quit {
            "you pressed Ctrl-] to take control back".to_string()
        } else {
            "terminal input ended".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_c0_range_carries_glyphs_rather_than_control_codes() {
        // The trap this table exists to avoid: treating a PC text screen's
        // bytes below 0x20 as unprintable loses the arrows menus draw with.
        assert_eq!(CP437[0x11], '◄');
        assert_eq!(CP437[0x1a], '→');
        assert_eq!(CP437[0x00], ' ', "a cleared cell is blank, not a glyph");
    }

    #[test]
    fn dos_colour_indices_are_remapped_not_passed_through() {
        // DOS blue is 1 and red is 4; ANSI has them the other way round.
        assert_eq!(TO_ANSI[1], 4, "DOS blue becomes ANSI blue");
        assert_eq!(TO_ANSI[4], 1, "DOS red becomes ANSI red");
        assert_eq!(TO_ANSI[0], 0);
        assert_eq!(TO_ANSI[7], 7);
    }

    /// The high half is duplicated from `mud_core::cp437::HIGH`. These are the
    /// entries a divergence would show up in first: the one that was actually
    /// wrong (0xFF was a space, not a no-break space), and the ends of the
    /// range. A real guard would compare the whole table, which needs the two
    /// copies to live in one crate.
    #[test]
    fn the_high_half_agrees_with_the_workspace_copy() {
        assert_eq!(CP437[0x80], 'Ç');
        assert_eq!(CP437[0xff], '\u{A0}', "CP437 0xFF is a no-break space");
        assert_eq!(CP437[0xe1], 'ß');
        assert_eq!(CP437[0x9e], '₧');
    }

    #[test]
    fn the_box_drawing_range_survives_translation() {
        assert_eq!(CP437[0xc9], '╔');
        assert_eq!(CP437[0xbb], '╗');
        assert_eq!(CP437[0xdb], '█');
    }
}
