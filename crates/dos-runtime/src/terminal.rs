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

use textscreen::paint::Painter;

use crate::driver::{Driver, Key};
use crate::screen::{Cells, Screen};

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
    painter: Painter,
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
            painter: Painter::new(),
            quit: false,
            painted: std::time::Instant::now(),
        })
    }

    /// Redraw, skipping rows that have not changed since the last paint.
    ///
    /// Takes a bare [`Cells`] and the cursor rather than a whole [`Screen`],
    /// because painting is the half of `Screen` that a Win32 console can reuse:
    /// that host owns its cells outright instead of sampling `B800:0000`, and
    /// has a `Screen` nowhere in it. Nothing about turning a grid into ANSI
    /// cares which of the two filled the grid in.
    ///
    /// The flush stays here rather than in [`Painter`]: the painter
    /// deliberately does not flush, because a caller batching several paints
    /// should not pay for each one.
    fn paint(&mut self, grid: &Cells, cursor: (u8, u8), cursor_visible: bool) {
        let mut out = io::stdout().lock();
        let _ = self.painter.paint(&mut out, grid, cursor, cursor_visible);
        let _ = out.flush();
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
        self.paint(&screen.grid, screen.cursor, screen.cursor_visible);
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
        self.paint(&screen.grid, screen.cursor, screen.cursor_visible);
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
