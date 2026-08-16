//! The smallest INT 10h that lets a text-mode program get on with its life.
//!
//! `LORDCFG.EXE` is not a batch installer -- it is a full-screen configuration
//! utility, so Turbo Pascal's CRT unit interrogates the display before any file
//! is touched. Leaving those calls unanswered does not merely skip the drawing:
//! the program reads uninitialised registers back and computes addresses from
//! them, which is what the 2.4 million reads of port 6 in an earlier run
//! actually were.
//!
//! Direct writes to `B800:0000` need nothing here -- that is guest memory, and
//! the program can scribble on it freely. Only the *queries* need answering.

use crate::driver::Key;
use crate::guest::{DosGuest, DosPtr, Flag};

/// Physical base of the colour text buffer.
const TEXT_BASE: DosPtr = DosPtr {
    seg: 0xb800,
    off: 0,
};

/// What the BIOS would keep in the display area of the BIOS data segment.
pub struct Video {
    pub mode: u8,
    pub columns: u16,
    pub rows: u8,
    pub page: u8,
    pub cursor_row: u8,
    pub cursor_col: u8,
}

impl Default for Video {
    fn default() -> Self {
        Self {
            mode: 3, // 80x25 colour text, what every DOS program assumes
            columns: 80,
            rows: 25,
            page: 0,
            cursor_row: 0,
            cursor_col: 0,
        }
    }
}

impl Video {
    fn cell(&self, row: u8, col: u8) -> DosPtr {
        let index = (u16::from(row) * self.columns + u16::from(col)) * 2;
        DosPtr::new(TEXT_BASE.seg, TEXT_BASE.off.wrapping_add(index))
    }
}

impl Video {
    /// Populate the BIOS data area at segment `0040`.
    ///
    /// Turbo Pascal's CRT unit does not ask `int 10h` for the screen size --
    /// it reads `0040:004A` and `0040:0084` directly, then writes to `B800`
    /// at offsets computed from them. Leaving the area zeroed makes the screen
    /// eighty columns by *zero* rows, so every line the program prints lands on
    /// top of the last one. That is not a rendering nicety; it is the
    /// difference between a legible screen and garbage.
    pub fn install_bda<G: DosGuest>(&self, g: &mut G) {
        let bda = |off: u16| DosPtr::new(0x0040, off);
        let _ = g.write(bda(0x0010), &0x0021u16.to_le_bytes()); // equipment: 80x25 colour
        let _ = g.write(bda(0x0013), &640u16.to_le_bytes()); // KiB of memory
        let _ = g.write(bda(0x0049), &[self.mode]);
        let _ = g.write(bda(0x004a), &self.columns.to_le_bytes());
        let _ = g.write(bda(0x004c), &0x1000u16.to_le_bytes()); // page size
        let _ = g.write(bda(0x004e), &0u16.to_le_bytes()); // page offset
        let _ = g.write(bda(0x0050), &[0u8; 16]); // cursor per page
        let _ = g.write(bda(0x0060), &0x0607u16.to_le_bytes()); // cursor shape
        let _ = g.write(bda(0x0062), &[self.page]);
        let _ = g.write(bda(0x0063), &0x03d4u16.to_le_bytes()); // CRTC base port
        let _ = g.write(bda(0x0084), &[self.rows - 1]);
        let _ = g.write(bda(0x0085), &16u16.to_le_bytes()); // character height
    }
}

/// Keystrokes waiting to be handed to the guest.
///
/// A real console would block here. A probe cannot: it has to be able to say
/// "the program is waiting for input and there is none" rather than hang.
#[derive(Default)]
pub struct Keyboard {
    pending: std::collections::VecDeque<u8>,
}

impl Keyboard {
    /// Queue keystrokes. `%XX` is an extended key -- scan code `0xXX` with a
    /// zero character, which is how DOS reports arrows and function keys.
    pub fn feed(&mut self, keys: &str) {
        let b = keys.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(scan) = u8::from_str_radix(&keys[i + 1..i + 3], 16) {
                    self.pending.push_back(0);
                    self.pending.push_back(scan);
                    i += 3;
                    continue;
                }
            }
            self.pending.push_back(b[i]);
            i += 1;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Queue one key. An extended key goes in as the zero-then-scan-code pair
    /// the BIOS reports, which is also how `feed` encodes `%XX`.
    pub fn push_key(&mut self, key: Key) {
        match key {
            Key::Char(c) => self.pending.push_back(c),
            Key::Ext(scan) => {
                self.pending.push_back(0);
                self.pending.push_back(scan);
            }
        }
    }
}

/// Service one `int 16h`. Returns false when the guest asked for a key and
/// none is queued, which the caller should treat as "waiting for the user".
pub fn int16<G: DosGuest>(g: &mut G, keys: &mut Keyboard) -> bool {
    let mut regs = g.regs();
    match regs.ah() {
        // 00h/10h -- wait for a keystroke: AL is the character, AH the scan code.
        0x00 | 0x10 => match keys.pending.pop_front() {
            // A zero character marks the extended pair queued by `feed`.
            Some(0) => match keys.pending.pop_front() {
                Some(scan) => {
                    regs.ax = u16::from(scan) << 8;
                    g.set_regs(regs);
                    true
                }
                None => false,
            },
            Some(ch) => {
                regs.ax = (u16::from(scancode(ch)) << 8) | u16::from(ch);
                g.set_regs(regs);
                true
            }
            None => false,
        },
        // 01h/11h -- is a key ready? ZF set means no. Peek, never consume.
        0x01 | 0x11 => {
            match keys.pending.front().copied() {
                Some(0) => {
                    let scan = keys.pending.get(1).copied().unwrap_or(0);
                    regs.ax = u16::from(scan) << 8;
                }
                Some(ch) => regs.ax = (u16::from(scancode(ch)) << 8) | u16::from(ch),
                None => regs.ax = 0,
            }
            g.set_regs(regs);
            g.set_flag(Flag::Zero, keys.pending.is_empty());
            true
        }

        _ => {
            regs.ax = 0;
            g.set_regs(regs);
            true
        }
    }
}

/// Move a rectangle of cells, blanking what it leaves behind.
///
/// `lines == 0`, or more lines than the window is tall, means blank all of it
/// -- which is the overwhelmingly common call, since that is `ClrScr`.
#[allow(clippy::too_many_arguments)]
fn scroll<G: DosGuest>(
    g: &mut G,
    video: &Video,
    top: u8,
    left: u8,
    bottom: u8,
    right: u8,
    lines: u8,
    attr: u8,
    up: bool,
) {
    let last_row = video.rows.saturating_sub(1);
    let last_col = (video.columns.saturating_sub(1)) as u8;
    let (top, left) = (top.min(last_row), left.min(last_col));
    let (bottom, right) = (bottom.min(last_row), right.min(last_col));
    if bottom < top || right < left {
        return;
    }

    let height = bottom - top + 1;
    let width = usize::from(right - left + 1);
    let blank: Vec<u8> = [0x20, attr].repeat(width);

    if lines == 0 || lines >= height {
        for row in top..=bottom {
            let _ = g.write(video.cell(row, left), &blank);
        }
        return;
    }

    // Copy in the direction that cannot overwrite a row before it is read.
    let rows: Vec<u8> = if up {
        (top..=bottom - lines).collect()
    } else {
        (top + lines..=bottom).rev().collect()
    };
    for row in rows {
        let from = if up { row + lines } else { row - lines };
        let Ok(line) = g.read(video.cell(from, left), width * 2).map(<[u8]>::to_vec) else {
            continue;
        };
        let _ = g.write(video.cell(row, left), &line);
    }
    let blanked: Vec<u8> = if up {
        (bottom - lines + 1..=bottom).collect()
    } else {
        (top..top + lines).collect()
    };
    for row in blanked {
        let _ = g.write(video.cell(row, left), &blank);
    }
}

/// Enough of the scan-code table for letters and the keys a menu reads.
fn scancode(ch: u8) -> u8 {
    const ROW: &[u8] = b"qwertyuiop";
    match ch.to_ascii_lowercase() {
        b'\r' => 0x1c,
        b' ' => 0x39,
        0x1b => 0x01,
        c if c.is_ascii_lowercase() => {
            if let Some(i) = ROW.iter().position(|&k| k == c) {
                0x10 + i as u8
            } else {
                0x1e
            }
        }
        _ => 0,
    }
}

/// Service one `int 10h`. Unknown functions are a no-op, which is what a BIOS
/// does with a function it does not have.
pub fn int10<G: DosGuest>(g: &mut G, video: &mut Video) {
    let mut regs = g.regs();
    match regs.ah() {
        // 00h -- set video mode.
        0x00 => {
            video.mode = regs.al() & 0x7f;
            video.cursor_row = 0;
            video.cursor_col = 0;
        }

        // 02h -- set cursor position (DH row, DL col).
        //
        // The BDA copy at 0040:0050 is not bookkeeping: a program that draws
        // its own screen reads the cursor back from there rather than asking
        // the BIOS, so failing to write it leaves the program computing every
        // write offset from a stale (0,0).
        0x02 => {
            video.cursor_row = (regs.dx >> 8) as u8;
            video.cursor_col = (regs.dx & 0xff) as u8;
            let page = usize::from(video.page).min(7);
            let at = DosPtr::new(0x0040, 0x0050 + (page as u16) * 2);
            let _ = g.write(at, &[video.cursor_col, video.cursor_row]);
        }

        // 03h -- get cursor position and shape. Read the BDA back, so that a
        // program which moved the cursor by poking 0040:0050 sees its own value.
        0x03 => {
            let page = usize::from(video.page).min(7);
            let at = DosPtr::new(0x0040, 0x0050 + (page as u16) * 2);
            if let Ok(b) = g.read(at, 2) {
                video.cursor_col = b[0];
                video.cursor_row = b[1];
            }
            regs.dx = (u16::from(video.cursor_row) << 8) | u16::from(video.cursor_col);
            regs.cx = 0x0607; // an ordinary underline cursor
            g.set_regs(regs);
        }

        // 08h -- read the character and attribute under the cursor.
        0x08 => {
            let at = video.cell(video.cursor_row, video.cursor_col);
            let cell = g.read(at, 2).map(|b| [b[0], b[1]]).unwrap_or([b' ', 0x07]);
            regs.ax = (u16::from(cell[1]) << 8) | u16::from(cell[0]);
            g.set_regs(regs);
        }

        // 09h/0Ah -- write character (and attribute) CX times at the cursor.
        0x09 | 0x0a => {
            let attr = if regs.ah() == 0x09 {
                (regs.bx & 0xff) as u8
            } else {
                0x07
            };
            let ch = regs.al();
            let count = regs.cx.min(u16::from(video.rows) * video.columns);
            let mut col = video.cursor_col;
            let mut row = video.cursor_row;
            for _ in 0..count {
                let _ = g.write(video.cell(row, col), &[ch, attr]);
                col = col.wrapping_add(1);
                if u16::from(col) >= video.columns {
                    col = 0;
                    row = row.wrapping_add(1);
                }
            }
        }

        // 0Fh -- get video mode: AL mode, AH column count, BH active page.
        0x0f => {
            regs.set_al(video.mode);
            regs.set_ah(video.columns as u8);
            regs.bx = (u16::from(video.page) << 8) | (regs.bx & 0xff);
            g.set_regs(regs);
        }

        // 11h -- character generator. Subfunction 30h hands back font data;
        // reporting 25 rows is the part callers actually read.
        0x11 => {
            if regs.al() == 0x30 {
                regs.cx = 16; // bytes per character
                regs.dx = u16::from(video.rows) - 1;
                g.set_regs(regs);
            }
        }

        // 12h -- alternate select. BL=10h asks for EGA configuration.
        0x12 => {
            if (regs.bx & 0xff) == 0x10 {
                regs.bx = 0x0003; // colour, 256 KiB
                regs.cx = 0x0009;
                g.set_regs(regs);
            }
        }

        // 0Eh -- teletype output. The one call that must actually move the
        // cursor: ignoring it piles every line of the program's output on top
        // of itself in row 0.
        0x0e => {
            let ch = regs.al();
            match ch {
                b'\r' => video.cursor_col = 0,
                b'\n' => video.cursor_row = video.cursor_row.saturating_add(1),
                0x08 => video.cursor_col = video.cursor_col.saturating_sub(1),
                0x07 => {}
                _ => {
                    let at = video.cell(video.cursor_row, video.cursor_col);
                    let _ = g.write(at, &[ch, 0x07]);
                    video.cursor_col = video.cursor_col.wrapping_add(1);
                    if u16::from(video.cursor_col) >= video.columns {
                        video.cursor_col = 0;
                        video.cursor_row = video.cursor_row.saturating_add(1);
                    }
                }
            }
            if video.cursor_row >= video.rows {
                // No scrollback here: a probe wants the whole screen kept.
                video.cursor_row = video.rows - 1;
            }
        }

        // 06h/07h -- scroll a window up or down; AL=0 blanks it outright.
        //
        // Ignoring these does not merely skip an animation. Blanking a window
        // is how a text-mode program clears the screen, so a no-op leaves the
        // previous screen's characters in the buffer and the next one paints
        // into the gaps between them. It reads as "issues painting" and is
        // really "the clear never happened".
        0x06 | 0x07 => {
            let lines = regs.al();
            let top = (regs.cx >> 8) as u8;
            let left = (regs.cx & 0xff) as u8;
            let bottom = (regs.dx >> 8) as u8;
            let right = (regs.dx & 0xff) as u8;
            let attr = (regs.bx >> 8) as u8;
            scroll(g, video, top, left, bottom, right, lines, attr, regs.ah() == 0x06);
        }

        // 01h set cursor shape, 05h select page: accepted and ignored. Direct
        // writes to B800 carry the rest of the screen.
        _ => {}
    }
}
