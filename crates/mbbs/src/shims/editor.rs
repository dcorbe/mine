//! The line editor behind `bgnedt` -- the `stline`/`ldunedt` half of
//! `EDITFSE.C` (`re/wg33src/SRC/api/wgsfse/EDITFSE.C`), the "System editor"
//! `MAJORBBS.H:73` declares and every message-writing module in the vendor
//! tree calls.
//!
//! # Why it is here
//!
//! `bgnedt` is not a routine a module imports; it is a *function pointer
//! global* (`FSD.H:54`, `int (*bgnedt)(...)`) that the editor's own
//! `init__inifse()` fills in at boot (`EDITFSE.C:251`, `bgnedt=fse_bgnedt`).
//! MajorMUD's sysop menu reaches it with `mov eax,[bgnedt]; call [eax]`
//! (`B - Edit the sysop bulletin file`, `E - Edit the wccmmud.ini file`).
//! This host served the global as zeroed memory, so both options faulted at
//! `0x00000000` the instant they were chosen. [`crate::Host::finish_init`]
//! now points the global at a host-reserved thunk that lands in
//! [`fse_bgnedt`] -- see `Host::vectors` for the mechanism.
//!
//! # How the vendor's editor works, and what is ported
//!
//! The editor is a module of its own (`struct module fseedit`,
//! `EDITFSE.C:74`). `bgnedt` switches the channel's `state` to it and hands
//! the channel to `ldunedt` -- its `sttrou` -- until the user saves or quits,
//! at which point the caller's `whndun(flags)` runs (`0` to save,
//! `ED_QUITEX` to quit) and is expected to put `state` back itself. That is
//! exactly the shape [`crate::Host::fsd_state`] already has for the FSD, so
//! the editor is the second [`crate::shims::system::Native`] slot, and
//! [`dispatch`] is its `sttrou`.
//!
//! Only the **line editor** is ported (`stline`, `ldunedt`, and everything
//! `ldunedt` reaches). The full-screen editor (`stfse`/`fsechi`/`dunedt`)
//! is not: [`fse_bgnedt`] takes the `stline` branch unconditionally, which
//! is what the real one does for a user with `PRFLIN` set or a screen
//! shorter than `FSEMHI`. The consequences, all deliberate:
//!
//! - `fseok()` is always false, so the menu never offers `M)ode` and the
//!   prompts are the `EDTPMT2`/`EDTPMTT` forms.
//! - `U)pload` (`fileup`) and `N)ew`'s message import (`imradr`) need
//!   host machinery this host does not have; `U` is rebuffed like any other
//!   unknown key, and `N` offers only the `C)lear`/`N)othing` sub-prompt the
//!   vendor shows when no import routine is installed.
//! - Profanity filtering (`profan`/`pfnlvl`) is not modelled; `pfnlvl` is
//!   never above 1 on this host, so the vendor's checks would all pass.
//! - `btumil` limits are honoured (`GSBL`'s `maxinl`) but this host's GSBL
//!   has no negative-margin word wrap, so `smargn`'s `-WRPLIM` becomes a
//!   hard 72-column stop. On every exit the limit goes back to `DFTIMX`; the
//!   vendor restores it only on `/S`, and leaves the caller at the editor's
//!   margin otherwise.
//! - `rstrxf()`/`btutsw()` on quit are FSE bookkeeping the line editor never
//!   disturbed; they are not called. `clrinp()` is.
//!
//! The messages are this host's own wording, keyed by the vendor's message
//! names and embedded rather than read from a `.MCV`, because a board
//! directory need not ship the editor's message file. Line breaks are
//! `\r`, the in-memory form `prf` writes and GSBL expands to CRLF.
//!
//! # The text buffer convention
//!
//! The vendor keeps the text as `\r`-*preceded* lines: `"\rline 1\rline 2"`.
//! `apndtx` writes the separator before each line and `lstlns`/`extlin`
//! start scanning at `txtbuf[1]`, so a buffer handed in as `"Hello\rWorld"`
//! lists as `01: ello`. That is what the real host does, and a file the
//! vendor editor itself wrote starts with a line break, so it is preserved
//! here rather than corrected.

use crate::abi::{self, Abi, Arg};
use crate::chan::Chan;
use crate::shims::{Call, ShimError};
use crate::strings::{sameas, sameto, toupper};
use crate::{Host, Outcome, Serviced};
use mbbs_machine::ptr::ModulePtr;

/// The name [`crate::Host::vectors`] records the `bgnedt` thunk under, and
/// the routine table serves [`fse_bgnedt`] as -- the vendor's own name for
/// the function behind the pointer (`EDITFSE.C:294`).
pub const VECTOR: &str = "fse_bgnedt";

// `MAJORBBS.H:75-85` -- flags that can be passed to `bgnedt()`.
const ED_CLRTOP: u32 = 4;
const ED_CLRTXT: u32 = 8;
const ED_FILESD: u32 = 16;
const ED_FIXTOP: u32 = 64;
/// `MAJORBBS.H:87` -- passed to `whndun()` when the user quit rather than
/// saved.
pub const ED_QUITEX: u16 = 256;

/// `EDITFSE.C:92` -- wrap point (72 for RelayNet compatibility).
const WRPLIM: u16 = 72;
/// `EDITFSE.C:93` -- maximum line size for replace in the line editor.
const MXLNSZ: usize = 79;
/// `MAJORBBS.H:42` -- default input-char count max per line.
const DFTIMX: u16 = 127;
/// `EDITFSE.C:122` -- "continue editing" return value of `bgnedt`.
const CONEDT: u16 = 1;

/// `ldunedt`'s sub-state -- `fseptr->substt`/`newett`, which the vendor
/// keys by the number of the message that prompted for the next line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sub {
    /// `0`: nothing asked yet (`bgnmsg` runs).
    Begin,
    /// `GETTPC`: waiting for a topic line.
    GetTpc,
    /// `ENTTXT`: entering text (append).
    EntTxt,
    /// `INSLIN`: entering text (insert before `curlin`).
    InsLin,
    /// `EDPWKS`/`EDTPMT2`/`EDTPMTT`: at the editor menu (`hdlecm`).
    Menu,
    /// `HLPWKS`: at the help menu (`hdlhcm`).
    HlpWks,
    /// `RWCHLN`: `C)hange` asked which line.
    Rwchln,
    /// `EWCHLN`: `R)etype` asked which line.
    Ewchln,
    /// `DWCHLN`: `D)elete` asked which line.
    Dwchln,
    /// `IWCHLN`: `I)nsert` asked before which line.
    Iwchln,
    /// `REPLAC`: `C)hange` asked what text.
    Replac,
    /// `RPLCWW`: `C)hange` asked what to replace it with.
    Rplcww,
    /// `EDITLN`: `R)etype` asked for the new line.
    Editln,
    /// `DELLIN`: `D)elete` asked for confirmation.
    Dellin,
    /// `CUSURB`: `N)ew` asked clear-or-nothing.
    Cusurb,
}

/// One channel's editing session -- the line-editor subset of the vendor's
/// `struct fseusr` (`EDITFSE.H`). Rust-side, like [`crate::FsdSession`]:
/// no module ever addresses it.
pub struct Session<A: Abi> {
    /// `txtbuf`/`txtsiz` -- the caller's text buffer and its size.
    text: A::Ptr,
    siz: usize,
    /// `topic`/`tpcsiz` -- the caller's topic buffer, `None` for `NULL`.
    topic: Option<A::Ptr>,
    tsiz: usize,
    /// `exitro` -- the caller's `whndun`, `None` for `NULL`.
    whndun: Option<A::Ptr>,
    /// `rflags` -- the `ED_*` flags `bgnedt` was called with.
    rflags: u32,
    /// `LIN1ST`: the initial topic question is still up, so `x` aborts.
    lin1st: bool,
    /// `INSTXT`: entered text inserts at `begstg` rather than appending.
    instxt: bool,
    /// `CHGTPC`: the topic is being changed from the menu.
    chgtpc: bool,
    sub: Sub,
    /// `nlines`, `curlin`, `crllen`, `rpclen` -- line bookkeeping.
    nlines: usize,
    curlin: usize,
    crllen: usize,
    rpclen: usize,
    /// `begstg`/`endstg` -- the current line, as offsets into the buffer.
    begstg: usize,
    endstg: usize,
}

impl<A: Abi> Clone for Session<A> {
    fn clone(&self) -> Self {
        Self {
            text: self.text,
            siz: self.siz,
            topic: self.topic,
            tsiz: self.tsiz,
            whndun: self.whndun,
            rflags: self.rflags,
            lin1st: self.lin1st,
            instxt: self.instxt,
            chgtpc: self.chgtpc,
            sub: self.sub,
            nlines: self.nlines,
            curlin: self.curlin,
            crllen: self.crllen,
            rpclen: self.rpclen,
            begstg: self.begstg,
            endstg: self.endstg,
        }
    }
}

impl<A: Abi> std::fmt::Debug for Session<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("text", &self.text)
            .field("siz", &self.siz)
            .field("topic", &self.topic)
            .field("whndun", &self.whndun)
            .field("sub", &self.sub)
            .field("nlines", &self.nlines)
            .finish()
    }
}

impl<A: Abi> Session<A> {
    /// The last thing the editor asked.
    #[cfg(test)]
    pub(crate) fn sub(&self) -> Sub {
        self.sub
    }

    /// `msgtpc()` -- does the message have a topic?
    fn msgtpc(&self) -> bool {
        self.topic.is_some()
    }

    /// `edttpc()` -- does it have an *editable* topic?
    fn edttpc(&self) -> bool {
        self.topic.is_some() && self.rflags & ED_FIXTOP == 0
    }

    /// `fseptr->flags & FLFLVR` -- the "file" flavour of messages.
    fn file_flavour(&self) -> bool {
        self.rflags & ED_FILESD != 0
    }
}

// --- Editor messages: this host's own wording, one per vendor message name ---

const EDTMNU2: &[u8] = b"\x1b[0;1;32m\rEDITOR COMMANDS:\r  \x1b[36mS\x1b[33m)ave and exit                  \x1b[36mR\x1b[33m)etype a line\r  \x1b[36mA\x1b[33m)dd more text                  \x1b[36mD\x1b[33m)elete a line\r  \x1b[36mL\x1b[33m)ist with numbers              \x1b[36mI\x1b[33m)nsert lines\r  \x1b[36mC\x1b[33m)hange a phrase                \x1b[36mN\x1b[33m)ew: start over\r  \x1b[36mH\x1b[33m)elp\r  \x1b[36mU\x1b[33m)pload a file\r";
const EDTMNUT: &[u8] = b"\x1b[0;1;32m\rEDITOR COMMANDS:\r  \x1b[36mS\x1b[33m)ave and exit                  \x1b[36mR\x1b[33m)etype a line\r  \x1b[36mA\x1b[33m)dd more text                  \x1b[36mD\x1b[33m)elete a line\r  \x1b[36mL\x1b[33m)ist with numbers              \x1b[36mI\x1b[33m)nsert lines\r  \x1b[36mC\x1b[33m)hange a phrase                \x1b[36mN\x1b[33m)ew: start over\r  \x1b[36mH\x1b[33m)elp                                \x1b[36mT\x1b[33m)opic change\r  \x1b[36mU\x1b[33m)pload a file\r";
const EDPWKS: &[u8] = b"\x1b[0;1;36m\rChoose one of the commands above: ";
const EDTPMT2: &[u8] = b"\x1b[0;1;36m\rEditor command (S,A,L,C,H,R,D,I,N,U, or ? for the list): ";
const EDTPMTT: &[u8] = b"\x1b[0;1;36m\rEditor command (S,A,L,C,H,R,D,I,N,T,U, or ? for the list): ";
const GETTPC: &[u8] = b"\x1b[0;1;36m\rTopic for this message (up to %d characters): ";
const ENTTXT: &[u8] = b"\x1b[0m\r\x1b[1;32mType your message, up to %d characters.  Finish with \"\x1b[36mOK\x1b[32m\" alone on\ra line, or \"\x1b[36m/S\x1b[32m\" to save it straight away without editing.\r";
const CNTENT: &[u8] = b"\x1b[0m\r\x1b[1;32mKeep typing.  \"\x1b[36mOK\x1b[32m\" alone on a line finishes; \"\x1b[36m/S\x1b[32m\" saves the message\rat once without editing.\r";
const HLPAVL: &[u8] = b"\x1b[0m\r\x1b[1;32mHelp is available for:\r   \x1b[36mS \x1b[33m... saving the message\r   \x1b[36mA \x1b[33m... adding more text\r   \x1b[36mL \x1b[33m... listing the lines by number\r   \x1b[36mC \x1b[33m... changing a phrase\r   \x1b[36mR \x1b[33m... retyping a line\r   \x1b[36mD \x1b[33m... deleting a line\r   \x1b[36mI \x1b[33m... inserting lines\r   \x1b[36mN \x1b[33m... starting again from nothing\r   \x1b[36mQ \x1b[33m... leaving the editor\r";
const HLPAVLWT: &[u8] = b"\x1b[0m\r\x1b[1;32mHelp is available for:\r   \x1b[36mS \x1b[33m... saving the message\r   \x1b[36mA \x1b[33m... adding more text\r   \x1b[36mL \x1b[33m... listing the lines by number\r   \x1b[36mC \x1b[33m... changing a phrase\r   \x1b[36mR \x1b[33m... retyping a line\r   \x1b[36mD \x1b[33m... deleting a line\r   \x1b[36mI \x1b[33m... inserting lines\r   \x1b[36mN \x1b[33m... starting again from nothing\r   \x1b[36mT \x1b[33m... changing the topic\r   \x1b[36mQ \x1b[33m... leaving the editor\r";
const HLPWKS: &[u8] = b"\x1b[0;1;36m\rHelp on which command? ";
const HLPQUT: &[u8] = b"\x1b[0m\r\x1b[1;32mWhile typing, \"\x1b[36mX\x1b[32m\" alone on a line returns to the editor menu, and \"\x1b[36mX\x1b[32m\"\rthere again abandons the message.  A new message is then not saved; an\redited one keeps its old contents on disk.\r";
const HLPTPC: &[u8] = b"\x1b[0;1;32m\r\x1b[36mT\x1b[32m)opic lets you type the message's topic line again.\r";
const HLPSAV: &[u8] = b"\x1b[0m\r\x1b[1;32m\x1b[36mS\x1b[32m)ave writes the message to disk and leaves the editor.  While typing\ryou can save at once with \"\x1b[36m.S\x1b[32m\" or \"\x1b[36m/S\x1b[32m\" alone on a line.\r";
const HLPAPP: &[u8] = b"\x1b[0;1;32m\r\x1b[36mA\x1b[32m)dd resumes typing after the last line you entered.\r";
const HLPLIS: &[u8] = b"\x1b[0m\r\x1b[1;32m\x1b[36mL\x1b[32m)ist shows the message with a number beside each line, for use by\rthe other commands.\r";
const HLPCHG: &[u8] = b"\x1b[0;1;32m\r\x1b[36mC\x1b[32m)hange swaps one phrase in a line for another, so a single misspelt\rword need not cost you the whole line.\r";
const HLPRTY: &[u8] = b"\x1b[0;1;32m\r\x1b[36mR\x1b[32m)etype replaces one whole line with a line you type afresh.\r";
const HLPDEL: &[u8] = b"\x1b[0;1;32m\r\x1b[36mD\x1b[32m)elete removes one line from the message.\r(( Shortcut: D2Y deletes line 2 and answers the confirmation for you.    ))\r(( Three lines from line 2 onward: D2Y three times.                      ))\r";
const HLPINS: &[u8] = b"\x1b[0;1;32m\r\x1b[36mI\x1b[32m)nsert puts new lines ahead of the line you name.  To add lines after\rthe last one, use \x1b[36mA\x1b[32m)dd instead.\r";
const HLPNEW2: &[u8] = b"\x1b[0;1;32m\r\x1b[36mN\x1b[32m)ew loads a copy of another message as the starting point for this\rone: a way to send the same text to several people, or to keep a form\rletter on hand.  Only messages you sent or received can be loaded.\r\x1b[36mN\x1b[32m)ew also clears the edit area, so it is the way to start again from\rnothing.\r";
const CNOTIL: &[u8] = b"\x1b[0;1;35m\r\"%c\" is not one of the commands.\r";
const INVLIN: &[u8] = b"\x1b[0;1;35m\rThere is no line with that number.\r";
const CRLRDS: &[u8] = b"\x1b[0;1;32m\rThe line now reads:\r\x1b[36m%02d\x1b[33m: %s\r";
const RWCHLN: &[u8] = b"\x1b[0;1;36m\rChange text in which line (1-%d)? ";
const REPLAC: &[u8] = b"\x1b[0;1;36m\rText to replace:\r: ";
const RPLCWW: &[u8] = b"\x1b[0;1;36m\rReplacement text (RETURN alone deletes it).\r: ";
const NOMCHF: &[u8] = b"\x1b[0;1;35m\r*** That text is not in the line.\r";
const NLNRDS: &[u8] = b"\x1b[0;1;32m\r*** The line now reads:\r\x1b[36m%02d\x1b[33m: %s\r";
const EWCHLN: &[u8] = b"\x1b[0;1;36m\rRetype which line (1-%d)? ";
const EDITLN: &[u8] = b"\x1b[0;1;36m\rNew line:\r: ";
const DWCHLN: &[u8] = b"\x1b[0;1;36m\rDelete which line (1-%d)? ";
const DELLIN: &[u8] = b"\x1b[0;1;36m\rDelete this line (Y/N)? ";
const YORN: &[u8] = b"\x1b[0;1;32m\rAnswer Y or N.\r";
const IWCHLN: &[u8] = b"\x1b[0;1;36m\rInsert ahead of which line (1-%d)? ";
const INSLIN: &[u8] = b"\x1b[0m\r\x1b[1;32mType the lines to insert.  \"\x1b[36mOK\x1b[32m\" alone on a line finishes; \"\x1b[36m/S\x1b[32m\"\rsaves the message at once without editing.\r";
const CUSURB: &[u8] = b"\x1b[0;1;36m\rC clears the message area to start again; N leaves it alone (loading\ranother message is not possible here): ";
const TOOBIG: &[u8] = b"\x1b[0;1;35m\rThe message is full; no more text will fit.\r";
const LINOVR: &[u8] = b"\x1b[0;1;35m*** The line was too long and has been cut short. ***\r";
/// Emitted where the vendor's RIP-only message would be; empty in every language this host serves.
const FSETRL: &[u8] = b"";

/// One `prfmsg` argument.
enum Fmt<'a> {
    D(usize),
    S(&'a [u8]),
    C(u8),
}

/// `prfmsg(msg, ...)`'s `%d`/`%02d`/`%s`/`%c`, in argument order --
/// everything `WGSEDTM.MSG`'s line-editor messages use.
fn prfmsg(out: &mut Vec<u8>, msg: &[u8], args: &[Fmt<'_>]) {
    let mut next = args.iter();
    let mut i = 0;
    while i < msg.len() {
        if msg[i] != b'%' {
            out.push(msg[i]);
            i += 1;
            continue;
        }
        // `%[0][width]conv`
        let mut j = i + 1;
        let zero = msg.get(j) == Some(&b'0');
        if zero {
            j += 1;
        }
        let mut width = 0usize;
        while let Some(d) = msg.get(j).filter(|b| b.is_ascii_digit()) {
            width = width * 10 + usize::from(d - b'0');
            j += 1;
        }
        let Some(&conv) = msg.get(j) else {
            out.extend_from_slice(&msg[i..]);
            break;
        };
        match (conv, next.next()) {
            (b'd', Some(Fmt::D(n))) => {
                let s = n.to_string();
                let pad = width.saturating_sub(s.len());
                out.extend(std::iter::repeat_n(if zero { b'0' } else { b' ' }, pad));
                out.extend_from_slice(s.as_bytes());
            }
            (b's', Some(Fmt::S(s))) => out.extend_from_slice(s),
            (b'c', Some(Fmt::C(c))) => out.push(*c),
            _ => out.extend_from_slice(&msg[i..=j]),
        }
        i = j + 1;
    }
}

// --- The text buffer ---------------------------------------------------

/// `strlen` of a NUL-terminated buffer, the buffer's whole length if it
/// has no terminator.
fn strlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

/// The lines of a buffer as `(start, end)` byte ranges, `end` naming the
/// `\r` or NUL that closes each -- `lstlns`'s walk (`EDITFSE.C:2868`),
/// starting at byte 1 as the vendor does.
fn lines(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 1;
    while at < buf.len() && buf[at] != 0 {
        let end = buf[at..]
            .iter()
            .position(|&b| b == b'\r' || b == 0)
            .map_or(buf.len(), |n| at + n);
        out.push((at, end));
        if end >= buf.len() || buf[end] == 0 {
            break;
        }
        at = end + 1;
    }
    out
}

impl<A: Abi> Session<A> {
    /// `lstlns(0)` -- recount lines and length.
    fn count(&mut self, buf: &[u8]) {
        self.nlines = lines(buf).len();
    }

    /// `lstlns(1)` -- list the message with line numbers.
    fn list(&mut self, buf: &[u8], topic: Option<&[u8]>, out: &mut Vec<u8>) {
        out.push(b'\r');
        if let Some(topic) = topic {
            out.extend_from_slice(if self.file_flavour() { b"File: " } else { b"Topic: " });
            out.extend_from_slice(topic);
            out.extend_from_slice(b"\r\r");
        }
        let all = lines(buf);
        for (n, &(s, e)) in all.iter().enumerate() {
            prfmsg(out, b"%02d: %s\r", &[Fmt::D(n + 1), Fmt::S(&buf[s..e])]);
        }
        self.nlines = all.len();
    }

    /// `extlin()` -- locate line `curlin`.
    fn extlin(&mut self, buf: &[u8]) {
        let all = lines(buf);
        match all.get(self.curlin.wrapping_sub(1)) {
            Some(&(s, e)) => {
                self.begstg = s;
                self.endstg = e;
                self.crllen = e - s;
            }
            None => {
                // Past the last line: the vendor's loop leaves `bstg`/`estg`
                // at the terminator. Only reachable from `insttx`, whose
                // `curlin++` can name the line just past the end.
                let end = strlen(buf);
                self.begstg = end;
                self.endstg = end;
                self.crllen = 0;
            }
        }
    }

    /// The current line's text.
    fn current<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        &buf[self.begstg..self.endstg]
    }

    /// `morspc()` -- is there room for another line? Sets the input limit
    /// to what is left when it is tight.
    fn morspc(&mut self, buf: &[u8], scnwid: u16, out: &mut Vec<u8>) -> Option<u16> {
        let amtlft = self.siz.saturating_sub(strlen(buf) + 1);
        if amtlft <= usize::from(scnwid) {
            if amtlft < 4 {
                out.extend_from_slice(TOOBIG);
                self.edtmnu(out);
                return None;
            }
            return Some(u16::try_from(amtlft - 1).unwrap_or(u16::MAX));
        }
        Some(0)
    }

    /// `apndtx()` -- append `line`, or insert it at `begstg` in `INSTXT`.
    fn apndtx(&mut self, buf: &mut Vec<u8>, line: &[u8]) {
        let txtlen = strlen(buf);
        let amtlft = self.siz.saturating_sub(txtlen + 1);
        let mut line = line;
        if amtlft < line.len() + 1 {
            if amtlft == 0 {
                return;
            }
            line = &line[..amtlft - 1];
        }
        if self.instxt {
            // `insttx()`: the new line goes in front of `begstg`, with its
            // own separator after it.
            let mut ins = line.to_vec();
            ins.push(b'\r');
            splice(buf, self.begstg, 0, &ins);
            self.nlines += 1;
            self.curlin += 1;
            self.extlin(buf);
        } else {
            buf[txtlen] = b'\r';
            let n = line.len();
            buf[txtlen + 1..txtlen + 1 + n].copy_from_slice(line);
            self.nlines += 1;
        }
    }

    /// `rplctx()` -- replace `rpclen` bytes at `begstg` with `input`.
    fn rplctx(&mut self, buf: &mut Vec<u8>, input: &[u8], out: &mut Vec<u8>) {
        let mut input = input;
        let mut ovrflo = false;
        // Signed, as the vendor's `int`s are: `dellin` sets `rpclen` one
        // past `crllen` to take the separator with the line.
        let nll = (self.crllen as isize - self.rpclen as isize) + input.len() as isize;
        if nll > MXLNSZ as isize {
            out.extend_from_slice(LINOVR);
            ovrflo = true;
            input = &input[..input.len() - (nll - MXLNSZ as isize) as usize];
        }
        let txtlen = strlen(buf) as isize;
        let would = (txtlen - self.crllen as isize) + (self.crllen as isize - self.rpclen as isize) + input.len() as isize;
        let room = self.siz as isize - 1;
        if would > room {
            if !ovrflo {
                out.extend_from_slice(LINOVR);
            }
            input = &input[..input.len() - (would - room) as usize];
        }
        splice(buf, self.begstg, self.rpclen, input);
        self.extlin(buf);
        if self.sub == Sub::Rplcww {
            let line = self.current(buf).to_vec();
            prfmsg(out, NLNRDS, &[Fmt::D(self.curlin), Fmt::S(&line)]);
        }
    }

    /// `edtmnu()` -- the full menu, then the `EDPWKS` prompt.
    fn edtmnu(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(if self.edttpc() { EDTMNUT } else { EDTMNU2 });
        self.instxt = false;
        out.extend_from_slice(EDPWKS);
        self.sub = Sub::Menu;
    }

    /// `edtpmt()` -- the short prompt.
    fn edtpmt(&mut self, out: &mut Vec<u8>) {
        self.instxt = false;
        out.extend_from_slice(if self.edttpc() { EDTPMTT } else { EDTPMT2 });
        self.sub = Sub::Menu;
    }

    /// `hlpmnu()`.
    fn hlpmnu(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(if self.edttpc() { HLPAVLWT } else { HLPAVL });
        out.extend_from_slice(HLPWKS);
        self.sub = Sub::HlpWks;
    }

    /// `bgntpc()` -- ask for the topic. Returns the input limit to set.
    fn bgntpc(&mut self, out: &mut Vec<u8>) -> u16 {
        prfmsg(out, GETTPC, &[Fmt::D(self.tsiz - 1)]);
        self.sub = Sub::GetTpc;
        u16::try_from(self.tsiz - 1).unwrap_or(u16::MAX)
    }

    /// `bgnmsg()` -- begin a message: topic first if there is an empty
    /// editable one, else straight into text. Returns the input limit.
    fn bgnmsg(&mut self, topic_empty: bool, scnwid: u16, out: &mut Vec<u8>) -> u16 {
        self.lin1st = true;
        if self.edttpc() && topic_empty {
            self.bgntpc(out)
        } else {
            prfmsg(out, ENTTXT, &[Fmt::D(self.siz - 1)]);
            self.sub = Sub::EntTxt;
            smargn(scnwid)
        }
    }
}

/// Replace `len` bytes at `at` with `with`, keeping the buffer's length
/// (the module's own allocation) by dropping or zero-filling the tail --
/// the `movmem`/`setmem` pairs of `rplctx`/`insttx`.
fn splice(buf: &mut Vec<u8>, at: usize, len: usize, with: &[u8]) {
    let siz = buf.len();
    let text_end = strlen(buf);
    let mut v = buf[..text_end].to_vec();
    let end = (at + len).min(v.len());
    v.splice(at.min(v.len())..end, with.iter().copied());
    v.truncate(siz - 1);
    v.resize(siz, 0);
    *buf = v;
}

/// `smargn()` -- the entry margin: 72 on an 80-column screen, else one
/// short of the width. (Positive here: this host's GSBL has no negative
/// word-wrap margin; see the module doc.)
fn smargn(scnwid: u16) -> u16 {
    if scnwid == 79 || scnwid == 80 {
        WRPLIM
    } else {
        scnwid.saturating_sub(1)
    }
}

/// `inword(stg1, stg2)` -- where `stg1` first matches (case-insensitively)
/// inside the line starting at `stg2`.
fn inword(needle: &[u8], line: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    (0..=line.len().saturating_sub(needle.len()))
        .find(|&i| line.len() - i >= needle.len() && sameto(needle, &line[i..]))
}

// --- The command line --------------------------------------------------

/// `nxtcmd` and the `cnc*` family over one input line, host-side.
///
/// After `bgncnc()` the vendor's `nxtcmd` is `margv[0]` -- the line from
/// its first non-blank byte, separators restored by `rstrin()`. `cncchr`
/// takes one byte, `cncint` the digits, `cncall` the rest.
struct Cursor {
    line: Vec<u8>,
    pos: usize,
    margc: usize,
}

impl Cursor {
    /// `bgncnc()` over `input`: skip leading blanks, count the words.
    fn new(input: &[u8]) -> Self {
        let start = input.iter().position(|b| !crate::strings::is_white(*b)).unwrap_or(input.len());
        let margc = input[start..]
            .split(|b| crate::strings::is_white(*b))
            .filter(|w| !w.is_empty())
            .count();
        Self {
            line: input[start..].to_vec(),
            pos: 0,
            margc,
        }
    }

    /// `margv[0]`.
    fn margv0(&self) -> &[u8] {
        let end = self.line.iter().position(|b| crate::strings::is_white(*b)).unwrap_or(self.line.len());
        &self.line[..end]
    }

    /// `*nxtcmd`, without taking it.
    fn peek(&self) -> u8 {
        self.line.get(self.pos).copied().unwrap_or(0)
    }

    /// `cncchr()`.
    fn chr(&mut self) -> u8 {
        let c = toupper(self.peek());
        if c != 0 {
            self.pos += 1;
        }
        c
    }

    /// `cncint()`.
    fn int(&mut self) -> usize {
        let mut n = 0usize;
        while let Some(d) = self.line.get(self.pos).filter(|b| b.is_ascii_digit()) {
            n = n.saturating_mul(10).saturating_add(usize::from(d - b'0'));
            self.pos += 1;
        }
        n
    }

    /// `cncyesno()` on an English lingo: the first letter, uppercased.
    fn yesno(&mut self) -> u8 {
        self.chr()
    }

    /// `cncall()` -- the rest of the line, and there is no more.
    fn all(&mut self) -> Vec<u8> {
        let rest = self.line[self.pos.min(self.line.len())..].to_vec();
        self.pos = self.line.len();
        rest
    }

    /// `endcnc()` -- what is left becomes the next command, or nothing.
    fn endcnc(&self) -> Option<Cursor> {
        if self.margc == 0 {
            return None;
        }
        let next = Cursor::new(&self.line[self.pos.min(self.line.len())..]);
        (next.margc != 0).then_some(next)
    }
}

// --- Entry: `bgnedt` ----------------------------------------------------

/// `INT fse_bgnedt(INT siz, CHAR *buf, INT tsiz, CHAR *topic, SHORT (*whndun)(SHORT), INT flags)`
/// -- `EDITFSE.C:294`, reached through the `bgnedt` pointer global.
///
/// Normalises the text (`\n` to `\r`, lines longer than `MXLNSZ` split),
/// then `stline()`: the channel's `state` becomes the editor's, `strtov()`
/// resets the session, and the first `ldunedt()` pass prompts. That pass
/// runs with whatever the caller left on its own command line; the vendor
/// re-splits it with `endcnc()`, and MajorMUD has consumed its menu letter
/// by then, so the pass sees an empty line and shows the menu. This shim
/// shows the menu unconditionally rather than re-reading the caller's
/// `nxtcmd`, which it then empties the way the vendor's trailing `cncall()`
/// does. Any output the caller had queued in `prfbuf` is dropped, as
/// `bgncnc()`'s `clrprf()` drops it.
///
/// Answers `CONEDT` (1). The caller's own `sttrou` return is what reaches
/// `hdlcri`, not this.
///
/// # Errors
///
/// If no channel is current, the editor was never registered
/// (`finish_init` has not run), or a buffer read runs off its segment.
pub fn fse_bgnedt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let siz = usize::try_from(Into::<u32>::into(call.int())).expect("u32 fits usize");
    let text = call.ptr();
    let tsiz = usize::try_from(Into::<u32>::into(call.int())).expect("u32 fits usize");
    let topic = call.ptr();
    let whndun = call.ptr();
    let flags: u32 = call.int().into();

    let chan = host.current_channel_mem(call.mem())?;
    let state = host.editor_state.ok_or_else(|| {
        ShimError::Failed("bgnedt: the editor was never registered -- finish_init has not run".into())
    })?;
    if siz < 2 {
        return Err(ShimError::Failed(format!("bgnedt: a {siz}-byte text buffer cannot hold a line")));
    }

    let mut buf = read_text::<A>(call.mem(), text, siz)?;
    normalise(&mut buf);

    let topic = (!is_null::<A>(topic)).then_some(topic);
    let mut session = Session::<A> {
        text,
        siz,
        topic,
        tsiz,
        whndun: (!is_null::<A>(whndun)).then_some(whndun),
        rflags: flags,
        lin1st: false,
        instxt: false,
        chgtpc: false,
        sub: Sub::Begin,
        nlines: 0,
        curlin: 0,
        crllen: 0,
        rpclen: 0,
        begstg: 0,
        endstg: 0,
    };

    // `stline()`: `usrptr->state=fsestt`.
    host.users
        .set_state_mem(call.mem(), chan, state as u16)
        .map_err(|e| ShimError::Failed(format!("bgnedt: {e}")))?;

    let mut out = Vec::new();
    let scnwid = account_scnwid::<A>(call.mem(), host, chan)?;
    let mut limit = None;

    // `strtov()`.
    if flags & (ED_CLRTXT | ED_CLRTOP) != 0 {
        if flags & ED_CLRTXT != 0 {
            buf.iter_mut().for_each(|b| *b = 0);
        }
        if flags & ED_CLRTOP != 0
            && let Some(topic) = topic
        {
            topic
                .write(call.mem(), &vec![0u8; tsiz])
                .map_err(|e| ShimError::Failed(e.to_string()))?;
        }
        // `substt=0`: the first `ldunedt` pass runs `bgnmsg()`.
        let topic_empty = match topic {
            Some(t) => topic_text::<A>(call.mem(), t, tsiz)?.is_empty(),
            None => true,
        };
        limit = Some(session.bgnmsg(topic_empty, scnwid, &mut out));
    } else {
        session.count(&buf);
        // `edtpmt()` here is overwritten by `bgncnc()`'s `clrprf()` in the
        // pass that follows, whose `hdlecm()` on an empty line is `edtmnu()`.
        session.edtmnu(&mut out);
    }
    write_text::<A>(call.mem(), text, &buf)?;

    if let Some(limit) = limit {
        host.gsbl_mut().channel_mut(chan).maxinl = limit;
    }
    host.editor_sessions[chan.index()] = Some(session);

    // `rtfedt()` then the trailing `cncall()`: flush, and the caller's
    // command line is spent.
    crate::shims::text::clrprf_mem(call.mem(), host)?;
    host.gsbl_mut().transmit(chan, &out);
    let empty = host.empty_string();
    host.globals()
        .write_mem(call.mem(), "nxtcmd", &A::ptr_to_bytes(empty))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(CONEDT)))
}

/// `bgnedt`'s own pass over the text (`EDITFSE.C:308-325`): every `\n`
/// becomes `\r`, and a line reaching `MXLNSZ` is broken with an inserted
/// `\r` when the buffer has room for one more byte.
fn normalise(buf: &mut Vec<u8>) {
    let siz = buf.len();
    let mut lcnt = 0usize;
    let mut i = 0;
    while i < buf.len() && buf[i] != 0 {
        let c = buf[i];
        if c == b'\r' {
            lcnt = 0;
        } else if c == b'\n' || lcnt == MXLNSZ {
            if c != b'\n' && strlen(buf) + 1 < siz {
                // `movmem(cp,cp+1,strlen(cp)+1)`: open a byte for the break.
                let end = strlen(buf);
                buf.copy_within(i..end + 1, i + 1);
                buf.truncate(siz);
            }
            buf[i] = b'\r';
            lcnt = 0;
        } else {
            lcnt += 1;
        }
        i += 1;
    }
}

fn is_null<A: Abi>(ptr: A::Ptr) -> bool {
    A::ptr_to_bytes(ptr).iter().all(|&b| b == 0)
}

fn read_text<A: Abi>(mem: &A::Mem, at: A::Ptr, siz: usize) -> Result<Vec<u8>, ShimError> {
    Ok(at
        .resolve(mem, siz)
        .map_err(|e| ShimError::Failed(format!("bgnedt: text buffer: {e}")))?
        .to_vec())
}

fn write_text<A: Abi>(mem: &mut A::Mem, at: A::Ptr, buf: &[u8]) -> Result<(), ShimError> {
    at.write(mem, buf)
        .map_err(|e| ShimError::Failed(format!("bgnedt: text buffer: {e}")))
}

/// The topic buffer's text, up to its NUL or its size.
fn topic_text<A: Abi>(mem: &A::Mem, at: A::Ptr, tsiz: usize) -> Result<Vec<u8>, ShimError> {
    let bytes = at
        .resolve(mem, tsiz)
        .map_err(|e| ShimError::Failed(format!("bgnedt: topic buffer: {e}")))?;
    Ok(bytes[..strlen(bytes)].to_vec())
}

/// `usaptr->scnwid` for `chan`.
fn account_scnwid<A: Abi>(mem: &A::Mem, host: &Host<A>, chan: Chan) -> Result<u16, ShimError> {
    let at = A::ptr_offset(host.users.account(chan), host.users().account_layout().scnwid);
    let byte = at
        .resolve(mem, 1)
        .map_err(|e| ShimError::Failed(e.to_string()))?[0];
    Ok(u16::from(byte))
}

// --- The channel's `sttrou`: `ldunedt` ---------------------------------

/// How one `ldunedt` pass ended.
enum Pass {
    /// Still editing; `sub` says what was asked.
    Continue,
    /// The session is over: call `whndun(flags)`.
    Done(u16),
}

/// `Dispatch::Native(Native::Editor)`'s side of `Host::poll`: entry `n` of
/// the editor's slot. Entry 1 (`sttrou`, on `CRSTG`) is `ldunedt`; the
/// rest (`stsrou`, which the line editor has no work for -- `dunedt`
/// answers `CONEDT` for a `LINEMO` user without looking) are serviced
/// silently.
///
/// When the session ends, the caller's `whndun` runs through
/// [`Host::run`], and its return is what the vendor's `ldunedt` returns
/// to `hdlcri`: zero hands the channel to the menuing system
/// (`Host::go2mnu`), anything else leaves it wherever `whndun` put
/// `state` -- MajorMUD's restores its own and answers 1.
///
/// # Errors
///
/// If the channel is in the editor's `state` with no session -- `bgnedt`
/// never ran, or the session already ended and something wrote the state
/// back -- or if `whndun` stops the machine.
pub(crate) fn dispatch<A: Abi>(
    machine: &mut A::Cpu,
    host: &mut Host<A>,
    module: &A::Module,
    chan: Chan,
    n: usize,
) -> Result<Serviced<A::Ptr>, ShimError> {
    if n != 1 {
        return Ok(Serviced::Host);
    }
    let (out, pass) = ldunedt(machine, host, chan)?;
    host.gsbl_mut().transmit(chan, &out);

    if let Pass::Done(flags) = pass {
        let Some(session) = host.editor_sessions[chan.index()].take() else {
            unreachable!("ldunedt answered Done with a session in place");
        };
        host.gsbl_mut().channel_mut(chan).maxinl = DFTIMX;
        crate::shims::text::clrprf_mem(A::mem(machine), host)?;
        let returned = match session.whndun {
            Some(whndun) => {
                let outcome = host
                    .run(machine, module, whndun, &[Arg::Int(A::Int::from(flags))], Some(chan))
                    .map_err(|e| ShimError::Failed(format!("editor: whndun call failed: {e}")))?;
                match outcome {
                    Outcome::Returned { lo, .. } => lo,
                    Outcome::Stopped(poison) => {
                        return Err(ShimError::Failed(format!(
                            "editor: whndun at {whndun} stopped the machine: {poison}"
                        )));
                    }
                }
            }
            // `(*(fseptr->exitro))(..)` is called unguarded; a `NULL` there
            // would have faulted the real host. Answering 1 leaves the
            // channel in the editor's state with no session, which the
            // next line reports rather than faults on.
            None => {
                host.note(format!("editor: channel {chan} finished editing with no whndun to call"));
                1
            }
        };
        if returned == 0 {
            host.go2mnu(machine, chan)?;
        }
    }
    Ok(Serviced::Host)
}

/// `ldunedt()` -- `EDITFSE.C:2314`, minus the FSE arms.
///
/// The line is `input`, separators restored (`bgncnc()`'s `rstrin()`), and
/// each iteration of the vendor's `do { .. } while (!endcnc())` is one
/// [`Cursor`]: a command that leaves text behind (`D2Y`) feeds it to the
/// next state as its own line.
fn ldunedt<A: Abi>(
    machine: &mut A::Cpu,
    host: &mut Host<A>,
    chan: Chan,
) -> Result<(Vec<u8>, Pass), ShimError> {
    let mut session = host.editor_sessions[chan.index()].clone().ok_or_else(|| {
        ShimError::Failed(format!(
            "editor: channel {chan} is in the editor's state but has no session -- bgnedt never \
             ran for it, or whndun failed to restore the caller's state"
        ))
    })?;

    crate::shims::text::rstrin_mem(A::mem(machine), host)?;
    let input_at = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    let input = input_at
        .read_cstr(A::mem_ref(machine))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let scnwid = account_scnwid::<A>(A::mem_ref(machine), host, chan)?;

    let mut buf = read_text::<A>(A::mem_ref(machine), session.text, session.siz)?;
    let mut topic = match session.topic {
        Some(t) => Some(topic_text::<A>(A::mem_ref(machine), t, session.tsiz)?),
        None => None,
    };
    let mut out = Vec::new();
    let mut limit: Option<u16> = None;

    let mut cursor = Cursor::new(&input);
    let pass = loop {
        let step = step(&mut session, &mut cursor, &mut buf, &mut topic, scnwid, &mut limit, &mut out);
        match step {
            Step::Done(flags) => break Pass::Done(flags),
            // Text entry never concatenates: the line is the text.
            Step::Return => break Pass::Continue,
            Step::Next => match cursor.endcnc() {
                Some(next) => cursor = next,
                None => break Pass::Continue,
            },
            Step::Stop => break Pass::Continue,
        }
    };

    write_text::<A>(A::mem(machine), session.text, &buf)?;
    if let (Some(t), Some(text)) = (session.topic, &topic) {
        let mut bytes = text.clone();
        bytes.truncate(session.tsiz.saturating_sub(1));
        bytes.resize(session.tsiz, 0);
        t.write(A::mem(machine), &bytes)
            .map_err(|e| ShimError::Failed(format!("editor: topic buffer: {e}")))?;
    }
    if let Some(limit) = limit {
        host.gsbl_mut().channel_mut(chan).maxinl = limit;
    }
    if matches!(pass, Pass::Done(_)) {
        // `clrinp()` on the way out: typed-ahead input is the editor's, not
        // the caller's.
        host.gsbl_mut().channel_mut(chan).input.clear();
        out.extend_from_slice(FSETRL);
    }
    host.editor_sessions[chan.index()] = Some(session);
    Ok((out, pass))
}

/// What one `switch (newett)` arm decided.
enum Step {
    /// `break` -- on to `endcnc()`.
    Next,
    /// `return(CONEDT)` -- the pass is over, whatever is left on the line.
    Return,
    /// `margc=0` -- `endcnc()` will say there is nothing more.
    Stop,
    /// The session ended; call `whndun` with these flags.
    Done(u16),
}

fn step<A: Abi>(
    s: &mut Session<A>,
    c: &mut Cursor,
    buf: &mut Vec<u8>,
    topic: &mut Option<Vec<u8>>,
    scnwid: u16,
    limit: &mut Option<u16>,
    out: &mut Vec<u8>,
) -> Step {
    match s.sub {
        Sub::Begin => {
            let empty = topic.as_ref().is_none_or(Vec::is_empty);
            *limit = Some(s.bgnmsg(empty, scnwid, out));
            Step::Next
        }
        Sub::GetTpc => {
            if c.margc == 0 {
                prfmsg(out, GETTPC, &[Fmt::D(s.tsiz - 1)]);
                c.all();
                return Step::Next;
            }
            if c.margc == 1 && sameas(c.margv0(), b"x") {
                if s.lin1st {
                    return Step::Done(ED_QUITEX);
                }
                c.all();
                s.edtpmt(out);
                *limit = Some(scnwid.saturating_sub(1));
                return Step::Stop;
            }
            s.lin1st = false;
            let mut tpc = c.all();
            tpc.truncate(s.tsiz.saturating_sub(1));
            *topic = Some(tpc);
            if s.chgtpc {
                s.chgtpc = false;
                s.edtpmt(out);
                *limit = Some(scnwid.saturating_sub(1));
            } else {
                prfmsg(out, ENTTXT, &[Fmt::D(s.siz - 1)]);
                s.sub = Sub::EntTxt;
                *limit = Some(smargn(scnwid));
            }
            Step::Next
        }
        Sub::InsLin | Sub::EntTxt => procln(s, c, buf, scnwid, limit, out),
        Sub::Menu => hdlecm(s, c, buf, topic.as_deref(), scnwid, limit, out),
        Sub::HlpWks => {
            let key = c.chr();
            c.all();
            if key == b'X' {
                s.edtpmt(out);
                return Step::Next;
            }
            const HELP: [(u8, &[u8]); 11] = [
                (b'S', HLPSAV),
                (b'A', HLPAPP),
                (b'L', HLPLIS),
                (b'C', HLPCHG),
                (b'R', HLPRTY),
                (b'D', HLPDEL),
                (b'I', HLPINS),
                (b'N', HLPNEW2),
                (b'T', HLPTPC),
                (b'F', HLPTPC),
                (b'Q', HLPQUT),
            ];
            match HELP.iter().find(|(k, _)| *k == key) {
                Some((_, msg)) => {
                    out.extend_from_slice(msg);
                    s.edtpmt(out);
                }
                None => s.hlpmnu(out),
            }
            Step::Next
        }
        Sub::Rwchln => vldlin(s, c, buf, Sub::Replac, RWCHLN, scnwid, limit, out),
        Sub::Ewchln => vldlin(s, c, buf, Sub::Editln, EWCHLN, scnwid, limit, out),
        Sub::Dwchln => vldlin(s, c, buf, Sub::Dellin, DWCHLN, scnwid, limit, out),
        Sub::Iwchln => vldlin(s, c, buf, Sub::InsLin, IWCHLN, scnwid, limit, out),
        Sub::Replac => {
            // `rplcwt()`.
            let line = c.all();
            if c.margc == 1 && sameas(c.margv0(), b"x") {
                s.edtpmt(out);
            } else if line.is_empty() {
                out.extend_from_slice(REPLAC);
            } else {
                let current = s.current(buf);
                match inword(&line, current) {
                    Some(at) => {
                        s.begstg += at;
                        s.rpclen = line.len();
                        s.sub = Sub::Rplcww;
                        out.extend_from_slice(RPLCWW);
                    }
                    None => {
                        out.extend_from_slice(NOMCHF);
                        s.edtpmt(out);
                    }
                }
            }
            Step::Next
        }
        Sub::Rplcww => {
            let line = c.all();
            if !(c.margc == 1 && sameas(c.margv0(), b"x")) {
                s.rplctx(buf, &line, out);
            }
            s.edtpmt(out);
            Step::Next
        }
        Sub::Editln => {
            let line = c.all();
            if !(c.margc == 1 && sameas(c.margv0(), b"x")) {
                s.rpclen = s.crllen;
                s.rplctx(buf, &line, out);
            }
            s.edtpmt(out);
            Step::Next
        }
        Sub::Dellin => {
            // `dellin()`.
            match c.yesno() {
                b'Y' => {
                    s.rpclen = s.crllen + 1;
                    if s.curlin == s.nlines {
                        s.begstg -= 1;
                    }
                    s.rplctx(buf, b"", out);
                    s.count(buf);
                    s.edtpmt(out);
                }
                b'N' => s.edtpmt(out),
                _ => {
                    out.extend_from_slice(YORN);
                    c.all();
                    out.extend_from_slice(DELLIN);
                }
            }
            Step::Next
        }
        Sub::Cusurb => {
            match c.chr() {
                b'C' => {
                    buf.iter_mut().for_each(|b| *b = 0);
                    // `strtov()` then `bgnmsg()`.
                    s.lin1st = false;
                    s.instxt = false;
                    s.chgtpc = false;
                    s.nlines = 0;
                    s.curlin = 0;
                    let empty = topic.as_ref().is_none_or(Vec::is_empty);
                    *limit = Some(s.bgnmsg(empty, scnwid, out));
                }
                b'X' | b'N' => {
                    c.all();
                    s.edtpmt(out);
                }
                _ => {
                    out.extend_from_slice(CUSURB);
                    c.all();
                }
            }
            Step::Next
        }
    }
}

/// `procln()` -- a line typed while entering text.
fn procln<A: Abi>(
    s: &mut Session<A>,
    c: &mut Cursor,
    buf: &mut Vec<u8>,
    scnwid: u16,
    limit: &mut Option<u16>,
    out: &mut Vec<u8>,
) -> Step {
    let line = c.all();
    if line.is_empty() && c.margc == 0 {
        out.extend_from_slice(CNTENT);
    } else if c.margc == 1 && (sameas(c.margv0(), b"ok") || sameas(c.margv0(), b"x")) {
        *limit = Some(scnwid.saturating_sub(1));
        s.edtmnu(out);
    } else if c.margc == 1 && (sameas(c.margv0(), b".s") || sameas(c.margv0(), b"/s")) {
        return Step::Done(0);
    } else {
        s.apndtx(buf, &line);
        match s.morspc(buf, scnwid, out) {
            Some(0) => {}
            Some(n) => *limit = Some(n),
            None => *limit = Some(DFTIMX),
        }
    }
    Step::Return
}

/// `hdlecm()` -- the editor menu.
fn hdlecm<A: Abi>(
    s: &mut Session<A>,
    c: &mut Cursor,
    buf: &[u8],
    topic: Option<&[u8]>,
    scnwid: u16,
    limit: &mut Option<u16>,
    out: &mut Vec<u8>,
) -> Step {
    if c.margc == 0 {
        s.edtmnu(out);
        return Step::Next;
    }
    let key = c.chr();
    match key {
        b'S' => return Step::Done(0),
        b'X' => return Step::Done(ED_QUITEX),
        b'A' => {
            *limit = Some(smargn(scnwid));
            match s.morspc(buf, scnwid, out) {
                Some(n) => {
                    if n != 0 {
                        *limit = Some(n);
                    }
                    out.extend_from_slice(CNTENT);
                    c.all();
                    s.sub = Sub::EntTxt;
                }
                None => *limit = Some(DFTIMX),
            }
        }
        b'L' => {
            s.list(buf, if s.msgtpc() { topic } else { None }, out);
            s.edtpmt(out);
        }
        b'C' => {
            prfmsg(out, RWCHLN, &[Fmt::D(s.nlines)]);
            s.sub = Sub::Rwchln;
        }
        b'R' => {
            prfmsg(out, EWCHLN, &[Fmt::D(s.nlines)]);
            s.sub = Sub::Ewchln;
        }
        b'D' => {
            prfmsg(out, DWCHLN, &[Fmt::D(s.nlines)]);
            s.sub = Sub::Dwchln;
        }
        b'I' => match s.morspc(buf, scnwid, out) {
            Some(n) => {
                if n != 0 {
                    *limit = Some(n);
                }
                prfmsg(out, IWCHLN, &[Fmt::D(s.nlines)]);
                s.sub = Sub::Iwchln;
            }
            None => *limit = Some(DFTIMX),
        },
        b'N' => {
            out.extend_from_slice(CUSURB);
            s.sub = Sub::Cusurb;
        }
        b'H' => {
            if sameto(b"help", c.margv0()) {
                c.pos += 3;
            }
            s.hlpmnu(out);
        }
        b'?' => s.edtmnu(out),
        // `M)ode` needs the FSE; `T)opic`/`F)ile` need an editable topic.
        b'T' | b'F' if s.edttpc() => {
            *limit = Some(s.bgntpc(out));
            s.chgtpc = true;
        }
        _ => {
            prfmsg(out, CNOTIL, &[Fmt::C(key)]);
            c.all();
            s.edtmnu(out);
        }
    }
    Step::Next
}

/// `vldlin(msg)` -- a line number for `C`/`R`/`D`/`I`. `ask` is the
/// prompt to repeat on an empty answer; `then` the state a valid number
/// leads to.
#[allow(clippy::too_many_arguments)]
fn vldlin<A: Abi>(
    s: &mut Session<A>,
    c: &mut Cursor,
    buf: &[u8],
    then: Sub,
    ask: &[u8],
    scnwid: u16,
    limit: &mut Option<u16>,
    out: &mut Vec<u8>,
) -> Step {
    if toupper(c.peek()) == b'X' {
        c.all();
        s.edtpmt(out);
        return Step::Next;
    }
    if c.margc == 0 {
        prfmsg(out, ask, &[Fmt::D(s.nlines)]);
        return Step::Next;
    }
    let lineno = c.int();
    if lineno >= 1 && lineno <= s.nlines {
        s.curlin = lineno;
        s.extlin(buf);
        if then == Sub::InsLin {
            s.instxt = true;
            *limit = Some(smargn(scnwid));
            c.all();
        } else {
            let line = s.current(buf).to_vec();
            prfmsg(out, CRLRDS, &[Fmt::D(s.curlin), Fmt::S(&line)]);
        }
        match then {
            Sub::Replac => out.extend_from_slice(REPLAC),
            Sub::Editln => out.extend_from_slice(EDITLN),
            Sub::Dellin => out.extend_from_slice(DELLIN),
            Sub::InsLin => out.extend_from_slice(INSLIN),
            _ => unreachable!("vldlin leads to one of four states"),
        }
        s.sub = then;
    } else {
        c.all();
        out.extend_from_slice(INVLIN);
        s.edtpmt(out);
    }
    Step::Next
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::Ret;
    use crate::testing::Fixture;
    use crate::users::Connection;
    use mbbs_machine::m16::FarPtr;

    fn text(buf: &[u8]) -> Vec<u8> {
        buf[..strlen(buf)].to_vec()
    }

    #[test]
    fn prfmsg_fills_d_02d_s_and_c_in_order() {
        let mut out = Vec::new();
        prfmsg(&mut out, b"%02d: %s (%d) %c", &[Fmt::D(7), Fmt::S(b"seven"), Fmt::D(1234), Fmt::C(b'!')]);
        assert_eq!(out, b"07: seven (1234) !");
    }

    #[test]
    fn normalise_turns_newlines_into_returns_and_breaks_long_lines() {
        let mut buf = b"ab\ncd\0\0\0".to_vec();
        normalise(&mut buf);
        assert_eq!(text(&buf), b"ab\rcd");

        // 79 characters, then one more: the 80th is pushed onto a new line
        // when there is room for the inserted separator.
        let mut buf = vec![b'x'; MXLNSZ + 1];
        buf.resize(MXLNSZ + 4, 0);
        normalise(&mut buf);
        let t = text(&buf);
        assert_eq!(t.len(), MXLNSZ + 2);
        assert_eq!(t[MXLNSZ], b'\r');
        assert_eq!(t[MXLNSZ + 1], b'x');
    }

    #[test]
    fn lines_start_at_byte_one_the_way_lstlns_does() {
        assert_eq!(lines(b"\rone\rtwo\0"), vec![(1, 4), (5, 8)]);
        assert_eq!(lines(b"\0\0"), vec![]);
        assert_eq!(lines(b"\r\0"), vec![]);
        // A buffer that does not start with a separator loses its first
        // byte, as the vendor's does.
        assert_eq!(lines(b"Hi\rthere\0"), vec![(1, 2), (3, 8)]);
    }

    #[test]
    fn cursor_reads_one_command_and_hands_the_rest_to_endcnc() {
        let mut c = Cursor::new(b"  D2Y");
        assert_eq!(c.margc, 1);
        assert_eq!(c.chr(), b'D');
        assert_eq!(c.int(), 2);
        let next = c.endcnc().expect("Y is left");
        assert_eq!(next.line, b"Y");
        let mut next = next;
        assert_eq!(next.yesno(), b'Y');
        assert!(next.endcnc().is_none());

        let mut c = Cursor::new(b"hello world");
        assert_eq!(c.margc, 2);
        assert_eq!(c.margv0(), b"hello");
        assert_eq!(c.all(), b"hello world");
        assert!(c.endcnc().is_none(), "cncall spends the line");
        assert!(Cursor::new(b"").endcnc().is_none());
    }

    /// A `whndun` stub that records its `flags` argument at `marker` and
    /// answers `ax = 1` -- what MajorMUD's own does.
    fn whndun_recording(f: &mut Fixture, code_offset: u16, marker: FarPtr) -> FarPtr {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x8b, 0xec]); // mov bp, sp
        code.extend_from_slice(&[0x8b, 0x46, 0x04]); // mov ax, [bp+4]
        code.push(0xb9); // mov cx, seg
        code.extend_from_slice(&marker.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xc1]); // mov es, cx
        code.extend_from_slice(&[0x26, 0xa3]); // mov es:[disp16], ax
        code.extend_from_slice(&marker.offset.to_le_bytes());
        code.extend_from_slice(&[0xb8, 0x01, 0x00]); // mov ax, 1
        code.push(0xcb); // retf
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &code).expect("stub fits");
        ptr
    }

    struct Editing {
        f: Fixture,
        chan: Chan,
        buf: FarPtr,
        marker: FarPtr,
        module: mbbs_machine::m16::Module,
    }

    /// A channel logged on and handed to the editor over `initial`, with a
    /// 256-byte text buffer, no topic, and a recording `whndun`.
    fn start(initial: &[u8], flags: u16) -> Editing {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        let mut initial = initial.to_vec();
        initial.resize(256, 0);
        let buf = f.bytes(&initial, false);
        let marker = f.buffer(2);
        f.machine.write(marker, &[0xEE, 0xEE]).expect("marker");
        let whndun = whndun_recording(&mut f, 0x600, marker);
        let _ = f.host.gsbl_mut().drain_output(chan);
        let ret = f
            .invoke(
                fse_bgnedt,
                &[256, buf.offset, buf.selector, 0, 0, 0, whndun.offset, whndun.selector, flags],
            )
            .expect("bgnedt");
        assert!(matches!(ret, Ret::U16(1)), "CONEDT, got {ret:?}");
        Editing { f, chan, buf, marker, module }
    }

    impl Editing {
        /// Type one line and run the editor's `sttrou` on it.
        fn line(&mut self, line: &str) -> String {
            let _ = self.f.host.gsbl_mut().drain_output(self.chan);
            self.f.host.gsbl_mut().push_input(self.chan, format!("{line}\r").as_bytes());
            self.f.host.poll(&mut self.f.machine, &self.module).expect("poll");
            String::from_utf8_lossy(&self.f.host.gsbl_mut().drain_output(self.chan)).into_owned()
        }

        fn text(&self) -> String {
            let bytes = self.f.machine.resolve(self.buf, 256).expect("buffer");
            String::from_utf8_lossy(&text(bytes)).into_owned()
        }

        fn state(&self) -> u16 {
            self.f.host.users().state_mem(self.f.machine.mem(), self.chan).expect("state")
        }

        fn whndun_got(&self) -> Option<u16> {
            let bytes = self.f.machine.resolve(self.marker, 2).expect("marker");
            let v = u16::from_le_bytes([bytes[0], bytes[1]]);
            (v != 0xEEEE).then_some(v)
        }

        fn session_sub(&self) -> Option<Sub> {
            self.f.host.editor_sessions[self.chan.index()].as_ref().map(Session::sub)
        }
    }

    #[test]
    fn bgnedt_takes_the_channel_and_shows_the_menu() {
        let mut e = start(b"\rfirst line\rsecond line", 0);
        assert_eq!(e.state(), e.f.host.editor_state.expect("registered") as u16, "usrptr->state=fsestt");
        let shown = String::from_utf8_lossy(&e.f.host.gsbl_mut().drain_output(e.chan)).into_owned();
        assert!(shown.contains("EDITOR COMMANDS:"), "the full menu: {shown:?}");
        assert!(shown.contains("Choose one of the commands above: "), "then EDPWKS: {shown:?}");
        assert_eq!(e.session_sub(), Some(Sub::Menu));
        assert_eq!(e.whndun_got(), None, "nothing finished yet");
    }

    #[test]
    fn list_numbers_the_lines_from_byte_one() {
        let mut e = start(b"\rfirst line\rsecond line", 0);
        let shown = e.line("L");
        assert!(shown.contains("01: first line\r\n02: second line\r\n"), "{shown:?}");
        assert!(shown.contains("Editor command (S,A,L,C,H,R,D,I,N,U, or ? for the list): "), "{shown:?}");
    }

    #[test]
    fn append_adds_lines_until_ok_and_save_calls_whndun_with_zero() {
        let mut e = start(b"", 0);
        let shown = e.line("A");
        assert!(shown.contains("Keep typing."), "{shown:?}");
        assert_eq!(e.session_sub(), Some(Sub::EntTxt));
        assert_eq!(e.f.host.gsbl_mut().channel_mut(e.chan).maxinl, WRPLIM, "smargn on an 80-column screen");

        e.line("Hello there");
        e.line("Second line");
        assert_eq!(e.text(), "\rHello there\rSecond line");
        let shown = e.line("OK");
        assert!(shown.contains("EDITOR COMMANDS:"), "ok returns to the menu: {shown:?}");

        e.line("S");
        assert_eq!(e.whndun_got(), Some(0), "whndun(0): save");
        assert!(e.f.host.editor_sessions[e.chan.index()].is_none(), "session torn down");
        assert_eq!(e.f.host.gsbl_mut().channel_mut(e.chan).maxinl, DFTIMX);
    }

    #[test]
    fn slash_s_while_entering_text_saves_at_once() {
        let mut e = start(b"", 0);
        e.line("A");
        e.line("only line");
        e.line("/s");
        assert_eq!(e.whndun_got(), Some(0));
        assert_eq!(e.text(), "\ronly line");
    }

    #[test]
    fn x_from_the_menu_quits_with_ed_quitex() {
        let mut e = start(b"\rkeep me", 0);
        e.line("X");
        assert_eq!(e.whndun_got(), Some(ED_QUITEX));
        assert_eq!(e.text(), "\rkeep me", "the buffer is the caller's to discard");
    }

    #[test]
    fn retype_replaces_one_line_and_delete_removes_one() {
        let mut e = start(b"\rone\rtwo\rthree", 0);
        let shown = e.line("R");
        assert!(shown.contains("Retype which line (1-3)? "), "{shown:?}");
        let shown = e.line("2");
        assert!(shown.contains("02\x1b[33m: two"), "CRLRDS: {shown:?}");
        assert!(shown.contains("New line:"), "{shown:?}");
        e.line("TWO!");
        assert_eq!(e.text(), "\rone\rTWO!\rthree");

        // `D2Y` in one go: the vendor's own EXPERTS NOTE.
        e.line("D2Y");
        assert_eq!(e.text(), "\rone\rthree");
        assert_eq!(e.session_sub(), Some(Sub::Menu));

        // Deleting the last line takes the separator before it.
        e.line("D2Y");
        assert_eq!(e.text(), "\rone");
        e.line("D1Y");
        assert_eq!(e.text(), "");
    }

    #[test]
    fn change_swaps_matching_text_inside_a_line() {
        let mut e = start(b"\rthe quick brown fox", 0);
        e.line("C");
        e.line("1");
        assert_eq!(e.session_sub(), Some(Sub::Replac));
        let shown = e.line("quick");
        assert!(shown.contains("Replacement text"), "{shown:?}");
        let shown = e.line("slow");
        assert!(shown.contains("01\x1b[33m: the slow brown fox"), "NLNRDS: {shown:?}");
        assert_eq!(e.text(), "\rthe slow brown fox");

        e.line("C");
        e.line("1");
        let shown = e.line("purple");
        assert!(shown.contains("not in the line"), "{shown:?}");
        assert_eq!(e.session_sub(), Some(Sub::Menu));
    }

    #[test]
    fn insert_puts_lines_before_the_named_one() {
        let mut e = start(b"\rone\rthree", 0);
        e.line("I");
        e.line("2");
        assert_eq!(e.session_sub(), Some(Sub::InsLin));
        e.line("two");
        assert_eq!(e.text(), "\rone\rtwo\rthree");
        e.line("OK");
        assert_eq!(e.session_sub(), Some(Sub::Menu));
    }

    #[test]
    fn out_of_range_and_unknown_keys_are_rebuffed() {
        let mut e = start(b"\rone", 0);
        let shown = e.line("R9");
        assert!(shown.contains("no line with that number"), "{shown:?}");
        let shown = e.line("Z");
        assert!(shown.contains("\"Z\" is not one of the commands."), "{shown:?}");
        assert!(shown.contains("EDITOR COMMANDS:"), "{shown:?}");
        let shown = e.line("H");
        assert!(shown.contains("Help is available"), "{shown:?}");
        let shown = e.line("D");
        assert!(shown.contains("removes one line from the message"), "{shown:?}");
    }

    #[test]
    fn clear_text_flag_starts_in_text_entry_and_new_clears() {
        let mut e = start(b"\rold", ED_CLRTXT as u16);
        assert_eq!(e.text(), "", "ED_CLRTXT emptied the buffer");
        assert_eq!(e.session_sub(), Some(Sub::EntTxt));
        e.line("fresh");
        e.line("OK");
        e.line("N");
        assert_eq!(e.session_sub(), Some(Sub::Cusurb));
        e.line("C");
        assert_eq!(e.text(), "");
        assert_eq!(e.session_sub(), Some(Sub::EntTxt));
    }

    #[test]
    fn a_topic_buffer_is_asked_for_and_editable() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        let buf = f.buffer(128);
        let topic = f.buffer(40);
        let marker = f.buffer(2);
        let whndun = whndun_recording(&mut f, 0x600, marker);
        let _ = f.host.gsbl_mut().drain_output(chan);
        f.invoke(
            fse_bgnedt,
            &[128, buf.offset, buf.selector, 40, topic.offset, topic.selector, whndun.offset, whndun.selector, ED_CLRTXT as u16],
        )
        .expect("bgnedt");
        let shown = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(shown.contains("Topic for this message (up to 39 characters): "), "{shown:?}");

        f.host.gsbl_mut().push_input(chan, b"Weather\r");
        f.host.poll(&mut f.machine, &module).expect("poll");
        assert_eq!(f.read(topic), "Weather");
        let shown = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(shown.contains("Type your message, up to 127 characters."), "{shown:?}");

        f.host.gsbl_mut().push_input(chan, b"OK\r");
        f.host.poll(&mut f.machine, &module).expect("poll");
        let shown = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(shown.contains("T\x1b[33m)opic change"), "the topic menu: {shown:?}");
    }

    #[test]
    fn x_at_the_first_topic_question_aborts() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        let buf = f.buffer(128);
        let topic = f.buffer(40);
        let marker = f.buffer(2);
        f.machine.write(marker, &[0xEE, 0xEE]).expect("marker");
        let whndun = whndun_recording(&mut f, 0x600, marker);
        f.invoke(
            fse_bgnedt,
            &[128, buf.offset, buf.selector, 40, topic.offset, topic.selector, whndun.offset, whndun.selector, ED_CLRTXT as u16],
        )
        .expect("bgnedt");
        f.host.gsbl_mut().push_input(chan, b"x\r");
        f.host.poll(&mut f.machine, &module).expect("poll");
        let bytes = f.machine.resolve(marker, 2).expect("marker");
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), ED_QUITEX);
    }

    #[test]
    fn a_buffer_with_no_room_refuses_more_text() {
        let mut e = start(b"\rabc", 0);
        // 256 bytes: fill to within three of the end.
        let mut long = e.f.machine.resolve(e.buf, 256).expect("buffer").to_vec();
        let fill = b"\r".iter().chain(std::iter::repeat_n(&b'y', 247)).copied().collect::<Vec<_>>();
        long[4..4 + fill.len()].copy_from_slice(&fill);
        e.f.machine.write(e.buf, &long).expect("write");
        let shown = e.line("A");
        assert!(shown.contains("no more text will fit"), "{shown:?}");
        assert_eq!(e.session_sub(), Some(Sub::Menu));
    }

    #[test]
    fn the_editor_state_with_no_session_is_refused_not_faulted() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &Connection::ansi("dan"))
            .expect("connected");
        let state = f.host.editor_state.expect("registered") as u16;
        f.host.users.set_state_mem(f.machine.mem_mut(), chan, state).expect("state");
        f.host.gsbl_mut().push_input(chan, b"L\r");
        let err = f.host.poll(&mut f.machine, &module);
        assert!(
            matches!(err, Ok(Some(Outcome::Stopped(_)))),
            "a channel in the editor's state without a session is a host bug, reported: {err:?}"
        );
    }

    #[test]
    fn hanging_up_drops_the_session() {
        let mut e = start(b"\rone", 0);
        assert!(e.f.host.editor_sessions[e.chan.index()].is_some());
        e.f.host.rstchn(&mut e.f.machine, e.chan).expect("reset");
        assert!(e.f.host.editor_sessions[e.chan.index()].is_none());
    }

    #[test]
    fn wg16_bgnedt_global_holds_the_reserved_vector() {
        let f = Fixture::new();
        let at = f.host.globals().pointer_mem(f.machine.mem(), "bgnedt").expect("bgnedt");
        let (index, _) = f
            .host
            .vectors
            .iter()
            .find(|(_, site)| site.symbol == mbbs_machine::module::Symbol::Name(VECTOR.to_owned()))
            .expect("the bgnedt vector is recorded")
            .clone();
        assert_eq!(at, f.machine.thunk_address(index), "the global names the host's own thunk");
        assert_ne!(at, FarPtr { offset: 0, selector: 0 }, "no longer a null call");
    }
}
