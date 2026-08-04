//! Message files: reading a module's `.MSG` and numbering what is in it.
//!
//! A MajorBBS module keeps its configuration options and its user-visible text
//! in `.MSG` files named by its `.MDF`. The real host compiled those into `.MCV`
//! at install time and read the compiled form at runtime; a module never sees
//! either, because `opnmsg` hands back a `FILE *` it only passes to `setmbk` and
//! `clsmsg`. So the on-disk format is entirely the host's business, and reading
//! the `.MSG` directly is one format where implementing both would be two.
//!
//! # The grammar is measured, not inferred
//!
//! `MSGRDR.H` documents the shape -- `<comments> NAME {value} [type] [args]`,
//! `OPTLEN` 8, `{` and `}` around the value -- but **no `MSGRDR.C` or `MSGUTL.C`
//! survives in the recovered archive**, so the header alone does not settle what
//! `rdmsg()` counted or what it did with line endings.
//!
//! What settles it is that ten `.MSG`/`.MCV` pairs *do* survive, and a `.MCV`
//! carries every compiled message in order. `crates/mbbs/tests/msgfile.rs` runs
//! this reader against all of them: **10,569 messages, byte for byte**. Every
//! rule below is one that measurement forced.
//!
//! # The load-bearing invariant is ordering
//!
//! `stgopt(N)` indexes by *position*. `N` is a compile-time constant the module
//! was built with, matching the Nth option in the file. Anything that miscounts
//! what an option is shifts every message after it, and the module then reads
//! the neighbouring string with no error anywhere -- not at read time, not at
//! use time, not ever. That is why the cross-check exists and why it compares
//! text rather than counts.
//!
//! `LANGUAGE` is where that bites. It looks exactly like an option and is not
//! one: it declares the file's language and is not numbered. Every recovered
//! pair whose file has a `LANGUAGE` line is off by exactly one without this
//! rule, and MajorMUD's three files have no `LANGUAGE` line at all -- so a
//! reader tested only against MajorMUD would pass, ship, and be wrong about
//! every other module.

use std::fmt;
use std::io;

use mbbs16::{FarPtr, Machine};

use crate::arena::Arena;

/// One `.MSG` file, as a numbered list of messages.
///
/// Message *text* only. The type letter and its arguments -- `S 30 <prompt>`,
/// `N 0 32767` -- describe the option to the sysop's configuration editor and
/// are not part of what any of `stgopt`, `numopt`, `ynopt`, `chropt` or `tokopt`
/// return; each of those parses the value it needs out of the text. Keeping the
/// spec would mean keeping a second, unused answer to the same question.
#[derive(Debug)]
pub struct MsgFile {
    messages: Vec<Vec<u8>>,
}

/// Why a `.MSG` file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsgError {
    /// A `{` where an option name was expected.
    ///
    /// The reader understands one construct, and this is not it. The known
    /// candidate is an alternate-language block: `MSGRDR.H` declares
    /// `scanalt()`, `MAXLANG` is 100, and no recovered file uses either -- so
    /// there is nothing to test a parser for it against, and a parser written
    /// blind would be worse than a refusal.
    ///
    /// Refusing is safe to do because it is measured: across all 91 recovered
    /// `.MSG` files, a `{` never once appears where a name should. So this
    /// fires on a file none of them resembles, and on nothing else.
    Unexpected { file: String, offset: usize },
}

impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unexpected { file, offset } => write!(
                f,
                "{file} has a '{{' at byte {offset} where an option name should be; \
                 this reader handles one language and does not know what that is"
            ),
        }
    }
}

impl std::error::Error for MsgError {}

/// The option name that declares the file's language rather than a message.
const LANGUAGE: &[u8] = b"LANGUAGE";

/// Where the reader is in an option.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Comment prose, between one option and the next name.
    PreName,
    /// Inside an option's name.
    Name,
    /// Past the name, before the `{`.
    PostName,
    /// Inside `{...}`.
    Value,
    /// Past the `}`, in the type letter and its arguments.
    PostValue,
}

/// Characters an option name is made of.
///
/// Digits and *upper-case* letters, and nothing else -- not underscore and not
/// lower case. Narrow enough that comment prose does not start an option by
/// accident, which is what makes `PreName` able to skip freely.
fn is_name(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase()
}

impl MsgFile {
    /// Read a `.MSG` file.
    ///
    /// `name` is only for error messages.
    ///
    /// # Errors
    ///
    /// If the file contains a construct this reader does not handle. See
    /// [`MsgError::Unexpected`].
    pub fn parse(name: &str, bytes: &[u8]) -> Result<Self, MsgError> {
        let mut messages = Vec::new();
        let mut state = State::PreName;
        let mut option = Vec::new();
        let mut value = Vec::new();

        // The byte *as the reader consumed it*, which is not always the byte in
        // the file: a dropped one leaves zero behind. That matters, because it
        // is what stops `~~~` from escaping twice and what keeps a `\r` from
        // standing in for a `~` before a closing brace.
        let mut previous = 0u8;

        for (offset, &byte) in bytes.iter().enumerate() {
            let mut consumed = byte;
            match state {
                State::PreName => {
                    if byte == b'{' {
                        return Err(MsgError::Unexpected {
                            file: name.to_owned(),
                            offset,
                        });
                    }
                    if is_name(byte) {
                        state = State::Name;
                        option.push(byte);
                    }
                }
                State::Name => {
                    if is_name(byte) {
                        option.push(byte);
                    } else if byte == b'{' {
                        // No space between the name and its value.
                        state = State::Value;
                    } else {
                        state = State::PostName;
                    }
                }
                State::PostName => {
                    if byte == b'{' {
                        state = State::Value;
                    } else if is_name(byte) {
                        // What looked like a name was prose. Whatever starts
                        // here is the real candidate.
                        state = State::Name;
                        option.clear();
                        option.push(byte);
                    }
                }
                State::Value => match byte {
                    b'}' if previous == b'~' => {
                        // `~}` is a literal brace, and the tilde is not part of
                        // the text.
                        value.pop();
                        value.push(b'}');
                        consumed = 0;
                    }
                    b'}' => {
                        // Compared exactly, not case-insensitively: `is_name`
                        // admits no lower case, so a name can only ever be
                        // upper case and a tolerant compare would be a
                        // reassurance about something that cannot happen.
                        if option != LANGUAGE {
                            messages.push(line_endings(&value));
                        }
                        option.clear();
                        value.clear();
                        state = State::PostValue;
                        consumed = 0;
                    }
                    // `~~` is a literal tilde: the first is kept, the second is
                    // what marked it as literal.
                    b'~' if previous == b'~' => consumed = 0,
                    // A `.MSG` is a CRLF text file, and a message's own line
                    // breaks are decided below rather than by what the file
                    // happens to hold.
                    b'\r' => consumed = 0,
                    _ => value.push(byte),
                },
                State::PostValue => {
                    if byte == b'\n' {
                        state = State::PreName;
                    }
                }
            }
            previous = consumed;
        }

        Ok(Self { messages })
    }

    /// The message numbered `n`, or `None` past the end of the file.
    pub fn get(&self, n: usize) -> Option<&[u8]> {
        self.messages.get(n).map(Vec::as_slice)
    }

    /// How many messages the file has.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the file has no messages at all.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Every message, in order.
    pub fn messages(&self) -> &[Vec<u8>] {
        &self.messages
    }
}

/// Decide a message's line breaks.
///
/// A `.MSG` file is CRLF and a compiled message is neither: the carriage
/// returns are dropped on the way in, and each surviving `\n` becomes **`\r`
/// when the next character cannot continue a sentence** and stays `\n`
/// otherwise. So a hard break between paragraphs is a `\r` and a soft wrap
/// inside one is a `\n`, and the last line of a message always ends `\r`.
///
/// That rule reads like a guess and is not: it is what the real compiler did.
/// The ten recovered `.MCV` files hold 3,601 bare `\r` and 3,324 bare `\n`
/// between them -- and only 38 `\r\n`, which is a blank line inside a value and
/// not a line ending the file was written with. This reproduces all of them
/// exactly. The set of continuing characters -- alphanumeric, `%`, `(`, `"` --
/// is the part no header explains; it comes from MBBSEmu's reading of the same
/// evidence, and the cross-check is what makes it a measurement here rather
/// than a borrowing.
fn line_endings(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for (i, &byte) in value.iter().enumerate() {
        if byte == b'\n' {
            let next = value.get(i + 1).copied().unwrap_or(0);
            if !next.is_ascii_alphanumeric() && !matches!(next, b'%' | b'(' | b'"') {
                out.push(b'\r');
                continue;
            }
        }
        out.push(byte);
    }
    out
}

/// The value an option carries, out of the message text.
///
/// Two shapes are in the files, and one rule reads both. An `S` option is the
/// bare value -- `ACTIVATE {DEMO}` -- while `N`, `B`, `E` and some `C` options
/// put the sysop's prompt in front of it: `GAMCRD {Credits per minute consumed
/// while in the game 60}`, `PROFCHEK {Profanity checking? NO}`. **The value is
/// the last whitespace-delimited token**, which is the bare value when there is
/// no prompt and the value when there is.
///
/// Measured across the 91 recovered `.MSG` files: all 1,408 `N` options have a
/// numeric last token, all 267 `B` options end in `YES` or `NO`, and the `C`
/// options this has to survive include `TLCCHR { =}` and `ANSCHR { \}`, whose
/// values are a leading space and one character.
///
/// [`MsgFile::get`] is what `stgopt` returns, and it is deliberately *not* this:
/// a string option is its whole text.
pub fn value(message: &[u8]) -> &[u8] {
    match message.iter().rposition(|b| b.is_ascii_whitespace()) {
        Some(at) => &message[at + 1..],
        None => message,
    }
}

/// Bytes of `struct msgblk`, as `MSGUTL.H` declares it: five far pointers, an
/// `int`, three `long`s and two more `int`s.
const MSGBLK: usize = 5 * 4 + 2 + 3 * 4 + 2 + 2;

/// One open message file.
struct Block {
    /// What it was opened as, for error messages.
    name: String,

    /// The `msgblk`-shaped region the module was handed, which is also this
    /// block's identity: `setmbk` and `clsmsg` name it and nothing else does.
    cookie: FarPtr,

    /// Where each message's text was interned, by message number.
    text: Vec<FarPtr>,
}

/// Every message file the host has open, and which one is current.
///
/// The current block is **not** here. It is `curmbk`, a host global living in
/// module memory (`GCOMM.H:282`), and it is read back from there every time --
/// the same rule `prfptr` is under, and for the same reason. What is here is
/// the stack of blocks to restore, which the module cannot see and has no way
/// to change.
#[derive(Default)]
pub struct Messages {
    arena: Arena,
    open: Vec<Block>,

    /// What `curmbk` held before each unmatched `setmbk`, oldest first.
    saved: Vec<FarPtr>,
}

impl Messages {
    /// Open a message file, and give the module something to name it by.
    ///
    /// The cookie is backed by a real, zeroed, `msgblk`-shaped region rather
    /// than an invented number. `MSGUTL.H` says the struct is used "for some
    /// special purposes by the application program", so a module that reads a
    /// field gets zeros instead of a fault. The two fields the host actually
    /// knows -- how many languages and how many messages -- are filled in,
    /// because writing zero where the truth is free is the habit this crate
    /// exists to avoid.
    ///
    /// # Errors
    ///
    /// If the arena cannot be extended.
    pub fn open(
        &mut self,
        machine: &mut Machine,
        name: &str,
        file: &MsgFile,
    ) -> io::Result<FarPtr> {
        let mut text = Vec::with_capacity(file.len());
        for message in file.messages() {
            text.push(self.arena.intern(machine, message)?);
        }

        let cookie = self.arena.reserve(machine, MSGBLK)?;
        let count = u16::try_from(file.len()).map_err(|_| {
            io::Error::other(format!("{name} has {} messages, which is more \
                than a 16-bit msgcnt holds", file.len()))
        })?;

        // `lngcnt` and `msgcnt` are the last two `int`s of the struct.
        let tail = FarPtr {
            offset: cookie.offset + (MSGBLK - 4) as u16,
            selector: cookie.selector,
        };
        let mut fields = 1u16.to_le_bytes().to_vec();
        fields.extend_from_slice(&count.to_le_bytes());
        machine.write(tail, &fields).map_err(io::Error::other)?;

        self.open.push(Block {
            name: name.to_owned(),
            cookie,
            text,
        });
        Ok(cookie)
    }

    /// Close a block.
    ///
    /// The text stays interned -- see [`Arena`] -- so this only forgets the
    /// block, which is what makes a later use of the cookie a refusal.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open block, or names one that is still set: closing
    /// the current block would leave `curmbk` pointing at something the host
    /// has forgotten, and every option read after it would be a refusal naming
    /// the wrong thing.
    pub fn close(&mut self, current: FarPtr, cookie: FarPtr) -> Result<(), String> {
        let at = self.find(cookie)?;
        if cookie == current || self.saved.contains(&cookie) {
            return Err(format!(
                "{} is the current message block, or is waiting under one",
                self.open[at].name
            ));
        }
        self.open.remove(at);
        Ok(())
    }

    /// Remember what was current, so `rstmbk` can put it back.
    pub fn push(&mut self, previous: FarPtr) {
        self.saved.push(previous);
    }

    /// What was current before the last unmatched `setmbk`.
    ///
    /// # Errors
    ///
    /// If nothing was saved. The alternative is guessing at a value for
    /// `curmbk`, and every option read afterwards would come from whichever
    /// block that guess named.
    pub fn pop(&mut self) -> Result<FarPtr, String> {
        self.saved
            .pop()
            .ok_or_else(|| "rstmbk with no setmbk to undo".to_owned())
    }

    /// Where message `n` of the block named by `cookie` was interned.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open block, or the block has no message `n`.
    pub fn text(&self, cookie: FarPtr, n: u16) -> Result<FarPtr, String> {
        let block = &self.open[self.find(cookie)?];
        block.text.get(usize::from(n)).copied().ok_or_else(|| {
            format!(
                "message {n} of {}, which has {}",
                block.name,
                block.text.len()
            )
        })
    }

    /// What a block was opened as.
    ///
    /// # Errors
    ///
    /// If `cookie` names no open block.
    pub fn name(&self, cookie: FarPtr) -> Result<&str, String> {
        Ok(&self.open[self.find(cookie)?].name)
    }

    /// How many message files are open.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no message file is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    fn find(&self, cookie: FarPtr) -> Result<usize, String> {
        self.open
            .iter()
            .position(|b| b.cookie == cookie)
            .ok_or_else(|| format!("{cookie:?} is not an open message block"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> MsgFile {
        MsgFile::parse("test.MSG", text.as_bytes()).expect("parses")
    }

    fn texts(file: &MsgFile) -> Vec<String> {
        file.messages()
            .iter()
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    #[test]
    fn an_option_is_a_name_a_value_and_a_spec() {
        let file = parse("ACTIVATE {DEMO} S 30 Enter your activation code\r\n");
        assert_eq!(texts(&file), ["DEMO"]);
    }

    #[test]
    fn comments_between_options_do_not_shift_the_numbering() {
        // The numbering is by position among options, and prose is not an
        // option however much of it there is. A reader that counted lines, or
        // that let a capitalised word in a comment start something, would put
        // every message after this one at the wrong number -- silently.
        let file = parse(concat!(
            "FIRST {one} S 8\r\n",
            "\r\n",
            " This is a comment. It has CAPITALS in it, and a name-shaped\r\n",
            " word like ACTIVATE, and even a colon: none of that is an option.\r\n",
            "\r\n",
            "SECOND {two} S 8\r\n",
        ));
        assert_eq!(texts(&file), ["one", "two"]);
        assert_eq!(file.get(1), Some(&b"two"[..]));
    }

    #[test]
    fn language_is_a_declaration_and_not_a_message() {
        // Measured, not assumed: `TSGARN-C.MCV` has 78 messages where its
        // `.MSG` has 79 things that look like options, and the first compiled
        // message is `LEVEL3`'s empty value rather than `English/ANSI`.
        let file = parse(concat!(
            "LANGUAGE {English/ANSI}\r\n",
            "LEVEL3 {}\r\n",
            "FULKEY {LIVE} S 8\r\n",
        ));
        assert_eq!(texts(&file), ["", "LIVE"]);
    }

    #[test]
    fn a_lower_case_name_is_not_a_name_at_all() {
        // `is_name` admits no lower case, so `Language` is the one-letter name
        // `L` followed by prose -- and `L` is not the declaration, so its value
        // is a message like any other. Not a nicety: the same rule is what
        // stops a capitalised word in a comment from starting an option, and
        // relaxing it here would relax it there.
        let file = parse("Language {English/ANSI}\r\nA {x} S 2\r\n");
        assert_eq!(texts(&file), ["English/ANSI", "x"]);
    }

    #[test]
    fn a_value_may_span_lines() {
        let file = parse("USRLOGIN {\r\nWelcome to\r\nMajorMUD\r\n} T Login text\r\n");
        // The inner breaks are soft -- a letter follows each -- and the last is
        // hard, because nothing follows it.
        assert_eq!(texts(&file), ["\nWelcome to\nMajorMUD\r"]);
    }

    #[test]
    fn a_soft_wrap_stays_a_newline_and_a_paragraph_break_becomes_a_return() {
        let file = parse("T {one\r\ntwo\r\n\r\nthree} T\r\n");
        assert_eq!(texts(&file), ["one\ntwo\r\nthree"]);
    }

    #[test]
    fn a_tilde_escapes_a_closing_brace() {
        let file = parse("BRACE {a ~} b} S 8\r\n");
        assert_eq!(texts(&file), ["a } b"]);
    }

    #[test]
    fn two_tildes_are_one_tilde_and_do_not_escape_what_follows() {
        // `~~}` is a literal tilde and then a real closing brace. Getting this
        // wrong swallows the rest of the file into one message.
        let file = parse("TILDE {a ~~} S 8\r\nNEXT {b} S 8\r\n");
        assert_eq!(texts(&file), ["a ~", "b"]);
    }

    #[test]
    fn a_name_that_turns_out_to_be_prose_does_not_become_the_option() {
        // `PLEASE` is followed by prose rather than a value, so the option is
        // whichever name actually reaches a `{`.
        let file = parse("PLEASE read this REAL {value} S 8\r\n");
        assert_eq!(texts(&file), ["value"]);
    }

    #[test]
    fn a_brace_where_a_name_belongs_is_refused_by_name() {
        let err = MsgFile::parse("WCCTEXT.MSG", b"A {x} S 2\r\n{alternate}\r\n")
            .expect_err("an alternate-language block is not understood");
        let MsgError::Unexpected { file, offset } = &err;
        assert_eq!(file, "WCCTEXT.MSG");
        assert_eq!(*offset, 11);
        assert!(err.to_string().contains("WCCTEXT.MSG"), "{err}");
    }

    #[test]
    fn an_empty_file_has_no_messages() {
        let file = parse("");
        assert!(file.is_empty());
        assert_eq!(file.get(0), None);
    }

    #[test]
    fn a_value_is_the_last_token_whether_or_not_a_prompt_precedes_it() {
        // Both shapes are in MajorMUD's own file, and both of these are real
        // lines from it.
        assert_eq!(value(b"DEMO"), b"DEMO");
        assert_eq!(
            value(b"Credits per minute consumed while in the game 60"),
            b"60"
        );
        assert_eq!(value(b"Profanity checking? NO"), b"NO");
        assert_eq!(value(b"Level of punishment for hanging up? NONE"), b"NONE");
    }

    #[test]
    fn a_character_option_survives_the_space_in_front_of_it() {
        // `TLCCHR { =}` and `ANSCHR { \}` are real options from the archive:
        // the value is one character with a space before it, and a reader that
        // took the whole text would hand the module a space.
        assert_eq!(value(b" ="), b"=");
        assert_eq!(value(b" \\"), b"\\");
        assert_eq!(value(b"Optional menu character: N"), b"N");
        assert_eq!(value(b"."), b".");
    }

    #[test]
    fn a_value_that_is_only_whitespace_is_empty_rather_than_whitespace() {
        assert_eq!(value(b"   "), b"");
        assert_eq!(value(b""), b"");
    }
}
