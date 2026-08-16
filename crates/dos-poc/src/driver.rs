//! Who decides the next keystroke.
//!
//! The loop this closes: the guest paints, then blocks on `int 16h` with an
//! empty queue. That block is not a failure -- it is the program saying it has
//! finished drawing and is waiting. Handing the screen to a driver at exactly
//! that moment turns an open loop (fire a fixed key string, inspect the
//! wreckage) into a closed one.
//!
//! A script and a live terminal are the same shape, which is the point: the
//! second is what a door needs, and it costs nothing extra once the first
//! exists.

use crate::screen::Screen;

/// A keystroke as the BIOS reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    /// An ordinary character: `AL` is the byte, `AH` a scan code.
    Char(u8),
    /// An extended key: `AL` is zero and `AH` carries the scan code. Arrows,
    /// function keys, Home/End.
    Ext(u8),
}

impl Key {
    /// Parse a script's spelling of a key.
    pub fn parse(word: &str) -> Option<Key> {
        let key = match word.to_ascii_lowercase().as_str() {
            "enter" | "return" | "cr" => Key::Char(b'\r'),
            "esc" | "escape" => Key::Char(0x1b),
            "tab" => Key::Char(b'\t'),
            "space" => Key::Char(b' '),
            "backspace" | "bs" => Key::Char(0x08),
            "up" => Key::Ext(0x48),
            "down" => Key::Ext(0x50),
            "left" => Key::Ext(0x4b),
            "right" => Key::Ext(0x4d),
            "home" => Key::Ext(0x47),
            "end" => Key::Ext(0x4f),
            "pgup" => Key::Ext(0x49),
            "pgdn" => Key::Ext(0x51),
            "f1" => Key::Ext(0x3b),
            "f2" => Key::Ext(0x3c),
            "f3" => Key::Ext(0x3d),
            "f4" => Key::Ext(0x3e),
            "f5" => Key::Ext(0x3f),
            "f6" => Key::Ext(0x40),
            "f7" => Key::Ext(0x41),
            "f8" => Key::Ext(0x42),
            "f9" => Key::Ext(0x43),
            "f10" => Key::Ext(0x44),
            other => {
                let bytes = other.as_bytes();
                // A bare single character, or `char:X` to be unambiguous about
                // one that collides with a name above.
                if let Some(rest) = other.strip_prefix("char:") {
                    return rest.as_bytes().first().map(|b| Key::Char(*b));
                }
                if bytes.len() == 1 {
                    // Preserve the case the script actually wrote.
                    return word.as_bytes().first().map(|b| Key::Char(*b));
                }
                return None;
            }
        };
        Some(key)
    }
}

/// Asked for the next keystroke whenever the guest goes idle.
pub trait Driver {
    /// Return the next key, or `None` to stop the program.
    fn next_key(&mut self, screen: &Screen) -> Option<Key>;

    /// Why the driver stopped, for the report.
    fn ending(&self) -> String {
        "driver finished".to_string()
    }
}

/// One line of a script.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Require this text on screen before going on.
    Expect(String),
    /// Require this to be the highlighted row.
    ExpectSelected(String),
    /// Require the cursor to be sitting on this line.
    ExpectCursor(String),
    /// Press a key.
    Send(Key),
}

/// Replays a fixed sequence, checking the screen as it goes.
#[derive(Debug)]
pub struct Script {
    steps: Vec<Step>,
    at: usize,
    failure: Option<String>,
    /// Each `Send` consumes one idle moment; this bounds a script that keeps
    /// pressing keys at a program which never asks for another.
    presses: u32,
    max_presses: u32,
}

impl Script {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps,
            at: 0,
            failure: None,
            presses: 0,
            max_presses: 200,
        }
    }

    /// Parse a script: one directive per line, `#` comments.
    ///
    /// ```text
    /// expect Exit the program
    /// cursor Exit the program
    /// selected Configure Nodes
    /// send down
    /// send enter
    /// ```
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut steps = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (verb, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let rest = rest.trim();
            match verb.to_ascii_lowercase().as_str() {
                "expect" => steps.push(Step::Expect(rest.to_string())),
                "selected" => steps.push(Step::ExpectSelected(rest.to_string())),
                "cursor" => steps.push(Step::ExpectCursor(rest.to_string())),
                "send" => {
                    for word in rest.split_whitespace() {
                        let key = Key::parse(word)
                            .ok_or_else(|| format!("line {}: unknown key {word:?}", n + 1))?;
                        steps.push(Step::Send(key));
                    }
                }
                other => return Err(format!("line {}: unknown directive {other:?}", n + 1)),
            }
        }
        Ok(Self::new(steps))
    }

    pub fn finished(&self) -> bool {
        self.at >= self.steps.len()
    }
}

impl Driver for Script {
    fn next_key(&mut self, screen: &Screen) -> Option<Key> {
        // Work through checks until the next key to press, or a failure.
        while self.at < self.steps.len() {
            match &self.steps[self.at] {
                Step::Expect(text) => {
                    if !screen.contains(text) {
                        self.failure = Some(format!(
                            "expected {text:?} on screen, but it is not there"
                        ));
                        return None;
                    }
                    self.at += 1;
                }
                Step::ExpectSelected(text) => {
                    let selected = screen.selected();
                    if selected.as_deref().map(str::trim) != Some(text.trim()) {
                        self.failure = Some(format!(
                            "expected {text:?} to be selected, but it is {selected:?}"
                        ));
                        return None;
                    }
                    self.at += 1;
                }
                Step::ExpectCursor(text) => {
                    let line = screen.cursor_line();
                    if !line.contains(text.trim()) {
                        self.failure = Some(format!(
                            "expected the cursor on a line containing {text:?}, but it is on {line:?}"
                        ));
                        return None;
                    }
                    self.at += 1;
                }
                Step::Send(key) => {
                    let key = *key;
                    self.at += 1;
                    self.presses += 1;
                    if self.presses > self.max_presses {
                        self.failure = Some(format!(
                            "stopped after {} keystrokes without finishing",
                            self.max_presses
                        ));
                        return None;
                    }
                    return Some(key);
                }
            }
        }
        None
    }

    fn ending(&self) -> String {
        match &self.failure {
            Some(why) => format!("script failed: {why}"),
            None => format!("script completed all {} steps", self.steps.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_parses_names_and_bare_characters() {
        let s = Script::parse("send down enter A\n# a comment\nexpect Main Menu\n").unwrap();
        assert_eq!(
            s.steps,
            vec![
                Step::Send(Key::Ext(0x50)),
                Step::Send(Key::Char(b'\r')),
                Step::Send(Key::Char(b'A')),
                Step::Expect("Main Menu".into()),
            ]
        );
    }

    #[test]
    fn an_unknown_key_is_refused_at_parse_time_not_at_run_time() {
        let err = Script::parse("send wiggle").unwrap_err();
        assert!(err.contains("unknown key"), "{err}");
    }

    #[test]
    fn a_bare_character_keeps_the_case_the_script_wrote() {
        assert_eq!(Key::parse("A"), Some(Key::Char(b'A')));
        assert_eq!(Key::parse("a"), Some(Key::Char(b'a')));
        // `char:` disambiguates one that collides with a name.
        assert_eq!(Key::parse("char:f"), Some(Key::Char(b'f')));
        assert_eq!(Key::parse("f1"), Some(Key::Ext(0x3b)));
    }
}
