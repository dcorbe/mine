//! Putting a changed value back without disturbing anything else.
//!
//! The hazard this file exists for: `stgopt(N)` indexes messages by position.
//! A rewrite that changes the message count shifts every message after it, and
//! nothing errors -- not at read time, not at write time, not at use time. So
//! every rewrite ends by re-reading its own output and proving it did not.

use crate::spec::{OptionType, SpecError, SpecFile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// The rewritten file no longer parses.
    Reparse(SpecError),
    /// The rewrite changed how many messages the file holds.
    CountChanged { was: usize, now: usize },
    /// A message nobody edited came back different.
    UneditedMessageChanged { index: usize },
    /// An edit named an option that does not exist.
    NoSuchOption { at: usize },
    /// The module `prf`s this text against a fixed argument list. Changing the
    /// conversions makes it read the wrong stack slot.
    SpecifiersChanged { was: Vec<Vec<u8>>, now: Vec<Vec<u8>> },
}

/// Splice new values into a file's bytes.
///
/// Edits are applied back to front so that an earlier edit never invalidates a
/// later span.
pub fn rewrite(file: &SpecFile, edits: &[(usize, Vec<u8>)]) -> Result<Vec<u8>, WriteError> {
    let mut ordered: Vec<&(usize, Vec<u8>)> = edits.iter().collect();
    ordered.sort_by_key(|(at, _)| std::cmp::Reverse(*at));

    let mut out = file.source().to_vec();
    for (at, value) in &ordered {
        let opt = file
            .options()
            .get(*at)
            .ok_or(WriteError::NoSuchOption { at: *at })?;
        out.splice(opt.value.start..opt.value.end, escape(value));
    }

    verify(file, &out, &ordered.iter().map(|(at, _)| *at).collect::<Vec<_>>())?;
    Ok(out)
}

/// Encode a plain value for storage in a `.MSG`.
///
/// The inverse of `msg.rs`'s decoder: `~` becomes `~~`, `}` becomes `~}`. Order
/// matters -- tildes first, or the tilde introduced by an escaped brace would
/// itself be escaped. Without this, an unescaped `}` in an edited value closes
/// the option early and shifts every message after it.
#[must_use]
pub fn escape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        match b {
            b'~' => out.extend_from_slice(b"~~"),
            b'}' => out.extend_from_slice(b"~}"),
            other => out.push(other),
        }
    }
    out
}

/// Prove the rewrite changed only what it meant to.
fn verify(before: &SpecFile, after: &[u8], edited: &[usize]) -> Result<(), WriteError> {
    let reparsed = SpecFile::parse(before.name(), after).map_err(WriteError::Reparse)?;

    let was = before.messages().len();
    let now = reparsed.messages().len();
    if was != now {
        return Err(WriteError::CountChanged { was, now });
    }

    let touched: Vec<usize> = edited
        .iter()
        .filter_map(|at| before.options().get(*at).map(|o| o.index))
        .collect();

    for n in 0..was {
        if touched.contains(&n) {
            continue;
        }
        if before.messages().get(n) != reparsed.messages().get(n) {
            return Err(WriteError::UneditedMessageChanged { index: n });
        }
    }
    Ok(())
}

/// Every printf conversion in `text`, in order.
///
/// `%%` is an escaped percent, not a conversion.
#[must_use]
pub fn specifiers(text: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text[i] != b'%' {
            i += 1;
            continue;
        }
        if text.get(i + 1) == Some(&b'%') {
            i += 2;
            continue;
        }
        let start = i;
        i += 1;
        while i < text.len() && !text[i].is_ascii_alphabetic() {
            i += 1;
        }
        if i < text.len() {
            i += 1;
            out.push(text[start..i].to_vec());
        }
    }
    out
}

/// Can this value replace that one?
///
/// For `T`, an edit is refused if it drops or reorders a `printf` conversion,
/// because that is checked here rather than at save time: a sysop who learns
/// at save time has already lost the edit. No other type is checked -- a
/// string option's value is not a format string.
pub fn check_edit(kind: &OptionType, old: &[u8], new: &[u8]) -> Result<(), WriteError> {
    if *kind != OptionType::Text {
        return Ok(());
    }

    let was = specifiers(old);
    let now = specifiers(new);
    if was != now {
        return Err(WriteError::SpecifiersChanged { was, now });
    }
    Ok(())
}
