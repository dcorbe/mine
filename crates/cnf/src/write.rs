//! Putting a changed value back without disturbing anything else.
//!
//! The hazard this file exists for: `stgopt(N)` indexes messages by position.
//! A rewrite that changes the message count shifts every message after it, and
//! nothing errors -- not at read time, not at write time, not at use time. So
//! every rewrite ends by re-reading its own output and proving it did not.

use std::collections::HashSet;

use mbbs::mcv;
use mbbs::msg::MsgFile;

use crate::spec::{OptionType, SpecError, SpecFile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// The `.MSG` bytes did not parse -- either `recompile` was handed one
    /// that never parsed to begin with, or `rewrite` produced one that no
    /// longer does.
    Reparse(SpecError),
    /// The rewrite changed how many messages the file holds.
    ///
    /// As of this writing, only reachable by breaking the implementation
    /// itself (mutation testing `rewrite`'s edit ordering catches it -- see
    /// `crates/cnf/tests/write.rs`'s TDD evidence in the fix report), not by
    /// any request a caller can currently construct: `escape` never emits an
    /// unescaped `}` (see its own doc), so a spliced-in value cannot open or
    /// close a brace boundary it should not; a non-duplicate edit's splice
    /// cannot touch anything past its own span; and `DuplicateEdit` refuses
    /// the one shape that could reach past it. Kept for the same reason as
    /// `UneditedMessageChanged`: cheap insurance against a future regression
    /// in either of those guarantees, not a defence against anything
    /// reachable today.
    CountChanged { was: usize, now: usize },
    /// A message nobody edited came back different.
    ///
    /// Unreached by any test as of this writing, and -- as far as could be
    /// established -- unreachable through this module's public API. A single
    /// edit's splice is confined exactly to its own value span; `escape` is a
    /// position-independent inverse of `msg.rs`'s decoder (see its own doc),
    /// so replacing that span with any escaped content reproduces the same
    /// parser state on the far side of it, no matter what the content is;
    /// and the one vector that could make one edit's bytes bleed into
    /// another message -- two edits naming the same option index, applied
    /// with stale coordinates -- is refused outright by `DuplicateEdit`
    /// before this check ever runs. This variant is kept as cheap forward
    /// defence against a future regression in `escape` or in how spans are
    /// computed, not because anything today can trigger it. Deleting the
    /// loop that produces it leaves every test in this crate green.
    UneditedMessageChanged { index: usize },
    /// An edited message did not come back as the value that was requested.
    ///
    /// Distinct from `UneditedMessageChanged`: this is the check that an
    /// edit did what it was asked, not that everything else was left alone.
    /// Reachable with fully correct code and no duplicate edits -- see
    /// `crates/cnf/tests/write.rs`'s
    /// `an_edit_containing_a_raw_cr_comes_back_without_it` for a case where
    /// the format itself, not a bug, is why the value does not round-trip:
    /// `msg.rs`'s decoder drops every `\r` inside a value unconditionally,
    /// and `escape` has no reason to touch `\r` (it is not one of the two
    /// bytes the grammar treats specially).
    EditedMessageWrong { index: usize, wanted: Vec<u8>, got: Vec<u8> },
    /// An edit named an option that does not exist.
    NoSuchOption { at: usize },
    /// Two edits named the same option index.
    ///
    /// There is no well-defined "the" requested value when that happens, so
    /// it is refused outright rather than resolved by picking one
    /// arbitrarily -- or, worse, by whichever splice happens to run last
    /// against stale coordinates left over from the first. Applying two
    /// edits to the same span this way can silently blend both values (if
    /// the second splice's stale range lands inside what the first one
    /// inserted) or merge two messages into one (if it reaches past that and
    /// swallows a real closing brace); neither is refused for its own sake
    /// here -- it is refused because the request itself does not name a
    /// single answer.
    DuplicateEdit { at: usize },
    /// The module `prf`s this text against a fixed argument list. Changing the
    /// conversions makes it read the wrong stack slot.
    SpecifiersChanged { was: Vec<Vec<u8>>, now: Vec<Vec<u8>> },
}

/// Splice new values into a file's bytes.
///
/// Edits are applied back to front so that an earlier edit never invalidates a
/// later span.
///
/// # Errors
///
/// [`WriteError::DuplicateEdit`] if the same option index appears twice in
/// `edits`. See that variant's doc for why this is refused rather than
/// resolved.
pub fn rewrite(file: &SpecFile, edits: &[(usize, Vec<u8>)]) -> Result<Vec<u8>, WriteError> {
    let mut seen_indices = HashSet::new();
    for (at, _) in edits {
        if !seen_indices.insert(*at) {
            return Err(WriteError::DuplicateEdit { at: *at });
        }
    }

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

    verify(file, &out, edits)?;
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

/// Prove the rewrite changed only what it meant to: every message named in
/// `edits` came back as exactly the value that was requested, and every
/// message `edits` did not name came back byte-identical to `before`.
fn verify(before: &SpecFile, after: &[u8], edits: &[(usize, Vec<u8>)]) -> Result<(), WriteError> {
    let reparsed = SpecFile::parse(before.name(), after).map_err(WriteError::Reparse)?;

    let was = before.messages().len();
    let now = reparsed.messages().len();
    if was != now {
        return Err(WriteError::CountChanged { was, now });
    }

    let mut touched: Vec<usize> = Vec::new();
    for (at, wanted) in edits {
        // `rewrite` already validated every `at` against `file.options()`
        // before ever calling `verify` -- an invalid index would have
        // returned `NoSuchOption` and splicing would never have run.
        let opt = before
            .options()
            .get(*at)
            .expect("rewrite validated every edit index before splicing");
        touched.push(opt.index);
        // The count check above already proved `reparsed` has exactly as
        // many messages as `before`, and `opt.index < before.messages().len()`
        // is guaranteed by `scan` -- so this index exists in `reparsed` too.
        let got = reparsed
            .messages()
            .get(opt.index)
            .expect("the count check above already proved this index exists");
        if got != wanted.as_slice() {
            return Err(WriteError::EditedMessageWrong {
                index: opt.index,
                wanted: wanted.clone(),
                got: got.to_vec(),
            });
        }
    }

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

/// Compile a `.MSG`'s bytes to the `.MCV` the host reads.
///
/// Goes through `MsgFile` rather than the spec layer so the compiled form is
/// produced by exactly the reader the host uses. Two paths to a `.MCV` would
/// be two things to keep in step.
///
/// # Errors
///
/// [`WriteError::Reparse`] if `msg` does not parse as a `.MSG`.
pub fn recompile(msg: &[u8], name: &str) -> Result<Vec<u8>, WriteError> {
    let parsed = MsgFile::parse(name, msg).map_err(|e| WriteError::Reparse(SpecError::Message(e)))?;
    // `MsgFile::language`'s own doc: `None` is ordinary -- every archived
    // `.MCV` still records `English/ANSI` for a `.MSG` with no `LANGUAGE`
    // line, so an empty language here would be a silent divergence from what
    // the real compiler wrote, not merely an absent field.
    let language = parsed.language().unwrap_or(mcv::DEFAULT_LANGUAGE);
    Ok(mcv::compile(parsed.messages(), language))
}
