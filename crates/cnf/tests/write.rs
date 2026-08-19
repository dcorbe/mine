use cnf::spec::{OptionType, SpecFile};
use cnf::write::{check_edit, escape, rewrite, specifiers, WriteError};

const SAMPLE: &[u8] = b"LEVEL0 {}\r\n\
\r\n\
 A comment that must survive.\r\n\
\r\n\
GAMCRD {Credits per minute 60} N 0 32767\r\n\
\r\n\
ACTIVATE {DEMO} S 30 Enter your activation code\r\n";

#[test]
fn no_edits_reproduces_the_file_byte_for_byte() {
    let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
    assert_eq!(rewrite(&f, &[]).expect("rewrite"), SAMPLE);
}

#[test]
fn an_edit_changes_only_the_value_bytes() {
    let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
    let out = rewrite(&f, &[(1, b"LIVE".to_vec())]).expect("rewrite");
    assert_eq!(
        out,
        b"LEVEL0 {}\r\n\
\r\n\
 A comment that must survive.\r\n\
\r\n\
GAMCRD {Credits per minute 60} N 0 32767\r\n\
\r\n\
ACTIVATE {LIVE} S 30 Enter your activation code\r\n"
            .to_vec()
    );
}

#[test]
fn two_edits_at_once_do_not_disturb_each_others_spans() {
    let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
    let out = rewrite(
        &f,
        &[(0, b"Credits per minute 999".to_vec()), (1, b"X".to_vec())],
    )
    .expect("rewrite");
    let back = SpecFile::parse("T.MSG", &out).expect("reparses");
    assert_eq!(
        &out[back.options()[0].value.start..back.options()[0].value.end],
        b"Credits per minute 999"
    );
    assert_eq!(
        &out[back.options()[1].value.start..back.options()[1].value.end],
        b"X"
    );
}

#[test]
fn a_value_containing_a_brace_is_escaped_not_refused() {
    // A raw `}` would close the option early and shift every message after it.
    // The fix is to encode it, not to forbid it -- a sysop may legitimately want
    // a brace in their text.
    let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
    let out = rewrite(&f, &[(1, b"a } and a ~ too".to_vec())]).expect("rewrite");
    let back = SpecFile::parse("T.MSG", &out).expect("reparses");
    assert_eq!(
        back.messages().len(),
        f.messages().len(),
        "the message count must not move"
    );
    assert_eq!(
        back.messages().get(back.options()[1].index).unwrap(),
        b"a } and a ~ too",
        "and the value must read back as it was typed"
    );
}

#[test]
fn escaping_is_the_inverse_of_the_readers_decoding() {
    // Round-trip every awkward case through a real parse.
    for raw in [&b"plain"[..], b"a~b}", b"}}}", b"~~~", b"} at line start"] {
        let src = [b"OPT {".as_slice(), &escape(raw), b"} S 40 p\r\n"].concat();
        let f = SpecFile::parse("T.MSG", &src).expect("parses");
        assert_eq!(f.options().len(), 1, "escaped value {raw:?} broke the parse");
        assert_eq!(f.messages().get(0).unwrap(), raw, "round trip failed for {raw:?}");
    }
}

#[test]
fn duplicate_edit_indices_are_refused() {
    // Two edits at the SAME option index -- not something a well-behaved
    // caller does, but a first draft of `rewrite`'s type signature did not
    // forbid it. Reviewer-found shape: the first edit's escaped value is
    // LONGER than the option's original span, so the second edit's stale
    // (pre-splice) coordinates land entirely INSIDE what the first edit just
    // inserted. No brace crosses a boundary, the message count does not
    // move, and the corrupted index is "touched" -- so a `verify` that only
    // checked count and untouched messages would return `Ok` with an option
    // holding neither of the two requested values. There is no well-defined
    // "the" requested value for a duplicate index, so `rewrite` refuses it
    // up front, before any splicing happens at all.
    let src = b"OPT {01} S 2 p\r\n";
    let f = SpecFile::parse("T.MSG", src).expect("parses");
    let out = rewrite(&f, &[(0, b"ABCDEFGHIJ".to_vec()), (0, b"Z".to_vec())]);
    assert_eq!(
        out,
        Err(WriteError::DuplicateEdit { at: 0 }),
        "two edits naming the same option index must be refused, not silently blended"
    );
}

#[test]
fn an_edit_containing_a_raw_cr_comes_back_without_it() {
    // Organic evidence for EditedMessageWrong: no mutation and no duplicate
    // index needed, just a value a real caller could plausibly submit. A
    // literal `\r` is not one of the two bytes `escape` treats specially --
    // it isn't supposed to be, since `msg.rs`'s decoder drops every `\r`
    // inside a value unconditionally, by the format's own rules, not by any
    // bug here. So a value containing `\r\n` (as a naive caller relaying a
    // CRLF text box would) is spliced in unchanged by `escape`, and comes
    // back out of a reparse with the `\r` gone -- a real, reachable case
    // where an edited message does not equal what was asked for, entirely
    // apart from anything `escape` or `verify` got wrong.
    let f = SpecFile::parse("T.MSG", SAMPLE).expect("parses");
    let wanted = b"line1\r\nline2".to_vec();
    let out = rewrite(&f, &[(1, wanted.clone())]);
    assert_eq!(
        out,
        Err(WriteError::EditedMessageWrong {
            index: 2,
            wanted,
            got: b"line1\nline2".to_vec(),
        }),
        "a raw CR the format silently drops must be caught, not written and forgotten"
    );
}

#[test]
fn specifiers_are_extracted_in_order_and_doubled_percent_is_not_one() {
    assert_eq!(
        specifiers(b"Hello %s, you have %d left. 100%% done."),
        vec![b"%s".to_vec(), b"%d".to_vec()]
    );
    assert!(specifiers(b"no specifiers here").is_empty());
}

#[test]
fn a_text_edit_that_drops_a_specifier_is_refused() {
    let old = b"AFK v%s. Type %s ? for help.";
    let new = b"AFK. Type %s ? for help.";
    assert!(matches!(
        check_edit(&OptionType::Text, old, new),
        Err(WriteError::SpecifiersChanged { .. })
    ));
}

#[test]
fn a_text_edit_that_reorders_specifiers_is_refused() {
    let old = b"%s has %d coins";
    let new = b"%d coins belong to %s";
    assert!(matches!(
        check_edit(&OptionType::Text, old, new),
        Err(WriteError::SpecifiersChanged { .. })
    ));
}

#[test]
fn a_text_edit_that_keeps_the_specifiers_is_allowed() {
    let old = b"%s has %d coins";
    let new = b"The mighty %s is carrying %d gold pieces";
    assert!(check_edit(&OptionType::Text, old, new).is_ok());
}

#[test]
fn a_brace_anywhere_is_accepted_because_the_writer_escapes_it() {
    // Both of these were refused by an earlier draft. Both are representable.
    let old = b"line one";
    assert!(check_edit(&OptionType::Text, old, b"a } mid-line brace").is_ok());
    assert!(check_edit(&OptionType::Text, old, b"line one\r\n} at a line start").is_ok());
}

#[test]
fn specifier_checking_does_not_apply_to_scalar_types() {
    // A string option's value is not a format string.
    assert!(check_edit(&OptionType::Char, b"%s", b"x").is_ok());
}
