use cnf::spec::SpecFile;
use cnf::write::{escape, rewrite, WriteError};

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
fn an_edit_that_would_change_the_message_count_is_refused() {
    // Two edits at the SAME option index -- not something a well-behaved
    // caller does, but `rewrite`'s type signature does not forbid it, and
    // `verify` exists to catch a rewrite that "goes wrong some other way"
    // rather than just the escaping cases the tests above invent. The second
    // splice reuses the first edit's ORIGINAL (now-stale) span coordinates
    // against an already-mutated buffer, so it deletes bytes it should not:
    // the first option's own closing brace, and everything up to the next
    // unescaped `}` in the file -- which happens to be the SECOND option's.
    // The result still parses (both braces it needed are still balanced
    // elsewhere), but the two messages the file used to hold have become
    // one. This is refused, not silently written.
    let src = b"AAAA {0123456789} S 5 p\r\nBBBB {Z} S 1 q\r\n";
    let f = SpecFile::parse("T.MSG", src).expect("parses");
    assert_eq!(f.messages().len(), 2, "fixture sanity: two messages before the rewrite");
    let out = rewrite(&f, &[(0, b"Q".to_vec()), (0, Vec::new())]);
    assert_eq!(
        out,
        Err(WriteError::CountChanged { was: 2, now: 1 }),
        "a rewrite that merges two messages into one must be refused via the count check"
    );
}
