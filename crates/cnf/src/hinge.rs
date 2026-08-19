//! Conditional visibility: `(NAME=VAL,VAL)` / `(NAME#VAL)` / `(NAME*)`,
//! `MSGRDR.H:27-32`. 77 of the 186 corpus files use them.

/// A condition under which an option is shown. `MSGRDR.H:27-32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hinge {
    pub on: Vec<u8>,
    pub op: HingeOp,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HingeOp {
    Eq,
    Ne,
    ExcludeAlways,
}

/// Split a hinge off an option's tail.
///
/// Returns the hinge, if any, and the tail with the hinge text spliced out so
/// the type parser never sees it.
///
/// The corpus does not put the hinge in one fixed place: an `=`/`#` hinge is
/// always written *before* the type letter (`(NEEDAPPR=YES) S 18 prompt`),
/// while `*` (exclude-always) turns up on either side (`(UNUSED*) H 0 FFFF`
/// as well as `B (UNUSED*)`). A version of this function that only trimmed a
/// trailing suffix -- matching just the second, rarer shape -- silently threw
/// away the type letter and its arguments on every occurrence of the first,
/// dropping the option from the scan entirely rather than mis-parsing it.
/// That was caught by `tests/corpus.rs`, not by any hand-written fixture: the
/// hand-written cases all happened to put the hinge last. The two flanks
/// around the hinge are joined by plain concatenation rather than a fixed
/// separator -- the corpus always leaves the field-separating space attached
/// to whichever flank has it, so concatenation reproduces ordinary
/// whitespace-separated fields; `parse_tail`'s tokenizer also discards empty
/// fields, so an incidental doubled space from two adjoining flanks is
/// harmless.
///
/// A `(...)` is accepted as a hinge only when the name before `=`/`#`/`*` is
/// name-shaped -- the same digits-and-upper-case-letters grammar `scan` uses
/// for an option name (`spec::is_name`). Without that check, `WGSEDTM.MSG`'s
/// `FSENIM` option -- tail `T FSE Import Rebuff (Bad #)`, ordinary English
/// prose that happens to contain a `#` -- parses as a hinge on the option
/// `"Bad "`, which does not exist, silently attaching a spurious visibility
/// condition to a `T` option that has none. A `T`/`S`/`E` tail's free-text
/// portion is exactly where this collides: those types carry a
/// human-readable prompt or description after their own arguments, so a
/// hinge search that accepts anything shaped like `(...)`, anywhere in the
/// tail, cannot tell real grammar from prose. Rejecting a non-name-shaped
/// match falls through to "no hinge, tail unchanged" rather than misreading
/// prose as one.
///
/// This function takes the *leftmost* `(...)` in the tail as the hinge,
/// unconditionally -- it does not check whether a second, later `(...)`
/// exists. That is safe only because real hinges are never nested and a tail
/// never carries two: checked by replicating this exact algorithm over all
/// 186 corpus files and finding zero violations, including the ~250 tails
/// that have a trailing prose parenthetical (like `FSENIM`'s, rejected by the
/// name-shaped check above) in addition to a real hinge elsewhere on the
/// line. If a future file ever put a real hinge second -- prose parenthetical
/// first, hinge after -- this function would silently pick the prose instead
/// and either misread it as a bogus hinge (if it happened to be name-shaped)
/// or treat the option as hingeless (if not), exactly the class of bug this
/// module exists to avoid. `tests/corpus.rs`'s `every_distinct_msg_file_parses`
/// would not catch a wrong hinge choice on a name-shaped false match, since it
/// only checks that the file parses and counts totals, not visibility.
#[must_use]
pub fn parse(tail: &[u8]) -> (Option<Hinge>, Vec<u8>) {
    let Some(open) = tail.iter().position(|b| *b == b'(') else {
        return (None, tail.to_vec());
    };
    let Some(close_rel) = tail[open..].iter().position(|b| *b == b')') else {
        return (None, tail.to_vec());
    };
    let close = open + close_rel;
    let inner = &tail[open + 1..close];
    let is_hinge_name = |name: &[u8]| !name.is_empty() && name.iter().copied().all(crate::spec::is_name);

    let hinge = if let Some(name) = inner.strip_suffix(b"*") {
        if !is_hinge_name(name) {
            return (None, tail.to_vec());
        }
        Hinge { on: name.to_vec(), op: HingeOp::ExcludeAlways, values: Vec::new() }
    } else if let Some(at) = inner.iter().position(|b| *b == b'=' || *b == b'#') {
        let name = &inner[..at];
        if !is_hinge_name(name) {
            return (None, tail.to_vec());
        }
        let op = if inner[at] == b'=' { HingeOp::Eq } else { HingeOp::Ne };
        Hinge {
            on: name.to_vec(),
            op,
            values: inner[at + 1..].split(|b| *b == b',').map(<[u8]>::to_vec).collect(),
        }
    } else {
        return (None, tail.to_vec());
    };

    let mut rest = tail[..open].to_vec();
    rest.extend_from_slice(&tail[close + 1..]);
    (Some(hinge), rest)
}

/// Is an option with this hinge shown?
///
/// A hinge naming an option that does not exist shows rather than hides: an
/// option the sysop cannot see is an option they cannot diagnose.
#[must_use]
pub fn visible(hinge: Option<&Hinge>, values: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> bool {
    let Some(h) = hinge else { return true };
    match h.op {
        HingeOp::ExcludeAlways => false,
        HingeOp::Eq | HingeOp::Ne => {
            let Some(actual) = values(&h.on) else { return true };
            let listed = h.values.contains(&actual);
            if h.op == HingeOp::Eq { listed } else { !listed }
        }
    }
}
