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
/// Returns the hinge, if any, and the tail with the hinge text removed so the
/// type parser never sees it.
#[must_use]
pub fn parse(tail: &[u8]) -> (Option<Hinge>, &[u8]) {
    let Some(open) = tail.iter().position(|b| *b == b'(') else {
        return (None, tail);
    };
    let Some(close) = tail[open..].iter().position(|b| *b == b')') else {
        return (None, tail);
    };
    let inner = &tail[open + 1..open + close];

    let hinge = if let Some(name) = inner.strip_suffix(b"*") {
        Hinge { on: name.to_vec(), op: HingeOp::ExcludeAlways, values: Vec::new() }
    } else if let Some(at) = inner.iter().position(|b| *b == b'=' || *b == b'#') {
        let op = if inner[at] == b'=' { HingeOp::Eq } else { HingeOp::Ne };
        Hinge {
            on: inner[..at].to_vec(),
            op,
            values: inner[at + 1..].split(|b| *b == b',').map(<[u8]>::to_vec).collect(),
        }
    } else {
        return (None, tail);
    };

    (Some(hinge), &tail[..open])
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
            let listed = h.values.iter().any(|v| *v == actual);
            if h.op == HingeOp::Eq { listed } else { !listed }
        }
    }
}
