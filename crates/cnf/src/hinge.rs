//! Filled in by Task 5.

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
