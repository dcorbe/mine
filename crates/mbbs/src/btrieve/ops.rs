//! Record-positioning operations, as ABI-independent methods on [`Block`].
//!
//! `crates/mbbs/src/shims/btrieve.rs` already has one implementation of this
//! dispatch -- the private `locate`, `absolute`, `answer_with_key` and
//! `deliver` functions, reached only through a 16-bit `Machine` and its
//! module memory. This module is the same semantics reached through plain
//! Rust values instead, so it is testable without a machine and so a later
//! task (`docs/plans/2026-08-12-btrieve-finish.md`, "Follow-up, owned by
//! nobody yet: make the shims delegate") can make the shim call through to
//! it rather than carry two implementations of the same nine comparisons.
//!
//! # The shim is a reference, not an oracle
//!
//! `shims/btrieve.rs` is under a commit freeze this module must not touch
//! (see `btrieve.rs`'s own top-of-file note), and it is read here freely for
//! its structure -- `locate` (`:1308`) and `absolute` (`:1201`) are exactly
//! the two functions this module's [`Block::query`]/[`Block::get`] and
//! [`Block::acquire_absolute`] replace. But it is a reimplementation of real
//! Btrieve, not real Btrieve itself, and one place below **disagrees with
//! it on purpose**: see [`here_for`]'s doc comment. Genuine Pervasive
//! Btrieve 6.15 under Wine (`tools/btrieve-oracle/`, driven here through
//! `crates/btrieve-engine`) decided every case the vendor source left open,
//! and `crates/mbbs/tests/btrieve.rs`'s `position_ops_oracle_scenarios`
//! (`#[ignore]`d, needs `wine`) is the transcript. Its scenario names (S1,
//! S2, ...) are cited throughout this file's doc comments so a measurement
//! can be re-run rather than taken on faith.
//!
//! # The op families
//!
//! - **Query**, Btrieve ops 55-63 ([`Block::query`]): position the file by
//!   key, deliver nothing. `dfaQuery` (`DFAAPI.C:227`) is the one genuinely
//!   position-only routine in the family -- it passes `NULL` for the data
//!   buffer. `dfaQueryNP` (`:277`) sits beside it but is **not** a query: it
//!   subtracts 50 and calls `btvu` with the module's own data buffer, which
//!   makes it a `Get` in every way that matters here.
//! - **Get**, Btrieve ops 5-13 ([`Block::get`]): the same nine comparisons,
//!   and the record is delivered. `dfaGetLock`/`dfaAcqLock` (`:314`,`:363`).
//! - **Step**, Btrieve ops 24 and 33-35 ([`Block::step`]): physical order,
//!   no key at all. `dfaStepLock` (`:507`).
//! - **Get Position**, Btrieve op 22 ([`Block::get_position`]): report where
//!   the file is positioned, as a physical position. `dfaAbs` (`:433`).
//! - **Get Direct / Acquire Absolute**, Btrieve op 23
//!   ([`Block::acquire_absolute`]): position the file at a physical
//!   position and deliver that record, establishing a key path so a
//!   following Get Next continues in that key's order. `dfaAcqAbsLock`
//!   (`:459`).
//!
//! Nine comparisons, not the eleven the op-code range might suggest:
//! `Equal`, `Next`, `Previous`, `Greater`, `AtLeast`, `Less`, `AtMost`,
//! `Lowest`, `Highest` -- [`Op`]'s own doc comment has the exact code-to-name
//! table, verified against `shims/btrieve.rs`'s `Op::of` (`:815`) rather
//! than assumed from the op-code range, because the range alone reads as
//! "11 = Lowest, 12 = Highest" and that is wrong: 11 is `AtMost`.
//!
//! # The returned-length contract
//!
//! `DFAAPI.C`'s `lastlen`/`dfaLastLen()` (`:934,948`) is Btrieve's own
//! `dbflen`, set from the module's offered buffer length going in and read
//! back as what Btrieve actually delivered coming out -- this host had no
//! field for that at all before this module. [`Delivery::bytes`] is that
//! contract: never longer than [`Block::maxlen`], and [`Delivery::truncated`]
//! records whether the record was longer than the buffer offered for it --
//! Btrieve's own status 22, which `dfaPosError` (`:881`) treats as success
//! with a truncated answer, not a failure.
//!
//! # Locking is out of scope, but the seam is here
//!
//! Every operation that takes a lock in real Btrieve takes one here too, as
//! a plain `i16` -- `loktyp`, exactly as `shims/btrieve.rs`'s `unlocked`
//! reads it. This host has no locking to give a nonzero one, and [`unlocked`]
//! refuses every value but zero, matching that function's policy exactly.
//! Query alone has no lock parameter at either layer: `dfaQuery`'s own
//! signature has none, and neither does `qrybtv`'s.

use std::fmt;

use super::keys::Key;
use super::{Block, BtvError, Cursor};

/// The nine comparisons Btrieve's Query (55-63) and Get (5-13) families both
/// make -- the same nine, fifty apart, per `BTVSTF.H`'s `q*btv` macros and
/// `DFAAPI.C:277`'s `btvu(qryopt,...)`.
///
/// **Verified against `shims/btrieve.rs`'s `Op::of` (`:815`), not derived
/// from the op-code range.** The Get codes are not "5 through 13 in order" --
/// `11` is `AtMost`, not `Lowest`; `Lowest` is `12` and `Highest` is `13`.
/// [`Self::from_get`] reproduces that table exactly rather than a plausible
/// reordering of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// The first record whose key is exactly this value.
    Equal,
    /// The next record in key order.
    Next,
    /// The previous record in key order.
    Previous,
    /// The first record whose key is above this value.
    Greater,
    /// The first record whose key is at least this value.
    AtLeast,
    /// The last record whose key is below this value.
    Less,
    /// The last record whose key is at most this value.
    AtMost,
    /// The lowest key in the file.
    Lowest,
    /// The highest key in the file.
    Highest,
}

impl Op {
    /// The comparison a `dfaGetLock`/`dfaAcqLock` code (5-13) names, or
    /// `None` for one outside that range.
    pub fn from_get(code: i16) -> Option<Self> {
        match code {
            5 => Some(Self::Equal),
            6 => Some(Self::Next),
            7 => Some(Self::Previous),
            8 => Some(Self::Greater),
            9 => Some(Self::AtLeast),
            10 => Some(Self::Less),
            11 => Some(Self::AtMost),
            12 => Some(Self::Lowest),
            13 => Some(Self::Highest),
            _ => None,
        }
    }

    /// The comparison a `dfaQuery` code (55-63) names -- fifty above the Get
    /// family's own, per `BTVSTF.H`'s `q*btv` macros (`qeqbtv(key,n)` is
    /// `qrybtv(key,n,55)`, `qlobtv(n)` is `qrybtv(NULL,n,62)`).
    pub fn from_query(code: i16) -> Option<Self> {
        Self::from_get(code - 50)
    }
}

/// The four Step operations: physical order, no key at all.
///
/// `DFAAPI.C:507`'s own `ASSERT(stpopt == 24 || (stpopt >= 33 && stpopt <=
/// 35))` -- 24 is Step Next, 33 Step First, 34 Step Last, 35 Step Previous,
/// verified against `shims/btrieve.rs`'s `stpbtvl` (`:1015`), which switches
/// on the same four numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    First,
    Last,
    Next,
    Previous,
}

impl Step {
    /// The step a `dfaStepLock` code names, or `None` for one outside the
    /// four Btrieve defines.
    pub fn from_code(code: i16) -> Option<Self> {
        match code {
            33 => Some(Self::First),
            34 => Some(Self::Last),
            24 => Some(Self::Next),
            35 => Some(Self::Previous),
            _ => None,
        }
    }
}

/// What a [`Block::get`]/[`Block::step`]/[`Block::acquire_absolute`] call
/// that finds a record actually hands back.
///
/// Mirrors the `dbflen` contract this module's own doc comment describes:
/// the module offers a buffer of [`Block::maxlen`] bytes, and Btrieve
/// reports back how many of them it actually used. [`Self::bytes`] is
/// already that length -- a caller copies it straight into the module's
/// buffer rather than the raw, possibly-longer, record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The record's bytes, already trimmed to at most [`Block::maxlen`].
    pub bytes: Vec<u8>,

    /// Whether the record was longer than [`Block::maxlen`] and got
    /// trimmed to fit. Real Btrieve's status 22 -- `dfaPosError`
    /// (`DFAAPI.C:881`) treats it as success with a truncated answer, not a
    /// failure, which is why this is a field here and not an [`OpError`].
    pub truncated: bool,

    /// The found record's value at the key the operation searched by, or
    /// `None` for [`Block::step`] -- a step has no key at all.
    /// `shims/btrieve.rs`'s `answer_with_key` (`:1474`) is the same fact,
    /// fetched from module memory instead of returned as a value: every
    /// read operation names `bb->keyseg` except `stpbtvl`, which passes
    /// `NULL` because "a step has no key" (`:1469`).
    pub key: Option<Vec<u8>>,
}

/// Why a [`Block`] position operation refused, ABI-independent -- no status
/// code, because assigning one is Task 7's argument-marshalling job, not
/// this module's. Each variant names the fact a caller marshalling a status
/// code back to a module would need, and the doc comment on each names the
/// real status this was measured as, where it was measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// The file has no key by this number. Real Btrieve status 6, "invalid
    /// key number" -- not independently measured here, but consistent with
    /// `shims/btrieve.rs`'s own `key_number` bounds check (`:1553`), which
    /// refuses the same condition before reaching the engine at all.
    NoSuchKey(u16),

    /// A lock type this host has no locking to give. See [`unlocked`].
    LockRefused(i16),

    /// [`Block::get_position`], [`Op::Previous`], or [`Step::Next`]/
    /// [`Step::Previous`], with nothing having positioned the file at all
    /// (`Cursor::Nowhere`).
    ///
    /// **Not** what [`Op::Next`] does in the same state -- measured
    /// (`position_ops_oracle_scenarios`, `S1`) to succeed instead, as
    /// though the file had been positioned by [`Op::Lowest`]. See
    /// [`here_for`]'s doc comment. [`Op::Previous`] on `Cursor::Nowhere` was
    /// measured too (`S1c`) and answers "not found" (status 9) rather than
    /// refusing -- that is [`Block::query`] returning `Ok(false)`, not this
    /// variant.
    ///
    /// Real Btrieve status 8, "invalid positioning" -- the same status
    /// `S1b` measured for [`Block::get_position`] on a freshly opened,
    /// never-positioned file.
    NotPositioned,

    /// [`Op::Next`]/[`Op::Previous`] asked for a key different from the one
    /// the file's current position was found by (`Cursor::Ordered { key:
    /// had, .. }` with `had != key`).
    ///
    /// Measured (`S6`): a `Get Equal` on key 0, followed by a `Get Next` on
    /// key 1, is refused with real Btrieve status 7, "different key
    /// number" -- **not** silently translated into key 1's order the way
    /// `shims/btrieve.rs`'s `locate` (`:1392-1400`) computes its own `here`.
    /// See [`here_for`]'s doc comment; this is the divergence it exists to
    /// avoid reproducing.
    DifferentKey { current: u16, wanted: u16 },

    /// [`Op::Next`]/[`Op::Previous`] asked on a file positioned by
    /// [`Block::step`] (`Cursor::Physical`), which establishes no key
    /// context at all.
    ///
    /// Measured (`S4`, `S4b`): a `Step First`, followed by a `Get Next` on
    /// *either* key of the two-key oracle fixture, is refused with real
    /// Btrieve status 8, "invalid positioning" -- again **not** the
    /// `Records::place_in` translation `shims/btrieve.rs`'s `locate`
    /// computes for a physical cursor.
    NoKeyEstablished,

    /// The cursor named a place in a key's order whose record no longer
    /// resolves to a physical one. This host is single-threaded and every
    /// write goes through `Records::reindex`, which keeps every key's order
    /// and the physical list in agreement -- so this is defensive rather
    /// than reachable today, the same status `stpbtvl`'s own `Cursor::
    /// Ordered` arm (`shims/btrieve.rs:1070`) guards against with an error
    /// rather than a panic.
    CursorStale,

    /// The records could not be read.
    Records(BtvError),
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchKey(key) => write!(f, "no such key: {key}"),
            Self::LockRefused(lock) => write!(
                f,
                "lock type {lock} refused -- this host has no locking to give it"
            ),
            Self::NotPositioned => write!(f, "the file is not positioned"),
            Self::DifferentKey { current, wanted } => write!(
                f,
                "positioned by key {current}, and asked to continue by key {wanted} -- \
                 Get Next/Previous do not switch keys"
            ),
            Self::NoKeyEstablished => write!(
                f,
                "positioned by a physical step, which establishes no key to continue by"
            ),
            Self::CursorStale => write!(
                f,
                "the cursor names a record the model no longer holds"
            ),
            Self::Records(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpError {}

impl From<BtvError> for OpError {
    fn from(e: BtvError) -> Self {
        Self::Records(e)
    }
}

/// Refuse a lock type this host cannot honour.
///
/// Exactly `shims/btrieve.rs`'s `unlocked` (`:1668`)'s policy, reproduced
/// here rather than shared with it: that file is frozen (see `btrieve.rs`'s
/// top-of-file note), so this is a second copy by necessity, not by choice.
/// **This is the seam Task 5 (`docs/plans/2026-08-12-btrieve-finish.md`)
/// widens**, not a decision of its own -- once a lock is tracked rather
/// than refused, every caller here already threads a plain `i16` through, so
/// nothing above this function has to change shape to hold real lock state.
fn unlocked(lock: i16) -> Result<(), OpError> {
    if lock == 0 {
        return Ok(());
    }
    Err(OpError::LockRefused(lock))
}

/// Where `key`'s order the file's current position sits, for [`Op::Next`]/
/// [`Op::Previous`] -- `Ok(None)` for `Cursor::Nowhere`, `Ok(Some(at))` when
/// the position was found by `key` itself, and an [`OpError`] for every
/// other cursor shape.
///
/// **This is the one place this module deliberately disagrees with
/// `shims/btrieve.rs`'s `locate`.** That function's own `here` (`:1392-1400`)
/// *translates* a cursor left by a different key, or by a physical
/// [`Block::step`], into the requested key's order: `Cursor::Ordered { key:
/// had, .. }` with `had != key` resolves through `Records::place_in`, and so
/// does `Cursor::Physical`. Ported here verbatim at first, on the
/// assumption that a reimplementation this careful had already earned its
/// keep -- and then measured against genuine Pervasive Btrieve 6.15 rather
/// than trusted (`crates/mbbs/tests/btrieve.rs`'s
/// `position_ops_oracle_scenarios`, per this task's own instruction that
/// the shim is a reference, not an oracle):
///
/// - `S6`: `Get Equal` on key 0 (landing on the fixture's tag 2), then `Get
///   Next` on key 1. Key 1's own order says the next record after tag 2 is
///   tag 1; key 0's says tag 3. **Neither answer came back.** The real
///   engine refused with status 7, "different key number".
/// - `S4`/`S4b`: `Step First`, then `Get Next` on key 1 *and*, separately,
///   on key 0. Both refused with status 8, "invalid positioning" -- a
///   physical step does not hand a following keyed Get anything to
///   continue from, on either key.
///
/// So the translation is not what real Btrieve does; it is a plausible
/// extra feature this host's own reimplementation grew, unmeasured until
/// now. This function refuses instead, and [`Block::query`]/[`Block::get`]
/// report the mismatch as [`OpError::DifferentKey`]/[`OpError::
/// NoKeyEstablished`] rather than silently continuing in a new order.
/// `shims/btrieve.rs`'s own translation is **not** corrected to match --
/// that file is frozen, and the correction belongs to whoever lifts the
/// freeze, not to this module.
fn here_for(cursor: Cursor, key: u16) -> Result<Option<usize>, OpError> {
    match cursor {
        Cursor::Nowhere => Ok(None),
        Cursor::Ordered { key: had, at } if had == key => Ok(Some(at)),
        Cursor::Ordered { key: had, .. } => Err(OpError::DifferentKey {
            current: had,
            wanted: key,
        }),
        Cursor::Physical { .. } => Err(OpError::NoKeyEstablished),
    }
}

/// Where a key-ordered place resolves in physical order, for [`Block::step`]
/// continuing on from a keyed position. `shims/btrieve.rs`'s `stpbtvl`
/// (`:1065-1082`), Task 12's fix: a keyed Get leaves the file positioned on
/// a key's order, and a physical step after it has to resolve that to a
/// physical slot before it can move by one. **This direction -- keyed,
/// then step -- is oracle-validated**, unlike [`here_for`]'s: `crates/mbbs/
/// tests/engine_diff.rs`'s `keyed_get_then_step_matches_the_real_engines_
/// duplicate_chain_walk` reproduces the real engine's own `GetEqual`-then-
/// `GetNext` chain walk by this exact computation and gets the same record
/// back. So [`Block::step`] keeps it; only [`here_for`] (the reverse
/// direction Task 12 never tested) does not.
fn physical_of(block: &Block, key: u16, at: usize) -> Result<usize, OpError> {
    let records = block.loaded().expect("Block::step already loaded the records");
    records
        .ordered(key, at)
        .and_then(|record| records.find_physical(record.position))
        .ok_or(OpError::CursorStale)
}

impl Block {
    /// Btrieve ops 55-63, `dfaQuery` -- position the file by `key`,
    /// delivering nothing. `dfaQuery` (`DFAAPI.C:227`) is the position-only
    /// half of the family; [`Block::get`] is the half that also delivers.
    ///
    /// Returns whether a record was found. **A record not found leaves the
    /// cursor exactly where it was** -- `shims/btrieve.rs`'s own comment at
    /// `locate`'s tail (`:1447-1448`) states this and the real engine agrees
    /// (`S2`: the cursor after a failed `Get Next` at end of file stays on
    /// the last record a successful call found, and a following `Get
    /// Previous` steps back from *there*, not from nowhere).
    ///
    /// # Errors
    ///
    /// [`OpError::NoSuchKey`] if the file has no such key.
    /// [`OpError::DifferentKey`]/[`OpError::NoKeyEstablished`] for
    /// [`Op::Next`]/[`Op::Previous`] asked by a key, or after a
    /// [`Block::step`], the current position was not found by -- see
    /// [`here_for`]. If the records cannot be read.
    pub fn query(&mut self, key: u16, op: Op, value: &[u8]) -> Result<bool, OpError> {
        let cursor = self.cursor();
        let definitions: Vec<Key> = self.keys().to_vec();

        let found = {
            let records = self.records()?;
            let count = records
                .ordered_len(key)
                .ok_or(OpError::NoSuchKey(key))?;

            match op {
                Op::Lowest => (count > 0).then_some(0),
                Op::Highest => count.checked_sub(1),
                Op::Equal => {
                    let at = records.seek(&definitions, key, value);
                    records.matches(&definitions, key, at, value).then_some(at)
                }
                Op::AtLeast => {
                    Some(records.seek(&definitions, key, value)).filter(|at| *at < count)
                }
                Op::Greater => {
                    // Past every record equal to the value, which is not
                    // `seek + 1`: a duplicate key may have many.
                    let mut at = records.seek(&definitions, key, value);
                    while records.matches(&definitions, key, at, value) {
                        at += 1;
                    }
                    Some(at).filter(|at| *at < count)
                }
                Op::AtMost => {
                    let mut at = records.seek(&definitions, key, value);
                    while records.matches(&definitions, key, at, value) {
                        at += 1;
                    }
                    at.checked_sub(1)
                }
                Op::Less => records.seek(&definitions, key, value).checked_sub(1),
                Op::Next => match here_for(cursor, key)? {
                    Some(at) => Some(at + 1).filter(|at| *at < count),
                    // Measured (`S1`): Get Next with nothing having
                    // positioned the file behaves like Get Lowest, not like
                    // a refusal -- unlike `shims/btrieve.rs`'s `locate`,
                    // which stops the module here.
                    None => (count > 0).then_some(0),
                },
                Op::Previous => match here_for(cursor, key)? {
                    Some(at) => at.checked_sub(1),
                    // Measured (`S1c`): Get Previous with nothing having
                    // positioned the file answers "not found", not a
                    // refusal.
                    None => None,
                },
            }
        };

        let Some(at) = found else {
            return Ok(false);
        };
        self.seek_to(Cursor::Ordered { key, at });
        Ok(true)
    }

    /// Btrieve ops 5-13, `dfaGetLock`/`dfaAcqLock` -- the same nine
    /// comparisons as [`Block::query`], and the record is delivered.
    ///
    /// `lock` is refused unless zero -- see [`unlocked`].
    ///
    /// # Errors
    ///
    /// Everything [`Block::query`] can return, plus [`OpError::LockRefused`].
    pub fn get(&mut self, key: u16, op: Op, value: &[u8], lock: i16) -> Result<Option<Delivery>, OpError> {
        unlocked(lock)?;
        if !self.query(key, op, value)? {
            return Ok(None);
        }
        Ok(Some(self.deliver_current(Some(key))?))
    }

    /// Btrieve op 22, `dfaAbs` -- where the file is currently positioned, as
    /// a physical position (what [`Block::acquire_absolute`] takes back).
    ///
    /// # Errors
    ///
    /// [`OpError::NotPositioned`] if nothing has positioned the file.
    /// **Not the same as no file being current** -- that is a fact this
    /// type cannot even represent, since a `Block` only exists for a file
    /// that is open. Measured (`S1b`): a freshly opened, never-positioned
    /// file answers status 8 here, the identical status [`OpError::
    /// NoKeyEstablished`] carries for a *different* unpositioned-adjacent
    /// case -- real Btrieve does not distinguish the two by status number,
    /// though this type still does, for the same reason `OpError`'s other
    /// variants stay split: assigning status codes is Task 7's job, not
    /// this one's.
    pub fn get_position(&self) -> Result<u32, OpError> {
        self.current().map(|r| r.position).ok_or(OpError::NotPositioned)
    }

    /// Btrieve op 23, `dfaAcqAbsLock` -- position the file at `position`
    /// and deliver that record, establishing `key`'s path so a following
    /// [`Block::get`]/[`Block::query`] with [`Op::Next`]/[`Op::Previous`]
    /// continues in that key's order. `aabbtv`/`gabbtvl`'s shared body in
    /// `shims/btrieve.rs` (`absolute`, `:1201`) is this same operation, read
    /// out of module memory instead of taken as parameters.
    ///
    /// Returns `Ok(None)` -- not an error -- if `position` names no record,
    /// matching [`Block::query`]'s "not found leaves the cursor where it
    /// was" contract: `position` naming nothing is not a reason to disturb
    /// whatever the file was positioned on before this call.
    ///
    /// **Establishing the key path is oracle-confirmed, not assumed.**
    /// Measured (`S5`): `Get Direct` at the fixture's tag 2, `keynum = 1`,
    /// then `Get Next` on key 1, lands on tag 1 -- key 1's own next record
    /// after tag 2, not key 0's (which would be tag 3). Real Btrieve status
    /// 0 both times.
    ///
    /// # Errors
    ///
    /// [`OpError::LockRefused`] for a nonzero `lock`. [`OpError::NoSuchKey`]
    /// if the file has no such key. If the records cannot be read.
    pub fn acquire_absolute(
        &mut self,
        position: u32,
        key: u16,
        lock: i16,
    ) -> Result<Option<Delivery>, OpError> {
        unlocked(lock)?;
        if usize::from(key) >= self.keys().len() {
            return Err(OpError::NoSuchKey(key));
        }

        let Some(physical) = self.records()?.find_physical(position) else {
            return Ok(None);
        };

        // The position names a record; the key says which order a later
        // Get Next should continue in. A physical cursor is the fallback
        // for a key `Records::place_in` cannot resolve the position
        // through -- not reachable for MajorMUD's own eighteen files (every
        // key indexes every record), kept because a partial or
        // freshly-narrowed key set is not something this type refuses to
        // represent elsewhere either.
        let cursor = match self.records()?.place_in(key, physical) {
            Some(at) => Cursor::Ordered { key, at },
            None => Cursor::Physical { at: physical },
        };
        self.seek_to(cursor);
        Ok(Some(self.deliver_current(Some(key))?))
    }

    /// Btrieve ops 24 and 33-35, `dfaStepLock` -- physical order, no key at
    /// all. `shims/btrieve.rs`'s `stpbtvl` (`:1015`) is this operation, read
    /// out of module memory instead of taken as parameters; its `Cursor::
    /// Ordered` arm (Task 12's fix, oracle-validated -- see
    /// [`physical_of`]'s doc comment) is reproduced verbatim below.
    ///
    /// `lock` is refused unless zero -- see [`unlocked`].
    ///
    /// # Errors
    ///
    /// [`OpError::LockRefused`] for a nonzero `lock`. [`OpError::
    /// NotPositioned`] for [`Step::Next`]/[`Step::Previous`] with nothing
    /// having positioned the file -- **kept as a refusal deliberately,
    /// unlike [`Op::Next`]'s oracle-measured "answers like Lowest"**: the
    /// one measurement taken of this exact case (`S1d`, `Step Next` on a
    /// freshly opened file) answered status 0 landing on the file's
    /// *second* physical record, not its first, which reads as an artifact
    /// of the wire probe's zeroed position block rather than a documented
    /// Btrieve contract -- nothing in `DFAAPI.C` or the Btrieve
    /// Programmer's Reference describes a Step landing on the second
    /// record of anything, and a real caller's position block always comes
    /// from a prior `B_OPEN`/positioning call rather than being fabricated
    /// zeroed the way the probe's did. Reproducing an unexplained one-off
    /// over a documented, defensible refusal is the wrong trade, so this
    /// keeps `shims/btrieve.rs`'s existing policy here rather than chase
    /// it; see this task's final report for the measurement in full.
    /// [`OpError::CursorStale`] if an ordered cursor's record no longer
    /// resolves to a physical one. If the records cannot be read.
    pub fn step(&mut self, step: Step, lock: i16) -> Result<Option<Delivery>, OpError> {
        unlocked(lock)?;
        let cursor = self.cursor();
        let count = self.records()?.len();

        let at = match (step, cursor) {
            (Step::First, _) => 0,
            (Step::Last, _) => match count.checked_sub(1) {
                Some(at) => at,
                None => return Ok(None),
            },
            (Step::Next, Cursor::Physical { at }) => at + 1,
            (Step::Previous, Cursor::Physical { at }) => match at.checked_sub(1) {
                Some(at) => at,
                None => return Ok(None),
            },
            (Step::Next, Cursor::Ordered { key, at }) => physical_of(self, key, at)? + 1,
            (Step::Previous, Cursor::Ordered { key, at }) => {
                match physical_of(self, key, at)?.checked_sub(1) {
                    Some(at) => at,
                    None => return Ok(None),
                }
            }
            (Step::Next | Step::Previous, Cursor::Nowhere) => {
                return Err(OpError::NotPositioned);
            }
        };

        if at >= count {
            return Ok(None);
        }
        self.seek_to(Cursor::Physical { at });
        Ok(Some(self.deliver_current(None)?))
    }

    /// The record the cursor currently names, as a [`Delivery`] --
    /// `shims/btrieve.rs`'s `deliver` (`:1515`) and, when `key` is given,
    /// `answer_with_key` (`:1474`), combined: both read off the same
    /// current record, and every caller here wants both or neither.
    ///
    /// `key` is `None` for [`Block::step`], which has no key
    /// (`shims/btrieve.rs`'s `stpbtvl` passes `NULL` for the key buffer,
    /// `:1469`), and `Some` for every other delivering operation.
    ///
    /// # Errors
    ///
    /// [`OpError::NotPositioned`] if the cursor names nothing -- callers
    /// only reach this right after setting the cursor to a record they just
    /// found, so this is defensive rather than reachable. [`OpError::
    /// NoSuchKey`] if `key` is `Some` and the file has no such key.
    fn deliver_current(&self, key: Option<u16>) -> Result<Delivery, OpError> {
        let record = self.current().ok_or(OpError::NotPositioned)?;
        let maxlen = usize::from(self.maxlen());
        let truncated = record.bytes.len() > maxlen;
        let take = maxlen.min(record.bytes.len());
        let bytes = record.bytes[..take].to_vec();

        let key = match key {
            None => None,
            Some(key) => {
                let definition = self
                    .keys()
                    .get(usize::from(key))
                    .ok_or(OpError::NoSuchKey(key))?;
                Some(definition.extract(&self.keyed(&record.bytes)))
            }
        };

        Ok(Delivery { bytes, truncated, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrieve::keys::{Kind, Segment};
    use crate::btrieve::{Geometry, Version, pages};
    use mbbs16::FarPtr;
    use std::path::{Path, PathBuf};

    /// A file with six records over two keys, chosen so key 0's order and
    /// key 1's order **diverge** -- a fixture where the two happened to
    /// coincide could not tell "this op followed the key it was given" from
    /// "this op just walked physical/insertion order regardless", which is
    /// exactly the distinction `here_for`'s divergence from `shims/
    /// btrieve.rs` turns on. The same six records, in the same order, as
    /// `crates/mbbs/tests/btrieve.rs`'s `position_ops_oracle_scenarios`
    /// (`OPS_PROBE_RECORDS`) -- so a finding measured there can be checked
    /// again here without re-deriving the shape.
    ///
    /// | tag | key0 | key1 | key0 rank | key1 rank |
    /// |-----|------|------|-----------|-----------|
    /// |  0  |  10  |  1   |     0     |     0     |
    /// |  1  |  20  |  2   |     1     |     2     |
    /// |  2  |  30  |  1   |     2     |     1     |
    /// |  3  |  40  |  3   |     3     |     4     |
    /// |  4  |  50  |  2   |     4     |     3     |
    /// |  5  |  60  |  3   |     5     |     5     |
    ///
    /// One data page (`page = 512`, `physical = 12`: an 8-byte record --
    /// `key0: u16 @0`, `key1: u16 @2`, `tag: u8 @4` -- plus four bytes of
    /// slack, comfortably inside one 512-byte page for all six slots).
    const RECLEN: u16 = 8;
    const PHYSICAL: u16 = 12;
    const RECORDS: [(u16, u16, u8); 6] = [
        (10, 1, 0),
        (20, 2, 1),
        (30, 1, 2),
        (40, 3, 3),
        (50, 2, 4),
        (60, 3, 5),
    ];

    fn seed(dir: &Path) -> PathBuf {
        let (page, pages_count) = (512usize, 2usize);
        let mut bytes = vec![0u8; page * pages_count];
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        let header = pages::Header {
            number: 1,
            data: true,
            stamp: 0,
        };
        bytes[page..page + 6].copy_from_slice(&header.encode());
        for (slot, (k0, k1, tag)) in RECORDS.iter().enumerate() {
            let at = page + 6 + slot * usize::from(PHYSICAL);
            bytes[at..at + 2].copy_from_slice(&k0.to_le_bytes());
            bytes[at + 2..at + 4].copy_from_slice(&k1.to_le_bytes());
            bytes[at + 4] = *tag;
        }
        let path = dir.join("OPS.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed`'s file, built directly rather than through
    /// `Btrieve::open` -- no module and no heap, only the file and the
    /// geometry a real `opnbtv` would have read out of it. Mirrors
    /// `btrieve.rs`'s own `tests::block`.
    fn block(path: PathBuf) -> Block {
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 2,
            reclen: RECLEN,
            physical: PHYSICAL,
            records: RECORDS.len() as u32,
            pages: 2,
            variable: false,
        };
        let keys = vec![
            Key {
                number: 0,
                definition: 0,
                segments: vec![Segment {
                    offset: 0,
                    length: 2,
                    kind: Kind::Unsigned,
                    descending: false,
                }],
                duplicates: false,
                chain: None,
            },
            Key {
                number: 1,
                definition: 1,
                segments: vec![Segment {
                    offset: 2,
                    length: 2,
                    kind: Kind::Unsigned,
                    descending: false,
                }],
                duplicates: true,
                chain: Some(8),
            },
        ];
        Block {
            name: "OPS.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: RECLEN,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
        }
    }

    /// A fresh `Block` over `seed`'s six records, in its own scratch
    /// directory. `name` must be unique per call site -- `crate::testing::
    /// scratch` clears and recreates the directory it names, and this
    /// crate's tests run in parallel, so two tests sharing a name would
    /// each see the other rewrite `OPS.DAT` out from under it mid-read.
    fn fixture(name: &str) -> Block {
        block(seed(&crate::testing::scratch(&format!("ops-{name}"))))
    }

    fn tag(delivery: &Delivery) -> u8 {
        delivery.bytes[4]
    }

    // -- Op::Equal / Greater / AtLeast / Less / AtMost / Lowest / Highest --

    #[test]
    fn get_equal_on_a_unique_key_finds_the_one_record() {
        let mut b = fixture("get_equal_on_a_unique_key_finds_the_one_record");
        let d = b
            .get(0, Op::Equal, &30u16.to_le_bytes(), 0)
            .expect("no error")
            .expect("found");
        assert_eq!(tag(&d), 2);
    }

    #[test]
    fn get_equal_that_finds_nothing_leaves_the_cursor_where_it_was() {
        let mut b = fixture("get_equal_that_finds_nothing_leaves_the_cursor_where_it_was");
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 2 });

        let miss = b.get(0, Op::Equal, &999u16.to_le_bytes(), 0).expect("no error");
        assert!(miss.is_none(), "999 is not a key-0 value in the fixture");
        assert_eq!(
            b.cursor(),
            Cursor::Ordered { key: 0, at: 2 },
            "a failed find must not move the cursor a successful one left"
        );
    }

    #[test]
    fn get_equal_on_a_duplicate_key_lands_on_the_position_ordered_first_match() {
        let mut b = fixture("get_equal_on_a_duplicate_key_lands_on_the_position_ordered_first_match");
        // key 1 = 1 matches tags 0 and 2 (key0 10 and 30); tag 0 has the
        // lower physical position, so it is first -- Records::reindex's own
        // tie-break, oracle-confirmed for this exact fixture by
        // `position_ops_oracle_scenarios`'s `S3`.
        let d = b.get(1, Op::Equal, &1u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_next_after_equal_on_a_duplicate_continues_to_the_next_match() {
        let mut b = fixture("get_next_after_equal_on_a_duplicate_continues_to_the_next_match");
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the second key-1=1 match, tag 2");
    }

    #[test]
    fn get_greater_lands_past_every_equal_record_not_on_the_first_one() {
        let mut b = fixture("get_greater_lands_past_every_equal_record_not_on_the_first_one");
        // key 1 = 1 matches two records (tags 0, 2); Greater must skip both.
        let d = b.get(1, Op::Greater, &1u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_ne!(tag(&d), 0);
        assert_ne!(tag(&d), 2, "Greater must not land on an equal record");
    }

    #[test]
    fn get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group() {
        let mut b = fixture("get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group");
        let d = b.get(1, Op::AtMost, &1u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the last of the two key-1=1 records");
    }

    #[test]
    fn get_lowest_and_highest_find_the_ends_of_key_0() {
        let mut b = fixture("get_lowest_and_highest_find_the_ends_of_key_0");
        assert_eq!(tag(&b.get(0, Op::Lowest, &[], 0).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.get(0, Op::Highest, &[], 0).unwrap().unwrap()), 5);
    }

    // -- Op::Next / Op::Previous: the oracle-measured cases --

    #[test]
    fn get_next_with_nothing_positioned_behaves_like_lowest() {
        // S1: measured status 0, landing on the file's true lowest by the
        // requested key -- not a refusal, unlike `shims/btrieve.rs`'s
        // `locate`.
        let mut b = fixture("get_next_with_nothing_positioned_behaves_like_lowest");
        assert_eq!(b.cursor(), Cursor::Nowhere);
        let d = b.get(0, Op::Next, &[], 0).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_previous_with_nothing_positioned_answers_not_found() {
        // S1c: measured status 9 ("not found"), not a refusal and not
        // Highest either.
        let mut b = fixture("get_previous_with_nothing_positioned_answers_not_found");
        let d = b.get(0, Op::Previous, &[], 0).unwrap();
        assert!(d.is_none());
    }

    #[test]
    fn get_next_on_a_different_key_than_the_current_position_is_refused() {
        // S6: Get Equal on key 0 (tag 2), then Get Next on key 1 -- real
        // Btrieve status 7, not a translation into key 1's order.
        let mut b = fixture("get_next_on_a_different_key_than_the_current_position_is_refused");
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        let err = b.get(1, Op::Next, &[], 0).expect_err("a different key is refused");
        assert_eq!(
            err,
            OpError::DifferentKey {
                current: 0,
                wanted: 1
            }
        );
    }

    #[test]
    fn get_next_after_a_step_is_refused_not_translated() {
        // S4/S4b: Step First, then Get Next on either key -- real Btrieve
        // status 8 both times, not `Records::place_in`'s translation.
        let mut b = fixture("get_next_after_a_step_is_refused_not_translated");
        b.step(Step::First, 0).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Physical { at: 0 });
        let err = b.get(1, Op::Next, &[], 0).expect_err("a physical step establishes no key");
        assert_eq!(err, OpError::NoKeyEstablished);
        let err0 = b.get(0, Op::Next, &[], 0).expect_err("neither key continues after a step");
        assert_eq!(err0, OpError::NoKeyEstablished);
    }

    #[test]
    fn get_next_at_end_of_file_fails_but_leaves_the_cursor_there() {
        let mut b = fixture("get_next_at_end_of_file_fails_but_leaves_the_cursor_there");
        b.get(0, Op::Highest, &[], 0).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 5 });
        let miss = b.get(0, Op::Next, &[], 0).expect("no error");
        assert!(miss.is_none());
        assert_eq!(
            b.cursor(),
            Cursor::Ordered { key: 0, at: 5 },
            "S2: the cursor stays on the last record a successful call found"
        );
        // And Get Previous from there steps back to the record before it.
        let d = b.get(0, Op::Previous, &[], 0).unwrap().unwrap();
        assert_eq!(tag(&d), 4);
    }

    // -- Step --

    #[test]
    fn step_walks_physical_order_not_key_order() {
        let mut b = fixture("step_walks_physical_order_not_key_order");
        // Physical order is insertion order here (tags 0..6, in slot
        // order), which key 1's order is NOT (see the fixture table).
        let first = b.step(Step::First, 0).unwrap().unwrap();
        assert_eq!(tag(&first), 0);
        let next = b.step(Step::Next, 0).unwrap().unwrap();
        assert_eq!(next.key, None, "a step has no key");
        assert_eq!(tag(&next), 1, "physical slot 1, tag 1 -- not key 1's next (tag 2)");
    }

    #[test]
    fn step_first_and_last_find_the_physical_ends() {
        let mut b = fixture("step_first_and_last_find_the_physical_ends");
        assert_eq!(tag(&b.step(Step::First, 0).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.step(Step::Last, 0).unwrap().unwrap()), 5);
    }

    #[test]
    fn step_next_past_end_of_file_finds_nothing() {
        let mut b = fixture("step_next_past_end_of_file_finds_nothing");
        b.step(Step::Last, 0).unwrap().unwrap();
        assert!(b.step(Step::Next, 0).unwrap().is_none());
    }

    #[test]
    fn step_next_and_previous_with_nothing_positioned_are_refused() {
        let mut b = fixture("step_next_and_previous_with_nothing_positioned_are_refused");
        assert_eq!(
            b.step(Step::Next, 0).expect_err("nothing has positioned this file"),
            OpError::NotPositioned
        );
        assert_eq!(
            b.step(Step::Previous, 0).expect_err("nothing has positioned this file"),
            OpError::NotPositioned
        );
    }

    #[test]
    fn step_after_a_keyed_position_resolves_through_that_keys_order() {
        // The direction Task 12 fixed and the oracle validated
        // (`keyed_get_then_step_matches_the_real_engines_duplicate_chain_walk`):
        // a keyed position is resolved to its *physical* slot before a step
        // moves by one, not stepped from its key-order rank directly.
        //
        // Landing on tag 0 first (key 1 = 1's first match) cannot tell the
        // two apart: tag 0 is physical slot 0 *and* key-1 rank 0, so a step
        // that used the rank directly would get the same answer as one that
        // resolved it properly, by coincidence. Advancing once more first,
        // to tag 2 (key-1 rank 1, physical slot 2), separates them: stepping
        // from the rank would land back on slot 1+1=2, i.e. tag 2 itself
        // (no movement); resolving to the physical slot first lands on
        // slot 2+1=3, tag 3.
        let mut b = fixture("step_after_a_keyed_position_resolves_through_that_keys_order");
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "key 1 = 1's second match");
        let d = b.step(Step::Next, 0).unwrap().unwrap();
        assert_eq!(tag(&d), 3, "the physical record after tag 2's slot, not its key-1 rank + 1");
    }

    // -- Get Position / Acquire Absolute --

    #[test]
    fn get_position_with_nothing_positioned_is_refused() {
        let b = fixture("get_position_with_nothing_positioned_is_refused");
        assert_eq!(b.get_position().expect_err("S1b"), OpError::NotPositioned);
    }

    #[test]
    fn get_position_reports_the_current_records_physical_position() {
        let mut b = fixture("get_position_reports_the_current_records_physical_position");
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        let position = b.get_position().expect("positioned");
        let expected = b.records().unwrap().find_physical(position).map(|_| ());
        assert!(expected.is_some(), "the reported position must resolve back to a record");
        let record = b.current().expect("positioned");
        assert_eq!(position, record.position);
    }

    #[test]
    fn acquire_absolute_establishes_the_key_path_for_a_following_get_next() {
        // S5: Get Direct at tag 2's position, keynum 1, then Get Next on
        // key 1 -- lands on tag 1 (key 1's own next after tag 2), not tag 3
        // (key 0's next).
        let mut b = fixture("acquire_absolute_establishes_the_key_path_for_a_following_get_next");
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        let position = b.get_position().unwrap();
        b.seek_to(Cursor::Nowhere); // as though nothing had positioned it

        let direct = b.acquire_absolute(position, 1, 0).unwrap().unwrap();
        assert_eq!(tag(&direct), 2);
        assert_eq!(direct.key.as_deref(), Some(&1u16.to_le_bytes()[..]));

        let next = b.get(1, Op::Next, &[], 0).unwrap().unwrap();
        assert_eq!(tag(&next), 1, "key 1's own next record after tag 2, not key 0's (tag 3)");
    }

    #[test]
    fn acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor() {
        let mut b = fixture("acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor");
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        let before = b.cursor();
        let miss = b.acquire_absolute(999_999, 0, 0).expect("no error");
        assert!(miss.is_none());
        assert_eq!(b.cursor(), before);
    }

    #[test]
    fn acquire_absolute_refuses_a_key_the_file_does_not_have() {
        let mut b = fixture("acquire_absolute_refuses_a_key_the_file_does_not_have");
        let position = {
            b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap();
            b.get_position().unwrap()
        };
        assert_eq!(
            b.acquire_absolute(position, 2, 0).expect_err("only keys 0 and 1 exist"),
            OpError::NoSuchKey(2)
        );
    }

    // -- Locking seam --

    #[test]
    fn every_delivering_operation_refuses_a_nonzero_lock() {
        let mut b = fixture("every_delivering_operation_refuses_a_nonzero_lock");
        assert_eq!(
            b.get(0, Op::Lowest, &[], 3).expect_err("lock type 3"),
            OpError::LockRefused(3)
        );
        assert_eq!(
            b.step(Step::First, 3).expect_err("lock type 3"),
            OpError::LockRefused(3)
        );
        assert_eq!(
            b.acquire_absolute(0, 0, 3).expect_err("lock type 3"),
            OpError::LockRefused(3)
        );
    }

    // -- Truncation (the returned-length contract) --

    #[test]
    fn a_record_longer_than_maxlen_is_delivered_truncated() {
        let mut b = fixture("a_record_longer_than_maxlen_is_delivered_truncated");
        b.maxlen = 4; // shorter than RECLEN (8)
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_eq!(d.bytes.len(), 4);
        assert!(d.truncated);
    }

    #[test]
    fn a_record_no_longer_than_maxlen_is_not_marked_truncated() {
        let mut b = fixture("a_record_no_longer_than_maxlen_is_not_marked_truncated");
        assert_eq!(b.maxlen, RECLEN);
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0).unwrap().unwrap();
        assert_eq!(d.bytes.len(), usize::from(RECLEN));
        assert!(!d.truncated);
    }

    // -- Op code parsing --

    #[test]
    fn op_from_get_matches_shims_btrieve_op_of_exactly() {
        let table = [
            (5, Op::Equal),
            (6, Op::Next),
            (7, Op::Previous),
            (8, Op::Greater),
            (9, Op::AtLeast),
            (10, Op::Less),
            (11, Op::AtMost),
            (12, Op::Lowest),
            (13, Op::Highest),
        ];
        for (code, op) in table {
            assert_eq!(Op::from_get(code), Some(op), "code {code}");
        }
        assert_eq!(Op::from_get(4), None);
        assert_eq!(Op::from_get(14), None);
    }

    #[test]
    fn op_from_query_is_fifty_above_get() {
        for code in 5..=13 {
            assert_eq!(Op::from_query(code + 50), Op::from_get(code));
        }
    }

    #[test]
    fn step_from_code_matches_dfaapi_cs_assert() {
        assert_eq!(Step::from_code(33), Some(Step::First));
        assert_eq!(Step::from_code(34), Some(Step::Last));
        assert_eq!(Step::from_code(24), Some(Step::Next));
        assert_eq!(Step::from_code(35), Some(Step::Previous));
        assert_eq!(Step::from_code(25), None);
    }
}
