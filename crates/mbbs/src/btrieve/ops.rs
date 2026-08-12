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
//! # Locking
//!
//! `docs/plans/2026-08-12-btrieve-finish.md`'s Task 5 originally answered
//! "do not build this" -- 191 call sites in `WCCMMUD.DLL`, all pushing a
//! literal zero `loktyp`, measured two ways. **That answer was reversed by
//! the repository owner**: "we're not going to skip over implementing
//! functionality because wccmmud won't need it." A routine with no
//! counterpart at all (the ABI difference case) legitimately gets an empty
//! slot; a routine that exists and is merely unexercised by the one module
//! under test does not. Locks are the second kind, so this module tracks
//! them for real. `docs/lock-oracle-answer.md` is the measurement this is
//! built against; nothing here goes beyond what it records.
//!
//! Every operation that takes a lock in real Btrieve takes one here too, as
//! a plain `i16` -- `loktyp`, exactly as `shims/btrieve.rs` reads it off the
//! module's stack. [`LockTable`] is the state machine
//! `docs/lock-oracle-answer.md` measured: a **single**-record lock (`loktyp`
//! under 300 -- `SLWTBV`/`SLNWBV`, `DFAAPI.H:40-41`, both 100 and 200)
//! auto-releases when the same session takes another single-record lock; a
//! **multiple**-record lock (300 or 400, `MLWTBV`/`MLNWBV`, `:42-43`)
//! accumulates; the two modes cannot be mixed in one session
//! ([`OpError::LockModeMixed`], real status 93); re-locking a record already
//! held is a harmless no-op; and a position operation that finds nothing
//! takes no lock at all, because [`Block::take_lock`] only ever runs after
//! [`Block::query`]/[`Block::step`]'s own positioning has already succeeded.
//! Query alone has no lock parameter at either layer: `dfaQuery`'s own
//! signature has none, and neither does `qrybtv`'s.
//!
//! **The wait/no-wait half of `loktyp` is deliberately not decoded.** A wait
//! bias only has anything to wait *for* when a second client is already
//! holding a conflicting lock, and single vs. multiple is the only half of
//! `loktyp` this table's own state depends on -- see [`LockMode::of`].
//!
//! ## Cross-client conflict (statuses 84/85) is deferred, not architecturally absent
//!
//! This host has exactly one Btrieve client today, so no lock this table
//! records can ever be contended, and nothing here implements the refusal a
//! second client's conflicting lock would produce. **This is a deferral with
//! a stated condition, not a case that cannot arise**: this project is
//! heading toward a single process serving both a 16-bit and a 32-bit
//! module, and whether that lands as one `Host` (still one Btrieve client,
//! conflict still impossible) or two `Host`s (two clients, conflict
//! reachable) is an open design question. [`LockTable`]'s entries are keyed
//! by [`BlockId`] and position only, with **no owner field**, because there
//! is exactly one owner and it does not need naming -- but the shape is
//! chosen so that adding one is additive: a second client's arrival would
//! give [`Held`] an `owner` field and every [`LockTable`] method an owner
//! parameter alongside `block`/`position`, without changing what is tracked
//! or how the single/multiple/mode-mixing rules above work. Building 84/85
//! before that owner exists would be conflict-detection code with nothing to
//! conflict against -- untestable by construction, which is exactly what
//! this task was told not to write.
//!
//! ## The oracle's transaction/wait-lock deadlock is not reproduced, and cannot be
//!
//! `docs/lock-oracle-answer.md` records that genuine Btrieve 6.15 hangs
//! (confirmed blocked past 15 seconds, twice) when a single-record **wait**
//! lock is taken inside the session's own transaction. That is a measured
//! defect in the real engine's wait implementation, not a contract to
//! honour: a host that reproduced it would be a denial of service with a
//! citation, and this crate already refuses other things the real engine
//! got wrong rather than copy them (`here_for`'s doc comment is the other
//! example on this file). The deeper reason it is not reproduced here is
//! structural rather than a judgement call: **this table never waits at
//! all**. Waiting is only meaningful against a second client's conflicting
//! lock, this host has no second client, and the wait/no-wait bias is not
//! even decoded (above) -- so [`LockTable::acquire`] always returns
//! immediately, transaction or not, and the precondition for the oracle's
//! hang never arises. There is no case to special-case.

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

    /// A lock was requested while the session already held a lock of the
    /// other mode -- real Btrieve status 93. See [`LockTable::acquire`].
    /// **No lock is taken when this is returned**, matching the oracle:
    /// "release the single lock first and the identical call succeeds."
    LockModeMixed { held: LockMode, wanted: LockMode },

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
            Self::LockModeMixed { held, wanted } => write!(
                f,
                "a {wanted} lock was asked for, but this session already holds a \
                 {held} lock -- the two modes cannot be mixed in one session \
                 (real Btrieve status 93)"
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

/// Identifies one open [`Block`] for [`LockTable`], independent of any ABI.
///
/// **Not** the module's `struct btvblk *` (`FarPtr`) -- this module avoids
/// that type where it can (see its own top-of-file note), and a lock table
/// keyed by module memory would tie this ABI-independent type back to one
/// ABI's pointer shape for no reason: nothing here needs to resolve a
/// `BlockId` back into module memory, only to tell two [`Block`]s apart and
/// to recognise the same one again. [`Self::fresh`] hands out ordinals from
/// a single process-wide counter, so two [`Block`]s -- even two opened for
/// files of the same name in two different tests -- never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(u64);

impl BlockId {
    /// A `BlockId` no other `Block`, anywhere in this process, already has.
    pub fn fresh() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// Single or multiple, decoded from the raw `loktyp` [`Block::get`]/
/// [`Block::step`]/[`Block::acquire_absolute`] were handed -- see
/// [`Self::of`] for the exact rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// `loktyp` under 300: `SLWTBV` (100) or `SLNWBV` (200),
    /// `DFAAPI.H:40-41`. At most one held at a time -- taking a second
    /// auto-releases the first.
    Single,
    /// `loktyp` 300 or more: `MLWTBV` (300) or `MLNWBV` (400), `:42-43`.
    /// Accumulates -- every one taken stays held.
    Multiple,
}

impl LockMode {
    /// Real Btrieve's four lock-type constants split into two 100-wide
    /// bands, single below 300 and multiple at or above it -- reproduced as
    /// a threshold rather than an exact match against the four so that a
    /// `loktyp` this host has never seen still decodes consistently rather
    /// than doing something undefined. Any nonzero `loktyp` reaches this;
    /// `0` ("no lock") never does -- see [`LockTable::acquire`].
    pub fn of(raw: i16) -> Self {
        if raw >= 300 { Self::Multiple } else { Self::Single }
    }
}

impl fmt::Display for LockMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Single => "single-record",
            Self::Multiple => "multiple-record",
        })
    }
}

/// One lock this session holds: which [`Block`], which record (by physical
/// position, the same identity [`Block::get_position`] reports), and the
/// raw `loktyp` the module asked for -- kept verbatim rather than only the
/// decoded [`LockMode`] so a caller inspecting a held lock (a future
/// `dfaWasLocked`, or a test) can see exactly what was asked for, not only
/// which half of it this table's own state machine cared about.
///
/// **No owner field.** See [`LockTable`]'s own doc comment for what adding
/// one would mean and why it is not here yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    block: BlockId,
    position: u32,
    raw: i16,
}

/// This session's Btrieve locks -- one table, shared by every open
/// [`Block`], because the mode-mixing rule below is a property of the
/// *session*, not of any one file: `docs/lock-oracle-answer.md` says "the
/// same session still holds an outstanding single lock", not "the same
/// file". A `Block` cannot enforce that against a sibling it has no
/// reference to, so this lives beside the blocks (on `Btrieve`,
/// `crates/mbbs/src/btrieve.rs`) rather than inside one.
///
/// **No owner field, by design, for exactly one reason: there is exactly
/// one owner.** This host is single-process and single-threaded by
/// construction, with one Btrieve client. See this module's own "Cross-
/// client conflict" doc section for the reachability condition under which
/// that stops being true, and for what adding an owner would mean: [`Held`]
/// gains an `owner` field, every method below gains an owner parameter, and
/// the single/multiple/mode-mixing rules are unchanged -- they would simply
/// be scoped per owner instead of over the one implicit owner this table has
/// today.
#[derive(Debug, Default)]
pub struct LockTable {
    held: Vec<Held>,
}

impl LockTable {
    /// Take `raw` at `block`'s `position`, once a positioning call has
    /// already found a record there. `raw == 0` -- "no lock was asked for"
    /// -- is always `Ok(())` and changes nothing.
    ///
    /// In order, each measured in `docs/lock-oracle-answer.md`:
    ///
    /// 1. **Re-locking a record already held is a no-op**, regardless of
    ///    mode: "status 0, harmless." Checked first so the record you
    ///    already hold can never be refused by the mode-mixing rule below,
    ///    even on the (unmeasured) case of asking for it again in the other
    ///    mode -- the conservative reading of "the record you already hold
    ///    cannot un-hold itself".
    /// 2. **Mode-mixing is refused.** If this session holds any lock at all,
    ///    a `raw` that decodes to the *other* [`LockMode`] is
    ///    [`OpError::LockModeMixed`], and nothing is recorded.
    /// 3. **A single lock replaces whatever single lock this session
    ///    already held** -- `self.held` can only ever contain locks of one
    ///    mode at a time (rule 2 forbids mixing), so when the mode is
    ///    [`LockMode::Single`] every existing entry is this session's one
    ///    prior single lock, and clearing before pushing is the auto-release
    ///    rule.
    /// 4. **A multiple lock is added** without disturbing what is already
    ///    held.
    ///
    /// # Errors
    /// [`OpError::LockModeMixed`].
    pub fn acquire(&mut self, block: BlockId, position: u32, raw: i16) -> Result<(), OpError> {
        if raw == 0 {
            return Ok(());
        }
        let mode = LockMode::of(raw);

        if self.held.iter().any(|h| h.block == block && h.position == position) {
            return Ok(());
        }

        if let Some(current) = self.held.first().map(|h| LockMode::of(h.raw))
            && current != mode
        {
            return Err(OpError::LockModeMixed { held: current, wanted: mode });
        }

        if mode == LockMode::Single {
            self.held.clear();
        }
        self.held.push(Held { block, position, raw });
        Ok(())
    }

    /// Release the lock this session holds on `block` at `position`, if any.
    /// Never an error -- releasing a record that was not locked is what
    /// [`Block::unlock`] measured as status 0.
    pub fn release_at(&mut self, block: BlockId, position: u32) {
        self.held.retain(|h| !(h.block == block && h.position == position));
    }

    /// Release every lock this session holds on `block`, as
    /// [`crate::btrieve::Btrieve::close`] does for a file going out of this
    /// host's reach -- measured: "closing a file releases every lock it
    /// held, immediately."
    pub fn release_all_for(&mut self, block: BlockId) {
        self.held.retain(|h| h.block != block);
    }

    /// The raw `loktyp` this session holds on `block` at `position`, or
    /// `None` -- test/inspection surface, not a Btrieve operation of its
    /// own.
    pub fn get(&self, block: BlockId, position: u32) -> Option<i16> {
        self.held
            .iter()
            .find(|h| h.block == block && h.position == position)
            .map(|h| h.raw)
    }

    /// Whether this session holds no locks at all.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
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
    /// `lock` is taken at the found record's position -- see
    /// [`Block::take_lock`] -- only once [`Block::query`] has already
    /// succeeded, so a `Get` that finds nothing takes no lock: measured
    /// ("an operation that fails takes no lock: a Get Equal that finds
    /// nothing leaves no lock behind").
    ///
    /// # Errors
    ///
    /// Everything [`Block::query`] can return, plus [`OpError::
    /// LockModeMixed`].
    pub fn get(
        &mut self,
        key: u16,
        op: Op,
        value: &[u8],
        lock: i16,
        locks: &mut LockTable,
    ) -> Result<Option<Delivery>, OpError> {
        if !self.query(key, op, value)? {
            return Ok(None);
        }
        self.take_lock(lock, locks)?;
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
    /// `lock` is taken at `position` once the record is found, the same
    /// order [`Block::get`] takes one -- naming nothing takes no lock,
    /// matching "an operation that fails takes no lock".
    ///
    /// # Errors
    ///
    /// [`OpError::LockModeMixed`]. [`OpError::NoSuchKey`] if the file has no
    /// such key. If the records cannot be read.
    pub fn acquire_absolute(
        &mut self,
        position: u32,
        key: u16,
        lock: i16,
        locks: &mut LockTable,
    ) -> Result<Option<Delivery>, OpError> {
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
        self.take_lock(lock, locks)?;
        Ok(Some(self.deliver_current(Some(key))?))
    }

    /// Btrieve ops 24 and 33-35, `dfaStepLock` -- physical order, no key at
    /// all. `shims/btrieve.rs`'s `stpbtvl` (`:1015`) is this operation, read
    /// out of module memory instead of taken as parameters; its `Cursor::
    /// Ordered` arm (Task 12's fix, oracle-validated -- see
    /// [`physical_of`]'s doc comment) is reproduced verbatim below.
    ///
    /// `lock` is taken at the landed position once the step succeeds, the
    /// same order [`Block::get`] takes one.
    ///
    /// # Errors
    ///
    /// [`OpError::LockModeMixed`]. [`OpError::
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
    pub fn step(&mut self, step: Step, lock: i16, locks: &mut LockTable) -> Result<Option<Delivery>, OpError> {
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
        self.take_lock(lock, locks)?;
        Ok(Some(self.deliver_current(None)?))
    }

    /// This block's identity, for [`LockTable`] -- see [`BlockId`]'s own
    /// doc comment.
    pub fn id(&self) -> BlockId {
        self.id
    }

    /// Take `lock` at wherever this block is currently positioned, once a
    /// caller has already positioned it there. `lock == 0` -- no lock was
    /// asked for -- is always `Ok(())`.
    ///
    /// Called by [`Block::get`], [`Block::acquire_absolute`] and
    /// [`Block::step`] only after their own positioning has already
    /// succeeded, which is what makes "an operation that fails takes no
    /// lock" true for all three: this is simply never reached on a miss.
    ///
    /// # Errors
    /// [`OpError::LockModeMixed`]. [`OpError::NotPositioned`] if nothing is
    /// positioned -- defensive, not reachable through the three callers
    /// above, the same as [`Block::deliver_current`]'s.
    pub fn take_lock(&self, lock: i16, locks: &mut LockTable) -> Result<(), OpError> {
        if lock == 0 {
            return Ok(());
        }
        let position = self.current().ok_or(OpError::NotPositioned)?.position;
        locks.acquire(self.id, position, lock)
    }

    /// Release the lock this session holds at wherever this block is
    /// currently positioned -- Btrieve op 27, Unlock, with `keynum = 0` and
    /// no data. **Always succeeds**, even with nothing positioned or
    /// nothing locked there: measured, "status 0 even when nothing is
    /// locked".
    ///
    /// **Not reachable from the 16-bit ABI today.** None of `WCCMMUD.DLL`'s
    /// seventeen imports is an Unlock call (`shims/btrieve.rs`'s own
    /// call-site table has no such entry), so nothing in that file calls
    /// this. It exists for Task 7's future `dfaUnlock`.
    pub fn unlock(&self, locks: &mut LockTable) {
        if let Some(record) = self.current() {
            locks.release_at(self.id, record.position);
        }
    }

    /// The raw lock type this session holds at wherever this block is
    /// currently positioned, if any -- test/inspection surface, not a
    /// Btrieve operation of its own.
    pub fn lock_at_current(&self, locks: &LockTable) -> Option<i16> {
        let record = self.current()?;
        locks.get(self.id, record.position)
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
            id: BlockId::fresh(),
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
        let mut locks = LockTable::default();
        let d = b
            .get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks)
            .expect("no error")
            .expect("found");
        assert_eq!(tag(&d), 2);
    }

    #[test]
    fn get_equal_that_finds_nothing_leaves_the_cursor_where_it_was() {
        let mut b = fixture("get_equal_that_finds_nothing_leaves_the_cursor_where_it_was");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 2 });

        let miss = b.get(0, Op::Equal, &999u16.to_le_bytes(), 0, &mut locks).expect("no error");
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
        let mut locks = LockTable::default();
        // key 1 = 1 matches tags 0 and 2 (key0 10 and 30); tag 0 has the
        // lower physical position, so it is first -- Records::reindex's own
        // tie-break, oracle-confirmed for this exact fixture by
        // `position_ops_oracle_scenarios`'s `S3`.
        let d = b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_next_after_equal_on_a_duplicate_continues_to_the_next_match() {
        let mut b = fixture("get_next_after_equal_on_a_duplicate_continues_to_the_next_match");
        let mut locks = LockTable::default();
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the second key-1=1 match, tag 2");
    }

    #[test]
    fn get_greater_lands_past_every_equal_record_not_on_the_first_one() {
        let mut b = fixture("get_greater_lands_past_every_equal_record_not_on_the_first_one");
        let mut locks = LockTable::default();
        // key 1 = 1 matches two records (tags 0, 2); Greater must skip both.
        let d = b.get(1, Op::Greater, &1u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        assert_ne!(tag(&d), 0);
        assert_ne!(tag(&d), 2, "Greater must not land on an equal record");
    }

    #[test]
    fn get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group() {
        let mut b = fixture("get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group");
        let mut locks = LockTable::default();
        let d = b.get(1, Op::AtMost, &1u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the last of the two key-1=1 records");
    }

    #[test]
    fn get_lowest_and_highest_find_the_ends_of_key_0() {
        let mut b = fixture("get_lowest_and_highest_find_the_ends_of_key_0");
        let mut locks = LockTable::default();
        assert_eq!(tag(&b.get(0, Op::Lowest, &[], 0, &mut locks).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.get(0, Op::Highest, &[], 0, &mut locks).unwrap().unwrap()), 5);
    }

    // -- Op::Next / Op::Previous: the oracle-measured cases --

    #[test]
    fn get_next_with_nothing_positioned_behaves_like_lowest() {
        // S1: measured status 0, landing on the file's true lowest by the
        // requested key -- not a refusal, unlike `shims/btrieve.rs`'s
        // `locate`.
        let mut b = fixture("get_next_with_nothing_positioned_behaves_like_lowest");
        let mut locks = LockTable::default();
        assert_eq!(b.cursor(), Cursor::Nowhere);
        let d = b.get(0, Op::Next, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_previous_with_nothing_positioned_answers_not_found() {
        // S1c: measured status 9 ("not found"), not a refusal and not
        // Highest either.
        let mut b = fixture("get_previous_with_nothing_positioned_answers_not_found");
        let mut locks = LockTable::default();
        let d = b.get(0, Op::Previous, &[], 0, &mut locks).unwrap();
        assert!(d.is_none());
    }

    #[test]
    fn get_next_on_a_different_key_than_the_current_position_is_refused() {
        // S6: Get Equal on key 0 (tag 2), then Get Next on key 1 -- real
        // Btrieve status 7, not a translation into key 1's order.
        let mut b = fixture("get_next_on_a_different_key_than_the_current_position_is_refused");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        let err = b.get(1, Op::Next, &[], 0, &mut locks).expect_err("a different key is refused");
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
        let mut locks = LockTable::default();
        b.step(Step::First, 0, &mut locks).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Physical { at: 0 });
        let err = b.get(1, Op::Next, &[], 0, &mut locks).expect_err("a physical step establishes no key");
        assert_eq!(err, OpError::NoKeyEstablished);
        let err0 = b.get(0, Op::Next, &[], 0, &mut locks).expect_err("neither key continues after a step");
        assert_eq!(err0, OpError::NoKeyEstablished);
    }

    #[test]
    fn get_next_at_end_of_file_fails_but_leaves_the_cursor_there() {
        let mut b = fixture("get_next_at_end_of_file_fails_but_leaves_the_cursor_there");
        let mut locks = LockTable::default();
        b.get(0, Op::Highest, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 5 });
        let miss = b.get(0, Op::Next, &[], 0, &mut locks).expect("no error");
        assert!(miss.is_none());
        assert_eq!(
            b.cursor(),
            Cursor::Ordered { key: 0, at: 5 },
            "S2: the cursor stays on the last record a successful call found"
        );
        // And Get Previous from there steps back to the record before it.
        let d = b.get(0, Op::Previous, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 4);
    }

    // -- Step --

    #[test]
    fn step_walks_physical_order_not_key_order() {
        let mut b = fixture("step_walks_physical_order_not_key_order");
        let mut locks = LockTable::default();
        // Physical order is insertion order here (tags 0..6, in slot
        // order), which key 1's order is NOT (see the fixture table).
        let first = b.step(Step::First, 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&first), 0);
        let next = b.step(Step::Next, 0, &mut locks).unwrap().unwrap();
        assert_eq!(next.key, None, "a step has no key");
        assert_eq!(tag(&next), 1, "physical slot 1, tag 1 -- not key 1's next (tag 2)");
    }

    #[test]
    fn step_first_and_last_find_the_physical_ends() {
        let mut b = fixture("step_first_and_last_find_the_physical_ends");
        let mut locks = LockTable::default();
        assert_eq!(tag(&b.step(Step::First, 0, &mut locks).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.step(Step::Last, 0, &mut locks).unwrap().unwrap()), 5);
    }

    #[test]
    fn step_next_past_end_of_file_finds_nothing() {
        let mut b = fixture("step_next_past_end_of_file_finds_nothing");
        let mut locks = LockTable::default();
        b.step(Step::Last, 0, &mut locks).unwrap().unwrap();
        assert!(b.step(Step::Next, 0, &mut locks).unwrap().is_none());
    }

    #[test]
    fn step_next_and_previous_with_nothing_positioned_are_refused() {
        let mut b = fixture("step_next_and_previous_with_nothing_positioned_are_refused");
        let mut locks = LockTable::default();
        assert_eq!(
            b.step(Step::Next, 0, &mut locks).expect_err("nothing has positioned this file"),
            OpError::NotPositioned
        );
        assert_eq!(
            b.step(Step::Previous, 0, &mut locks).expect_err("nothing has positioned this file"),
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
        let mut locks = LockTable::default();
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "key 1 = 1's second match");
        let d = b.step(Step::Next, 0, &mut locks).unwrap().unwrap();
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
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
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
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        let position = b.get_position().unwrap();
        b.seek_to(Cursor::Nowhere); // as though nothing had positioned it

        let direct = b.acquire_absolute(position, 1, 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&direct), 2);
        assert_eq!(direct.key.as_deref(), Some(&1u16.to_le_bytes()[..]));

        let next = b.get(1, Op::Next, &[], 0, &mut locks).unwrap().unwrap();
        assert_eq!(tag(&next), 1, "key 1's own next record after tag 2, not key 0's (tag 3)");
    }

    #[test]
    fn acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor() {
        let mut b = fixture("acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        let before = b.cursor();
        let miss = b.acquire_absolute(999_999, 0, 0, &mut locks).expect("no error");
        assert!(miss.is_none());
        assert_eq!(b.cursor(), before);
    }

    #[test]
    fn acquire_absolute_refuses_a_key_the_file_does_not_have() {
        let mut b = fixture("acquire_absolute_refuses_a_key_the_file_does_not_have");
        let mut locks = LockTable::default();
        let position = {
            b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap();
            b.get_position().unwrap()
        };
        assert_eq!(
            b.acquire_absolute(position, 2, 0, &mut locks).expect_err("only keys 0 and 1 exist"),
            OpError::NoSuchKey(2)
        );
    }

    // -- Locking: the state machine, `docs/lock-oracle-answer.md` --

    #[test]
    fn a_single_lock_auto_releases_when_the_session_takes_another_single_lock() {
        // Measured: "Lock key 1, then key 2: an outside observer sees key 1
        // free and key 2 held."
        let mut b = fixture("a_single_lock_auto_releases_when_the_session_takes_another_single_lock");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 100, &mut locks).unwrap().unwrap();
        let held = b.current().unwrap().position;

        assert_eq!(locks.get(b.id(), a), None, "the first lock auto-released");
        assert_eq!(locks.get(b.id(), held), Some(100), "the second is held");
    }

    #[test]
    fn a_multiple_lock_accumulates() {
        // Measured: "lock two records and both stay held."
        let mut b = fixture("a_multiple_lock_accumulates");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks).unwrap().unwrap();
        let bb = b.current().unwrap().position;

        assert_eq!(locks.get(b.id(), a), Some(300), "the first stays held");
        assert_eq!(locks.get(b.id(), bb), Some(300), "the second is held too");
    }

    #[test]
    fn mixing_a_multiple_lock_in_while_a_single_lock_is_outstanding_is_refused_and_takes_no_lock() {
        // Measured: "Taking a multiple lock while the same session still
        // holds an outstanding single lock is refused with 93, and no lock
        // is taken; release the single lock first and the identical call
        // succeeds."
        let mut b = fixture(
            "mixing_a_multiple_lock_in_while_a_single_lock_is_outstanding_is_refused_and_takes_no_lock",
        );
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks).unwrap().unwrap();
        let single = b.current().unwrap().position;

        let err = b
            .get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks)
            .expect_err("mode mixing is refused");
        assert_eq!(
            err,
            OpError::LockModeMixed {
                held: LockMode::Single,
                wanted: LockMode::Multiple
            }
        );
        let refused = b.current().unwrap().position;
        assert_eq!(locks.get(b.id(), refused), None, "the refused record took no lock");
        assert_eq!(locks.get(b.id(), single), Some(100), "and the held one is untouched");

        // "release the single lock first and the identical call succeeds."
        locks.release_at(b.id(), single);
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks)
            .expect("no error")
            .expect("found");
        assert_eq!(locks.get(b.id(), refused), Some(300), "now taken, in multiple mode");
    }

    /// The oracle measured only "multiple while single held" (above). This
    /// completes the rule the other way -- a decision, not a second
    /// measurement, made because this module's own doc comment states the
    /// rule session-wide ("the two modes cannot be mixed in one session"),
    /// not one-directionally, and `docs/lock-oracle-answer.md` names the
    /// symmetry question open rather than answering it "no".
    #[test]
    fn mixing_the_other_direction_a_single_lock_while_multiple_is_outstanding_is_also_refused() {
        let mut b = fixture(
            "mixing_the_other_direction_a_single_lock_while_multiple_is_outstanding_is_also_refused",
        );
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks).unwrap().unwrap();
        let err = b
            .get(0, Op::Equal, &20u16.to_le_bytes(), 100, &mut locks)
            .expect_err("mode mixing, the other direction");
        assert_eq!(
            err,
            OpError::LockModeMixed {
                held: LockMode::Multiple,
                wanted: LockMode::Single
            }
        );
    }

    #[test]
    fn relocking_a_record_already_held_is_a_harmless_no_op() {
        // Measured: "Re-locking a record you already hold is fine (status
        // 0)."
        let mut b = fixture("relocking_a_record_already_held_is_a_harmless_no_op");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks)
            .expect("re-locking is not refused")
            .expect("found");
        assert_eq!(locks.get(b.id(), a), Some(300), "unchanged");
    }

    #[test]
    fn a_get_that_finds_nothing_takes_no_lock() {
        // Measured: "An operation that fails takes no lock: a Get Equal
        // that finds nothing leaves no lock behind."
        let mut b = fixture("a_get_that_finds_nothing_takes_no_lock");
        let mut locks = LockTable::default();
        let miss = b
            .get(0, Op::Equal, &999u16.to_le_bytes(), 100, &mut locks)
            .expect("no error -- a miss is Ok(None), not a refusal");
        assert!(miss.is_none());
        assert!(locks.is_empty(), "nothing was found, so nothing was locked");
    }

    #[test]
    fn unlock_releases_the_lock_at_the_current_position_and_is_ok_even_with_nothing_locked() {
        // Measured: "Unlock (op 27) ... releases the lock at the current
        // position, and is status 0 even when nothing is locked."
        let mut b = fixture("unlock_releases_the_lock_at_the_current_position_and_is_ok_even_with_nothing_locked");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks).unwrap().unwrap();
        assert_eq!(b.lock_at_current(&locks), Some(100));

        b.unlock(&mut locks);
        assert_eq!(b.lock_at_current(&locks), None, "released");

        // Unlocking again, with nothing held, does not error -- `unlock`
        // returns nothing to check, so the assertion is that this line does
        // not panic and the position stays unlocked.
        b.unlock(&mut locks);
        assert_eq!(b.lock_at_current(&locks), None);
    }

    // -- Truncation (the returned-length contract) --

    #[test]
    fn a_record_longer_than_maxlen_is_delivered_truncated() {
        let mut b = fixture("a_record_longer_than_maxlen_is_delivered_truncated");
        let mut locks = LockTable::default();
        b.maxlen = 4; // shorter than RECLEN (8)
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
        assert_eq!(d.bytes.len(), 4);
        assert!(d.truncated);
    }

    #[test]
    fn a_record_no_longer_than_maxlen_is_not_marked_truncated() {
        let mut b = fixture("a_record_no_longer_than_maxlen_is_not_marked_truncated");
        let mut locks = LockTable::default();
        assert_eq!(b.maxlen, RECLEN);
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks).unwrap().unwrap();
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
