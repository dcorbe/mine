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
//! # What is reachable from a module today, and what is not
//!
//! Stated because this crate has twice been bitten by implemented-but-dead
//! code that looked like an oversight (44 shadowed registrations,
//! `docs/2026-08-15-dead-twin-shims.md`; 26 dead twin bodies). **These are
//! deliberate, and the difference matters to anyone tempted to delete them.**
//!
//! A module reaches Btrieve here through the **36 BTVSTF wrappers** —
//! `obtbtv`, `qrybtv`, `dinsbtv`, `stpbtv` and the rest — all registered and
//! pinned by `shims::mod`'s own `every_routine_btvstf_declares_is_registered`.
//! Those are record verbs, and the operations backing them are reached.
//!
//! The families added by Track B Tasks 10–11 are **not** reachable from any
//! registered shim, and measurably so: chunk access, index create/drop, the
//! five extended operations, continuous operations, percentage positioning,
//! extended-file and system-data introspection, and concurrent transactions.
//! None of them has a BTVSTF wrapper — `BTVSTF.H` declares none — and there
//! is **no `btrcall` in this crate at all**, so there is no raw operation-code
//! door either. No surveyed module imports one.
//!
//! They are here because this host is an API surface rather than an
//! application: a verb missing when a module finally asks for it stops the
//! machine, and the genuine 6.15 engine is available to settle behaviour now
//! and will not be more available later. They are unit-tested against it.
//! What they are *not* is wired, and no test asserts otherwise — the
//! honest record is this comment, because any test that tried to assert
//! "unreachable" here would either be vacuous or a brittle scan of sibling
//! source files.
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
//! `crates/btrieve-oracle`) decided every case the vendor source left open,
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
//! **`+50`, "Get Key", is not a tenth family.** Real Btrieve's own alias for
//! ops 55-63 (Programmer's Reference pp. 113-115) -- "the Get Key bias
//! allows you to perform a Get operation without actually retrieving a data
//! record," answering with the key in the Key Buffer and status 0, while the
//! Data Buffer is untouched. [`Op::from_query`] already reproduces the raw
//! arithmetic (`code - 50`), and `shims/btrieve.rs`'s `qrybtv` (`:1098`)
//! already routes 55-63 through the same `locate`/`answer_with_key` engine
//! `obtbtv` uses, passing `into: None` so only the key is written back --
//! this was true before this task and needed no change. **Not reproduced
//! here**: p. 114's duplicate-skip rule ("the MicroKernel ignores the
//! duplicate instances of the current retrieved key value" -- a `Get
//! Key`/`Get Equal` on a key with eight `Smith`s and one `Smythe` leaves the
//! logical next position on `Smythe`, not the second `Smith`). Reproducing
//! that needs [`Block::query`]'s cursor to remember *which* operation found
//! it, not only where -- a real change to [`Cursor`], which lives in
//! `btrieve.rs` and is out of this file's freeze. Flagged rather than
//! silently matched: a caller driving [`Block::get`] through op 55 and
//! discarding [`Delivery::bytes`] gets the record's key correctly but the
//! *next* op after it would walk every duplicate, not skip them.
//!
//! # File- and session-level administrative operations
//!
//! Task 10 of `docs/plans/2026-08-15-host-api-surface-track-b.md` added six
//! more op codes: `17`/`18` (Set/Get Directory), `26` (Version), `28`
//! (Reset), `29`/`30` (Set/Clear Owner), `16` (Extend). None of them
//! position a file the way everything above this section does -- two of
//! them ([`WorkingDirectory`]'s pair, and [`EngineVersion`]) do not even
//! take a [`Block`], because real Btrieve's own Sent/Returned tables for
//! them have no Position Block column at all (Programmer's Reference
//! pp. 104, 163, 213). They are grouped here rather than given a new file
//! because they answer real Btrieve op codes the same way everything above
//! does, and this module -- not `btrieve.rs`, under its own commit freeze,
//! and not `shims/btrieve.rs`, under a second one -- is where op-code
//! answers land per this track's own architecture note.
//!
//! Two of the six ([`Block::set_owner`]/[`Block::clear_owner`] and
//! [`LockTable::clear_all`] for Reset) need session state this module does
//! track (an [`OwnerTable`], sibling to [`LockTable`]) or already does
//! ([`LockTable`] itself); [`Block::extend`] needs no state at all. None of
//! the six needs a new field on [`Block`], which is why all six fit here
//! without touching `btrieve.rs` -- except two gaps, named at their own
//! doc comments rather than worked around: Reset's "abort every open
//! transaction and close every open file" is `Btrieve`-level orchestration
//! this module cannot reach (it has no notion of "every currently open
//! block"), and `16 Extend`'s "already extended" one-shot rule needs a
//! per-`Block` flag `Block`'s fixed field list does not have. Both are
//! reported in this task's own final report, not silently worked around.
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
//! ### Reconciling this with `lock::Locks` (Task 9)
//!
//! **Two different senses of "owner" now exist in this crate, at two
//! different granularities, and this section's reasoning above still holds
//! for the one it is about.** The "second client" this section discusses is
//! a second *Host*/process -- a second Btrieve connection entirely, the
//! axis this table (`LockTable`) is shaped to extend along if that day
//! comes. That question is still open exactly as written above: one `Host`
//! still means one `LockTable`, still with no owner field, still
//! session-wide, still answering nothing for a second *client* -- nothing
//! below changes any of that.
//!
//! What Task 9 added (`crates/btrieve/src/lock.rs`) is a second, narrower
//! axis this section never considered: *channels* -- players -- multiplexed
//! onto the single `dfa*`-importing `Host` this project already runs, none
//! of them a second Btrieve client by this section's own definition (one
//! process, one connection, one `LockTable`). `lock::Locks` is a second,
//! independent table, not an edit to this one -- see its own top-of-file
//! doc comment for the two reasons it is not a field added here -- and it
//! answers status 84 at *that* granularity, for the four `dfa*` calls only.
//! A reader of this file alone should still conclude cross-*client* conflict
//! is deferred, exactly as above; cross-*channel* conflict within one
//! client is the separate thing `lock.rs` now implements.
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

use crate::mem::Mem;

use super::keys::Key;
use super::{nav, Block, BtvError, Cursor, Version};

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

    /// [`Block::set_owner`]/[`Block::clear_owner`] with a transaction
    /// active. Real Btrieve status 41, "the MicroKernel does not allow the
    /// attempted operation" -- `BtrieveStatusCodes.pdf` p. 11 names Set
    /// Owner, Clear Owner, Create Index and Drop Index by name as the
    /// operations this covers, and the Programmer's Reference states the
    /// same precondition on both operations directly ("No transactions can
    /// be active", pp. 41, 165).
    NotAllowedDuringTransaction,

    /// [`Block::set_owner`] on a file that already has an owner. Real
    /// Btrieve status 50, "the file owner is already set" -- Programmer's
    /// Reference p. 167. Use [`Block::clear_owner`] first.
    OwnerAlreadySet,

    /// [`Block::set_owner`] with a name longer than the eight characters
    /// real Btrieve allows -- Programmer's Reference p. 165, "The owner
    /// name can be up to eight characters long." Real status 51, "the
    /// owner name is invalid" (p. 167); that status also covers the
    /// Data-Buffer/Key-Buffer mismatch check p. 166 describes, which is a
    /// 16-bit-ABI marshalling fact this ABI-independent type cannot see
    /// and so does not check.
    OwnerNameInvalid { len: usize },

    /// [`WorkingDirectory::set`] with an empty path. Real Btrieve status
    /// 35, "the application encountered a directory error... a Set
    /// Directory operation specified an invalid pathname" --
    /// `BtrieveStatusCodes.pdf` p. 10.
    InvalidDirectory,

    /// [`Block::extend`] (Btrieve op 16) against a v6-format file. Real
    /// engines removed `Extend` in 6.0 -- it is absent from every entry in
    /// the Programmer's Reference's own alphabetical operation list
    /// (pp. 34-35) -- so a v6-capable engine given op 16 answers the way it
    /// answers any operation code it does not recognise: status 1, "the
    /// specified operation does not exist or is not valid"
    /// (`BtrieveStatusCodes.pdf` p. 1). See [`Block::extend`]'s own doc
    /// comment for why a v5 file is not refused the same way.
    ObsoleteOperation,

    /// A chunk operation ([`Block::get_chunks`]/[`Block::update_chunks`],
    /// Btrieve ops 23-chunk and 53) against a pre-v6 file. Real Btrieve
    /// status 107, verbatim: `BtrieveStatusCodes.pdf` p. 30 (also indexed
    /// under "1 to 199"), "The application attempted to perform a chunk
    /// operation on a pre-v6.0 file." Task 11's own instruction is that this
    /// is a behaviour to reproduce, not a reason to refuse implementing the
    /// operation -- see both methods' own doc comments for the v6-file path.
    PreV6Chunk,

    /// [`Block::get_chunks`]/[`Block::update_chunks`] named a chunk whose
    /// offset and length run past the end of the record. Real status 103,
    /// "the chunk offset is too big" (Programmer's Reference pp. 99, 211,
    /// listed for both Get Direct/Chunk and Update Chunk).
    ChunkOffsetTooBig,

    /// [`Block::get_chunks`] with a physical position naming no record.
    /// Real status 43, "the specified record address is invalid"
    /// (Programmer's Reference pp. 99, 82, 86 -- shared with the percentage
    /// operations, which name a position the same way).
    InvalidRecordAddress,

    /// [`Block::insert_extended`] with a record whose value, at a key that
    /// forbids duplicates, already exists in the file. Real status 5, "the
    /// record has a key field containing a duplicate key value"
    /// (Programmer's Reference p. 148, and p. 5/`BtrieveStatusCodes.pdf`).
    /// Mirrors `shims/btrieve.rs`'s own `duplicate_key` pre-check for plain
    /// Insert (`dinsbtv`) -- this module has no access to that private
    /// helper (it lives in the frozen shim file), so this recomputes the
    /// same fact through [`Block::query`]`(key, Op::Equal, value)`, which is
    /// already this module's own answer to "does a record with this key
    /// value exist."
    DuplicateKey { key: u16 },

    /// [`Block::insert_extended`] asked for the no-currency-change (NCC)
    /// option (Key Number `-1`, Programmer's Reference p. 147). **Not
    /// implemented, and not implementable in this file alone.** NCC's own
    /// contract is "establishes physical currency without affecting logical
    /// currency" (p. 149) -- two currencies held independently. `Cursor`
    /// (`btrieve.rs`, out of this file's freeze) is a single value, either
    /// [`Cursor::Ordered`] or [`Cursor::Physical`], never both at once, so
    /// there is nowhere to put "physical moved, logical did not" without a
    /// new `Cursor` shape. Refused rather than approximated: leaving the
    /// cursor untouched would silently break a `Step` that follows an NCC
    /// insert (spec: it "operates based on the new physical currency"), and
    /// overwriting it with `Cursor::Physical` would silently break a `Get`
    /// that follows (spec: logical currency is unchanged). Both are the
    /// silent-wrong-answer class this crate refuses rather than risks.
    NccUnsupported,

    /// A concurrent transaction (Btrieve op `1019`) was asked for. **Not
    /// implementable from this file's own state, or from any state this
    /// crate has today.** Real Btrieve's own Begin Transaction section
    /// (Programmer's Reference p. 38) draws the line precisely: op 19 begins
    /// an *exclusive* transaction, op 1019 a *concurrent* one -- a different
    /// lock granularity, page/record rather than whole-engine. `Btrieve::
    /// begin` (`btrieve.rs:2064`) is a single `bool` (`self.transaction`)
    /// that covers every currently open [`Block`] at once the moment it
    /// goes true; there is no per-page or per-record grain anywhere in this
    /// engine for a concurrent transaction's own conflict tracking to hang
    /// off of. This is not a missing case of an existing state machine (the
    /// way [`Self::NccUnsupported`]'s `Cursor` gap is one field short); it
    /// is a state machine this engine does not have at all. **No real
    /// Btrieve status names this**, deliberately not invented: every real
    /// 6.x-or-later engine supports 1019 unconditionally, so the vendor has
    /// never had to document what a concurrency-incapable engine answers.
    /// This is a fact about this host, not about the file or the request,
    /// the same shape `Self::writable`'s v5-only-write refusal is (a `BtvError`,
    /// not a status code) -- Task 7's marshalling decides what a module
    /// sees; this only says the concurrent half of Begin Transaction cannot
    /// be honoured, which is what a caller needs to know before it can
    /// decide anything else. See this task's own final report for a fuller
    /// account of why `19`'s own file-format-dependent granularity change
    /// (whole-file pre-6.0, page/record 6.x) does not close this gap either.
    ConcurrentTransactionUnsupported,

    /// [`create_index`]/[`drop_index`] -- Btrieve ops 31/32. **Not
    /// implementable from this file alone; a structural gap, not a vendor
    /// refusal.** See both functions' own doc comments for the full
    /// account: in short, the one piece of state that would make a new key
    /// queryable -- [`super::records::Records`]'s private `order`/`rank`,
    /// rebuilt only by its own private `reindex` -- lives in a sibling
    /// module (`records.rs`) this file cannot reach, because a Rust private
    /// item is visible to its defining module's descendants, and `ops` is
    /// not a descendant of `records`; both hang off `btrieve` as siblings.
    /// Mutating [`Block::keys`] without it would make [`Block::query`]/
    /// [`Block::get`] answer [`Self::NoSuchKey`] for the very key Create
    /// Index just claimed to add -- the silent-wrong-answer shape this
    /// crate refuses everywhere else, so this refuses too rather than
    /// produce it.
    IndexMutationUnsupported,

    /// [`ContinuousOperation::start`] named a file already in continuous
    /// operation mode. Real status 88, verbatim from the operation's own
    /// Details section (Programmer's Reference p. 47): "The MicroKernel
    /// returns Status Code 88 if a file is specified that is already in
    /// continuous operation mode."
    AlreadyInContinuousOperation { file: String },

    /// A percentage-based operation ([`Block::get_by_percentage`]/
    /// [`Block::find_percentage`]) against an empty key order or an empty
    /// file. Real status 9, "the operation encountered the end-of-file" --
    /// listed as a failure status for both operations (Programmer's
    /// Reference pp. 82, 87).
    EndOfFile,
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
            Self::NotAllowedDuringTransaction => write!(
                f,
                "the MicroKernel does not allow this operation while a transaction is active \
                 (real Btrieve status 41)"
            ),
            Self::OwnerAlreadySet => write!(
                f,
                "the file owner is already set (real Btrieve status 50); clear it first"
            ),
            Self::OwnerNameInvalid { len } => write!(
                f,
                "an owner name must be at most 8 bytes, not {len} (real Btrieve status 51)"
            ),
            Self::InvalidDirectory => write!(
                f,
                "not a usable directory path (real Btrieve status 35)"
            ),
            Self::ObsoleteOperation => write!(
                f,
                "Extend (op 16) does not exist on a v6-format file (real Btrieve status 1)"
            ),
            Self::PreV6Chunk => write!(
                f,
                "a chunk operation on a pre-v6.0 file (real Btrieve status 107)"
            ),
            Self::ChunkOffsetTooBig => write!(
                f,
                "the chunk offset is too big (real Btrieve status 103)"
            ),
            Self::InvalidRecordAddress => write!(
                f,
                "the specified record address is invalid (real Btrieve status 43)"
            ),
            Self::DuplicateKey { key } => write!(
                f,
                "key {key} already holds this value, and duplicates are not allowed \
                 (real Btrieve status 5)"
            ),
            Self::NccUnsupported => write!(
                f,
                "the no-currency-change option is not supported: this host's cursor \
                 cannot hold a physical and a logical position at once"
            ),
            Self::ConcurrentTransactionUnsupported => write!(
                f,
                "a concurrent transaction (op 1019) cannot be honoured: this engine \
                 models exactly one whole-engine exclusive transaction and no finer \
                 lock granularity at all"
            ),
            Self::IndexMutationUnsupported => write!(
                f,
                "Create/Drop Index cannot be honoured: the records model that would \
                 need to know about the change lives in a sibling module this file \
                 cannot reach"
            ),
            Self::AlreadyInContinuousOperation { file } => write!(
                f,
                "{file} is already in continuous operation mode (real Btrieve status 88)"
            ),
            Self::EndOfFile => write!(
                f,
                "the operation encountered the end-of-file (real Btrieve status 9)"
            ),
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
    /// [`crate::Btrieve::close`] does for a file going out of this
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

    /// Btrieve op 28, `Reset`'s own contribution to this table: "releases
    /// all locks held" (Programmer's Reference p. 162), for every
    /// [`Block`] at once -- unlike [`Self::release_all_for`], which Reset
    /// is not. **Only one third of Reset.** The other two -- "aborts any
    /// active transactions" and "closes all open files" (p. 162) -- are
    /// facts about every currently-open [`Block`] and its `txn_active`
    /// flag, which this table does not enumerate and `Btrieve` (in
    /// `btrieve.rs`, out of this file's freeze) does. Reported rather than
    /// worked around: a real Reset wrapper still has to loop every open
    /// block, abort it if `txn_active`, and close it, before or after
    /// calling this.
    pub fn clear_all(&mut self) {
        self.held.clear();
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
        // The v5 rank helper; a v6 `Positioned` cursor never reaches it (a
        // v5 block never sets one). Defensive, not reachable.
        Cursor::Positioned { .. } => Err(OpError::NoKeyEstablished),
    }
}

/// [`here_for`]'s v6 positional counterpart: the record position a keyed
/// `Get Next`/`Previous` continues from, given the cursor a prior v6 read or
/// acquire left behind.
///
/// The same three non-continuations [`here_for`] gives: nothing positioned
/// (`Ok(None)`, so `Get Next` falls to `Get Lowest`); a cursor on a
/// *different* key ([`OpError::DifferentKey`]); a physical-step cursor that
/// established no key at all ([`OpError::NoKeyEstablished`], the same refusal
/// `here_for` gives its `Cursor::Physical` -- a physical step hands a
/// following keyed Get nothing to continue from). A v6 fast-path block leaves
/// `Positioned`, never `Ordered`, so the latter is the defensive, unreachable
/// arm here.
fn here_position(cursor: Cursor, key: u16) -> Result<Option<u32>, OpError> {
    match cursor {
        Cursor::Nowhere => Ok(None),
        Cursor::Positioned { key: had, position } if had == key => Ok(Some(position)),
        Cursor::Positioned { key: had, .. } => Err(OpError::DifferentKey {
            current: had,
            wanted: key,
        }),
        Cursor::Physical { .. } => Err(OpError::NoKeyEstablished),
        Cursor::Ordered { .. } => Err(OpError::NoKeyEstablished),
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
fn physical_of<M: Mem>(block: &Block<M>, key: u16, at: usize) -> Result<usize, OpError> {
    if block.v6_fast_reads() {
        let position = block.v6_position_at(key, at)?.ok_or(OpError::CursorStale)?;
        return block.v6_physical_rank_of(position)?.ok_or(OpError::CursorStale);
    }
    let records = block.loaded().expect("Block::step already loaded the records");
    records
        .ordered(key, at)
        .and_then(|record| records.find_physical(record.position))
        .ok_or(OpError::CursorStale)
}

impl<M: Mem> Block<M> {
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

        if self.v6_fast_reads() {
            let Some(position) = self.v6_query_position(cursor, key, op, value)? else {
                return Ok(false);
            };
            self.seek_to(Cursor::Positioned { key, position });
            return Ok(true);
        }

        let found = {
            let definitions: Vec<Key> = self.keys().to_vec();
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

    /// [`Block::query`]'s v6 fast path (`Block::v6_fast_reads`): the
    /// identical nine-way match, but answering **record positions** the tree
    /// is seeked to directly (`Block::v6_seek_position`/`Block::v6_next_
    /// position`/`Block::v6_prev_position`) rather than ranks into a
    /// materialised order. No [`order::OrderIndex`] is built or consulted on
    /// this path -- a write between two reads leaves nothing for the next
    /// read to rebuild, which is what keeps the 32-bit board from stalling.
    ///
    /// `Next`/`Previous` re-seek the tree from the cursor's current position
    /// (`here_position`) and step once; every other op is a bounded seek. The
    /// rank the old fast path materialised for `Get by Percentage` is the one
    /// caller that still needs a count, and it builds the order on demand.
    ///
    /// # Errors
    ///
    /// [`OpError::NoSuchKey`] if `key` names no key this block has (checked
    /// explicitly, first, so this answers the identical error the
    /// `Records`-based path's `ordered_len(key).ok_or(...)` gives). Whatever
    /// [`here_position`] or the v6 seeks themselves refuse otherwise.
    fn v6_query_position(&mut self, cursor: Cursor, key: u16, op: Op, value: &[u8]) -> Result<Option<u32>, OpError> {
        if !self.keys().iter().any(|k| k.number == key) {
            return Err(OpError::NoSuchKey(key));
        }
        Ok(match op {
            Op::Lowest => self.v6_seek_position(key, nav::Bias::Lowest, None)?,
            Op::Highest => self.v6_seek_position(key, nav::Bias::Highest, None)?,
            Op::Equal => self.v6_seek_position(key, nav::Bias::Equal, Some(value))?,
            Op::AtLeast => self.v6_seek_position(key, nav::Bias::AtLeast, Some(value))?,
            Op::Greater => self.v6_seek_position(key, nav::Bias::Greater, Some(value))?,
            Op::AtMost => self.v6_seek_position(key, nav::Bias::AtMost, Some(value))?,
            Op::Less => self.v6_seek_position(key, nav::Bias::Less, Some(value))?,
            Op::Next => match here_position(cursor, key)? {
                Some(position) => self.v6_next_position(key, position)?,
                // Measured (`S1`): Get Next with nothing having positioned the
                // file behaves like Get Lowest, not like a refusal.
                None => self.v6_seek_position(key, nav::Bias::Lowest, None)?,
            },
            Op::Previous => match here_position(cursor, key)? {
                Some(position) => self.v6_prev_position(key, position)?,
                // Measured (`S1c`): Get Previous with nothing having positioned
                // the file answers "not found", not a refusal.
                None => None,
            },
        })
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
        offered: u16,
    ) -> Result<Option<Delivery>, OpError> {
        if !self.query(key, op, value)? {
            return Ok(None);
        }
        self.take_lock(lock, locks)?;
        Ok(Some(self.deliver_current(Some(key), offered)?))
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
        offered: u16,
    ) -> Result<Option<Delivery>, OpError> {
        let Some(cursor) = self.resolve_cursor(key, position)? else {
            return Ok(None);
        };
        self.seek_to(cursor);
        self.take_lock(lock, locks)?;
        Ok(Some(self.deliver_current(Some(key), offered)?))
    }

    /// The [`Cursor`] `position` occupies in `key`'s order, or `None` if
    /// `position` names no live record -- [`Self::acquire_absolute`]'s own
    /// fast-path-first resolution, exposed standalone for a caller that only
    /// wants the cursor computed, with no lock taken and no record
    /// delivered alongside it.
    ///
    /// **Why this exists**: an insert or update already knows the position
    /// it just wrote (`Block::insert`/`Block::update`'s own return value/
    /// argument) and only needs currency on it -- `crates/mbbs`'s
    /// `insert_record`/`update_variable` used to answer this by calling
    /// `Block::records()` outright, which materialises this file's *entire*
    /// record model regardless of `Block::v6_fast_reads`. That is the exact
    /// per-operation whole-file read the page cache exists to avoid: this
    /// method rides it (or the bounded v6 lookups it backs) the same way
    /// `Block::query`/`Block::step` already do, instead of a second,
    /// crate-external implementation reaching around them.
    ///
    /// # Errors
    ///
    /// [`OpError::NoSuchKey`] if `key` names no key this block has. If the
    /// records cannot be read (non-fast-path files only).
    pub fn cursor_for(&mut self, key: u16, position: u32) -> Result<Option<Cursor>, OpError> {
        self.resolve_cursor(key, position)
    }

    /// Shared body of [`Self::acquire_absolute`] and [`Self::cursor_for`]:
    /// the fast-path-first cursor resolution.
    ///
    /// **The `key` bounds check is this function's own first statement**,
    /// not each caller's -- an earlier version left it to the callers and
    /// only [`Self::cursor_for`] carried one, so [`Self::acquire_absolute`]
    /// let an out-of-range `key` fall all the way into the fast/slow split
    /// below. On the fast path that surfaced as `OpError::Records` (a
    /// generic, run-halting failure) instead of the ordinary status-6
    /// [`OpError::NoSuchKey`]; on the slow path the refusal (when one
    /// happened at all) came back only after [`Self::acquire_absolute`]
    /// had already called [`Self::seek_to`]/[`Self::take_lock`], so a call
    /// that must refuse cleanly moved the cursor -- and could take a lock
    /// -- first. Checking here, before either branch, is what makes both
    /// callers refuse identically and before anything else runs.
    fn resolve_cursor(&mut self, key: u16, position: u32) -> Result<Option<Cursor>, OpError> {
        if usize::from(key) >= self.keys().len() {
            return Err(OpError::NoSuchKey(key));
        }
        if self.v6_fast_reads() {
            let found = self.v6_record_bytes_at(position).map_err(|why| {
                OpError::Records(BtvError {
                    file: self.name().to_owned(),
                    why,
                })
            })?;
            if found.is_none() {
                return Ok(None);
            }
            // The position names a record; the key says which order a later
            // Get Next should continue in -- exactly what `Cursor::Positioned`
            // is, and it costs nothing to establish (no rank, no
            // `OrderIndex`). A key that excludes this record from its own
            // index answers a following Get Next "not found" through the
            // positional seek rather than through a physical cursor; not
            // reachable for MajorMUD's eighteen files (every key indexes every
            // record), and a distinction this type no longer needs to draw.
            Ok(Some(Cursor::Positioned { key, position }))
        } else {
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
            Ok(Some(match self.records()?.place_in(key, physical) {
                Some(at) => Cursor::Ordered { key, at },
                None => Cursor::Physical { at: physical },
            }))
        }
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
    pub fn step(
        &mut self,
        step: Step,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Option<Delivery>, OpError> {
        if self.step_position(step)?.is_none() {
            return Ok(None);
        }
        self.take_lock(lock, locks)?;
        Ok(Some(self.deliver_current(None, offered)?))
    }

    /// [`Self::step`]'s own positioning, on its own -- for a caller with no
    /// [`LockTable`] of this `Block`'s to hand in (`crates/mbbs`'s
    /// `Btrieve` session keeps its one [`LockTable`] to itself; only
    /// [`crate::Btrieve::take_lock`] reaches it, not a `&mut` a caller could
    /// pass here) and no record delivery to make either -- `stpbtvl`
    /// (`shims/btrieve.rs`) positions with this, then takes its lock and
    /// delivers through its own existing calls, exactly the split
    /// [`Self::cursor_for`] already makes for [`Self::acquire_absolute`].
    ///
    /// Returns the physical position landed on, or `None` for the same two
    /// reasons [`Self::step`] returns `Ok(None)`: a [`Step::Last`]/
    /// [`Step::Previous`] on an empty range, or a landed position at or past
    /// [`Self::v6_fast_reads`]'s (or [`Self::records`]'s) own count. Sets
    /// [`Self::cursor`] to it on success; leaves the cursor untouched on
    /// `None`, matching every other positioning method here.
    ///
    /// # Errors
    ///
    /// [`OpError::NotPositioned`] for [`Step::Next`]/[`Step::Previous`] with
    /// nothing having positioned the file -- see [`Self::step`]'s own doc
    /// comment for why this is kept as a refusal. [`OpError::CursorStale`]
    /// if an ordered cursor's record no longer resolves to a physical one.
    /// If the records cannot be read.
    pub fn step_position(&mut self, step: Step) -> Result<Option<usize>, OpError> {
        let cursor = self.cursor();
        let count = if self.v6_fast_reads() {
            self.v6_physical_len()?
        } else {
            self.records()?.len()
        };

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
            // A v6 keyed cursor already names the record's position; a
            // physical step from it is that position's physical rank, plus or
            // minus one -- no `OrderIndex`, no rank translation.
            (Step::Next, Cursor::Positioned { position, .. }) => {
                self.v6_physical_rank_of(position)?.ok_or(OpError::CursorStale)? + 1
            }
            (Step::Previous, Cursor::Positioned { position, .. }) => {
                match self.v6_physical_rank_of(position)?.ok_or(OpError::CursorStale)?.checked_sub(1) {
                    Some(at) => at,
                    None => return Ok(None),
                }
            }
            // A file with no position yet sits *before the first record*, so
            // a cold `Step-Next` returns the first record and a cold
            // `Step-Previous` is already at end-of-file. Measured against
            // genuine Btrieve 6.15 (`tools/btrieve-oracle` `stepcold`): a
            // fresh `B_STEP_NEXT` answers status 0 with record 0 (or status 9
            // on an empty file), and a fresh `B_STEP_PREV` answers status 9.
            // Refusing this stopped The Rose's post-init pass, which does
            // `dfaStepLock(24)` on `rci_play.dat` without positioning first.
            (Step::Next, Cursor::Nowhere) => 0,
            (Step::Previous, Cursor::Nowhere) => return Ok(None),
        };

        if at >= count {
            return Ok(None);
        }
        self.seek_to(Cursor::Physical { at });
        Ok(Some(at))
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
    /// # `offered` is the *call's* buffer, not the block's
    ///
    /// This used to read [`Block::maxlen`] -- the length the module named
    /// once, at `opnbtv(filnam, maxlen)`. That is the right ceiling for the
    /// shim edge, where one module allocates one buffer and reuses it for the
    /// file's whole open lifetime, and `crates/mbbs`'s shims read `maxlen()`
    /// directly for exactly that. It is the wrong ceiling here: this function
    /// is reached only through [`Block::get`], [`Block::step`] and
    /// [`Block::acquire_absolute`], and all three are called only by the
    /// numeric BTRCALL wire, whose caller declares a buffer length on *every*
    /// call and is free to change it between them. Genuine Btrieve's own
    /// Open carries no buffer-size hint at all (`datalen: 0` in every
    /// recorded fixture), so a ceiling taken at Open is a number the real
    /// engine never had.
    ///
    /// Under the old rule a later call offering a *smaller* buffer than Open
    /// did was delivered a record longer than it asked for, and both guest
    /// edges write the delivery straight back to the guest's own pointer
    /// (`crates/dos-runtime/src/btrieve.rs`'s `guest.write(datbuf_ptr, ..)`,
    /// and the Win32 edge's `Flat32Ptr(databuf_at).write(..)`) without
    /// re-checking its length. That is an overrun of the guest's buffer, not
    /// merely a fidelity gap.
    ///
    /// # Errors
    ///
    /// [`OpError::NotPositioned`] if the cursor names nothing -- callers
    /// only reach this right after setting the cursor to a record they just
    /// found, so this is defensive rather than reachable. [`OpError::
    /// NoSuchKey`] if `key` is `Some` and the file has no such key.
    fn deliver_current(&self, key: Option<u16>, offered: u16) -> Result<Delivery, OpError> {
        let record = self.current().ok_or(OpError::NotPositioned)?;
        let offered = usize::from(offered);
        let truncated = record.bytes.len() > offered;
        let take = offered.min(record.bytes.len());
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

/// Btrieve op 26, `Version` -- the MicroKernel/Requester identification a
/// module gets back verbatim (Programmer's Reference pp. 213-216). **No
/// file needs to be open and no [`Block`] is involved**: p. 213's own
/// Sent/Returned table has no Position Block column at all, unlike every
/// operation above this point in the file, and the body opens "Either the
/// MicroKernel or the Requester must be loaded" -- a fact about the
/// process, not about any one open file.
///
/// **The `(version, revision, engine)` triple to advertise is not this
/// module's decision, and is not filled in here.** No surveyed module
/// calls it -- `BTVSTF.H` has no `ver*btv` macro, and none of the three
/// generations of `PLBTVSTF.C` surveyed for Task 1 wraps op 26 -- so there
/// is no vendor call site measuring what a caller expects back, and
/// inventing a specific number this host has never been told to claim is
/// exactly the "plausible zero" this track's own Global Constraints forbid.
/// What *is* measured, and complete, is the wire layout below
/// ([`Self::encode`]): Table 2-29 (p. 214), worked example p. 215 ("07 00
/// 00 00 53" is version 7, revision 0, engine `S`, little-endian
/// throughout). Choosing the actual triple to advertise -- this crate's own
/// repeatedly-cited oracle is Pervasive Btrieve 6.15, the least-invented
/// candidate if one is ever needed -- is Task 14's integration call, not
/// this file's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineVersion {
    /// Btrieve's own major version number, e.g. `6` for "6.x".
    pub version: u16,
    /// Btrieve's own revision number, e.g. `15` for "6.15".
    pub revision: u16,
    /// The one-byte "Requester or Engine Type" identifier, Table 2-29
    /// (p. 214) -- `N` (`0x4E`) for a client Requester, `S` (`0x53`) for a
    /// NetWare server, and six others, none of which names a native Linux
    /// host. Left for the caller to choose rather than guessed here.
    pub engine: u8,
}

impl EngineVersion {
    /// The 5-byte "Version Block" wire form (Table 2-29), one per
    /// MicroKernel or Requester identified. Little-endian throughout,
    /// matching every other multi-byte value this crate reads or writes --
    /// measured against the worked example on p. 215.
    pub fn encode(&self) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[0..2].copy_from_slice(&self.version.to_le_bytes());
        out[2..4].copy_from_slice(&self.revision.to_le_bytes());
        out[4] = self.engine;
        out
    }
}

/// Btrieve ops 17 (`Set Directory`) / 18 (`Get Directory`) -- the
/// MicroKernel's own idea of "the current directory," tracked independently
/// of any open file (Programmer's Reference pp. 104, 163-164). Neither
/// operation's own Sent/Returned table has a Position Block column, so this
/// is a standalone type rather than a [`Block`] method -- the same shape as
/// [`EngineVersion`], for the same reason.
///
/// **This host has exactly one logical drive.** Real Btrieve's `drive`
/// parameter (1 = A, 2 = B, ..., 0 = "the default drive") names one of
/// several DOS/NetWare drive letters; nothing in this codebase assigns a
/// meaning to "drive 2" on a Linux filesystem, so [`Self::directory`]
/// accepts and ignores it -- a stated environment reduction, not an
/// invented per-drive behaviour, the same shape as the lock table's own
/// "there is exactly one owner" reduction (this module's top-of-file doc).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkingDirectory {
    current: Vec<u8>,
}

/// Which of [`WorkingDirectory`]'s two operations a raw op code names --
/// [`Op`]/[`Step`]'s own `from_code` pattern, reused here because Set
/// Directory and Get Directory are exactly the shape that gets copied
/// backwards: same [`WorkingDirectory`] receiver, same lone `[u8]`
/// parameter, opposite direction of data flow. [`WorkingDirectory::dispatch`]
/// is the one place this task's own mutation ("swap Set Directory and Get
/// Directory") is aimed at, rather than at [`WorkingDirectory::set`]/
/// [`WorkingDirectory::get`] individually.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryOp {
    /// Op 17.
    Set,
    /// Op 18.
    Get,
}

impl DirectoryOp {
    /// The directory operation a raw op code names, or `None` for one
    /// outside the pair.
    pub fn from_code(code: i16) -> Option<Self> {
        match code {
            17 => Some(Self::Set),
            18 => Some(Self::Get),
            _ => None,
        }
    }
}

impl WorkingDirectory {
    /// A working directory starting at `initial` -- not NUL-terminated;
    /// see [`Self::get`] for where the terminator is added back.
    pub fn new(initial: impl Into<Vec<u8>>) -> Self {
        Self { current: initial.into() }
    }

    /// Op 17 -- replace or extend the current directory, per p. 163.
    /// `path` is the module's own path bytes, already stripped of its
    /// trailing NUL.
    ///
    /// **"Complete path" is measured against this host's own filesystem
    /// convention, not DOS's.** p. 163: "If you do not specify the
    /// complete path for the directory, the MicroKernel appends the
    /// directory path specified in the Key Buffer to the current
    /// directory." On this host, a path beginning with `/` is complete and
    /// replaces the current directory outright; anything else is appended.
    ///
    /// # Errors
    /// [`OpError::InvalidDirectory`] on an empty path. This host does not
    /// check that the resulting path exists on disk -- p. 164 documents no
    /// such prerequisite either, and [`crate::Btrieve::open`] (out
    /// of this module's scope) is what would fail on a nonexistent
    /// directory in practice.
    pub fn set(&mut self, path: &[u8]) -> Result<(), OpError> {
        if path.is_empty() {
            return Err(OpError::InvalidDirectory);
        }
        if path[0] == b'/' {
            self.current = path.to_vec();
        } else {
            if !self.current.is_empty() && !self.current.ends_with(b"/") {
                self.current.push(b'/');
            }
            self.current.extend_from_slice(path);
        }
        Ok(())
    }

    /// Op 18 -- the current directory, NUL-terminated as p. 104 requires
    /// ("The MicroKernel returns the current directory, terminated by a
    /// binary 0, in the Key Buffer").
    pub fn get(&self) -> Vec<u8> {
        let mut out = self.current.clone();
        out.push(0);
        out
    }

    /// Route a raw op code to [`Self::set`]/[`Self::get`] -- see
    /// [`DirectoryOp`]'s own doc comment for why this exists as a separate
    /// function rather than being inlined at each call site. Op 17 answers
    /// with an empty buffer (real Btrieve returns nothing in the Data
    /// Buffer for Set Directory, p. 163's own table); op 18 answers with
    /// [`Self::get`]'s NUL-terminated bytes.
    pub fn dispatch(&mut self, op: DirectoryOp, path: &[u8]) -> Result<Vec<u8>, OpError> {
        match op {
            DirectoryOp::Set => {
                self.set(path)?;
                Ok(Vec::new())
            }
            DirectoryOp::Get => Ok(self.get()),
        }
    }
}

/// Real Btrieve's four Set Owner access/encryption codes, Table 2-19
/// (p. 166).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCode {
    /// 0 -- requires the owner name for any access; no encryption.
    RequireForAnyAccess,
    /// 1 -- read-only access is permitted without the owner name; no
    /// encryption.
    PermitReadOnly,
    /// 2 -- like [`Self::RequireForAnyAccess`], and the MicroKernel
    /// encrypts the file's data.
    RequireForAnyAccessEncrypted,
    /// 3 -- like [`Self::PermitReadOnly`], and the MicroKernel encrypts the
    /// file's data.
    PermitReadOnlyEncrypted,
}

impl AccessCode {
    /// The access code Table 2-19's own Key Number value names, or `None`
    /// for one outside the four the MicroKernel defines.
    pub fn from_code(code: i16) -> Option<Self> {
        match code {
            0 => Some(Self::RequireForAnyAccess),
            1 => Some(Self::PermitReadOnly),
            2 => Some(Self::RequireForAnyAccessEncrypted),
            3 => Some(Self::PermitReadOnlyEncrypted),
            _ => None,
        }
    }
}

/// One [`Block`]'s owner, as [`Block::set_owner`] recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Owned {
    block: BlockId,
    name: Vec<u8>,
    access: AccessCode,
}

/// This session's Set Owner assignments -- one table, shared by every open
/// [`Block`], the same shape as [`LockTable`] and for the same reason: it
/// lives beside the blocks (on `Btrieve`, `crates/mbbs/src/btrieve.rs`)
/// rather than inside any one of them, because nothing in [`Block`]'s own
/// fixed field list (`btrieve.rs`, out of this file's freeze) has anywhere
/// to hold one.
///
/// **Gating access on the name, not encrypting the data, is what this
/// tracks.** Real Btrieve's Set Owner also encrypts every page of the file
/// when [`AccessCode::RequireForAnyAccessEncrypted`]/
/// [`AccessCode::PermitReadOnlyEncrypted`] is asked for (pp. 166-167) --
/// page-level work this module does not own (`pages.rs`, per the plan's own
/// File Structure table). [`AccessCode`] is still recorded in full, so a
/// caller can see which of the four was asked for even though only the
/// gating half is honoured.
#[derive(Debug, Default)]
pub struct OwnerTable {
    set: Vec<Owned>,
}

impl OwnerTable {
    /// This block's owner name, if [`Block::set_owner`] assigned one.
    pub fn name(&self, block: BlockId) -> Option<&[u8]> {
        self.set.iter().find(|o| o.block == block).map(|o| o.name.as_slice())
    }

    /// This block's [`AccessCode`], if one was assigned.
    pub fn access(&self, block: BlockId) -> Option<AccessCode> {
        self.set.iter().find(|o| o.block == block).map(|o| o.access)
    }

    fn set(&mut self, block: BlockId, name: Vec<u8>, access: AccessCode) {
        self.set.push(Owned { block, name, access });
    }

    /// Remove this block's owner, if any -- [`Block::clear_owner`]'s own
    /// no-op-if-absent contract (see that method's doc comment).
    pub fn clear(&mut self, block: BlockId) {
        self.set.retain(|o| o.block != block);
    }
}

/// Which of [`Block::set_owner`]/[`Block::clear_owner`] a raw op code
/// names -- the same [`DirectoryOp`]/`Op`/`Step` pattern, and the same
/// reason: Set Owner (29) and Clear Owner (30) take the identical call
/// shape (a [`Block`] and an [`OwnerTable`]) and differ only in which
/// one-line method runs. [`Block::owner`] is what this task's own mutation
/// ("swap Set Owner and Clear Owner") is aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerOp {
    /// Op 29.
    Set,
    /// Op 30.
    Clear,
}

impl OwnerOp {
    /// The owner operation a raw op code names, or `None` for one outside
    /// the pair.
    pub fn from_code(code: i16) -> Option<Self> {
        match code {
            29 => Some(Self::Set),
            30 => Some(Self::Clear),
            _ => None,
        }
    }
}

impl<M: Mem> Block<M> {
    /// Btrieve op 29, `Set Owner` -- pp. 165-167. Assigns `name` (at most
    /// eight bytes, p. 165: "The owner name can be up to eight characters
    /// long") to this block's file in `owners`, gating future access on it.
    /// See [`OwnerTable`]'s own doc comment for what "gating" does and does
    /// not cover.
    ///
    /// # Errors
    /// [`OpError::NotAllowedDuringTransaction`] -- status 41. [`OpError::
    /// OwnerAlreadySet`] -- status 50, if `owners` already holds a name for
    /// this block; [`Block::clear_owner`] first. [`OpError::
    /// OwnerNameInvalid`] -- status 51, if `name` is longer than eight
    /// bytes.
    pub fn set_owner(&self, name: &[u8], access: AccessCode, owners: &mut OwnerTable) -> Result<(), OpError> {
        if self.txn_active {
            return Err(OpError::NotAllowedDuringTransaction);
        }
        if owners.name(self.id).is_some() {
            return Err(OpError::OwnerAlreadySet);
        }
        if name.len() > 8 {
            return Err(OpError::OwnerNameInvalid { len: name.len() });
        }
        owners.set(self.id, name.to_vec(), access);
        Ok(())
    }

    /// Btrieve op 30, `Clear Owner` -- pp. 41-42. Removes whatever owner
    /// [`Block::set_owner`] assigned. **Always succeeds even if no owner
    /// was ever set** -- p. 41's own procedure states no prerequisite that
    /// one exists, the mirror of [`Block::unlock`]'s identical
    /// no-op-on-nothing-to-undo shape.
    ///
    /// # Errors
    /// [`OpError::NotAllowedDuringTransaction`] -- status 41, the same
    /// precondition [`Block::set_owner`] enforces (p. 41: "No transactions
    /// can be active").
    pub fn clear_owner(&self, owners: &mut OwnerTable) -> Result<(), OpError> {
        if self.txn_active {
            return Err(OpError::NotAllowedDuringTransaction);
        }
        owners.clear(self.id);
        Ok(())
    }

    /// Route a raw op code to [`Self::set_owner`]/[`Self::clear_owner`] --
    /// see [`OwnerOp`]'s own doc comment for why. `name`/`access` are
    /// ignored for [`OwnerOp::Clear`], matching real Clear Owner's own
    /// Sent parameter table (p. 41): Operation Code and Position Block
    /// only.
    pub fn owner(&self, op: OwnerOp, name: &[u8], access: AccessCode, owners: &mut OwnerTable) -> Result<(), OpError> {
        match op {
            OwnerOp::Set => self.set_owner(name, access, owners),
            OwnerOp::Clear => self.clear_owner(owners),
        }
    }

    /// Btrieve op 16, `Extend` -- absent from this crate's Programmer's
    /// Reference (a 6.15 manual): its own alphabetical operation list
    /// (pp. 34-35, every entry in Chapter 2 checked against it) has no
    /// "Extend" heading at all, the direct evidence that real engines
    /// dropped it in 6.0. **The NE modules target 5.x, where it existed**,
    /// and this track's scope rule is explicit -- YAGNI is suspended, `16
    /// Extend` included -- so this answers per the file's own version
    /// rather than refusing outright:
    ///
    /// - **v6 file: refused**, [`OpError::ObsoleteOperation`]. Measured
    ///   indirectly: `BtrieveStatusCodes.pdf` status 16 ("application
    ///   encountered an expansion error," p. 4) and status 31 ("file is
    ///   already extended," p. 9) are each marked, in the vendor's own
    ///   text, "obsolete in MicroKernel versions 6.0 and later" -- and
    ///   nothing in the 6.x operation table (pp. 26-35) lists op 16 at all.
    ///   A v6-capable engine given an operation code it does not recognise
    ///   answers status 1 (p. 1); this reproduces that rather than
    ///   inventing a v6-specific Extend behaviour the vendor never
    ///   documented, the same reasoning `Self::writable`'s v5-only-write refusal
    ///   already uses for a different operation.
    /// - **v5 file: succeeds.** Extend's still-current neighbour, status 32
    ///   ("the file cannot be extended... a file which is growing larger
    ///   than the operating system file size limit," p. 9), names its
    ///   entire documented purpose: pre-expanding a file before it outgrows
    ///   a DOS/NetWare partition ceiling. This host has no such ceiling --
    ///   an ordinary file on this filesystem grows as it is written -- so
    ///   the precondition Extend exists to satisfy already holds, and
    ///   answering success is the documented purpose degenerating to a
    ///   no-op here, not an invented behaviour.
    ///
    /// **Not tracked here: "already extended," status 31's one-extend-only
    /// rule.** Enforcing it needs a per-[`Block`] flag this type does not
    /// have, and [`Block`]'s field list is fixed by `btrieve.rs`, out of
    /// this file's freeze. Reported rather than worked around: a second
    /// `extend()` call on the same v5 [`Block`] answers success again here,
    /// where real Btrieve would answer status 31 the second time.
    ///
    /// # Errors
    /// [`OpError::ObsoleteOperation`] for a v6-format file.
    pub fn extend(&self) -> Result<(), OpError> {
        match self.geometry().version {
            Version::V6 => Err(OpError::ObsoleteOperation),
            Version::V5 => Ok(()),
        }
    }
}

// # Task 11: the version-gated operation families
//
// `docs/plans/2026-08-15-host-api-surface-track-b.md` Task 11: `23`-chunk
// mode and `53` (Update Chunk), `31`/`32` (Create/Drop Index), `36`-`39`
// (extended Get/Step), `40` (Insert Extended), `42` (Continuous Operation),
// `44`/`45` (Get By Percentage/Find Percentage), `65` (Stat Extended), and
// `1019` (concurrent transaction).
//
// A version gate is a *behaviour* here, not an omission: the chunk family is
// refused against a pre-v6 file with the real engine's own status (107),
// never silently made to work and never silently refused for every file
// regardless of version. Every other family in this task turned out, on
// reading the two cited references in full
// (`archive/tooling/reference-documents/Btrieve_Programmers_Reference_1998.pdf`,
// `BtrieveStatusCodes.pdf`), to carry **no version restriction stated in
// either** -- including Create/Drop Index, which the design doc's own § 4
// survey describes as "5.x restricted to *supplemental* indexes" without a
// citation this task could confirm. Neither reference uses the word
// "supplemental" at all (checked by full-text search of both), so that
// claim is not reproduced here as a gate; Create/Drop Index below is
// unimplementable for an entirely different, structural reason -- see
// [`OpError::IndexMutationUnsupported`].
//
// `36`-`39` and `40` get no "6.x-only" doc comment anywhere below, per this
// task's own instruction: the design's § 8.7 records a search, not a
// finding -- "no statement found in any manual here dating their
// introduction relative to 5.x" -- and a searched-and-not-found is not
// license to assert an age this crate never measured.

/// One chunk of a record -- offset and length -- as the **direct random
/// chunk descriptor** names it (Table 2-10, p. 92, for Get Direct/Chunk;
/// Table 2-26, p. 203, for Update Chunk). The only chunk-descriptor shape
/// this module reproduces.
///
/// **Not reproduced**: the Rectangle Chunk Descriptor (Tables 2-11, 2-27),
/// indirect addressing (chunks read from or written to a module-memory
/// pointer named by a chunk's own User Data element, rather than the Data
/// Buffer itself), the Next-in-Record and Append subfunction biases
/// (pp. 97-98, 209-210), and the Truncate Descriptor (Table 2-28, which
/// changes a record's length -- out of scope for the reason [`Block::
/// update_chunks`]'s own doc comment gives). All five are Data Buffer wire
/// shapes a caller would decode before reaching this type, the same
/// marshalling boundary [`Block::get_extended`] draws against the filter
/// grammar it does not reproduce either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// Byte offset into the record, zero-relative.
    pub offset: u32,
    /// How many bytes, from `offset`.
    pub length: u32,
}

impl<M: Mem> Block<M> {
    /// Btrieve op 23 in its chunk-mode form, `Get Direct/Chunk` -- pp. 88-100.
    ///
    /// `position` is a physical record address, the same coordinate
    /// [`Block::acquire_absolute`] and [`Block::get_position`] use. Chunks
    /// are concatenated into the returned buffer in the order given,
    /// matching "the MicroKernel returns the chunks one after another in
    /// the Data Buffer" (p. 98, direct descriptor case).
    ///
    /// A chunk that begins at or beyond the end of the record is refused
    /// ([`OpError::ChunkOffsetTooBig`], status 103). A chunk whose offset
    /// and length only *combine* to run past the end of the record is not
    /// an error -- p. 98: "the MicroKernel returns Status Code 0 but
    /// ceases processing subsequent chunks" -- so this method truncates
    /// that one chunk to whatever remains, includes it, and stops,
    /// returning `Ok` with however many bytes were actually collected.
    /// There is no channel here for "succeeded, but check the length"
    /// beyond that truncation -- this mirrors [`Delivery::truncated`], the
    /// one other place this module carries a soft partial-success signal,
    /// rather than invent a second one.
    ///
    /// **Does not update currency, deliberately.** p. 100: "no effect on
    /// logical currency... makes the record from which chunks are
    /// retrieved the physical current record" -- physical currency moves,
    /// logical currency does not, the identical shape [`OpError::
    /// NccUnsupported`]'s doc comment describes and this crate's single-
    /// valued [`Cursor`] cannot hold. Setting `Cursor::Physical` here would
    /// silently corrupt a following keyed `Get`; leaving the cursor alone
    /// means a following `Step` will not see the new physical position
    /// either. Of the two silently-incomplete choices this leaves the
    /// cursor untouched, because `position` is a parameter the caller
    /// already has (from a prior [`Block::get_position`]), so nothing about
    /// *this* call depends on the cursor moving -- only a call after it
    /// would, and that is reported here rather than answered wrong. The
    /// same reasoning drops the optional lock bias Table entry for this
    /// operation names: [`Block::take_lock`] keys off wherever the block is
    /// *currently* positioned, and since this method never repositions it,
    /// there is no "current position" left to hand it that means what the
    /// module asked for.
    ///
    /// # Errors
    ///
    /// [`OpError::PreV6Chunk`] -- status 107 -- against a pre-v6 file:
    /// `BtrieveStatusCodes.pdf`, status 107, "The application attempted to
    /// perform a chunk operation on a pre-v6.0 file," verbatim. [`OpError::
    /// InvalidRecordAddress`] -- status 43 -- if `position` names no
    /// record. [`OpError::ChunkOffsetTooBig`] -- status 103 -- if a chunk
    /// begins at or past the end of the record. If the records cannot be
    /// read.
    pub fn get_chunks(&mut self, position: u32, chunks: &[Chunk]) -> Result<Vec<u8>, OpError> {
        if self.geometry().version != Version::V6 {
            return Err(OpError::PreV6Chunk);
        }
        let physical = self
            .records()?
            .find_physical(position)
            .ok_or(OpError::InvalidRecordAddress)?;
        let bytes = self
            .records()?
            .physical(physical)
            .expect("just found")
            .bytes
            .clone();

        let mut out = Vec::new();
        for chunk in chunks {
            let start = usize::try_from(chunk.offset).unwrap_or(usize::MAX);
            if start >= bytes.len() {
                return Err(OpError::ChunkOffsetTooBig);
            }
            let end = start.saturating_add(usize::try_from(chunk.length).unwrap_or(usize::MAX));
            out.extend_from_slice(&bytes[start..end.min(bytes.len())]);
            if end > bytes.len() {
                break;
            }
        }
        Ok(out)
    }

    /// Btrieve op 53, `Update Chunk` -- pp. 201-211, restricted to
    /// **in-place** chunks: every chunk's new data is exactly as long as
    /// the chunk it replaces. Real Update Chunk can also append past the
    /// end of a record or truncate it (the Append and Truncate
    /// subfunctions, pp. 209-210) -- both change the record's own length,
    /// which conflicts with the fixed-length contract [`Block::update`]
    /// already enforces (see that method's own doc comment for why a short
    /// or long buffer is refused rather than padded or grown), so neither
    /// is modelled here.
    ///
    /// Splices `chunks` (each an `(offset, replacement bytes)` pair) into a
    /// copy of the current record and calls [`Block::update`] with the
    /// result. This method's own [`OpError::PreV6Chunk`] gate says "this
    /// file's *format* is too old for a chunk operation at all" (any
    /// pre-v6 file); past that gate, a v6 file reaches [`Block::update`]
    /// like any other caller and inherits whatever *that* method still
    /// refuses -- a variable-length record whose fragment is chained or
    /// changes length (see [`Block::update_v6`]'s own doc comment) or a key
    /// root missing the v6 marker bit -- neither of which is specific to
    /// chunk update. The splicing logic above the write call is tested
    /// against [`Block::update`] directly.
    ///
    /// # Errors
    ///
    /// [`OpError::PreV6Chunk`] -- status 107. [`OpError::NotPositioned`] if
    /// nothing is positioned. [`OpError::ChunkOffsetTooBig`] -- status 103
    /// -- if a chunk runs past the end of the record. [`OpError::Records`]
    /// for anything [`Block::update`] itself refuses.
    pub fn update_chunks(&mut self, chunks: &[(u32, Vec<u8>)]) -> Result<(), OpError> {
        if self.geometry().version != Version::V6 {
            return Err(OpError::PreV6Chunk);
        }
        // `Block::current`'s own v6 fast path (`Block::v6_fast_reads`)
        // fetches through the page cache directly and needs nothing primed
        // here; priming it anyway would be exactly the whole-file walk
        // Task 7's ops cutover exists to stop paying. A variable-length v6
        // file (excluded from the fast path) still needs it, same as
        // always.
        if !self.v6_fast_reads() {
            self.records()?;
        }
        let record = self.current().ok_or(OpError::NotPositioned)?;
        let position = record.position;
        let mut bytes = record.bytes.clone();

        for (offset, data) in chunks {
            let start = usize::try_from(*offset).unwrap_or(usize::MAX);
            let end = start.checked_add(data.len()).ok_or(OpError::ChunkOffsetTooBig)?;
            if end > bytes.len() {
                return Err(OpError::ChunkOffsetTooBig);
            }
            bytes[start..end].copy_from_slice(data);
        }

        self.update(position, &bytes)?;
        Ok(())
    }

    /// Btrieve op 31, `Create Index` -- pp. 67-71. **Always refused.** See
    /// [`OpError::IndexMutationUnsupported`] for the full account: the
    /// state that would make a new key answerable at all --
    /// [`super::records::Records`]'s private `order`/`rank`, rebuilt only by
    /// its own private `reindex` -- lives in a sibling module this file
    /// cannot reach under this round's file boundary. Pushing a [`Key`] onto
    /// [`Block::keys`] without it would make the key visible to a `Stat`
    /// but unusable by [`Block::query`]/[`Block::get`], which read a key's
    /// order through [`super::records::Records::ordered_len`] and would
    /// answer [`OpError::NoSuchKey`] for the very key this call just
    /// claimed to add -- real Btrieve's own contract is the opposite ("You
    /// can use the new key to access your data as soon as the operation
    /// completes," p. 71). A create that cannot be used is not a smaller
    /// version of Create Index; it is a different, wrong operation wearing
    /// its name, so this refuses instead.
    ///
    /// # Errors
    /// [`OpError::IndexMutationUnsupported`], always.
    pub fn create_index(&mut self) -> Result<(), OpError> {
        Err(OpError::IndexMutationUnsupported)
    }

    /// Btrieve op 32, `Drop Index` -- pp. 74-76. **Always refused**, for the
    /// same structural reason as [`Block::create_index`]: removing `key`
    /// from [`Block::keys`] without also rebuilding [`super::records::
    /// Records`]'s per-key order would leave every *other* key's
    /// [`Block::query`]/[`Block::get`] answers untouched only by accident
    /// -- `key`'s own place in [`super::records::Records`]'s internal
    /// per-key vectors, indexed by number, would still exist and still be
    /// consulted by a caller that has not yet learned the number was
    /// dropped.
    ///
    /// # Errors
    /// [`OpError::IndexMutationUnsupported`], always.
    pub fn drop_index(&mut self, key: u16) -> Result<(), OpError> {
        let _ = key;
        Err(OpError::IndexMutationUnsupported)
    }
}

/// Which record an extended Get begins with -- Table 2-12 (p. 126)'s "EG"/
/// "UC" header value. Step Next/Previous Extended always behave as "EG"
/// (p. 126: "For Step Next Extended operations, always set this value to
/// 'EG'"), so [`Block::step_next_extended`]/[`Block::step_previous_extended`]
/// take no value for it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedStart {
    /// "EG" -- begin with the record after the one at which the file is
    /// positioned.
    AfterCurrent,
    /// "UC" -- begin with the record at which the file is positioned.
    AtCurrent,
}

impl<M: Mem> Block<M> {
    /// Btrieve ops 36/37, `Get Next/Previous Extended` -- pp. 125-141 --
    /// and the shared core [`Block::step_next_extended`]/[`Block::
    /// step_previous_extended`] (ops 38/39, pp. 185-196) reuse too.
    ///
    /// **Filtering and field-extraction are not modelled.** Table 2-12's
    /// Filter (a logic expression of up to `n` AND/OR-combined field
    /// comparisons, pp. 127-129) and Descriptor (which fields of a matching
    /// record to return, p. 129) are Data Buffer wire shapes -- how a
    /// module's raw bytes name a filter and a projection -- the same
    /// marshalling boundary this module already draws between itself and
    /// `shims/btrieve.rs` for every other operation (see this file's own
    /// top-of-file note). What is modelled is the **unfiltered** case the
    /// vendor's own spec calls out as first-class, not a degenerate one:
    /// "0 means the MicroKernel performs no filtering" (p. 127). This
    /// returns up to `count` whole records, walking [`Op::Next`]/[`Op::
    /// Previous`] one at a time -- the same comparison [`Block::get`]
    /// already answers -- and stops at the first miss, which under an
    /// unfiltered walk is exactly end-of-file, one of the four documented
    /// stop conditions (p. 130: "The MicroKernel reaches the end of the
    /// file").
    fn get_extended(
        &mut self,
        key: u16,
        op: Op,
        count: u16,
        start: ExtendedStart,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Vec<Delivery>, OpError> {
        let mut out = Vec::new();
        if count == 0 {
            return Ok(out);
        }
        if start == ExtendedStart::AtCurrent {
            out.push(self.deliver_current(Some(key), offered)?);
        }
        while (out.len() as u16) < count {
            match self.get(key, op, &[], lock, locks, offered)? {
                Some(delivery) => out.push(delivery),
                None => break,
            }
        }
        Ok(out)
    }

    /// Btrieve op 36, `Get Next Extended`. See [`Block::get_extended`].
    pub fn get_next_extended(
        &mut self,
        key: u16,
        count: u16,
        start: ExtendedStart,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Vec<Delivery>, OpError> {
        self.get_extended(key, Op::Next, count, start, lock, locks, offered)
    }

    /// Btrieve op 37, `Get Previous Extended`. See [`Block::get_extended`].
    pub fn get_previous_extended(
        &mut self,
        key: u16,
        count: u16,
        start: ExtendedStart,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Vec<Delivery>, OpError> {
        self.get_extended(key, Op::Previous, count, start, lock, locks, offered)
    }

    /// Btrieve op 38, `Step Next Extended` -- pp. 185-190. Always "EG"; see
    /// [`ExtendedStart`]'s own doc comment.
    pub fn step_next_extended(
        &mut self,
        count: u16,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Vec<Delivery>, OpError> {
        let mut out = Vec::new();
        while (out.len() as u16) < count {
            match self.step(Step::Next, lock, locks, offered)? {
                Some(delivery) => out.push(delivery),
                None => break,
            }
        }
        Ok(out)
    }

    /// Btrieve op 39, `Step Previous Extended` -- pp. 191-196.
    pub fn step_previous_extended(
        &mut self,
        count: u16,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Vec<Delivery>, OpError> {
        let mut out = Vec::new();
        while (out.len() as u16) < count {
            match self.step(Step::Previous, lock, locks, offered)? {
                Some(delivery) => out.push(delivery),
                None => break,
            }
        }
        Ok(out)
    }

    /// Whether a record with `value` already exists under `key`, without
    /// disturbing the cursor -- [`Block::query`]'s own `Op::Equal`
    /// arithmetic (`records.seek` then `records.matches`), recomputed
    /// rather than called through, because `query` always repositions on a
    /// hit and [`Block::insert_extended`] needs the same fact *without*
    /// that side effect: refusing to insert a record must not move the
    /// cursor toward the record it collided with.
    fn key_exists(&mut self, key: u16, value: &[u8]) -> Result<bool, OpError> {
        if self.v6_fast_reads() {
            return Ok(self.v6_seek_rank(key, nav::Bias::Equal, value)?.is_some());
        }
        let definitions: Vec<Key> = self.keys().to_vec();
        let records = self.records()?;
        let at = records.seek(&definitions, key, value);
        Ok(records.matches(&definitions, key, at, value))
    }
}

/// [`Block::insert_extended`]'s own error: how many records made it in
/// before the one that failed, and why the rest did not run.
///
/// Programmer's Reference p. 148: "the first word of the [returned] Data
/// Buffer equals the number of records that were successfully inserted...
/// The record that caused the error is the number of records that were
/// successfully inserted plus one." [`Self::inserted`] is that first word,
/// already computed rather than left for a caller to count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertExtendedError {
    /// Physical positions of the records inserted before the failure, in
    /// insertion order.
    pub inserted: Vec<u32>,
    /// Why the next record was not inserted.
    pub error: OpError,
}

impl<M: Mem> Block<M> {
    /// Btrieve op 40, `Insert Extended` -- pp. 147-150.
    ///
    /// `key` is the key currency is established by once every record has
    /// been inserted; `ncc` is the no-currency-change option (Key Number
    /// `-1`, p. 147) -- always refused, [`OpError::NccUnsupported`], see
    /// that variant's own doc comment for why. `records` are the record
    /// images to insert, in order.
    ///
    /// Every record is checked, before it is written, against every key
    /// that forbids duplicates -- [`Block::key_exists`], the same fact
    /// [`Block::query`]'s `Op::Equal` computes, without that method's side
    /// effect of moving the cursor toward a hit. `dinsbtv`'s own duplicate
    /// pre-check (`shims/btrieve.rs`'s private `duplicate_key`) is not
    /// called through -- it lives in the frozen shim file, and is private
    /// to it besides -- so this recomputes the same answer from the public
    /// primitives [`Block::query`] itself is built on, rather than
    /// duplicate its *policy* (which keys are checked; that a hit refuses
    /// rather than warns) with a second, drifting copy.
    ///
    /// On success, establishes currency on the **last** inserted record
    /// under `key` -- p. 150: "makes the last inserted record the current
    /// one... based on the specified key" -- the same `records().
    /// find_physical` then `records().place_in` pair [`Block::
    /// acquire_absolute`] and `shims/btrieve.rs`'s `dinsbtv` both use.
    ///
    /// # Errors
    ///
    /// [`InsertExtendedError`], carrying every position already inserted.
    /// [`OpError::NccUnsupported`] if `ncc` is set. [`OpError::
    /// DuplicateKey`] -- status 5 -- for the first record that collides.
    /// [`OpError::Records`] for anything [`Block::insert`] itself refuses
    /// (a short disk, a variable-length file, a v6 file -- see [`Block::
    /// insert`]'s own doc comment).
    pub fn insert_extended(
        &mut self,
        key: u16,
        ncc: bool,
        records: &[Vec<u8>],
    ) -> Result<Vec<u32>, InsertExtendedError> {
        if ncc {
            return Err(InsertExtendedError {
                inserted: Vec::new(),
                error: OpError::NccUnsupported,
            });
        }

        let mut inserted = Vec::new();
        for bytes in records {
            for candidate in self.keys().to_vec() {
                if candidate.duplicates {
                    continue;
                }
                // Off the *keyed* record: a key's `offset` is a physical-slot
                // offset, two bytes ahead of `Record::bytes` on v6, and
                // `self.insert` below keys the same record through `keyed()`
                // when it reaches `insert_v6`. Extracting off the bare `bytes`
                // read a v6 key two bytes late, off the end of the record --
                // the same defect `shims::btrieve::duplicate_key` carried.
                let keyed = self.keyed(bytes);
                let value = candidate.extract(&keyed);
                match self.key_exists(candidate.number, &value) {
                    Ok(true) => {
                        return Err(InsertExtendedError {
                            inserted,
                            error: OpError::DuplicateKey { key: candidate.number },
                        });
                    }
                    Ok(false) => {}
                    Err(error) => return Err(InsertExtendedError { inserted, error }),
                }
            }

            match self.insert(bytes) {
                Ok(position) => inserted.push(position),
                Err(error) => {
                    return Err(InsertExtendedError { inserted, error: OpError::from(error) });
                }
            }
        }

        if let Some(&last) = inserted.last() {
            let cursor = if self.v6_fast_reads() {
                // The just-inserted record's own position is the currency; the
                // key says which order a following Get Next continues in. No
                // rank, no `OrderIndex` -- an insert during a table rebuild
                // leaves nothing for the next keyed read to rebuild.
                Cursor::Positioned { key, position: last }
            } else {
                let physical = match self.records() {
                    Ok(r) => r.find_physical(last).expect("just inserted"),
                    Err(error) => {
                        return Err(InsertExtendedError { inserted, error: OpError::from(error) })
                    }
                };
                match self.records() {
                    Ok(r) => match r.place_in(key, physical) {
                        Some(at) => Cursor::Ordered { key, at },
                        None => Cursor::Physical { at: physical },
                    },
                    Err(error) => {
                        return Err(InsertExtendedError { inserted, error: OpError::from(error) })
                    }
                }
            };
            self.seek_to(cursor);
        }

        Ok(inserted)
    }
}

/// Btrieve op 42, `Continuous Operation` -- pp. 44-48. **Server-based
/// MicroKernels only** (p. 44's own note); this host runs as one, so the
/// operation is answered rather than refused outright.
///
/// File-name based rather than [`Block`]-based -- p. 44's own Sent/Returned
/// table has no Position Block column, the same shape [`EngineVersion`]/
/// [`WorkingDirectory`] already are and for the same reason.
///
/// **Only the name-set bookkeeping is modelled**, not what the operation is
/// actually *for*: real Continuous Operation shadows writes into a delta
/// file (p. 44) so a backup running concurrently sees a consistent
/// snapshot, and rolls the delta back in when the file leaves continuous
/// operation mode. This host has no backup subsystem and no delta file --
/// nothing here reads [`Self::is_active`] to change how a write behaves.
/// What is modelled is the part a caller can observe independent of that:
/// which files are currently in the set, and the one status code the
/// vendor's own text names outright.
#[derive(Debug, Default)]
pub struct ContinuousOperationTable {
    active: Vec<String>,
}

impl ContinuousOperationTable {
    /// Add `files` to the set, Key Number 0's subfunction (p. 45). **All or
    /// nothing**: if any name in `files` is already active, none of them
    /// are added -- an inferred reading, not a measured one (no engine was
    /// available to check a partial-conflict batch against), chosen because
    /// "the presence of duplicate filenames... does not affect how the
    /// operation works" (p. 47) already establishes that repeats within one
    /// call are harmless, and refusing the whole call on any genuine
    /// collision is the same shape [`Block::set_owner`]'s "already set"
    /// refusal takes rather than a half-applied batch.
    ///
    /// # Errors
    /// [`OpError::AlreadyInContinuousOperation`] -- status 88, the vendor's
    /// own text verbatim (p. 47) -- naming the first colliding file.
    pub fn start(&mut self, files: &[String]) -> Result<(), OpError> {
        for file in files {
            if self.active.contains(file) {
                return Err(OpError::AlreadyInContinuousOperation { file: file.clone() });
            }
        }
        for file in files {
            if !self.active.contains(file) {
                self.active.push(file.clone());
            }
        }
        Ok(())
    }

    /// Remove `files` from the set (Key Number 2), or every file (Key
    /// Number 1, `files: None`) -- p. 45's two subfunctions. Never an
    /// error: p. 46's own Details name no precondition for ending
    /// continuous operation on a file that was never in it.
    pub fn end(&mut self, files: Option<&[String]>) {
        match files {
            Some(names) => self.active.retain(|active| !names.contains(active)),
            None => self.active.clear(),
        }
    }

    /// Whether `file` is currently in continuous operation mode.
    pub fn is_active(&self, file: &str) -> bool {
        self.active.iter().any(|active| active == file)
    }
}

/// What [`Block::get_by_percentage`] positions by -- p. 85's Key Number
/// rule: an actual key number for a key-path position, or `-1` (0xFF) for
/// the record's physical location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PercentageBasis {
    /// Relative to this key's own order.
    Key(u16),
    /// Relative to physical position in the file.
    Physical,
}

impl<M: Mem> Block<M> {
    /// Btrieve op 44, `Get By Percentage` -- pp. 83-87.
    ///
    /// `percentage` is p. 85's own 0-10,000 range (0.00% to 100.00%),
    /// clamped rather than refused for a value past 10,000 -- the
    /// Programmer's Reference states the valid range but not what happens
    /// outside it, and clamping to the nearest end is the smallest
    /// extrapolation past a documented range this crate makes elsewhere
    /// (compare [`Block::deliver_current`]'s truncation, which is the same
    /// shape: bring an out-of-range request back to the nearest answer
    /// this host can give rather than refuse it outright). The position
    /// formula (`percentage * count / 10,000`, clamped to the last record)
    /// is the natural reading of "a value in the range of 0... through
    /// 10,000" applied to a file of `count` records or key entries; the
    /// worked example on p. 82 (50% -> the middle record) is consistent
    /// with it but the exact rounding at the edges was not measured
    /// against a live engine.
    ///
    /// # Errors
    ///
    /// [`OpError::NoSuchKey`] for a [`PercentageBasis::Key`] the file does
    /// not have. [`OpError::EndOfFile`] -- status 9 -- for an empty file
    /// or an empty key order. [`OpError::LockModeMixed`]. If the records
    /// cannot be read.
    pub fn get_by_percentage(
        &mut self,
        basis: PercentageBasis,
        percentage: u16,
        lock: i16,
        locks: &mut LockTable,
        offered: u16,
    ) -> Result<Delivery, OpError> {
        let percentage = usize::from(percentage.min(10_000));
        match basis {
            PercentageBasis::Key(key) => {
                let count = if self.v6_fast_reads() {
                    if !self.keys().iter().any(|k| k.number == key) {
                        return Err(OpError::NoSuchKey(key));
                    }
                    self.v6_order_len(key)?
                } else {
                    self.records()?.ordered_len(key).ok_or(OpError::NoSuchKey(key))?
                };
                if count == 0 {
                    return Err(OpError::EndOfFile);
                }
                let at = (percentage * count / 10_000).min(count - 1);
                // Get by Percentage is the one keyed read genuinely addressed
                // by rank. On v6 it resolves that rank to a position through
                // the on-demand `OrderIndex` (the only op that still builds
                // it) and stores a `Positioned` cursor, so a following Get Next
                // continues positionally like every other v6 read.
                if self.v6_fast_reads() {
                    let position = self.v6_position_at(key, at)?.ok_or(OpError::EndOfFile)?;
                    self.seek_to(Cursor::Positioned { key, position });
                } else {
                    self.seek_to(Cursor::Ordered { key, at });
                }
                self.take_lock(lock, locks)?;
                self.deliver_current(Some(key), offered)
            }
            PercentageBasis::Physical => {
                let count = if self.v6_fast_reads() {
                    self.v6_physical_len()?
                } else {
                    self.records()?.len()
                };
                if count == 0 {
                    return Err(OpError::EndOfFile);
                }
                let at = (percentage * count / 10_000).min(count - 1);
                self.seek_to(Cursor::Physical { at });
                self.take_lock(lock, locks)?;
                self.deliver_current(None, offered)
            }
        }
    }
}

/// What [`Block::find_percentage`] is finding the position of -- the same
/// two shapes [`PercentageBasis`] positions by, carrying the value or the
/// address to look up rather than a percentage to land on. Kept as a
/// separate type rather than reusing [`PercentageBasis`] because Find
/// Percentage's inputs are a *value* (or an address) where Get By
/// Percentage's is a *percentage* -- the two operations are inverses, not
/// the same request read two ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindBasis {
    /// Where this key's value would sort, per p. 80's own procedure ("set
    /// the Key Buffer parameter to the key value").
    Key { key: u16, value: Vec<u8> },
    /// Where this physical address sits in the file.
    Physical(u32),
}

impl<M: Mem> Block<M> {
    /// Btrieve op 45, `Find Percentage` -- pp. 80-83, the inverse of
    /// [`Block::get_by_percentage`]: `at * 10,000 / count`, the natural
    /// inverse of that method's own formula, clamped into `0..=10_000` by
    /// construction (`at < count` always, since [`super::records::Records::
    /// seek`]/[`super::records::Records::find_physical`] both bound `at` by
    /// the order/file they search). Same rounding caveat as [`Block::
    /// get_by_percentage`]'s doc comment: consistent with the one worked
    /// example the Programmer's Reference gives, not measured against a
    /// live engine at the edges.
    ///
    /// **Does not change any currency** -- p. 83: "The Find Percentage
    /// operation does not change any currency information" -- so, unlike
    /// every positioning method above this one, this never calls
    /// [`Block::seek_to`].
    ///
    /// # Errors
    ///
    /// [`OpError::NoSuchKey`] for a [`FindBasis::Key`] the file does not
    /// have. [`OpError::InvalidRecordAddress`] -- status 43 -- for a
    /// [`FindBasis::Physical`] address naming no record. [`OpError::
    /// EndOfFile`] -- status 9 -- for an empty file or key order. If the
    /// records cannot be read.
    pub fn find_percentage(&mut self, basis: &FindBasis) -> Result<u16, OpError> {
        match basis {
            FindBasis::Key { key, value } => {
                if self.v6_fast_reads() {
                    if !self.keys().iter().any(|k| k.number == *key) {
                        return Err(OpError::NoSuchKey(*key));
                    }
                    let count = self.v6_order_len(*key)?;
                    if count == 0 {
                        return Err(OpError::EndOfFile);
                    }
                    // The lower-bound rank itself, not filtered to `None`
                    // the way `Op::AtLeast` is: a value past every entry
                    // this key holds still has a well-defined percentage
                    // (100%), which is exactly what `Bias::AtLeast`
                    // answering `None` (nothing found *at or after* it)
                    // means here -- the lower bound is `count`.
                    let at = self.v6_seek_rank(*key, nav::Bias::AtLeast, value)?.unwrap_or(count);
                    return Ok(((at as u64 * 10_000) / count as u64) as u16);
                }
                let definitions: Vec<Key> = self.keys().to_vec();
                let records = self.records()?;
                let count = records.ordered_len(*key).ok_or(OpError::NoSuchKey(*key))?;
                if count == 0 {
                    return Err(OpError::EndOfFile);
                }
                let at = records.seek(&definitions, *key, value).min(count);
                Ok(((at as u64 * 10_000) / count as u64) as u16)
            }
            FindBasis::Physical(position) => {
                if self.v6_fast_reads() {
                    let count = self.v6_physical_len()?;
                    if count == 0 {
                        return Err(OpError::EndOfFile);
                    }
                    let at = self
                        .v6_physical_rank_of(*position)?
                        .ok_or(OpError::InvalidRecordAddress)?;
                    return Ok(((at as u64 * 10_000) / count as u64) as u16);
                }
                let records = self.records()?;
                let count = records.len();
                if count == 0 {
                    return Err(OpError::EndOfFile);
                }
                let at = records.find_physical(*position).ok_or(OpError::InvalidRecordAddress)?;
                Ok(((at as u64 * 10_000) / count as u64) as u16)
            }
        }
    }
}

/// [`Block::extended_files`]'s answer -- Table 2-24 (p. 177), the extended-
/// files subfunction of Stat Extended (op 65). This host never splits a
/// file across extension files (that is a `create.rs`/`pages.rs` feature
/// this crate does not implement at all), so [`Self::files`] is always `1`
/// and [`Self::extensions`] is always empty -- the vendor's own defined
/// answer for a file that has none, not an invented one: "If you specify a
/// number higher than the number of extension files, the MicroKernel
/// returns Status Code 0 and no filenames" (p. 176), which is this host's
/// only possible case for every `first` past `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedFiles {
    /// Number of operating-system files that comprise the extended file --
    /// always `1` here.
    pub files: u32,
    /// Extension filenames past the base file -- always empty here.
    pub extensions: Vec<String>,
}

/// [`Block::system_data_stat`]'s answer -- Table 2-25 (p. 178), Stat
/// Extended's system-data subfunction. This host implements no
/// system-defined log key (key number 125, "system data") anywhere --
/// nothing in `keys.rs`/`create.rs` reads or writes one -- so the fixed
/// facts about it are all `false`/`0`; [`Self::is_loggable`] is the one
/// field genuinely computed, from whether the file has any key that
/// forbids duplicates, which is p. 178's own definition of loggable: "a
/// unique key that can be used to implement transaction durability... a
/// user-defined unique key or a system-defined log key."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemDataStat {
    /// Whether the file's records carry a system-defined log key -- always
    /// `false`.
    pub has_system_data: bool,
    /// Whether the system-defined log key is in use -- always `false`.
    pub has_log_key: bool,
    /// Whether the file has a unique key transaction durability could use.
    pub is_loggable: bool,
    /// The key number used as the transaction log key -- `0` here, since
    /// this host never designates one; real Btrieve reports `125` only
    /// when the system-defined log key specifically is in that role.
    pub log_key_number: u8,
    /// Size of the system-defined log key -- the vendor's own constant,
    /// p. 178: "which is 8."
    pub size: u16,
    /// The vendor's own constant, p. 178: "The constant 700 (0x2BC)."
    pub version: u16,
}

impl<M: Mem> Block<M> {
    /// Btrieve op 65, `Stat Extended`, extended-files subfunction
    /// (Subfunction `1`) -- pp. 175-178. `first` is p. 176's "First File
    /// Sequence" (`0` for the base file, `1` for the first extension, and
    /// so on); see [`ExtendedFiles`]'s own doc comment for why this host's
    /// answer never depends on it beyond that.
    pub fn extended_files(&self, first: u32) -> ExtendedFiles {
        let _ = first;
        ExtendedFiles { files: 1, extensions: Vec::new() }
    }

    /// Btrieve op 65, `Stat Extended`, system-data subfunction (Subfunction
    /// `2`) -- pp. 175-178. See [`SystemDataStat`]'s own doc comment.
    pub fn system_data_stat(&self) -> SystemDataStat {
        SystemDataStat {
            has_system_data: false,
            has_log_key: false,
            is_loggable: self.keys().iter().any(|key| !key.duplicates),
            log_key_number: 0,
            size: 8,
            version: 700,
        }
    }
}

/// Btrieve op `1019`, `Begin Transaction` in its **concurrent** form --
/// Programmer's Reference p. 38: "Set the Operation Code to 19 to begin an
/// exclusive transaction, or 1019 to begin a concurrent transaction." Op
/// 19's own exclusive form is [`crate::Btrieve::begin`]
/// (`btrieve.rs:2064`), out of this file's freeze, and this file does not
/// call it -- this function names only what a `1019` dispatcher needs to
/// know before it can decide anything else: **this engine cannot honour
/// it, at all, structurally.**
///
/// The design's own § 4 records the fact that motivates this task: op 19's
/// own lock granularity already changes by target file format --
/// whole-file on a pre-6.0 file, page/record on a 6.x one -- and 1019 is a
/// *third*, finer granularity again, concurrent rather than exclusive.
/// `Btrieve::begin` (`btrieve.rs:2064-2074`) is a single `bool` --
/// `self.transaction` -- that, the instant it goes true, marks **every**
/// currently open [`Block`] `txn_active` at once. There is no per-file, let
/// alone per-page or per-record, grain anywhere in that state for a
/// concurrent transaction's own conflict tracking to hang off of, and nothing
/// in that shape can be turned into one without adding new state to
/// `Btrieve` itself (`btrieve.rs`, out of this file's freeze this round).
/// This is categorically different from this task's other structural gap,
/// [`OpError::NccUnsupported`]: that one is a single [`Cursor`] field short
/// of expressing "physical moved, logical did not." This one is a whole
/// state machine `Btrieve` does not have at all, the same way [`OpError::
/// IndexMutationUnsupported`]'s gap is a whole per-key index `Records` does
/// not maintain incrementally.
///
/// **No real Btrieve status code names this**, deliberately not invented:
/// every real 6.x-or-later engine supports `1019` unconditionally (Btrieve
/// dropped 5.x-and-earlier engines' total absence of the concurrent form
/// long before this host's target modules were written), so the vendor has
/// never had to document what a concurrency-incapable *engine* answers --
/// only what a well-formed *request* can go wrong. This is a fact about
/// this host, not about the file or the request, the same shape
/// `Self::writable`'s v5-only-write refusal is: a host-level message
/// (`OpError`, here; `BtvError`, there), not a status code -- assigning the
/// status a module actually sees is Task 7's marshalling job, same as
/// every other [`OpError`] in this file.
///
/// # Errors
/// [`OpError::ConcurrentTransactionUnsupported`], always.
pub fn begin_concurrent_transaction() -> Result<(), OpError> {
    Err(OpError::ConcurrentTransactionUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Flat, FlatPtr};
    use crate::keys::{Kind, Segment};
    use crate::records::Records;
    use crate::{Geometry, Version, pages};
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
    /// The fixture's two key definitions, factored out of [`block`] so
    /// [`fixture_v6`] (Task 11) can build the same [`Records`] without
    /// duplicating this list.
    fn ops_keys() -> Vec<Key> {
        vec![
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
                modifiable: true,
                chain: None,
                            acs: None,
                            null: None,
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
                modifiable: true,
                chain: Some(8),
                            acs: None,
                            null: None,
},
        ]
    }

    fn ops_geometry() -> Geometry {
        Geometry {
            version: Version::V5,
            page: 512,
            keys: 2,
            reclen: RECLEN,
            physical: PHYSICAL,
            records: RECORDS.len() as u32,
            pages: 2,
            variable: false,
        }
    }

    fn block(path: PathBuf) -> Block<Flat> {
        Block {
            id: BlockId::fresh(),
            name: "OPS.DAT".to_owned(),
            path,
            geometry: ops_geometry(),
            keys: ops_keys(),
            block: FlatPtr::NULL,
            maxlen: RECLEN,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            bundle: crate::bundle::Bundle::default(),
            // A test-only fixture, not `Block::open` -- see
            // `Block::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that captures a mode at all.
            mode: crate::PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
        }
    }

    /// A fresh `Block` over `seed`'s six records, in its own scratch
    /// directory. `name` must be unique per call site -- `crate::testing::
    /// scratch` clears and recreates the directory it names, and this
    /// crate's tests run in parallel, so two tests sharing a name would
    /// each see the other rewrite `OPS.DAT` out from under it mid-read.
    fn fixture(name: &str) -> Block<Flat> {
        block(seed(&crate::testing::scratch(&format!("ops-{name}"))))
    }

    /// The same six records, but claiming to be a v6-format file --
    /// **Task 11's own test double for "this method's version gate must
    /// pass a genuinely-v6 file through," not a claim that this is what a
    /// real v6 file's bytes look like.** `seed`'s bytes are laid out for
    /// v5 (no 2-byte v6 slot marker, no `"PP"` allocation table -- building
    /// either is `v6.rs`/`pages.rs` work, out of this file's freeze), so
    /// [`Records::read`] is called against the *true* v5 geometry first, to
    /// parse correctly, and only then is the returned [`Block`]'s own
    /// [`Geometry::version`] flipped to [`Version::V6`] -- after
    /// [`Records`] is already built and cached in [`Block::records`], which
    /// [`Block::records`] (`btrieve.rs:849`) never re-derives once it is
    /// `Some`. So every test built on this fixture exercises exactly one
    /// thing genuinely: whether a method's own `geometry.version == V6`
    /// check lets a v6 file through -- not whether this host's v6 page
    /// walk is correct, which is measured elsewhere entirely
    /// (`docs/plans/2026-08-11-btrieve-v6-page-addressing.md`).
    fn fixture_v6(name: &str) -> Block<Flat> {
        let path = seed(&crate::testing::scratch(&format!("ops-{name}")));
        let read_geometry = ops_geometry();
        let keys = ops_keys();
        let records = Records::read("OPS.DAT", &path, &read_geometry, &keys)
            .expect("the fixture's own v5-shaped bytes parse under v5 rules");
        let mut geometry = read_geometry;
        geometry.version = Version::V6;
        Block {
            id: BlockId::fresh(),
            name: "OPS.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen: RECLEN,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: Some(records),
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            bundle: crate::bundle::Bundle::default(),
            // A test-only fixture, not `Block::open` -- see
            // `Block::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that captures a mode at all.
            mode: crate::PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
        }
    }

    /// A genuinely v6 fixture -- `V6EMPTY1KEY.DAT`, engine-built under Wine
    /// (`tools/btrieve-oracle/`, the same file `lib.rs`'s own `v6_scratch`
    /// uses), copied fresh into `name`'s own scratch directory and opened
    /// with its real geometry and keys. Unlike [`fixture_v6`], every byte on
    /// disk is really v6-shaped: a real `"FC"` control record, a real
    /// `"PP"` allocation table, and a key root carrying the v6 marker bit --
    /// so a write that reaches [`Block::update`]'s v6 path here exercises
    /// that path for real rather than hitting the marker-bit refusal
    /// [`fixture_v6`]'s synthetic bytes cannot avoid.
    fn fixture_v6_real(name: &str) -> Block<Flat> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let dir = crate::testing::scratch(&format!("ops-v6-{name}"));
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&fixture, &path).expect("the engine-built fixture copies into scratch");

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("a readable v6 file");
        let fcr = std::fs::read(&path).expect("the copy reads back");
        let keys = crate::keys::parse("V6EMPTY1KEY.DAT", &fcr, geometry.keys, &[])
            .expect("its key definitions parse");
        let maxlen = geometry.reclen;

        Block {
            id: BlockId::fresh(),
            name: "V6EMPTY1KEY.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            bundle: crate::bundle::Bundle::default(),
            // A test-only fixture, not `Block::open` -- see
            // `Block::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that captures a mode at all.
            mode: crate::PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Block::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
        }
    }

    /// [`fixture_v6_real`], with a real [`crate::cache::PageCache`]
    /// attached -- the one difference between the two that
    /// [`Block::v6_fast_reads`] actually checks (`self.cache.is_some()`),
    /// so this is what a caller needs to exercise the fast path rather
    /// than the `self.records()` one every other v6 fixture in this test
    /// module takes. `Block::open` builds this exact `cache` field for any
    /// real v6 file; this constructs it by hand for the same reason
    /// [`fixture_v6_real`] constructs the rest of `Block` by hand -- no
    /// `Btrieve`/heap/memory machinery needed for a test that only calls a
    /// `Block` method directly.
    fn fixture_v6_real_cached(name: &str) -> Block<Flat> {
        let mut block = fixture_v6_real(name);
        let cache = crate::cache::PageCache::open(&block.path, block.geometry.page)
            .expect("the same file fixture_v6_real just confirmed readable");
        block.cache = Some(std::rc::Rc::new(std::cell::RefCell::new(cache)));
        block
    }

    /// A 20-byte record shaped for `V6EMPTY1KEY.DAT`: `key` at bytes 0..4,
    /// `0xEE` filler for the rest -- the same shape `lib.rs`'s own
    /// `v6_record` uses on the same fixture.
    fn v6_real_record(key: &[u8; 4]) -> Vec<u8> {
        let mut bytes = vec![0xEEu8; 20];
        bytes[..4].copy_from_slice(key);
        bytes
    }

    fn tag(delivery: &Delivery) -> u8 {
        delivery.bytes[4]
    }

    /// A record buffer in the fixture's own layout (`key0: u16 @0`, `key1:
    /// u16 @2`, `tag: u8 @4`), for Task 11's insert tests.
    fn ops_record(key0: u16, key1: u16, tag: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; RECLEN as usize];
        bytes[0..2].copy_from_slice(&key0.to_le_bytes());
        bytes[2..4].copy_from_slice(&key1.to_le_bytes());
        bytes[4] = tag;
        bytes
    }

    // -- Op::Equal / Greater / AtLeast / Less / AtMost / Lowest / Highest --

    #[test]
    fn get_equal_on_a_unique_key_finds_the_one_record() {
        let mut b = fixture("get_equal_on_a_unique_key_finds_the_one_record");
        let mut locks = LockTable::default();
        let d = b
            .get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN)
            .expect("no error")
            .expect("found");
        assert_eq!(tag(&d), 2);
    }

    #[test]
    fn get_equal_that_finds_nothing_leaves_the_cursor_where_it_was() {
        let mut b = fixture("get_equal_that_finds_nothing_leaves_the_cursor_where_it_was");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 2 });

        let miss = b.get(0, Op::Equal, &999u16.to_le_bytes(), 0, &mut locks, RECLEN).expect("no error");
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
        let d = b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_next_after_equal_on_a_duplicate_continues_to_the_next_match() {
        let mut b = fixture("get_next_after_equal_on_a_duplicate_continues_to_the_next_match");
        let mut locks = LockTable::default();
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the second key-1=1 match, tag 2");
    }

    #[test]
    fn get_greater_lands_past_every_equal_record_not_on_the_first_one() {
        let mut b = fixture("get_greater_lands_past_every_equal_record_not_on_the_first_one");
        let mut locks = LockTable::default();
        // key 1 = 1 matches two records (tags 0, 2); Greater must skip both.
        let d = b.get(1, Op::Greater, &1u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_ne!(tag(&d), 0);
        assert_ne!(tag(&d), 2, "Greater must not land on an equal record");
    }

    #[test]
    fn get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group() {
        let mut b = fixture("get_at_most_lands_on_the_last_equal_record_of_a_duplicate_group");
        let mut locks = LockTable::default();
        let d = b.get(1, Op::AtMost, &1u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "the last of the two key-1=1 records");
    }

    #[test]
    fn get_lowest_and_highest_find_the_ends_of_key_0() {
        let mut b = fixture("get_lowest_and_highest_find_the_ends_of_key_0");
        let mut locks = LockTable::default();
        assert_eq!(tag(&b.get(0, Op::Lowest, &[], 0, &mut locks, RECLEN).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.get(0, Op::Highest, &[], 0, &mut locks, RECLEN).unwrap().unwrap()), 5);
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
        let d = b.get(0, Op::Next, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_previous_with_nothing_positioned_answers_not_found() {
        // S1c: measured status 9 ("not found"), not a refusal and not
        // Highest either.
        let mut b = fixture("get_previous_with_nothing_positioned_answers_not_found");
        let mut locks = LockTable::default();
        let d = b.get(0, Op::Previous, &[], 0, &mut locks, RECLEN).unwrap();
        assert!(d.is_none());
    }

    #[test]
    fn get_next_on_a_different_key_than_the_current_position_is_refused() {
        // S6: Get Equal on key 0 (tag 2), then Get Next on key 1 -- real
        // Btrieve status 7, not a translation into key 1's order.
        let mut b = fixture("get_next_on_a_different_key_than_the_current_position_is_refused");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let err = b.get(1, Op::Next, &[], 0, &mut locks, RECLEN).expect_err("a different key is refused");
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
        b.step(Step::First, 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Physical { at: 0 });
        let err = b.get(1, Op::Next, &[], 0, &mut locks, RECLEN).expect_err("a physical step establishes no key");
        assert_eq!(err, OpError::NoKeyEstablished);
        let err0 = b.get(0, Op::Next, &[], 0, &mut locks, RECLEN).expect_err("neither key continues after a step");
        assert_eq!(err0, OpError::NoKeyEstablished);
    }

    #[test]
    fn get_next_at_end_of_file_fails_but_leaves_the_cursor_there() {
        let mut b = fixture("get_next_at_end_of_file_fails_but_leaves_the_cursor_there");
        let mut locks = LockTable::default();
        b.get(0, Op::Highest, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(b.cursor(), Cursor::Ordered { key: 0, at: 5 });
        let miss = b.get(0, Op::Next, &[], 0, &mut locks, RECLEN).expect("no error");
        assert!(miss.is_none());
        assert_eq!(
            b.cursor(),
            Cursor::Ordered { key: 0, at: 5 },
            "S2: the cursor stays on the last record a successful call found"
        );
        // And Get Previous from there steps back to the record before it.
        let d = b.get(0, Op::Previous, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 4);
    }

    // -- Step --

    #[test]
    fn step_walks_physical_order_not_key_order() {
        let mut b = fixture("step_walks_physical_order_not_key_order");
        let mut locks = LockTable::default();
        // Physical order is insertion order here (tags 0..6, in slot
        // order), which key 1's order is NOT (see the fixture table).
        let first = b.step(Step::First, 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&first), 0);
        let next = b.step(Step::Next, 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(next.key, None, "a step has no key");
        assert_eq!(tag(&next), 1, "physical slot 1, tag 1 -- not key 1's next (tag 2)");
    }

    #[test]
    fn step_first_and_last_find_the_physical_ends() {
        let mut b = fixture("step_first_and_last_find_the_physical_ends");
        let mut locks = LockTable::default();
        assert_eq!(tag(&b.step(Step::First, 0, &mut locks, RECLEN).unwrap().unwrap()), 0);
        assert_eq!(tag(&b.step(Step::Last, 0, &mut locks, RECLEN).unwrap().unwrap()), 5);
    }

    #[test]
    fn step_next_past_end_of_file_finds_nothing() {
        let mut b = fixture("step_next_past_end_of_file_finds_nothing");
        let mut locks = LockTable::default();
        b.step(Step::Last, 0, &mut locks, RECLEN).unwrap().unwrap();
        assert!(b.step(Step::Next, 0, &mut locks, RECLEN).unwrap().is_none());
    }

    #[test]
    fn step_next_from_cold_is_the_first_record_and_previous_is_end_of_file() {
        // A file with no position sits *before the first record*: a cold
        // `Step-Next` returns the first record, a cold `Step-Previous` is
        // already at end-of-file. Measured against genuine Btrieve 6.15
        // (`tools/btrieve-oracle` `stepcold`): `B_STEP_NEXT` on a fresh open
        // answers status 0 with record 0, `B_STEP_PREV` answers status 9.
        let mut b = fixture("step_next_from_cold_is_the_first_record_and_previous_is_end_of_file");
        let mut locks = LockTable::default();
        let cold = b.step(Step::Next, 0, &mut locks, RECLEN).unwrap().expect("cold next = first");
        // Same record `Step::First` reaches, from a fresh file.
        let mut b2 = fixture("step_next_from_cold_is_the_first_record_and_previous_is_end_of_file_b");
        let first = b2.step(Step::First, 0, &mut locks, RECLEN).unwrap().expect("first");
        assert_eq!(tag(&cold), tag(&first), "cold Step-Next lands on the first record");
        // A cold Step-Previous is end-of-file, not a refusal.
        let mut b3 = fixture("step_next_from_cold_is_the_first_record_and_previous_is_end_of_file_c");
        assert!(
            b3.step(Step::Previous, 0, &mut locks, RECLEN).unwrap().is_none(),
            "cold Step-Previous is end-of-file"
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
        b.get(1, Op::Equal, &1u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let d = b.get(1, Op::Next, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&d), 2, "key 1 = 1's second match");
        let d = b.step(Step::Next, 0, &mut locks, RECLEN).unwrap().unwrap();
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
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
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
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let position = b.get_position().unwrap();
        b.seek_to(Cursor::Nowhere); // as though nothing had positioned it

        let direct = b.acquire_absolute(position, 1, 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&direct), 2);
        assert_eq!(direct.key.as_deref(), Some(&1u16.to_le_bytes()[..]));

        let next = b.get(1, Op::Next, &[], 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(tag(&next), 1, "key 1's own next record after tag 2, not key 0's (tag 3)");
    }

    #[test]
    fn acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor() {
        let mut b = fixture("acquire_absolute_at_an_unknown_position_finds_nothing_and_keeps_the_cursor");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let before = b.cursor();
        let miss = b.acquire_absolute(999_999, 0, 0, &mut locks, RECLEN).expect("no error");
        assert!(miss.is_none());
        assert_eq!(b.cursor(), before);
    }

    #[test]
    fn acquire_absolute_refuses_a_key_the_file_does_not_have() {
        let mut b = fixture("acquire_absolute_refuses_a_key_the_file_does_not_have");
        let mut locks = LockTable::default();
        let position = {
            b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap();
            b.get_position().unwrap()
        };
        assert_eq!(
            b.acquire_absolute(position, 2, 0, &mut locks, RECLEN).expect_err("only keys 0 and 1 exist"),
            OpError::NoSuchKey(2)
        );
    }

    /// The cached-v6 (fast-path) sibling of the refusal above --
    /// **failing-first for the bug this task's re-review found.**
    /// `resolve_cursor` used to trust its two callers to bounds-check
    /// `key` first, and `Block::acquire_absolute` did not: on a cached v6
    /// block an out-of-range key fell straight into
    /// `Block::v6_record_bytes_at`, which surfaces as a generic
    /// `OpError::Records` (a run-halting failure one layer up), not this
    /// file's ordinary status-6 `OpError::NoSuchKey`. On the slow path
    /// (the test above) the same missing check meant the refusal, when it
    /// happened at all, came from `Block::deliver_current` -- after
    /// `Block::acquire_absolute` had already called `Block::seek_to`/
    /// `Block::take_lock`. Reverting `resolve_cursor`'s bounds check (this
    /// commit's own fix) reproduces both: this assertion fails with
    /// `OpError::Records(..)` instead of `OpError::NoSuchKey(1)`.
    #[test]
    fn acquire_absolute_on_a_cached_v6_block_refuses_an_out_of_range_key_before_touching_anything() {
        let mut b = fixture_v6_real_cached("acquire_absolute_cached_refuses_out_of_range_key");
        assert!(b.v6_fast_reads(), "this fixture must exercise the fast path, not the one above's");
        let mut locks = LockTable::default();
        let before = b.cursor();

        let err = b
            .acquire_absolute(0, 1, 100, &mut locks, RECLEN)
            .expect_err("V6EMPTY1KEY.DAT has one key, numbered 0 -- key 1 does not exist");
        assert_eq!(err, OpError::NoSuchKey(1));

        assert_eq!(b.cursor(), before, "a refused Acquire Absolute must not move the cursor");
        assert!(locks.is_empty(), "a refused Acquire Absolute must not take a lock either");
    }

    // -- Locking: the state machine, `docs/lock-oracle-answer.md` --

    #[test]
    fn a_single_lock_auto_releases_when_the_session_takes_another_single_lock() {
        // Measured: "Lock key 1, then key 2: an outside observer sees key 1
        // free and key 2 held."
        let mut b = fixture("a_single_lock_auto_releases_when_the_session_takes_another_single_lock");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks, RECLEN).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 100, &mut locks, RECLEN).unwrap().unwrap();
        let held = b.current().unwrap().position;

        assert_eq!(locks.get(b.id(), a), None, "the first lock auto-released");
        assert_eq!(locks.get(b.id(), held), Some(100), "the second is held");
    }

    #[test]
    fn a_multiple_lock_accumulates() {
        // Measured: "lock two records and both stay held."
        let mut b = fixture("a_multiple_lock_accumulates");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let bb = b.current().unwrap().position;

        assert_eq!(locks.get(b.id(), a), Some(300), "the first stays held");
        assert_eq!(locks.get(b.id(), bb), Some(300), "the second is held too");
    }

    /// [`LockTable::release_all_for`] must release **only** the block it is
    /// given.
    ///
    /// **A measured gap, not a hypothetical.** Every other lock test in this
    /// module uses a single [`Block`], so none of them could tell a
    /// per-block release from a global one. Replacing the body with
    /// `self.held.clear()` -- so closing one file released every *other*
    /// file's locks too -- left the entire suite of 1358 green.
    ///
    /// That is the shape those tests share rather than a gap in any one of
    /// them, which is why this test opens a second file and does nothing
    /// else interesting: two blocks is the only thing the rest of the module
    /// never does.
    #[test]
    fn closing_one_file_leaves_another_files_locks_alone() {
        let mut one = fixture("closing_one_file_leaves_another_alone_one");
        let mut two = fixture("closing_one_file_leaves_another_alone_two");
        let mut locks = LockTable::default();

        one.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let in_one = one.current().unwrap().position;
        two.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let in_two = two.current().unwrap().position;

        locks.release_all_for(one.id());

        assert_eq!(
            locks.get(one.id(), in_one),
            None,
            "the closed file's own lock is released"
        );
        assert_eq!(
            locks.get(two.id(), in_two),
            Some(300),
            "and the other file's lock is untouched -- a release is per block"
        );
    }

    /// [`Block::get`]'s own lock tests above all go through `get` -- every
    /// one of `step`/`acquire_absolute`'s own `take_lock` calls was
    /// otherwise unreached by anything asserting on a *held* lock (only on
    /// the old blanket refusal, gone now). Measured: deleting either call
    /// entirely left the whole suite green. These two close that gap.
    #[test]
    fn step_takes_a_lock_at_the_position_it_lands_on() {
        let mut b = fixture("step_takes_a_lock_at_the_position_it_lands_on");
        let mut locks = LockTable::default();

        b.step(Step::First, 100, &mut locks, RECLEN).unwrap().unwrap();
        let position = b.current().unwrap().position;
        assert_eq!(locks.get(b.id(), position), Some(100));
    }

    #[test]
    fn acquire_absolute_takes_a_lock_at_the_position_it_lands_on() {
        let mut b = fixture("acquire_absolute_takes_a_lock_at_the_position_it_lands_on");
        let mut locks = LockTable::default();

        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        let position = b.get_position().unwrap();
        b.seek_to(Cursor::Nowhere);

        b.acquire_absolute(position, 1, 100, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(locks.get(b.id(), position), Some(100));
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

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks, RECLEN).unwrap().unwrap();
        let single = b.current().unwrap().position;

        let err = b
            .get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks, RECLEN)
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
        b.get(0, Op::Equal, &20u16.to_le_bytes(), 300, &mut locks, RECLEN)
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

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let err = b
            .get(0, Op::Equal, &20u16.to_le_bytes(), 100, &mut locks, RECLEN)
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

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let a = b.current().unwrap().position;
        b.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN)
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
            .get(0, Op::Equal, &999u16.to_le_bytes(), 100, &mut locks, RECLEN)
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

        b.get(0, Op::Equal, &10u16.to_le_bytes(), 100, &mut locks, RECLEN).unwrap().unwrap();
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
    fn a_record_longer_than_the_offered_buffer_is_delivered_truncated() {
        let mut b = fixture("a_record_longer_than_the_offered_buffer_is_delivered_truncated");
        let mut locks = LockTable::default();
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, 4).unwrap().unwrap();
        assert_eq!(d.bytes.len(), 4);
        assert!(d.truncated);
    }

    #[test]
    fn a_record_no_longer_than_the_offered_buffer_is_not_marked_truncated() {
        let mut b = fixture("a_record_no_longer_than_the_offered_buffer_is_not_marked_truncated");
        let mut locks = LockTable::default();
        let d = b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap().unwrap();
        assert_eq!(d.bytes.len(), usize::from(RECLEN));
        assert!(!d.truncated);
    }

    /// The block's own `maxlen` is the *module's* buffer, read directly by
    /// `crates/mbbs`'s shims and by nothing here. A delivery that still
    /// consulted it would either starve a wire caller that offered more (the
    /// genuine wire's Open declares `0`) or overrun one that offered less --
    /// so it is set to both extremes here and neither is allowed to move the
    /// answer.
    #[test]
    fn the_blocks_own_maxlen_does_not_bound_a_delivery() {
        let mut locks = LockTable::default();

        let mut starved = fixture("the_blocks_own_maxlen_does_not_bound_a_delivery_starved");
        starved.maxlen = 0;
        let d = starved
            .get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN)
            .unwrap()
            .unwrap();
        assert_eq!(d.bytes.len(), usize::from(RECLEN), "maxlen 0 starved the delivery");
        assert!(!d.truncated);

        let mut generous = fixture("the_blocks_own_maxlen_does_not_bound_a_delivery_generous");
        generous.maxlen = u16::MAX;
        let d = generous
            .get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, 4)
            .unwrap()
            .unwrap();
        assert_eq!(d.bytes.len(), 4, "maxlen overrode the caller's own buffer");
        assert!(d.truncated);
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

    /// Task 10's own deliverable for `+50`, "Get Key": establishing that the
    /// *raw op codes* 55-63 already route to the right comparison, per this
    /// task's own instruction ("this task is therefore about the raw op
    /// code, not new semantics"). The generic loop above already proves the
    /// arithmetic; this pins the literal numbers a caller reads off the
    /// wire, matched against the alphabetical listing in `Get Key (+50)`'s
    /// own entry, Programmer's Reference pp. 113-115 ("Get Key/Get Equal
    /// (55)" through the implied 63 for Get Last).
    #[test]
    fn get_key_op_codes_55_to_63_are_fifty_above_the_named_get_operations() {
        let table = [
            (55, Op::Equal),    // Get Key / Get Equal
            (56, Op::Next),     // Get Key / Get Next
            (57, Op::Previous), // Get Key / Get Previous
            (58, Op::Greater),  // Get Key / Get Greater
            (59, Op::AtLeast),  // Get Key / Get Greater Than or Equal
            (60, Op::Less),     // Get Key / Get Less Than
            (61, Op::AtMost),   // Get Key / Get Less Than or Equal
            (62, Op::Lowest),   // Get Key / Get First
            (63, Op::Highest),  // Get Key / Get Last
        ];
        for (code, op) in table {
            assert_eq!(Op::from_query(code), Some(op), "raw code {code}");
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

    // -- Task 10: the cheap operation-code families --

    // Version (26)

    #[test]
    fn engine_version_encodes_little_endian_matching_the_worked_example() {
        // Programmer's Reference p. 215: Btrieve for NetWare 7.0 answers
        // "07 00 00 00 53" -- version 7, revision 0, engine 'S' (NetWare
        // server, Table 2-29).
        let v = EngineVersion { version: 7, revision: 0, engine: b'S' };
        assert_eq!(v.encode(), [0x07, 0x00, 0x00, 0x00, 0x53]);
    }

    #[test]
    fn engine_version_encodes_a_nonzero_revision() {
        let v = EngineVersion { version: 6, revision: 15, engine: b'S' };
        assert_eq!(v.encode(), [0x06, 0x00, 0x0F, 0x00, 0x53]);
    }

    // Set Directory (17) / Get Directory (18)

    #[test]
    fn get_directory_on_a_fresh_working_directory_is_just_the_terminator() {
        let dir = WorkingDirectory::default();
        assert_eq!(dir.get(), vec![0u8]);
    }

    #[test]
    fn set_directory_with_an_absolute_path_replaces_it() {
        let mut dir = WorkingDirectory::new(*b"/old/place");
        dir.set(b"/rooms/newhaven").unwrap();
        assert_eq!(dir.get(), b"/rooms/newhaven\0".to_vec());
    }

    #[test]
    fn set_directory_with_a_relative_path_appends_to_the_current_one() {
        // p. 163: "the MicroKernel appends the directory path specified in
        // the Key Buffer to the current directory."
        let mut dir = WorkingDirectory::new(*b"/rooms");
        dir.set(b"newhaven").unwrap();
        assert_eq!(dir.get(), b"/rooms/newhaven\0".to_vec());
    }

    #[test]
    fn set_directory_with_an_empty_path_is_refused() {
        let mut dir = WorkingDirectory::default();
        assert_eq!(dir.set(b""), Err(OpError::InvalidDirectory));
    }

    #[test]
    fn directory_op_from_code_matches_the_published_pair() {
        assert_eq!(DirectoryOp::from_code(17), Some(DirectoryOp::Set));
        assert_eq!(DirectoryOp::from_code(18), Some(DirectoryOp::Get));
        assert_eq!(DirectoryOp::from_code(19), None, "19 is Begin Transaction, not a directory op");
    }

    /// Task 10's own named mutation: swap Set Directory and Get Directory.
    /// Dispatching `Set` must change what a following `Get` reports, and a
    /// swapped `dispatch` -- `Set` reading instead of writing, `Get` writing
    /// instead of reading -- must fail this.
    #[test]
    fn directory_dispatch_routes_set_and_get_to_the_right_halves() {
        let mut dir = WorkingDirectory::default();
        let set_reply = dir.dispatch(DirectoryOp::Set, b"/rooms").unwrap();
        assert_eq!(set_reply, Vec::<u8>::new(), "Set Directory returns nothing in the Data Buffer");

        let get_reply = dir.dispatch(DirectoryOp::Get, b"").unwrap();
        assert_eq!(
            get_reply,
            b"/rooms\0".to_vec(),
            "a swapped dispatch would leave the directory unset here"
        );
    }

    #[test]
    fn directory_dispatch_mutation_swap_is_caught() {
        // The mutation itself, inlined: if `Set`/`Get` traded bodies, the
        // first call below is a no-op read (state never changes) and the
        // second is a write attempt with an empty path, which
        // `WorkingDirectory::set` refuses -- so the swapped version returns
        // `Err` where this test expects `Ok`.
        fn swapped(dir: &mut WorkingDirectory, op: DirectoryOp, path: &[u8]) -> Result<Vec<u8>, OpError> {
            match op {
                DirectoryOp::Set => Ok(dir.get()),
                DirectoryOp::Get => {
                    dir.set(path)?;
                    Ok(Vec::new())
                }
            }
        }
        let mut dir = WorkingDirectory::default();
        swapped(&mut dir, DirectoryOp::Set, b"/rooms").unwrap();
        let result = swapped(&mut dir, DirectoryOp::Get, b"");
        assert!(result.is_err(), "the swapped dispatch fails, which is exactly the finding");
    }

    // Set Owner (29) / Clear Owner (30)

    #[test]
    fn access_code_from_code_matches_table_2_19() {
        assert_eq!(AccessCode::from_code(0), Some(AccessCode::RequireForAnyAccess));
        assert_eq!(AccessCode::from_code(1), Some(AccessCode::PermitReadOnly));
        assert_eq!(AccessCode::from_code(2), Some(AccessCode::RequireForAnyAccessEncrypted));
        assert_eq!(AccessCode::from_code(3), Some(AccessCode::PermitReadOnlyEncrypted));
        assert_eq!(AccessCode::from_code(4), None);
    }

    #[test]
    fn owner_op_from_code_matches_the_published_pair() {
        assert_eq!(OwnerOp::from_code(29), Some(OwnerOp::Set));
        assert_eq!(OwnerOp::from_code(30), Some(OwnerOp::Clear));
        assert_eq!(OwnerOp::from_code(31), None, "31 is Create Index, not an owner op");
    }

    #[test]
    fn set_owner_then_get_returns_the_name_and_access_code() {
        let b = fixture("set_owner_then_get_returns_the_name_and_access_code");
        let mut owners = OwnerTable::default();
        b.set_owner(b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners).unwrap();
        assert_eq!(owners.name(b.id()), Some(&b"SYSOP"[..]));
        assert_eq!(owners.access(b.id()), Some(AccessCode::RequireForAnyAccess));
    }

    #[test]
    fn set_owner_twice_is_refused_with_owner_already_set() {
        let b = fixture("set_owner_twice_is_refused_with_owner_already_set");
        let mut owners = OwnerTable::default();
        b.set_owner(b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners).unwrap();
        assert_eq!(
            b.set_owner(b"OTHER", AccessCode::RequireForAnyAccess, &mut owners),
            Err(OpError::OwnerAlreadySet)
        );
        assert_eq!(owners.name(b.id()), Some(&b"SYSOP"[..]), "the refused call did not overwrite it");
    }

    #[test]
    fn set_owner_with_a_name_longer_than_eight_bytes_is_refused() {
        let b = fixture("set_owner_with_a_name_longer_than_eight_bytes_is_refused");
        let mut owners = OwnerTable::default();
        assert_eq!(
            b.set_owner(b"TOOLONGNAME", AccessCode::RequireForAnyAccess, &mut owners),
            Err(OpError::OwnerNameInvalid { len: 11 })
        );
        assert_eq!(owners.name(b.id()), None);
    }

    #[test]
    fn set_owner_during_a_transaction_is_refused() {
        let mut b = fixture("set_owner_during_a_transaction_is_refused");
        b.txn_active = true;
        let mut owners = OwnerTable::default();
        assert_eq!(
            b.set_owner(b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners),
            Err(OpError::NotAllowedDuringTransaction)
        );
    }

    #[test]
    fn clear_owner_removes_a_set_owner() {
        let b = fixture("clear_owner_removes_a_set_owner");
        let mut owners = OwnerTable::default();
        b.set_owner(b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners).unwrap();
        b.clear_owner(&mut owners).unwrap();
        assert_eq!(owners.name(b.id()), None);
    }

    /// **A measured gap, not a hypothetical** -- mirrors [`LockTable`]'s own
    /// `closing_one_file_leaves_another_files_locks_alone` for exactly the
    /// same reason it exists: every other owner test in this module uses a
    /// single [`Block`], so none of them could tell a per-block
    /// [`OwnerTable::clear`] from a global one. Replacing the body with
    /// `self.set.clear()` -- so clearing one file's owner cleared every
    /// *other* file's too -- left the rest of this file's own suite green
    /// (60 passed, 0 failed), measured while writing this task.
    #[test]
    fn clear_owner_releases_only_the_named_blocks_owner() {
        let one = fixture("clear_owner_releases_only_the_named_blocks_owner_one");
        let two = fixture("clear_owner_releases_only_the_named_blocks_owner_two");
        let mut owners = OwnerTable::default();

        one.set_owner(b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners).unwrap();
        two.set_owner(b"OTHER", AccessCode::RequireForAnyAccess, &mut owners).unwrap();

        one.clear_owner(&mut owners).unwrap();

        assert_eq!(owners.name(one.id()), None, "the cleared file's own owner is gone");
        assert_eq!(
            owners.name(two.id()),
            Some(&b"OTHER"[..]),
            "and the other file's owner is untouched -- a clear is per block"
        );
    }

    #[test]
    fn clear_owner_with_nothing_set_is_a_harmless_no_op() {
        let b = fixture("clear_owner_with_nothing_set_is_a_harmless_no_op");
        let mut owners = OwnerTable::default();
        b.clear_owner(&mut owners).expect("no prerequisite that an owner exists");
    }

    #[test]
    fn clear_owner_during_a_transaction_is_refused() {
        let mut b = fixture("clear_owner_during_a_transaction_is_refused");
        b.txn_active = true;
        let mut owners = OwnerTable::default();
        assert_eq!(b.clear_owner(&mut owners), Err(OpError::NotAllowedDuringTransaction));
    }

    /// Task 10's own named mutation: swap Set Owner and Clear Owner.
    #[test]
    fn owner_dispatch_routes_set_and_clear_to_the_right_halves() {
        let b = fixture("owner_dispatch_routes_set_and_clear_to_the_right_halves");
        let mut owners = OwnerTable::default();

        b.owner(OwnerOp::Set, b"SYSOP", AccessCode::RequireForAnyAccess, &mut owners)
            .expect("Set assigns an owner");
        assert_eq!(
            owners.name(b.id()),
            Some(&b"SYSOP"[..]),
            "a swapped dispatch would run Clear here and leave no owner set"
        );

        b.owner(OwnerOp::Clear, b"", AccessCode::RequireForAnyAccess, &mut owners)
            .expect("Clear removes it");
        assert_eq!(
            owners.name(b.id()),
            None,
            "a swapped dispatch would run Set here (again) and leave the owner in place"
        );
    }

    // Extend (16)

    #[test]
    fn extend_succeeds_for_a_v5_file() {
        let b = fixture("extend_succeeds_for_a_v5_file");
        assert_eq!(b.geometry().version, Version::V5, "the fixture is v5 by construction");
        b.extend().expect("v5's file-size ceiling does not exist on this host");
    }

    #[test]
    fn extend_is_refused_for_a_v6_file() {
        let mut b = fixture("extend_is_refused_for_a_v6_file");
        b.geometry.version = Version::V6;
        assert_eq!(b.extend(), Err(OpError::ObsoleteOperation));
    }

    // Reset (28) -- the one third of it this file owns

    #[test]
    fn lock_table_clear_all_releases_every_locked_block_not_just_one() {
        let mut one = fixture("lock_table_clear_all_releases_every_locked_block_not_just_one_one");
        let mut two = fixture("lock_table_clear_all_releases_every_locked_block_not_just_one_two");
        let mut locks = LockTable::default();

        one.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let in_one = one.current().unwrap().position;
        two.get(0, Op::Equal, &10u16.to_le_bytes(), 300, &mut locks, RECLEN).unwrap().unwrap();
        let in_two = two.current().unwrap().position;

        locks.clear_all();

        assert_eq!(locks.get(one.id(), in_one), None, "Reset releases all locks held (p. 162)");
        assert_eq!(
            locks.get(two.id(), in_two),
            None,
            "clear_all is session-wide, unlike release_all_for's per-block scope"
        );
    }

    // -- Task 11: the version-gated operation families --

    // Get Direct/Chunk (23-chunk) / Update Chunk (53)

    #[test]
    fn get_chunks_on_a_pre_v6_file_is_refused_with_status_107() {
        let mut b = fixture("get_chunks_on_a_pre_v6_file_is_refused_with_status_107");
        assert_eq!(b.geometry().version, Version::V5, "the fixture is v5 by construction");
        let err = b
            .get_chunks(0, &[Chunk { offset: 0, length: 1 }])
            .expect_err("a chunk operation on a pre-v6 file");
        assert_eq!(err, OpError::PreV6Chunk);
    }

    #[test]
    fn get_chunks_on_a_v6_file_extracts_the_named_bytes() {
        let mut b = fixture_v6("get_chunks_on_a_v6_file_extracts_the_named_bytes");
        let position = b.records().unwrap().physical(0).unwrap().position;
        let bytes = b
            .get_chunks(position, &[Chunk { offset: 0, length: 2 }, Chunk { offset: 4, length: 1 }])
            .expect("a v6 file, both chunks in range");
        assert_eq!(bytes, vec![10, 0, 0], "key0=10 little-endian, then tag=0");
    }

    #[test]
    fn get_chunks_a_chunk_beginning_past_the_end_of_the_record_is_refused() {
        let mut b = fixture_v6("get_chunks_a_chunk_beginning_past_the_end_of_the_record_is_refused");
        let position = b.records().unwrap().physical(0).unwrap().position;
        let err = b
            .get_chunks(position, &[Chunk { offset: 100, length: 1 }])
            .expect_err("p. 98: begins beyond the end of the record -- status 103");
        assert_eq!(err, OpError::ChunkOffsetTooBig);
    }

    #[test]
    fn get_chunks_a_chunk_that_only_overruns_is_truncated_and_processing_stops() {
        let mut b = fixture_v6("get_chunks_a_chunk_that_only_overruns_is_truncated_and_processing_stops");
        let position = b.records().unwrap().physical(0).unwrap().position;
        // The fixture's record is 8 bytes; offset 6, length 4 overruns by 2.
        let bytes = b
            .get_chunks(
                position,
                &[Chunk { offset: 6, length: 4 }, Chunk { offset: 0, length: 2 }],
            )
            .expect("p. 98: status 0, but ceases processing subsequent chunks");
        assert_eq!(bytes.len(), 2, "only the 2 bytes remaining of the overrunning chunk");
    }

    #[test]
    fn get_chunks_a_chunk_starting_exactly_at_the_records_end_is_refused() {
        // The boundary `offset == record length` (not past it): "begins
        // beyond the end" (status 103) means at-or-past one-past-the-last
        // byte, not strictly past it -- a chunk of any positive length
        // starting there has nothing to read. Mutation-found: `start >=
        // bytes.len()` weakened to `start > bytes.len()` passed every other
        // test in this file (RECLEN=8, and no other test used offset 8
        // exactly), returning `Ok(vec![])` instead of refusing.
        let mut b = fixture_v6("get_chunks_a_chunk_starting_exactly_at_the_records_end_is_refused");
        let position = b.records().unwrap().physical(0).unwrap().position;
        let err = b
            .get_chunks(position, &[Chunk { offset: RECLEN.into(), length: 1 }])
            .expect_err("offset == record length has nothing to read");
        assert_eq!(err, OpError::ChunkOffsetTooBig);
    }

    #[test]
    fn get_chunks_on_an_invalid_position_is_refused() {
        let mut b = fixture_v6("get_chunks_on_an_invalid_position_is_refused");
        let err = b
            .get_chunks(999_999, &[Chunk { offset: 0, length: 1 }])
            .expect_err("no record at that position");
        assert_eq!(err, OpError::InvalidRecordAddress);
    }

    #[test]
    fn update_chunks_on_a_pre_v6_file_is_refused_with_status_107() {
        let mut b = fixture("update_chunks_on_a_pre_v6_file_is_refused_with_status_107");
        let err = b.update_chunks(&[(4, vec![9])]).expect_err("a chunk operation on a pre-v6 file");
        assert_eq!(err, OpError::PreV6Chunk);
    }

    /// v6 chunk update on a **genuinely** v6 file succeeds.
    ///
    /// The predecessor to this test, `update_chunks_on_a_v6_file_passes_
    /// the_gate_and_reaches_the_still_refused_v6_write`, ran against
    /// [`fixture_v6`] -- v5 bytes on disk with `geometry.version` force-set
    /// to `V6` in memory -- and asserted an error, naming it "the pre-
    /// existing v6-write refusal". That was true of the error but not of
    /// the reason: v5 bytes have no `"PP"` allocation table and no v6
    /// marker bit on the key root, so the write it actually hit was
    /// [`Block::v6_reindex`]'s "root does not carry the v6 marker bit"
    /// check (`lib.rs`, refusal #7 in `tmp/plan-3-update-survey.md`), which
    /// is a real refusal but not "v6 write does not exist" -- v6 write was
    /// implemented in a later task and this test never noticed, because a
    /// fake-v6 fixture cannot tell the two refusals apart. [`fixture_v6_real`]
    /// is a genuine engine-built v6 file, so this test exercises the real
    /// predicate: chunked update on a v6 file reaches [`Block::update`]'s
    /// v6 path and succeeds.
    #[test]
    fn update_chunks_on_a_genuinely_v6_file_succeeds() {
        let mut b = fixture_v6_real("update_chunks_on_a_genuinely_v6_file_succeeds");
        let position = b.insert(&v6_real_record(b"AAAA")).expect("insert into the real v6 fixture");
        let at = b.records().expect("just inserted").find_physical(position).expect("just inserted");
        b.seek_to(Cursor::Physical { at });

        // Offset 8 is past the 4-byte key at 0..4, so this chunk cannot
        // trip `Block::unmodifiable_key_changed` -- the subject here is
        // whether a v6 chunk update reaches disk at all, not the key rule.
        b.update_chunks(&[(8, vec![0x42])]).expect("a chunk update on a real v6 file must succeed");

        b.records = None;
        let reread = b.records().expect("re-reads after the update");
        let mut want = v6_real_record(b"AAAA");
        want[8] = 0x42;
        assert_eq!(
            reread.physical(reread.find_physical(position).expect("still there")).expect("in range").bytes,
            want,
            "the spliced byte reached disk"
        );
    }

    #[test]
    fn update_chunks_without_a_position_is_refused() {
        let mut b = fixture_v6("update_chunks_without_a_position_is_refused");
        let err = b.update_chunks(&[(0, vec![1])]).expect_err("nothing positioned");
        assert_eq!(err, OpError::NotPositioned);
    }

    #[test]
    fn update_chunks_offset_past_the_record_is_refused() {
        let mut b = fixture_v6("update_chunks_offset_past_the_record_is_refused");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &10u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap();
        let err = b.update_chunks(&[(100, vec![1])]).expect_err("past the end of the record");
        assert_eq!(err, OpError::ChunkOffsetTooBig);
    }

    // Create Index (31) / Drop Index (32)

    #[test]
    fn create_index_is_always_refused_a_structural_gap_not_a_vendor_one() {
        let mut b = fixture("create_index_is_always_refused_a_structural_gap_not_a_vendor_one");
        assert_eq!(b.create_index(), Err(OpError::IndexMutationUnsupported));
    }

    #[test]
    fn drop_index_is_always_refused_the_same_way() {
        let mut b = fixture("drop_index_is_always_refused_the_same_way");
        assert_eq!(b.drop_index(0), Err(OpError::IndexMutationUnsupported));
    }

    // Get Next/Previous Extended (36/37), Step Next/Previous Extended (38/39)

    #[test]
    fn get_next_extended_after_current_retrieves_the_requested_count_forward() {
        let mut b = fixture("get_next_extended_after_current_retrieves_the_requested_count_forward");
        let mut locks = LockTable::default();
        let out = b.get_next_extended(0, 3, ExtendedStart::AfterCurrent, 0, &mut locks, RECLEN).unwrap();
        let tags: Vec<u8> = out.iter().map(tag).collect();
        assert_eq!(tags, vec![0, 1, 2], "S1: nothing positioned behaves like Lowest, then walks forward");
    }

    #[test]
    fn get_next_extended_stops_at_end_of_file_short_of_count() {
        let mut b = fixture("get_next_extended_stops_at_end_of_file_short_of_count");
        let mut locks = LockTable::default();
        let out = b.get_next_extended(0, 100, ExtendedStart::AfterCurrent, 0, &mut locks, RECLEN).unwrap();
        assert_eq!(out.len(), 6, "only six records exist -- the fourth documented stop condition, p. 130");
    }

    #[test]
    fn get_next_extended_at_current_includes_the_positioned_record_first() {
        let mut b = fixture("get_next_extended_at_current_includes_the_positioned_record_first");
        let mut locks = LockTable::default();
        b.get(0, Op::Equal, &30u16.to_le_bytes(), 0, &mut locks, RECLEN).unwrap();
        let out = b.get_next_extended(0, 2, ExtendedStart::AtCurrent, 0, &mut locks, RECLEN).unwrap();
        let tags: Vec<u8> = out.iter().map(tag).collect();
        assert_eq!(tags, vec![2, 3], "UC: begins with the positioned record (tag 2), then the next");
    }

    #[test]
    fn get_previous_extended_walks_backward() {
        let mut b = fixture("get_previous_extended_walks_backward");
        let mut locks = LockTable::default();
        b.get(0, Op::Highest, &[], 0, &mut locks, RECLEN).unwrap();
        let out = b.get_previous_extended(0, 2, ExtendedStart::AfterCurrent, 0, &mut locks, RECLEN).unwrap();
        let tags: Vec<u8> = out.iter().map(tag).collect();
        assert_eq!(tags, vec![4, 3]);
    }

    #[test]
    fn get_next_extended_with_count_zero_returns_nothing() {
        let mut b = fixture("get_next_extended_with_count_zero_returns_nothing");
        let mut locks = LockTable::default();
        let out = b.get_next_extended(0, 0, ExtendedStart::AfterCurrent, 0, &mut locks, RECLEN).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn step_next_extended_walks_physical_order_after_the_current_position() {
        let mut b = fixture("step_next_extended_walks_physical_order_after_the_current_position");
        let mut locks = LockTable::default();
        b.step(Step::First, 0, &mut locks, RECLEN).unwrap();
        let out = b.step_next_extended(2, 0, &mut locks, RECLEN).unwrap();
        let tags: Vec<u8> = out.iter().map(tag).collect();
        assert_eq!(tags, vec![1, 2], "always EG: starts after the current position, p. 126");
    }

    #[test]
    fn step_previous_extended_walks_backward_in_physical_order() {
        let mut b = fixture("step_previous_extended_walks_backward_in_physical_order");
        let mut locks = LockTable::default();
        b.step(Step::Last, 0, &mut locks, RECLEN).unwrap();
        let out = b.step_previous_extended(2, 0, &mut locks, RECLEN).unwrap();
        let tags: Vec<u8> = out.iter().map(tag).collect();
        assert_eq!(tags, vec![4, 3]);
    }

    #[test]
    fn step_next_extended_from_cold_starts_at_the_first_record() {
        // `Step Next Extended` is repeated `Step Next`, so from a cold file
        // it begins at the first record -- the same "before the first record"
        // start `step_next_from_cold_is_the_first_record_...` measures for the
        // plain op. A refusal here would have made Step Next Extended the one
        // reader that could not begin a file without a separate positioning
        // call.
        let mut b = fixture("step_next_extended_from_cold_starts_at_the_first_record");
        let mut locks = LockTable::default();
        let cold = b.step_next_extended(3, 0, &mut locks, RECLEN).unwrap();
        let mut b2 = fixture("step_next_extended_from_cold_starts_at_the_first_record_b");
        b2.step(Step::First, 0, &mut locks, RECLEN).unwrap().expect("first");
        let warm = b2.step_next_extended(2, 0, &mut locks, RECLEN).unwrap();
        // Cold(3) is First plus the next two -- so cold[1..] equals warm.
        assert_eq!(cold.len(), 3, "three records from cold");
        assert_eq!(
            cold[1..].iter().map(tag).collect::<Vec<_>>(),
            warm.iter().map(tag).collect::<Vec<_>>(),
            "cold Step-Next-Extended begins at the first record, then walks forward"
        );
    }

    // Insert Extended (40)

    #[test]
    fn insert_extended_inserts_every_record_and_establishes_currency_on_the_last() {
        let mut b = fixture("insert_extended_inserts_every_record_and_establishes_currency_on_the_last");
        let records = vec![ops_record(100, 9, 9), ops_record(200, 9, 8)];
        let positions = b.insert_extended(0, false, &records).expect("no collision");
        assert_eq!(positions.len(), 2);
        let current = b.current().expect("p. 150: currency established on the last inserted record");
        assert_eq!(current.bytes[4], 8, "the second record's tag");
    }

    #[test]
    fn insert_extended_refuses_a_duplicate_key_and_reports_how_many_made_it_in() {
        let mut b = fixture("insert_extended_refuses_a_duplicate_key_and_reports_how_many_made_it_in");
        // key0=100 is new; key0=10 already exists (tag 0), and key 0 forbids duplicates.
        let records = vec![ops_record(100, 9, 9), ops_record(10, 9, 8)];
        let err = b
            .insert_extended(0, false, &records)
            .expect_err("the second record collides on key 0");
        assert_eq!(err.inserted.len(), 1, "p. 148: the first record made it in");
        assert_eq!(err.error, OpError::DuplicateKey { key: 0 });
    }

    #[test]
    fn insert_extended_ncc_is_refused() {
        let mut b = fixture("insert_extended_ncc_is_refused");
        let err = b.insert_extended(0, true, &[]).expect_err("NCC is not supported");
        assert_eq!(err.error, OpError::NccUnsupported);
        assert!(err.inserted.is_empty());
    }

    // Continuous Operation (42)

    #[test]
    fn continuous_operation_start_then_is_active() {
        let mut c = ContinuousOperationTable::default();
        c.start(&["A.DAT".to_owned(), "B.DAT".to_owned()]).expect("no conflict");
        assert!(c.is_active("A.DAT"));
        assert!(c.is_active("B.DAT"));
        assert!(!c.is_active("C.DAT"));
    }

    #[test]
    fn continuous_operation_starting_an_already_active_file_is_refused_with_status_88() {
        let mut c = ContinuousOperationTable::default();
        c.start(&["A.DAT".to_owned()]).unwrap();
        let err = c.start(&["A.DAT".to_owned()]).expect_err("already in continuous operation mode");
        assert_eq!(err, OpError::AlreadyInContinuousOperation { file: "A.DAT".to_owned() });
    }

    #[test]
    fn continuous_operation_duplicate_names_in_one_call_are_harmless() {
        let mut c = ContinuousOperationTable::default();
        c.start(&["A.DAT".to_owned(), "A.DAT".to_owned()])
            .expect("p. 47: duplicate filenames in one call do not error");
        assert!(c.is_active("A.DAT"));
    }

    #[test]
    fn continuous_operation_end_specific_files_leaves_others_active() {
        let mut c = ContinuousOperationTable::default();
        c.start(&["A.DAT".to_owned(), "B.DAT".to_owned()]).unwrap();
        c.end(Some(&["A.DAT".to_owned()]));
        assert!(!c.is_active("A.DAT"));
        assert!(c.is_active("B.DAT"));
    }

    #[test]
    fn continuous_operation_end_with_no_names_ends_every_file() {
        let mut c = ContinuousOperationTable::default();
        c.start(&["A.DAT".to_owned(), "B.DAT".to_owned()]).unwrap();
        c.end(None);
        assert!(!c.is_active("A.DAT"));
        assert!(!c.is_active("B.DAT"));
    }

    // Get By Percentage (44) / Find Percentage (45)

    #[test]
    fn get_by_percentage_zero_is_the_lowest_record() {
        let mut b = fixture("get_by_percentage_zero_is_the_lowest_record");
        let mut locks = LockTable::default();
        let d = b.get_by_percentage(PercentageBasis::Key(0), 0, 0, &mut locks, RECLEN).unwrap();
        assert_eq!(tag(&d), 0);
    }

    #[test]
    fn get_by_percentage_10000_is_the_highest_record() {
        let mut b = fixture("get_by_percentage_10000_is_the_highest_record");
        let mut locks = LockTable::default();
        let d = b.get_by_percentage(PercentageBasis::Key(0), 10_000, 0, &mut locks, RECLEN).unwrap();
        assert_eq!(tag(&d), 5);
    }

    #[test]
    fn get_by_percentage_clamps_a_value_past_10000() {
        let mut b = fixture("get_by_percentage_clamps_a_value_past_10000");
        let mut locks = LockTable::default();
        let d = b.get_by_percentage(PercentageBasis::Key(0), 60_000, 0, &mut locks, RECLEN).unwrap();
        assert_eq!(tag(&d), 5, "clamped to the highest record, not out of range");
    }

    #[test]
    fn get_by_percentage_physical_basis_returns_no_key() {
        let mut b = fixture("get_by_percentage_physical_basis_returns_no_key");
        let mut locks = LockTable::default();
        let d = b.get_by_percentage(PercentageBasis::Physical, 0, 0, &mut locks, RECLEN).unwrap();
        assert!(d.key.is_none(), "p. 86: physical basis returns nothing in the Key Buffer");
    }

    #[test]
    fn get_by_percentage_no_such_key_is_refused() {
        let mut b = fixture("get_by_percentage_no_such_key_is_refused");
        let mut locks = LockTable::default();
        let err = b
            .get_by_percentage(PercentageBasis::Key(9), 0, 0, &mut locks, RECLEN)
            .expect_err("no such key");
        assert_eq!(err, OpError::NoSuchKey(9));
    }

    #[test]
    fn find_percentage_is_the_inverse_of_get_by_percentage() {
        let mut b = fixture("find_percentage_is_the_inverse_of_get_by_percentage");
        // key0 = 30 (tag 2) sits at ordered index 2 of 6.
        let pct = b
            .find_percentage(&FindBasis::Key { key: 0, value: 30u16.to_le_bytes().to_vec() })
            .unwrap();
        assert_eq!(pct, (2 * 10_000) / 6);
    }

    #[test]
    fn find_percentage_does_not_move_the_cursor() {
        let mut b = fixture("find_percentage_does_not_move_the_cursor");
        assert_eq!(b.cursor(), Cursor::Nowhere);
        b.find_percentage(&FindBasis::Key { key: 0, value: 30u16.to_le_bytes().to_vec() })
            .unwrap();
        assert_eq!(b.cursor(), Cursor::Nowhere, "p. 83: Find Percentage changes no currency");
    }

    #[test]
    fn find_percentage_physical_basis() {
        let mut b = fixture("find_percentage_physical_basis");
        let position = b.records().unwrap().physical(0).unwrap().position;
        let pct = b.find_percentage(&FindBasis::Physical(position)).unwrap();
        assert_eq!(pct, 0, "the first physical record is at 0%");
    }

    #[test]
    fn find_percentage_invalid_physical_address_is_refused() {
        let mut b = fixture("find_percentage_invalid_physical_address_is_refused");
        let err = b.find_percentage(&FindBasis::Physical(999_999)).expect_err("no such record");
        assert_eq!(err, OpError::InvalidRecordAddress);
    }

    // Stat Extended (65)

    #[test]
    fn extended_files_reports_one_file_and_no_extensions() {
        let b = fixture("extended_files_reports_one_file_and_no_extensions");
        let files = b.extended_files(0);
        assert_eq!(files.files, 1);
        assert!(files.extensions.is_empty());
    }

    #[test]
    fn system_data_stat_is_loggable_because_key_0_forbids_duplicates() {
        let b = fixture("system_data_stat_is_loggable_because_key_0_forbids_duplicates");
        let stat = b.system_data_stat();
        assert!(!stat.has_system_data);
        assert!(!stat.has_log_key);
        assert!(stat.is_loggable, "key 0 has duplicates: false");
        assert_eq!(stat.size, 8);
        assert_eq!(stat.version, 700);
    }

    // Begin Transaction, concurrent form (1019)

    #[test]
    fn begin_concurrent_transaction_is_always_refused() {
        assert_eq!(begin_concurrent_transaction(), Err(OpError::ConcurrentTransactionUnsupported));
    }
}
