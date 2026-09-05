# Oracle fixtures

Each `*.fixture` file here is a recorded conversation with a real copy of
Pervasive Btrieve 6.15, running under Wine, driven over TCP through
`tools/btrieve-oracle/btrvprobe serve` (wire format documented at
`crates/btrieve-oracle/src/lib.rs:1-11`). A fixture is a `Scenario` (the
sequence of `BTRCALL`s sent) paired with a `Transcript` (the genuine engine's
answer to each one, plus the resulting file's bytes read back off disk). The
scenarios themselves are defined in `crates/btrieve-oracle/src/scenario.rs`'s
`all_scenarios()`; the recording test (`record_fixtures_from_the_genuine_
engine`) is `#[ignore]`d and never runs in an ordinary `cargo test` — it
requires the Wine setup, which is why the recordings are committed rather
than regenerated on demand.

Replaying them (`crates/btrieve/tests/differential.rs`) diffs status codes,
successful-Get `databuf`, and post-scenario record contents against what the
engine under test produced for the same calls. It never compares `posblk`
(genuine Btrieve's is 128 bytes of engine-private cursor state; this
project's is a host-side handle — neither shape is scenario data) and never
compares raw file bytes for the `B_CREATE`-seeded fixtures. Four of the nine
fixtures are seeded that way, over the wire, so their files are genuine
Btrieve's own v6 layout, and nothing this project builds is byte-identical to
that in principle. The five `v5_variable_*` fixtures are seeded the other
way, from a v5 file `btrieve::create` wrote, and their transcripts hold that
same file after the genuine engine wrote into it -- for those, the replay
does compare bytes: every variable page, and the two control-record fields a
variable-length write owns.

## `open_close.fixture` (3,963 bytes)

**Scenario:** create an 8-byte-record, single-key file (`OPENCLOSE.DAT`),
then Open, then Close. The smallest possible scenario.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** contains the literal path
`C:\btrieve\3586646OPENCLOSE.DAT` (three times — once per call that carries
a KeySpec/FileSpec referencing it), the two-byte `"FC"` v6 control-record
signature, and two `"PP"` allocation-table page markers.

**What it proves:** a baseline. If the recorded engine and the engine under
test disagree on Open/Close against the simplest file that can exist, no
other fixture's disagreement means anything either.

## `insert_get_step_stat.fixture` (15,668 bytes)

**Scenario:** create an 8-byte-record file (`GETSTEPSTAT.DAT`), then insert
keys 100, 200, 50 in that physical order, then read them back through every
positioning call the engine's Get and Step families offer: Get First/Next×3
(key order 50, 100, 200, then status 9 end-of-file), Get Equal 100, Get
Previous, Get Last, Get Greater 100, Get At Most 150, Step First/Next×4
(physical/insertion order 100, 200, 50, then end-of-file), Stat, Close.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**What it proves:** key order and physical/insertion order are different
things, and this scenario is built so the two diverge (50, 100, 200 by key;
100, 200, 50 by insertion). A Get that silently answered in physical order
instead of key order, or a Step that answered in key order instead of
physical order, would be caught by this fixture and no other.

## `update_and_delete.fixture` (9,180 bytes)

**Scenario:** create an 8-byte-record file (`UPDDEL.DAT`), insert key 42,
Get Equal (establishes currency), Update (payload only, key unchanged), Get
Equal (confirms the payload changed), Delete (removes the record Get just
positioned on), Get Equal (status 4: gone), Close.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**What it proves:** the currency-then-mutate-then-reverify pattern, and
specifically that a Get Equal against a key whose only record was just
deleted answers status **4** ("end of file" / not found), not status 9 or
some other code an implementation might guess at.

## `status_ten_refusal_and_same_value_rewrite.fixture` (9,838 bytes)

**Scenario:** create an 8-byte-record file (`MODKEY.DAT`) whose one key is
declared **not modifiable**, insert key 42, Get Equal (currency), Update to
99 — **refused, status 10, nothing written** — Get Equal 42 (still there,
untouched), Get Equal 99 (status 4: nothing was written under the new key),
Get Equal 42 (re-establish currency), Update 42→9 (**allowed**: same key
value, payload-only change), Get Equal 42 (payload changed).

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**What it proves:** both halves of the unmodifiable-key rule in one
scenario — a real value change is refused with status 10 and writes
nothing, while an identical rewrite of the same key value is allowed and
changes only the payload. This matches `docs/2026-08-16-v6-update-delete-
oracle.md`'s narration of the same rule measured through the raw C probe
(`delprobe.exe modsame`), so this fixture confirms the same behaviour again
through the wire this crate's own Rust client uses, not only through a
probe transcript.

## `v5_variable_insert.fixture` (16,193 bytes)

**Scenario:** seeded, unlike every fixture above it, with a file this
project's own `btrieve::create` wrote rather than with a `B_CREATE` over the
wire. The seed is a **version 5** file with **variable-length** records, a
31-byte fixed portion, and one key: a 30-byte string at offset 0 collating
through the **ALLCAPS** alternate collating sequence MajorBBS itself uses.
Open, insert `Sysop` with the tail `DEMO NORMAL SYSOP`, insert `&USER` with
`DEMO NORMAL`, Get Equal `sysop` **in lower case**, Get First, Get Next, Get
Next (status 9), Close. Statuses: 0, 0, 0, 0, 0, 0, 9, 0.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** the 4,096-byte seed came back 6,144 bytes,
six 1,024-byte pages, still opening with a v5 control record: four zero
bytes, version byte 4 at offset 0x07, no `"FC"`. The virgin file's
`ff ff ff ff` at 0x38..0x3c now reads `ff 00 05 00`, the engine's own record
of which page the variable tail reached.

**What it proves:** two things nothing else in this repository could answer.
First, a v6 engine handed a v5 file does not quietly rebuild it in its own
format. It writes into the v5 layout, so every v5 measurement taken from
these transcripts is about a file the engine really had. Second, the
alternate collating sequence works. The Get Equal for `sysop` answers status
0 and returns the record inserted as `Sysop`, tail and all, where raw byte
ordering would have answered 4. That is the genuine engine reading the ACS
block and the key's collating flag out of a file this project wrote, the
strongest confirmation available that `btrieve::create` writes them
correctly.

## `v5_variable_delete.fixture` (16,151 bytes)

**Scenario:** the same seed file. Open, insert `Sysop` with the tail
`DEMO NORMAL SYSOP` (48 bytes) and `Test` with `DEMO` (35 bytes), Get Equal
`Sysop` to establish currency, Delete, Get Equal `Sysop` again, insert
`Testy` with a longer tail, `DEMO NORMAL MODERATE MASS_MAIL` (61 bytes),
Close. Statuses: 0, 0, 0, 0, 0, **4**, 0, 0.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** 6,144 bytes, still v5 (version byte 4),
0x38..0x3c reading `ff 00 05 00`. The record inserted after the delete needed
no page beyond the one the deleted record had already reached.

**What it proves:** deletion on a *variable-length* file, which no fixture
above covers and no corpus file can show. A Get Equal for the deleted key
answers **4**, the same code `update_and_delete.fixture` measured on a
fixed-length v6 file, and the following insert of a record **longer** than
the one deleted still succeeds. That last call is the one that matters for
the engine under test: whatever it decides to do with the freed fragment,
the genuine engine's answer and resulting file are recorded here to check it
against.

## `v5_variable_grow.fixture` (73,083 bytes)

**Scenario:** the same seed file, then 60 inserts, `User00` through `User59`,
each with the tail `DEMO NORMAL MODERATE`, 51 bytes a record. Then a Get
Equal for `User59`, and Close. 63 calls, every one status 0.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** the 4,096-byte seed came back 13,312
bytes, thirteen 1,024-byte pages, so the engine allocated nine new ones. It
is still v5: version byte 4, no `"FC"`. 0x38..0x3c reads `ff 00 0a 00`
against the insert fixture's `05`, so the variable tail reached page 10
rather than page 5.

**What it proves:** growth. The seed file carries exactly one pre-allocated
data page, so 60 records cannot fit it. This fixture records what genuine
Btrieve does when a v5 variable-length file has to allocate: how many pages,
in what order, and with what bookkeeping in the control record. Without it
the engine under test would be free to invent an allocation policy with
nothing to check it against. The final Get Equal for the last-inserted key
answering 0 says the index survived every one of those allocations.

## `v5_variable_release_empty.fixture` (14,319 bytes)

**Scenario:** the same seed file. Open, insert `Only` with the tail `DEMO`
(35 bytes), Get Equal `Only` to establish currency, Delete, Get Equal `Only`
again, Close. Statuses: 0, 0, 0, 0, **4**, 0.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** 6,144 bytes, six 1,024-byte pages, still
v5 (version byte 4, no `"FC"`). Its variable page 5 at `0x1400` reads
`00 00 05 00 | 01 00 | ff 00 ff ff | 00 00` -- its own page number, a
modification stamp of 1, still on the free-space chain and last on it, and a
fragment count of **zero**. Every byte from `0x140c` to the entry array is
zero, and the array's one remaining member, at `0x17fe`, names `0x0c`. The
control record still reads `00 00 06 00` at `0x26` (six pages) and
`ff 00 05 00` at `0x38`, and its record free list at `0x10` now names
`0x1006`, the slot the deleted record vacated.

**What it proves:** what genuine Btrieve does to a variable page whose last
fragment is deleted, which no fixture above reaches and which the engine
under test previously refused outright rather than guess at. The answer is
that it does nothing beyond emptying it: the page stays in the file, stays
on the free-space chain, keeps its own number, and neither `fcr::PAGES` nor
the chain head at `0x3a` moves. An engine that released the page, truncated
the file, or blanked the header would disagree with this fixture at the
first byte.

## `v5_variable_release_reinsert.fixture` (14,228 bytes)

**Scenario:** the same seed file and the same first four calls -- open,
insert `Only` with `DEMO`, Get Equal, Delete -- then insert `Next` with the
longer tail `DEMO NORMAL` (42 bytes), Get Equal `next` in lower case, Close.
Seven calls, every one status 0.

**Engine:** genuine Pervasive Btrieve 6.15 under Wine.

**Confirmed by reading the file:** 6,144 bytes, six pages, still v5. Page 5
at `0x1400` reads `00 00 05 00 | 02 00 | ff 00 ff ff | 01 00` followed by
`"EMO NORMAL\0"` at `0x140c`, with entries `17 00 0c 00` at `0x17fc`. The
new record sits at `0x1006` and its own fragment pointer at `0x1025` reads
`00 05 00 00` -- page 5, fragment 0.

**What it proves:** the emptied page is **reused**, not abandoned. The
insert that follows the delete goes back onto the same page rather than
claiming a fresh one, which is why the file is still six pages. It also
pins the page's modification stamp as a plain counter of writes rather than
"one less than the fragment count": 1 on a page holding none, 2 on the same
page holding one again.

## Why these are kept, and what changed

The design spec that pitches the old census machinery (`census.rs`,
`census_pin.rs`, `tests/data/census/CORPUS.tsv` — see the doc comment on
`crates/btrieve/src/census.rs`) flagged these four fixtures for a separate
decision, "so it can be overruled": keeping the *data* while moving
`differential.rs` (the harness that replays it) out of the active suite
until an engine exists to replay it against.

That recommendation is now load-bearing rather than merely prudent. This
plan implemented the v6 fragment/overflow-page path (`TAG_VARIABLE` pages,
Task 20) from the decompiled engine and from these recordings, because at
the time no corpus file was known to exercise it. Deleting the fixtures
then would have left that code with no ground truth at all.

**That has since changed, partially.** The final task of Stage C
(`crates/btrieve/src/read.rs`, `emit.rs`, `model.rs`) found that the corpus
itself carries 17 files with 19,231 genuine `TAG_VARIABLE` fragment pages
and 35,442 live entries. The fragment/overflow-page path is no longer
unwitnessed — the corpus now confirms it independently, at a scale (35,442
entries) these four fixtures cannot approach. So for that one behaviour,
the fixtures' role has changed from *sole* ground truth to a second,
independent source.

**What the corpus still cannot witness, and these fixtures are the only
ground truth for:**

- **Genuine v6 deletion.** `update_and_delete.fixture` records a real
  Delete call against a real v6 file and the real engine's answer to the
  Get Equal that follows it. A static corpus file is a single snapshot; it
  cannot show what deleting a record does, only what a file looks like
  after some unknown history of edits.
- **Mutation behaviour of any kind** — Update, the modifiable/unmodifiable
  key rule, currency after a mutating call. Same reason: a corpus file is a
  snapshot, not a sequence of operations.
- **Variable-tail Allocation Tables (VATs).** The four `B_CREATE`-seeded
  fixtures cannot cover this: each creates a fixed-length, single-key file
  (`create_request`'s `record_len` is a plain byte count, and the FileSpec's
  flags word is always built with no variable-length bit set). The five
  `v5_variable_*` fixtures do hold variable-length records the genuine
  engine wrote, so that path is witnessed here as well as in the corpus.
  Whether their files carry a VAT specifically has **not** been measured,
  and nothing above claims it. VATs found zero corpus evidence and zero
  mentions in the 45,175-line decompile (harvest 5), and that gap stands
  until someone measures one.

A recording nobody can interpret is not evidence — that is why each section
above states the scenario, the engine, and what was directly confirmed by
reading the file, rather than only citing the harvest document that first
measured them.
