# Known bugs

Open defects, each with what has already been measured so the next person does
not repeat the investigation. Fixed bugs belong in the git history, not here.

Entries are ordered by how much they get in the way, not by severity.

---

## 1. "[X] Exit Game" does not disconnect the player

**Symptom.** In MajorMUD, choosing `X` at the main menu redraws the menu
instead of ending the session. The player is left at a prompt that nothing
will ever answer again: input still arrives and is pushed into GSBL, but the
module has stopped polling the channel and never dispatches for it again.
Measured: after `X`, **601,807 shim dispatches with not one for that channel**.

**What this host does have.** `Registration::AbsentBbs` occupies module slot
zero, `Host::sweep_ended` notices a channel whose `state` names it, and
`Host::drain_ended` hands it to the driver, which sends `Out::Close`. That
mechanism is implemented and tested
(`a_channel_handed_back_to_the_absent_bbs_is_reported_as_ended`). It is
correct and it never fires, because MajorMUD never triggers it.

**Ruled out, each by measurement rather than reading:**

| candidate | verdict |
|---|---|
| a missing host symbol | **No.** `--survey-unimplemented-and-corrupt-the-session` across login → menu → `X` → `X` wrote **zero bytes**. Every symbol MajorMUD reaches on that path is served. |
| `byenow` | The host's own logoff, called from `ACCOUNT.C:910/918/927/939/1040` and `AAEFU.C:222` with reasons `SEEYEZ`/`OUTTDY`/`OUTOFT`/`NOTIME` — out of time, out of credit. MajorMUD never calls it, and it never appears in a trace. |
| `hdlinp` | Never reached. |
| `xitmod` | Not registered here, and **not imported** by `WCCMMUD.DLL`. |
| `stop_polling` | **15 call sites** in MajorMUD, with 10 `begin_polling` — routine traffic, not an exit signal. Hooking a disconnect to it would hang up on live players. |
| `usrptr->state = 0` | This *is* the vendor's protocol — `MENUING.C:390` loops `while (i < XTRIES && usrptr->state != 0)` and `:397` returns `usrptr->state == 0`, "did the module let go?". **MajorMUD never writes it.** |
| `usrptr->substt` | Set to `0x38` on reaching the main menu, and **unchanged by `X`**. |

**The decisive measurement.** Every write to `struct user`'s `state` field in
`re/exports/WCCMMUD_named.c`, across both access paths:

- 14 writes via `_usrptr_629 + 6`
- 1 write via `_user_625 + n * 0x29 + 6` (hand-indexed, the path a naive grep
  misses)
- **0 writes of zero**

All 15 write `DAT_1118_0e0a`, which is assigned once at `:10274` from
`Ordinal_492(...)` — `_REGISTER_MODULE`. That is MajorMUD's own module index.
**It only ever claims a channel; it has no code that releases one.**

Watch the strides when reading that decompile: `struct user` is **41 bytes**
(`0x29`), while `0xad` (173) is MajorMUD's own per-player record. `+ 6) = 0`
matches at the 173 stride are a different struct's field, not `state`.

**Live confirmation** (state probe in `Host::sweep_ended`, since reverted):

```
chan 0: state=0 substt=0x0000    before connect
chan 0: state=1 substt=0x0000    connected, connect_state put it in MajorMUD
chan 0: state=1 substt=0x0038    reached the main menu
                                 ...and X changes neither
```

**Where to pick it up.** The handback is not `state`, not `substt`, and not a
missing symbol, so it is something else about the exit path — the likeliest
remaining reading is that `X`'s handler takes a branch that depends on a real
BBS being present, and does nothing when it is not. `rstrxf` is worth a look
(it is called exactly once, at exit, and is *"restore screen-length to usracc
setting"*, `MAJORBBS.C:3776`), but it is `Ordinal_512`, whose thunk Ghidra
failed to decompile (`halt_baddata()`), so its call sites are not resolvable
there. Finding the `X` handler probably needs disassembly rather than the
decompile.

---

## 2. v6 files grow without bound, and a live file already has content where table blocks belong

**Found 2026-08-29 while fixing the `WCCACMS2.DAT` commit refusal; neither is fixed.**

**Growth.** `Map::claim` and `Map::relocate` append a fresh physical page for
every claim and for every relocation that finds no abandoned twin. The genuine
engine pre-assigns each allocation-table slot a physical page (`(0, first+2+i)`
in every fresh block of every shipped `.vir`) and reuses abandoned pages, so
its files stay near their claimed size. Measured on the live board after one
boot's automatic database update: `wccmp002.vir` is 13,607 pages and the
`WCCMP002.DAT` it became is **20,744** -- 29 MB of pages nothing claims. The
file-control-record page count (`fcr::PAGES`, `+0x26`) is not maintained on
the v6 write path either: the live `WCCACMS2.DAT` says 3 at 1,016 pages, where
the vendor's `wccmp002.vir` says 13,572 at 13,607.

**Stranded block positions.** Before `Map::append_content`, a claim that
landed on a table block's formula position wrote content there. The live
`WCCMP002.DAT` has data pages at physical **14338 and 15362** (blocks 15 and
16's positions, 4096-byte pages). The engine now reads and writes such a file
correctly -- its table ends at block 14 -- but it can never grow a fifteenth
block: once blocks 1-14 have no free slot, `claim` refuses with `growing a new
block is not implemented`. Blocks 1-13 are full and block 14 has ~740 free
slots. The remedy is a reinstall of that file from `wccmp002.vir` (the boot's
database update regenerates it); nothing in the engine can move the pages.

---

## 3. The host stops the machine where the runtime returned an error code

**Not one bug — a shape, and the one most likely to bite next.**

Three of these were found and fixed in a single sitting (`9c018f8`), all in
one routine, all only reachable once `d0cc910` made this host dispatch a
module's `finrou` at all:

| routine | condition | was | is |
|---|---|---|---|
| `clsmsg` | the block is current | stop | close it, `curmbk` goes null |
| `clsmsg` | the block waits under the current one | stop | close it, the `saved` entry goes null in place |
| `fclose` | the file is already closed | stop | `EOF`, and a note |
| `rstmbk` | nothing to restore | stop | the vendor's ten-slot window: the stale slot below, or null |

The fourth (2026-08-29) was not teardown: a Mystic typing `spells` has
MajorMUD pop three times for two `setmbk`s, and the refusal stopped the
module for every player on the board. `MCVAPI.C:229` cannot fail.

None of the first three was the vendor's rule. `MCVAPI.H:66` declares `void
clsmsg(FILE *mb)` and no body survives in the recovered tree; C's `fclose`
reports failure in its return value. All three were this host's own
inventions, written against paths that had never run.

**Why it will recur.** Teardown is error-tolerant by nature: it closes things
it is not certain are open, frees what may already be freed, and ignores what
it is told. Every such call is a place where a host that answers "stop the
machine" instead of "here is your error code" turns ordinary cleanup into a
crash. Shutdown is simply the first path that exercises a lot of them at once.

**What to do when the next one appears.** Ask what the *real* routine
returned, not what would be tidy. If the vendor header gives a failure return
(`EOF`, `NULL`, `-1`, a zero count), give that and note it. Reserve stopping
for a state that has no answer at all — a pointer into memory the module does
not own, an unimplemented import with a live caller.

---

## 4. `wg32_abi` boot-stub test is flaky under the full workspace run

**Symptom.**
`boot_bug::entering_the_pe_entry_stub_faults_but_the_real_init_routine_does_not`
(`crates/mbbs/tests/wg32_abi.rs`) fails roughly **one run in three**, but only
when the whole workspace runs. It passes reliably on its own, both
`--test-threads=1` and in parallel, and the `wg32_abi` binary passes alone
either way.

**Why it is suspicious.** The test deliberately provokes a **SIGSEGV** and
catches it through a process-wide fault handler (`mbbs-machine/src/m32/fault.rs`).
The likeliest cause is contention for low address space between concurrent
test *processes* — `MAP_32BIT` is a finite, process-external resource — rather
than anything about the test's own logic.

**Pre-existing.** Observed before and after the 2026-08-14 merge and unrelated
to any commit from it.

---

## 5. Btrieve record tests share scratch directories and race

**Symptom.** An intermittent
`written: Os { code: 2, kind: NotFound }` from `records.rs`'s `read` test
helper, under a parallel run. The suite passes on a re-run and passes
reliably under `--test-threads=1`.

**Cause, measured rather than guessed.** `crate::testing::scratch` does
`remove_dir_all` and then `create_dir_all` on a directory named after the
file, and several tests pass the same file name:

```
4x  read("FREESLOT.DAT")
2x  read("STALETWIN.DAT")
```

Two tests with the same name get the same directory, and one wipes it while
the other is writing into it.

**Fix.** Give every test its own name, or key `scratch` on the test rather
than on the file. Cheap either way; it is listed here rather than done because
it was found while chasing something else.

---

## 6. A doc comment cites the `wg20` tree

`crates/mbbs/src/lib.rs:2549` cites
`archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3368`.

The repo's rule is to cite **wg1**, never wg20: the same file in wg20 carries
different line numbers, so a wg20 citation is silently wrong when read against
the tree everything else cites. Re-anchor it against wg1 and check the line
number rather than assuming it transfers.

---

## 7. `WCCUSERS.DAT` falls off the `setbtv` stack

**Not a bug in this host — recorded so it is not re-investigated.**

The `setbtv`/`rstbtv` stack is ten deep (`BTVSTF.H:14`, `#define BBSTSZ 10`),
and `PLBTVSTF.C:227` shifts and drops the bottom entry exactly the way this
host does. MajorMUD calls `setbtv` more often than `rstbtv` — measured
**26,091 against 25,459** in one session — so the stack overflows constantly
and the oldest file is discarded. That happened on the real host too.

`WCCUSERS.DAT` fell off twice in a session against `WCCMP001.DAT`'s 203 times,
and character saving demonstrably works (the record reaches the data pages and
the file control record's `RECORDS_LOW` at `+0x1c` increments), so the overflow
is noisy rather than harmful. Worth remembering only if a *write* is ever
observed landing on the wrong file.

---

## 8. In-process recovery has never been observed completing

**Open question, not a known defect.**

MajorMUD's recovery mode clears itself: `_PRELOAD_AND_GENERATE_BUFFERS`
reaches state 4, clears `DAT_1148_00d6`, announces **"Recovery mode has now
completed."** and hands off to `_BACKGROUND_SAVE_BUFFERS` at `SECBUFF`
(1200s). That is read off the decompile and off the module's own strings; it
has **not** been watched happening.

A poller logging in every two minutes reported `IN RECOVERY` at 0, 139, 278,
417 and 557 seconds of uptime, and was stopped before the twenty-minute mark
to free the board for other work. So the claim "the board recovers on its own,
given time" is unverified above nine minutes.

It matters much less than it did — clean shutdown (`d0cc910`) removes
`WCCRECOV.FLG` and keeps the board out of recovery in the first place — but if
a board ever *is* dirty, this is the thing to watch, and
`mbbs-server: console:` now carries the announcement (`f99327b`) where it used
to be swallowed.

The offline path exists too and has never been run: `WCCMMUTL.EXE -recover`
(or `-needed`, which no-ops when the flag is absent). Eleven copies are in
`archive/_acquire/pools/full`, all PE32 + Phar Lap TNT — the Dec 30 2005 one
matches this module's build stamp exactly.

---

## 9. Latency and idle cost in the Realm

**Largely closed. Kept for the numbers.**

The felt "1+ second command latency" had two causes, both now fixed, and one
piece of evidence that turned out to be an artefact:

- **`--passes` was 1024, above the poll budget of 512** (`fdf2dde`), so
  `Ended::Bound` was unreachable, and one `cycle` call spent the entire budget
  without returning to read the socket. Worst cycle 4s → 352ms.
- **Btrieve `reindex` re-sorted every record, per key, on every write**
  (`288fdaa`) against a 38,754-record `WCCUPDAT.DAT`. `Segment::order` went
  from **18.52% of CPU to 0.07%**.
- **The "N seconds of timers in one pass -- the host stalled" note was a false
  positive** (`f20929c`). `tcklst` persists across `cycle` calls, so it
  counted the driver's *sleep*. Every note on a live board read exactly "2
  seconds", the signature of a two-second sleep. Two earlier investigations
  (`e0ae785`, `0903399`) built conclusions on that flood; both premises are
  gone, including the case for a `maxpol` throttle.

Measured after all three, time-to-first-byte over eight `look` commands on a
live board, stock defaults:

```
min 1 ms | median 64 ms | max 110 ms
```

**What is left is structural.** `shims::entry` is now the top cost at 23.65%:
the emulation boundary itself, about 900ns per host call measured by
`ptrtile_round_trip_cost`, of which only ~16ns is any shim's own body. Roughly
30% idle CPU with a player in the Realm is MajorMUD's world simulation running
— `2b888c7`'s `syscyc` fix is what made it run at all — and 96.5% of idle
dispatches being `ptrtile` is `_GET_ROOM_DATA`'s own hash probing, not
something this host introduced. See `docs/2026-08-14-ptrtile-hot-path.md`,
with the correction that its `Ended::Bound` spin diagnosis was wrong: `Bound`
was unreachable at the budgets it was measuring.

## 10. Genuine Btrieve does not use the empty data page our v5 `create` pre-allocates

**Symptom.** A v5 file written by `btrieve::create` and then maintained by
genuine Pervasive Btrieve 6.15 is not byte-identical to the same sequence
run through this engine. The first difference is at page 0 offset 0x10, the
free chain: genuine ignores the empty data page `create` pre-allocates,
appends a data page of its own, and threads its slots onto `fcr::FREE`. Our
engine fills the pre-allocated page.

**Measured.** 2026-09-04, `crates/btrieve/tests/differential.rs`, replaying
`v5_variable_insert.fixture` against genuine's transcript. The variable
pages and the variable FCR fields match genuine byte for byte apart from
each page's own number; only the fixed-length allocator diverges. The
whole-file diff is recorded in that test's `BYTE_COMPARED` doc comment.

**What it costs.** Interoperability only. Both engines read either layout,
so no data is lost. A file this host created and a real board then wrote to
will not match one the real engine created from scratch.

**Not done.** Measuring what a virgin v5 data page must look like for the
genuine engine to accept it. `create`'s data page was measured against
MajorMUD's shipped `.VIR` files, which the vendor's own tools wrote, not
against a virgin file the engine itself created.

---

## 11. A version 6 key file can stop the board on a ring rewrite

**Symptom.** None yet on this board, because every account pair here was
created by `Host::open_accounts` and this host's `btrieve::create` writes
version 5. A genuine Worldgroup 3 board's `wgskey2.dat` is a version 6 file,
and dropping one into a board directory is a supported thing to do. On such a
pair, two ordinary operations can take the whole board down: replacing a key
ring, which is a delete followed by an insert because a ring's length changes,
and the nightly purge, which deletes a departing user's keyrec. A Btrieve
fault on the account path is `shim_stop`, so the failure is the board
stopping, not a ring going missing.

**Measured.** `variable::free_fragment_v6` refuses two shapes outright, each
with its own test: freeing the only fragment on a page
(`freeing_the_only_fragment_on_a_page_is_refused`), because the page would
then report zero fragments and `Header::read` refuses that for version 6; and
compacting past an entry an earlier free already vacated
(`freeing_past_an_already_freed_entry_is_refused`). Both refuse because no
recording in `crates/btrieve-oracle/fixtures` reaches them -- every version 6
delete the oracle ladder measured left at least one fragment behind, and none
of them deleted twice from one page. `Space::place` fills a freed slot on
version 5 only, for the same reason, so a version 6 file also grows rather
than reusing what a delete gave back. A one-keyrec key file is exactly the
first case: the ring is the only fragment on its page.

`Host::open_accounts` says so at boot, once, through `accounts::version_note`
-- a console line naming the file, not a refusal, because refusing would
refuse the very boards this exists to serve.

**What it costs.** A board running on a vendor key file works until the first
ring rewrite or the first purge of a keyrec, and then stops. Reading and
adding accounts are unaffected: inserts and lookups have measured version 6
paths.

**Not done.** Three recordings against genuine Pervasive Btrieve 6.15 over a
version 6 variable-length file, in the shape the existing fixtures use:
freeing the only fragment on a page, freeing a fragment with an already-freed
entry between it and the page's boundary, and an insert onto a page holding a
freed slot, to settle whether version 6 reuses the slot the way version 5
does or appends past it. Until those exist the refusals stay, because a
guessed answer here writes a file neither engine can read back.
