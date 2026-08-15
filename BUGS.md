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

## 2. `wg32_abi` boot-stub test is flaky under the full workspace run

**Symptom.** `boot_bug::entering_the_pe_entry_stub_faults_but_the_real_init_routine_does_not`
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

## 3. A doc comment cites the `wg20` tree

`crates/mbbs/src/lib.rs:2549` cites
`archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3368`.

The repo's rule is to cite **wg1**, never wg20: the same file in wg20 carries
different line numbers, so a wg20 citation is silently wrong when read against
the tree everything else cites. Re-anchor it against wg1 and check the line
number rather than assuming it transfers.

---

## 4. `WCCUSERS.DAT` falls off the `setbtv` stack

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

## 5. Latency and idle cost in the Realm

Carried over rather than newly measured: a player in the Realm sees **1+
second** command latency, and **96.5%** of idle dispatches are `ptrtile`.

Idle CPU is ~3% with nobody connected and ~32% with one session, which matches
the recorded expectation that roughly 30% is the Realm's real-time engine
turning rather than a regression. The latency is the part worth attacking.
