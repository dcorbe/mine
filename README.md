# &lt;name&gt;

Runs unmodified MajorBBS and Worldgroup modules natively on Linux.

These are 16-bit protected-mode DOS binaries from the early '90s — Phar Lap NE
images linked against Galacticomm's host library and Btrieve. For most of them,
no source survives.

They are not emulated. x86-64's compatibility mode can execute a 16-bit code
segment directly — `CS.L=0, CS.D=0`, installed in the process LDT — so the
module's original instructions run on the bare CPU, with no interpreter and no
hypervisor. What this project supplies is everything underneath: the
Galacticomm host API, a Btrieve implementation, and a modern socket.

## Requirements

**x86-64 Linux only.** That is architectural, not a porting gap — the whole
approach rests on x86-64 compatibility mode. There is no arm64 story.

Your kernel must be built with:

```
CONFIG_X86_16BIT=y      # modify_ldt accepts a 16-bit code descriptor
CONFIG_X86_ESPFIX64=y   # safe signal delivery with a 16-bit SS
```

Check yours:

```sh
zgrep -E 'CONFIG_X86_16BIT|CONFIG_X86_ESPFIX64' /proc/config.gz
grep  -E 'CONFIG_X86_16BIT|CONFIG_X86_ESPFIX64' /boot/config-$(uname -r)
```

`CONFIG_X86_16BIT=n` is a legitimate and increasingly common hardening choice.
On such a kernel nothing here works, and it fails at the first `modify_ldt`.

To find out whether your machine can do this **before building anything**:

```sh
git clone https://github.com/dcorbe/x86-compat16
cd x86-compat16 && make test
```

That is the standalone falsification suite for the claim this host rests on —
that a 64-bit process can create a 16-bit code segment, far-jump into it,
execute there, take a signal, and return. If your kernel cannot, it says
exactly where it breaks.

Developed against Linux 6.18.

## Status

Early. One module is driven end to end; a second boots alongside it.

| area | state |
|---|---|
| Module load (16-bit NE) | Works. `WCCMMUD.DLL` (MajorMUD 1.11p) loads and initialises. |
| Telnet | Works. Multiple channels, CP437→UTF-8 for modern clients, raw CP437/ANSI for period ones. |
| Character creation | Works. Full-screen data entry (FSD) drives creation through to a saved character. |
| In-Realm play | **Partial.** The real-time engine runs, movement delay counts down, ambient world activity appears. One known defect: a move produces no room description — the handler never reaches `btuxmt`. |
| Btrieve | Works for this module's files, including duplicate-key chains. Verified against genuine Pervasive Btrieve. |
| 32-bit (PE) modules | Early. LunatiX initialises on the same generic host; not yet playable. |
| Modules generally | Untested. Two modules is not a platform. Expect gaps in the host API. |

## Quickstart

You supply the module. This project ships no game content and no vendor
binaries — see [Provenance](#provenance-and-licence).

```sh
cargo build --release

./target/release/mbbs-server \
    --root  /path/to/board-data \
    --module /path/to/WCCMMUD.DLL \
    --listen 127.0.0.1:2323
```

Then `telnet 127.0.0.1 2323`.

Useful flags:

| flag | why |
|---|---|
| `--listen-raw ADDR` | A second port for period clients (SyncTERM, MegaMUD) that already speak CP437/ANSI.SYS. |
| `--terms N` | Channel count. Default 2. |
| `--module32 P --root32 D` | Boot a 32-bit module alongside the 16-bit one; a connect-time selector chooses. |

`--help` documents the rest.

## How it works

**Execution.** 16-bit code runs on the CPU in compatibility mode via LDT
descriptors; 32-bit modules run flat. Faults and signals are arbitrated
process-wide because a process has exactly one LDT and one set of signal
dispositions. → `crates/mbbs-machine`

**The host API.** Every entry point a module imports from `MAJORBBS`, `GSBL`
and `GALME` is reimplemented in Rust and dispatched at the ABI border, so one
host drives both word sizes. → `crates/mbbs`, [`docs/dll-imports.md`](docs/dll-imports.md)

**Btrieve.** The record manager these modules store everything in, implemented
from the file format up — pages, keys, duplicate chains.

**Transport.** Tokio owns the sockets; the machine owns one thread. Terminal
translation happens at the socket, never in the module's view of the world.
→ `crates/mbbs-server`

Design documents for each piece of work live in [`docs/plans/`](docs/plans/).

## Verification

The method is oracles rather than opinion. Genuine Pervasive Btrieve runs under
Wine and answers the same calls, so the Btrieve implementation is diffed
against the real thing instead of against expectations. The original
`MAJORBBS.EXE` is loadable and callable, so host behaviour can be asked of the
host itself. Captures from a live period board pin the wire format byte for
byte.

Tests outnumber source in the crates where behaviour is the product.

## Repository layout

| crate | what it does |
|---|---|
| `mbbs` | The host API — every entry point a module can call — plus the Btrieve implementation. |
| `mbbs-machine` | Execution: LDT, faults, NE/PE loading, the 16/32-bit ABI border. |
| `mbbs-server` | The socket edge: tokio, telnet, CP437, ANSI compatibility, channel pool. |

Three further crates are a separate track — a from-scratch MajorMUD
reimplementation (`mud-core`, `mud-server`) and a scriptable client
(`mud-client`, binary `mmc`). They are not the goal; they are where the game's
behaviour was worked out and where ground truth gets captured.

## What this is not

- **Not a MajorMUD reimplementation.** It runs the original binary. (This repo
  contains one anyway — see above — but that is a different track.)
- **Not MBBSEmu.** MBBSEmu is the mature C# MajorBBS emulator and the prior art
  this project learned from. Different goal, different tradeoffs; not a
  competitor and not a replacement.
- **Not a BBS.** No logon, no menus, no user manager. It boots one module
  headless and puts a socket in front of it.
- **Not a preservation archive.** It ships no game content and no vendor
  binaries.
- **Not finished.** See Status.

## Acknowledgements

This would not exist without work other people did first and published.

- **[MBBSEmu](https://github.com/mbbsemu/MBBSEmu)** (MIT, © Nusbaum Consulting)
  — prior art for running MajorBBS modules at all.
- **[MMUD Explorer](https://github.com/syntax53/MMUD-Explorer)** and
  **[Nightmare Redux](https://github.com/syntax53/Nightmare-Redux)**
  (syntax53) — the MajorMUD database structures, made readable.
- **[OmegaMUD](https://gitlab.com/beckersource/OmegaMUD)** — the only open
  specification of the MegaMud `.mp` path format and room-hash scheme.
- **[ReMUD](https://github.com/lucid2310/ReMUD)** (lucid2310).
- The documentation community that kept thirty-year-old material alive:
  voidbbs.com, majormud.com, kyau.net, wiki.mud.fyi, mudcentral.org,
  mudinfo.net, megamud.net, bearfather.net, and The Phoenix Project.
- **The Internet Archive**, without which mudcentral.com and mudcentral.net
  would simply be gone.

Full source provenance: [`docs/MIRRORS.md`](docs/MIRRORS.md).

## Provenance and licence

This host contains no Galacticomm, Borland, or Phar Lap code. It is an original
Rust implementation written against a documented API surface.

The one vendor-derived artefact is a set of ordinal→symbol-name tables for
`MAJORBBS`, `GSBL`, `GALME` and Phar Lap's `DOSCALLS`, extracted from the
export tables of the corresponding binaries. That is interoperability
information of exactly the kind Wine has shipped as `.spec` files for thirty
years.

You supply your own module binaries and your own board data. Nothing here
distributes either.

MIT.
