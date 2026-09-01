# MINE

**MBBS Is Not an Emulator.** Runs unmodified MajorBBS and Worldgroup modules
natively on Linux.

These modules are protected-mode binaries from the early '90s: 16-bit Phar Lap
NE images and, for Worldgroup 3 and later, 32-bit PE images, linked against
Galacticomm's host library and Btrieve. For most of them no source survives.

They are not emulated. x86-64's compatibility mode executes a 16-bit code
segment directly (`CS.L=0, CS.D=0`, installed in the process LDT), so the
module's original instructions run on the bare CPU with no interpreter and no
hypervisor. 32-bit modules run flat. What this project supplies is everything
underneath: the Galacticomm host API, a Btrieve implementation, and a modern
socket.

## Requirements

**x86-64 Linux only.** That is architectural, not a porting gap: the whole
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

To find out whether your machine can do this before building anything:

```sh
git clone https://github.com/dcorbe/x86-compat16
cd x86-compat16 && make test
```

That is the standalone falsification suite for the claim this host rests on:
a 64-bit process can create a 16-bit code segment, far-jump into it, execute
there, take a signal, and return. If your kernel cannot, it says exactly where
it breaks.

Developed against Linux 6.18.

## Status

Early. A handful of 16-bit and 32-bit modules from different vendors boot and
are playable end to end. The host API is not complete: a module that imports a
routine this host does not serve stops at startup with the routine named.

| area | state |
|---|---|
| Module loading | Works for both 16-bit NE and 32-bit PE modules. Add-on modules load alongside the main one. |
| Terminals | Works. Modern clients get UTF-8; period clients get the original CP437 and ANSI bytes. |
| Full-screen forms | Works, in both line mode and ANSI full-screen mode. |
| Btrieve | Works. Modules read and write their data files through a complete record manager. |
| BBS doors | Works. A real BBS can hang a module as a door through the relay binary. |
| Scripting | Works. Lua scripts can add commands a module never had. |
| Host API | Partial. Each new module tends to import something not yet implemented. |

## Quickstart

You supply the module. This project ships no game content and no vendor
binaries; see [Provenance](#provenance-and-licence).

```sh
cargo build --release

./target/release/mbbs-server \
    --root   /path/to/board-data \
    --module /path/to/MODULE.DLL \
    --bturno 12345678 \
    --listen 127.0.0.1:2323
```

Then `telnet 127.0.0.1 2323`.

Useful flags:

| flag | why |
|---|---|
| `--module P` | Repeatable. The first is the one a caller enters; the rest are add-ons whose exports the first can reach. NE or PE decides which machine boots. |
| `--listen-raw ADDR` | A second port for period clients (SyncTERM and the like) that already speak CP437/ANSI.SYS. |
| `--listen-door PATH` | A Unix socket for door sessions; `mbbs-door` connects here on a BBS caller's behalf. |
| `--terms N` | Channel count. Default 2. |
| `--bturno DIGITS` | The board's eight-digit registration number. Modules key their licensing on it. |
| `--syscyc HZ` | How often the idle `syscyc` vector fires. Some modules step their world from it. |
| `--scripts DIR` | Lua scripts to load above the module. |

`--help` documents the rest.

## How it works

**Execution.** 16-bit code runs on the CPU in compatibility mode via LDT
descriptors; 32-bit modules run flat. Faults and signals are arbitrated
process-wide, because a process has exactly one LDT and one set of signal
dispositions. See `crates/mbbs-machine`.

**The host API.** Every entry point a module imports from `MAJORBBS`, `GSBL`
and `GALME` is reimplemented in Rust and dispatched at the ABI border, so one
host drives both word sizes. See `crates/mbbs`.

**Btrieve.** The record manager these modules store everything in, implemented
from the file format up: pages, keys, duplicate chains, transactions. See
`crates/btrieve`.

**Transport.** Tokio owns the sockets; the machine owns one thread. Terminal
translation happens at the socket, never in the module's view of the world.
See `crates/mbbs-server`.

## Repository layout

| crate | what it does |
|---|---|
| `mbbs` | The host API: every entry point a module can call. |
| `mbbs-machine` | Execution: LDT, faults, NE/PE loading, the 16/32-bit ABI border. |
| `mbbs-server` | The socket edge: tokio, telnet, CP437, ANSI compatibility, channel pool, doors. |
| `mbbs-lua` | The Lua extension seam. |
| `btrieve` | The Btrieve 6.15 engine. |
| `btrieve-oracle` | The wire protocol for driving genuine Btrieve under Wine. |
| `dos`, `dos-runtime` | A DOS kernel and runtime, for the DOS services modules and their utilities reach. |
| `textscreen` | Codepage, cell grid and painter behind the full-screen work. |
| `cnf` | An editor for a module's sysop-configurable options. |
| `bropey` | A byte-first persistent rope. |
| `mud-core`, `mud-server`, `mud-client`, `mud-oracle` | A game-specific side track that predates MINE. Not part of the host; slated to leave this repository. |


## What this is not

- **Not an emulator.** It runs the original binary on the CPU.
- **Not MBBSEmu.** MBBSEmu is the mature C# MajorBBS emulator and the prior art
  this project learned from. Different goal, different tradeoffs; not a
  competitor and not a replacement.
- **Not a BBS.** No logon, no menus, no user manager. It boots modules headless
  and puts a socket in front of them. A real BBS can hang them as doors.
- **Not a preservation archive.** It ships no game content and no vendor
  binaries.
- **Not finished.** See Status.

## Acknowledgements

- **[MBBSEmu](https://github.com/mbbsemu/MBBSEmu)** (MIT, © Nusbaum Consulting):
  prior art for running MajorBBS modules at all.
- The documentation community that kept thirty-year-old material alive, and
  **The Internet Archive**, without which much of it would simply be gone.

## Provenance and licence

This host contains no Galacticomm, Borland, Pervasive, or Phar Lap IP. It is
an original Rust implementation written against a documented API surface,
including the Btrieve record manager, which is implemented from the file
format up rather than wrapped.

The one vendor-derived artefact is a set of ordinal-to-symbol-name tables for
`MAJORBBS`, `GSBL`, `GALME` and Phar Lap's `DOSCALLS`, extracted from the
export tables of the corresponding binaries. That is interoperability
information of exactly the kind Wine has shipped as `.spec` files for thirty
years.

You supply your own module binaries and your own board data. Nothing here
distributes either.

MIT. See [`LICENSE.md`](LICENSE.md).
