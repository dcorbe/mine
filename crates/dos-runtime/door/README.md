# Serving LORD to Synchronet

The runtime already speaks the contract Synchronet uses for a native door: it
is handed a pty on stdin/stdout, it reads `DOOR.SYS`, and it exits. What it
adds over the dosemu path is that it *is* the far end of the line.

How a door reaches that line is the door's own configuration, not something it
probes for. LORDCFG's per-node **"Fossil / Internal"** setting decides:

| Setting | What LORD does | Served by |
|---|---|---|
| `Internal (No fossil driver used)` | programs an 8250 directly | `uart.rs` |
| `Regular Fossil Driver` | calls `int 14h` | `fossil.rs` |

Both are supported and both move bytes through the same queues, so the choice
changes nothing in this directory. Measured on a real session, `Regular Fossil`
produced 1467 `AH=01` transmits and exactly 1467 bytes out.

The two settings do not put the same bytes on the wire, because LORD renders
differently for each: over the same screens it sent 6035 bytes on `Internal`
against 3050 on `Regular Fossil`, with 675 colour changes against 267 and 38
cursor-forwards against 120. `Internal` pads with real spaces carrying
attributes; FOSSIL compresses with `ESC[nC` skips and leans on the terminal
for the rest, which was the right trade at 2400 baud. That comparison is still
true and still interesting; it just no longer settles the question by itself.

It used to settle the question, because FOSSIL's compression only laid out
correctly on a terminal exactly 80 columns wide. LORD's screen data assumes
that width in two separate ways: some rows run past column 80 with no CR/LF,
relying on the terminal to wrap them for free, and some `ESC[nC` (cursor
forward) sequences rely on the terminal clamping at the right margin rather
than naming their target column outright. Around the `(F)lirt with Violet the
Virgin` menu in `LORDTXT.DAT` there was an unbroken 82-character run depending
on the first of those -- on a wider terminal it never wraps, two rows collapse
into one, and everything below shifts. That was the finding behind this
document's old recommendation, **"run the live board on `Internal`."**

**That cause was removed.** `d8f27ee` ("make LORD's art render the same at
any terminal width") rewrapped `LORDTXT.DAT`, inserting a CR/LF at each of the
68 places across `@#ARTHUR`, `@#CHANCE`, `@#TURGON`, `@#VIOLET`, `@#BT` and
`@#FOOT` where an 80-column terminal used to wrap for free -- Violet's screen,
the one that surfaced the bug, among them. On an 80-column terminal the output
is byte-for-byte unchanged; on any other width the file now says what the
terminal used to do for it, instead of leaving it to a wrap that no longer
happens. The patched file is what the live board serves.

The same commit deliberately left the second dependency, `ESC[nC` clamping,
alone: three sites rely on it, against the 68 fixed. Pre-clamping them was
tried and abandoned -- deleting a forward that was already at the margin also
clears the terminal's pending-wrap flag, which moves the next character too,
so the rewrite was not idempotent without also modelling pending-wrap
semantics. Not worth it for three sites, so they are counted, reported, and
left alone (`d8f27ee`'s commit message has the detail). If a screen ever looks
subtly wrong near the right edge on a wide terminal, this is where to look
first -- a known, narrow gap, not a guess.

**Run the live board on `Regular Fossil`.** Nodes 1-4 already do. This is
still a bug in LORD, not here, and it is still deliberately not worked around
by rewriting a program's escape sequences on the wire -- `d8f27ee` fixed the
data LORD ships, not the transport.

If a door is set to a FOSSIL mode and the driver does not answer, the failure
is not subtle -- LORD says `Fossil was not initialized properly! You should
change to INTERNAL`. `AH=04h` returning `0x1954` is what prevents that.

## Install

```sh
cargo build --release -p dos-runtime
cp target/release/runexe            /sbbs/xtrn/lord/runexe
cp crates/dos-runtime/door/lord-dospoc.sh /sbbs/xtrn/lord/
chmod +x /sbbs/xtrn/lord/lord-dospoc.sh
```

## The Synchronet entry

Add to `/sbbs/ctrl/xtrn.ini`, then recycle Synchronet so it re-reads the file.
The settings are the same ones the existing dosemu entry uses, and they matter:
`type=3` asks for a `DOOR.SYS` dropfile, and `16388` is `XTRN_NATIVE |
XTRN_STDIO`, which is what makes Synchronet give the door a real pty instead of
a pipe.

```ini
[prog:MAIN:LORDDP]
	name=Legend of the Red Dragon (dos-runtime)
	ars=
	execution_ars=
	type=3
	settings=16388
	event=0
	cost=0
	cmd=/sbbs/xtrn/lord/lord-dospoc.sh %#
	clean_cmd=
	startup_dir=/sbbs/xtrn/lord
	textra=0
	max_time=0
	max_inactivity=0
```

Deliberately a **second** entry rather than a replacement for the working
dosemu one. Two doors against the same data directory can be compared
side by side, and the one that has been serving players keeps serving them
while this is shaken out.

## Trying it without a board

Everything the wrapper touches is overridable, so a session can be driven from
a scratch copy:

```sh
mkdir -p /tmp/x/node9 && cp -r /sbbs/xtrn/lord /tmp/x/lord
# ... write a 52-line DOOR.SYS to /tmp/x/node9/DOOR.SYS ...
LORD_DIR=/tmp/x/lord SBBS_NODE_DIR=/tmp/x/node9 \
  RUNEXE=$PWD/target/release/runexe \
  crates/dos-runtime/door/lord-dospoc.sh 9
```

## Baud

Taken from the dropfile: line 2 is the connect rate, line 5 the DTE rate, and a
telnet door commonly reports 0 on line 2 meaning no modem is involved. `--baud
<n>` overrides it and `--baud 0` disables pacing entirely.

Pacing is not only politeness to a slow link. LORD's text effects and ANSI
animation were authored for 2400 to 14400 baud, and sending them instantly
removes timing the author put there on purpose -- the same class of thing as a
dramatic pause, in the other direction.

## What is not here yet

- **In-game modules.** LORD exits with code 254 to ask its caller to run
  `DO<node>.BAT`. The wrapper detects it and says so rather than dumping the
  player back to the BBS as though the game had ended, but the IGM does not
  run: that needs `int 21h AH=4Bh` (EXEC), which is unimplemented.
- **Multinode against the live data has not been exercised.** `AH=5Ch` record
  locking is implemented and unit-tested, but no two players have yet been in
  the same file at once through this runtime.
