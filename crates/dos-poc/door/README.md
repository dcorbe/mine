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
changes nothing on the wire and nothing in this directory. Measured on a real
session, `Regular Fossil` produced 1467 `AH=01` transmits and exactly 1467
bytes out.

If a door is set to a FOSSIL mode and the driver does not answer, the failure
is not subtle -- LORD says `Fossil was not initialized properly! You should
change to INTERNAL`. `AH=04h` returning `0x1954` is what prevents that.

## Install

```sh
cargo build --release -p dos-poc
cp target/release/runexe            /sbbs/xtrn/lord/runexe
cp crates/dos-poc/door/lord-dospoc.sh /sbbs/xtrn/lord/
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
	name=Legend of the Red Dragon (dos-poc)
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
  crates/dos-poc/door/lord-dospoc.sh 9
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
