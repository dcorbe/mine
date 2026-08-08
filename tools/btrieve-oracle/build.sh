#!/bin/sh
# Build btrvprobe.exe and install it, with the Btrieve 6.15 engine, into the
# Wine prefix the oracle runs in. Idempotent; re-run after editing the C.
#
# The prefix is deliberately NOT ~/.wine: the engine registers itself under
# HKLM\Software\WOW6432Node\Btrieve Technologies, and no other Wine prefix on
# this machine should inherit that.
set -e

# Resolved from this script's own location, NOT from `git rev-parse
# --show-toplevel`, which answers about the CURRENT DIRECTORY. Running
# `sh .worktrees/x/tools/btrieve-oracle/build.sh` from the main checkout used
# that answer to compile the main checkout's btrvprobe.c and install it over
# the worktree's, and the next sweep then measured the wrong program while
# reporting the worktree's paths. The script knows where it lives; use that.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPO=$HERE
PREFIX=${BTRIEVE_WINEPREFIX:-$HOME/.btrieve-wine}
ENGINE=$REPO/docs/mirrors/github-syntax53-Nightmare-Redux
WORK=$PREFIX/drive_c/btrieve

# -Wno-cast-function-type: GetProcAddress returns FARPROC and every Win32
# program has to cast it. The cast is the documented way to call the export.
i686-w64-mingw32-gcc -O2 -Wall -Wextra -Wno-cast-function-type \
    -o "$REPO/tools/btrieve-oracle/btrvprobe.exe" \
    "$REPO/tools/btrieve-oracle/btrvprobe.c"

if [ ! -d "$PREFIX" ]; then
    # WINEARCH=win32 is rejected by wow64-mode Wine (11.x on this box), so the
    # prefix is win64 and the 32-bit engine lives in syswow64.
    WINEPREFIX=$PREFIX wineboot -u
    for r in btrieve-settings-64bit.reg btrieve-settings-32bit.reg; do
        WINEPREFIX=$PREFIX wine regedit "$REPO/docs/mirrors/files.mud.fyi/$r"
    done
fi

mkdir -p "$WORK"
for f in WBTRV32.DLL W32MKDE.EXE W32MKRC.DLL W32MKSET.DLL; do
    cp "$ENGINE/$f" "$PREFIX/drive_c/windows/syswow64/$f"
    cp "$ENGINE/$f" "$WORK/$f"
done
cp "$REPO/tools/btrieve-oracle/btrvprobe.exe" "$WORK/"

echo "built; prefix $PREFIX, work dir $WORK"
