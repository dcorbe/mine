#!/usr/bin/env bash
# build.sh -- headless DOSBox harness for the v5.00c Btrieve oracle attempt
# (Track B Task 7). Everything it touches lives under tmp/btvcompat/dos,
# which is mounted into DOSBox as C:.
#
# Usage:
#   tools/btrieve-oracle/v5/build.sh setup     # extract TC 2.01 + stage BTRIEVE.EXE
#   tools/btrieve-oracle/v5/build.sh control   # compile+link control_no_header.c
#   tools/btrieve-oracle/v5/build.sh repro     # compile+link repro_dos_h_bug.c
#   tools/btrieve-oracle/v5/build.sh v5create  # compile+link+run v5create.c (will fail until repro is fixed)
#   tools/btrieve-oracle/v5/build.sh bisect    # scaffolded, NOT run -- see below
#
# Every target mints a fresh DOSBox conf + autoexec .BAT under
# tmp/btvcompat/dos, runs `dosbox -conf ... -c exit` headless (SDL dummy
# driver, no window), and leaves logs + .OBJ/.EXE next to the source.
#
# `bisect`: the plan for finding exactly which dos.h declaration breaks
# TCC.EXE (see repro_dos_h_bug.c's header comment for why a naive line-range
# split of dos.h doesn't work -- it breaks the file's own include guard).
# The correct approach:
#   1. Run dos.h through CPP.EXE (already proven to work, see repro comment)
#      to get a directive-free, fully macro-expanded flat file.
#   2. Binary-search THAT file: take a prefix, append `int main(void){return 0;}`,
#      compile with TCC.EXE, check for PUBDEF _main in the .OBJ (grep -a -o
#      '_main' on the .OBJ is sufficient -- see how this script's `check_obj`
#      helper does it below).
#   3. Halve the search range based on whether _main appears; repeat.
# This is NOT implemented here -- it is real work for a follow-up session,
# scaffolded so it does not need to be rediscovered.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DOS="$ROOT/tmp/btvcompat/dos"
TC201_ZIP="$ROOT/archive/tooling/compilers/tc201.zip"
BTRIEVE_EXE="$ROOT/re/wg33src/BIN/BTRIEVE.EXE"
V5DIR="$ROOT/tools/btrieve-oracle/v5"

# check_obj OBJFILE -- prints "LINKED" if the OBJ has a real _main PUBDEF
# (i.e. the compile actually generated code), else "NO_MAIN".
check_obj() {
    if grep -a -o '_main' "$1" >/dev/null 2>&1; then
        echo LINKED
    else
        echo NO_MAIN
    fi
}

setup() {
    mkdir -p "$DOS/tc201" "$DOS/scratch"
    if [ ! -f "$DOS/tc201/TCC.EXE" ]; then
        echo "extracting Turbo C 2.01 to $DOS/tc201" >&2
        unzip -o -q "$TC201_ZIP" -d "$DOS/tc201"
    fi
    if [ ! -f "$DOS/BTRIEVE.EXE" ]; then
        cp "$BTRIEVE_EXE" "$DOS/BTRIEVE.EXE"
        chmod +w "$DOS/BTRIEVE.EXE"
    fi
    echo "setup OK: $DOS/tc201/TCC.EXE, $DOS/BTRIEVE.EXE" >&2
}

# run_dosbox BATNAME -- writes tmp/btvcompat/dos/<BATNAME>, a matching
# dosbox conf, and runs it headless with a 90s timeout.
run_dosbox() {
    local bat="$1"
    local conf="$DOS/${bat%.BAT}.conf"
    cat > "$conf" <<EOF
[sdl]
fullscreen=false
[dosbox]
[autoexec]
mount c $DOS
c:
call $bat
exit
EOF
    ( cd "$DOS" && timeout 90 env SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy \
        dosbox -conf "$conf" -c exit > "${bat%.BAT}.stdout.log" 2>&1 )
}

compile_one() {
    # NOTE: every generated DOS filename (batch, conf, logs) must fit 8.3 --
    # this bit a first version of this script: an 11-char "RUN_CONTROL.BAT"
    # autoexec target was silently un-callable (no error surfaced, the
    # `call` just did nothing) under DOSBox's local-drive 8.3 mapping. Keep
    # $stem itself <= 8 chars (CONTROL, REPRO, V5CREATE all qualify) and
    # never prefix/suffix it past that limit for a DOS-side filename.
    local src="$1" stem="$2"
    cp "$V5DIR/$src" "$DOS/scratch/$stem.C"
    cat > "$DOS/${stem}.BAT" <<EOF
@echo off
set PATH=C:\TC201
cd \SCRATCH
C:\TC201\TCC.EXE -IC:\TC201 -LC:\TC201 ${stem}.C > CLOG.TXT
echo DONE > CDONE.TXT
EOF
    run_dosbox "${stem}.BAT"
    echo "--- ${stem} compile log ---"
    cat "$DOS/scratch/CLOG.TXT" 2>/dev/null || echo "(no log)"
    echo "--- ${stem}.OBJ ---"
    check_obj "$DOS/scratch/${stem}.OBJ"
}

case "${1:-}" in
    setup)    setup ;;
    control)  setup; compile_one control_no_header.c CONTROL ;;
    repro)    setup; compile_one repro_dos_h_bug.c REPRO ;;
    v5create)
        setup
        compile_one v5create.c V5CREATE
        ;;
    bisect)
        echo "not implemented -- see this script's header comment for the plan" >&2
        exit 1
        ;;
    *)
        echo "usage: $0 {setup|control|repro|v5create|bisect}" >&2
        exit 1
        ;;
esac
