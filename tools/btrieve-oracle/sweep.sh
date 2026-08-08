#!/bin/sh
# Run the real Btrieve engine over every Btrieve file in a directory and report
# stat / walk / descend for each key of each file.
#
#   sweep.sh                       the shipped data in tmp/
#   sweep.sh target/btrieve-corpus a corpus this host wrote
#
# With no argument it sweeps $REPO/tmp, which is what it did when it only ever
# read MajorMUD's own files. `cargo test -p mbbs --test forge -- --ignored`
# produces the other kind, one subdirectory per write variant; each has to be
# swept separately, since a directory is what this takes.
#
# Files are COPIED into the Wine work dir first. tmp/ holds the only copies of
# the shipped data this repo has, and Btrieve writes to files it opens even in
# read-only mode (pre-image and lock bookkeeping) -- the fixtures must not be
# the thing under test.
set -e

# This script's own checkout, not `git rev-parse --show-toplevel`'s answer
# about the current directory -- see the same note in build.sh.
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
FROM=${1:-$REPO/tmp}
case $FROM in /*) ;; *) FROM=$REPO/$FROM ;; esac
[ -d "$FROM" ] || { echo "no such directory: $FROM" >&2; exit 2; }
PREFIX=${BTRIEVE_WINEPREFIX:-$HOME/.btrieve-wine}
WORK=$PREFIX/drive_c/btrieve
export WINEPREFIX=$PREFIX

# Per-invocation ceiling. The Btrieve workstation engine is a shared process:
# running other wine clients against it while a sweep is in flight was observed
# to wedge one invocation indefinitely (the sweep stalled on WCCGANGS while a
# mutation test ran alongside it; the same call completed in under a second on
# its own). A timeout turns that into a reported gap instead of a hung script.
# Nothing else should touch the prefix while this runs.
LIMIT=${BTRIEVE_TIMEOUT:-300}

quiet() { grep -v -E 'fixme|:err:|^$' || true; }

# THE PATH A FILE IS PRESENTED UNDER MUST NEVER BE REUSED.
#
# The Btrieve workstation Microkernel is a shared server process that outlives
# any one client and caches pages by path. Copying two different files to the
# same `C:\btrieve\WCCITEMS.VIR` -- the shipped one and a rebuilt one, which is
# exactly what sweeping two directories does -- gets the second one served from
# the first one's cached pages. Measured: an early `compare.sh` did that and the
# engine dumped 2,861 keys out of a file whose own stat, on the same open, said
# 1,950 records. Nothing in the reply says "stale"; the numbers simply stop
# adding up, and only because the dump reported both did it show at all.
#
# The run's PID makes every path new, so there is nothing to serve stale.
RUN=$$

echo "##### $FROM"
for src in "$FROM"/*.VIR "$FROM"/*.DAT; do
    [ -f "$src" ] || continue
    base=$(basename "$src")
    name="$RUN$base"
    cp "$src" "$WORK/$name"

    echo "===== $base"
    keys=$(cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe stat "C:\\btrieve\\$name" 2>/dev/null \
           | sed -n 's/^indexes  *\([0-9]*\).*/\1/p')
    if [ -z "$keys" ]; then
        echo "  stat failed:"
        (cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe stat "C:\\btrieve\\$name" 2>&1) | quiet | sed 's/^/  /'
        continue
    fi
    (cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe stat "C:\\btrieve\\$name" 2>&1) | quiet | sed 's/^/  /'

    k=0
    while [ "$k" -lt "$keys" ]; do
        echo "  --- key $k"
        (cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe walk    "C:\\btrieve\\$name" "$k" 2>&1) | quiet | sed 's/^/    /'
        (cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe descend "C:\\btrieve\\$name" "$k" 2>&1) | quiet | sed 's/^/    /'
        k=$((k + 1))
    done
    rm -f "$WORK/$name"
done
