#!/bin/sh
# Run the real Btrieve engine over every MajorMUD data file in tmp/ and report
# stat / walk / descend for each key of each file.
#
# Files are COPIED into the Wine work dir first. tmp/ holds the only copies of
# the shipped data this repo has, and Btrieve writes to files it opens even in
# read-only mode (pre-image and lock bookkeeping) -- the fixtures must not be
# the thing under test.
set -e

REPO=$(git rev-parse --show-toplevel)
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

for src in "$REPO"/tmp/*.VIR "$REPO"/tmp/*.DAT; do
    [ -f "$src" ] || continue
    name=$(basename "$src")
    cp "$src" "$WORK/$name"

    echo "===== $name"
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
