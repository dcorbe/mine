#!/bin/sh
# Dump every key of every file in two directories, in index order, and diff the
# two sequences.
#
#   compare.sh tmp target/btrieve-corpus/reindex
#
# `sweep.sh` reports the first key, the last key and the count. Those three can
# all agree while the middle of the sequence is permuted -- which is exactly
# what a wrong key comparator produces, since a permutation preserves the
# extremes. This is what closes that gap: the whole sequence, read out of each
# file by the real engine, compared entry for entry.
#
# Files present in the first directory and absent from the second are skipped;
# a corpus holds only the files that hold records.
set -e

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PREFIX=${BTRIEVE_WINEPREFIX:-$HOME/.btrieve-wine}
WORK=$PREFIX/drive_c/btrieve
export WINEPREFIX=$PREFIX
LIMIT=${BTRIEVE_TIMEOUT:-600}

[ $# -eq 2 ] || { echo "usage: compare.sh <dir-a> <dir-b>" >&2; exit 2; }

abs() { case $1 in /*) echo "$1" ;; *) echo "$REPO/$1" ;; esac; }
A=$(abs "$1")
B=$(abs "$2")

# The dumps go here rather than through a pipe: a diff is only worth trusting if
# what it compared is still on disk to look at afterwards.
OUT=${BTRIEVE_DUMPS:-$REPO/target/btrieve-dumps}
rm -rf "$OUT"
mkdir -p "$OUT"

# EVERY FILE IS PRESENTED UNDER A PATH NOTHING HAS USED BEFORE.
#
# The Btrieve workstation Microkernel is a shared server process that outlives
# any one client and caches pages by path. This script is where that was found:
# presenting the shipped WCCITEMS.VIR and a rebuilt one as the same
# `C:\btrieve\WCCITEMS.VIR`, seconds apart, made the engine dump 2,861 keys out
# of a file whose own stat said 1,950 records -- and the four "DIFFER" verdicts
# that produced were the tool, not the data. The PID plus a counter makes every
# path new, so there is nothing to serve stale.
RUN=$$
seq=0

# The engine's own view of a file, presented fresh: prints the key count, or
# nothing if the file will not open.
indexes() {   # indexes <dir> <name>
    seq=$((seq + 1))
    as="$RUN-$seq-$2"
    cp "$1/$2" "$WORK/$as"
    ( cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe stat "C:\\btrieve\\$as" 2>/dev/null ) \
        | sed -n 's/^indexes  *\([0-9]*\).*/\1/p'
    rm -f "$WORK/$as"
}

# One file's whole key sequence, into $OUT/<tag>.keys.
dump() {   # dump <dir> <name> <keynum> <tag>
    dir=$1; file=$2; keynum=$3; tag=$4
    seq=$((seq + 1))
    as="$RUN-$seq-$file"
    cp "$dir/$file" "$WORK/$as"
    ( cd "$WORK" && timeout "$LIMIT" wine btrvprobe.exe keys "C:\\btrieve\\$as" "$keynum" \
        2>"$OUT/$tag.err" ) > "$OUT/$tag.keys"
    rm -f "$WORK/$as"

    # `dump` reports how many keys it yielded and how many records the file's
    # own stat claims, from the same open. They must agree: a walk that yields
    # more entries than the file has records has been served pages that do not
    # belong to it, and comparing that against anything is meaningless. This is
    # the check that would have caught the stale-cache reading above on sight.
    got=$(sed -n 's/^dumped \([0-9]*\) keys of \([0-9]*\)$/\1/p' "$OUT/$tag.err")
    want=$(sed -n 's/^dumped \([0-9]*\) keys of \([0-9]*\)$/\2/p' "$OUT/$tag.err")
    if [ "$got" != "$want" ]; then
        echo "INCOHERENT $tag: dumped ${got:-none} keys, stat says ${want:-none}" >&2
        exit 3
    fi
}

same=0
differ=0
for src in "$A"/*.VIR "$A"/*.DAT; do
    [ -f "$src" ] || continue
    name=$(basename "$src")
    [ -f "$B/$name" ] || continue

    keys=$(indexes "$A" "$name")
    [ -n "$keys" ] || { echo "$name: stat failed"; differ=$((differ + 1)); continue; }

    k=0
    while [ "$k" -lt "$keys" ]; do
        dump "$A" "$name" "$k" "a-$name-$k"
        dump "$B" "$name" "$k" "b-$name-$k"
        if cmp -s "$OUT/a-$name-$k.keys" "$OUT/b-$name-$k.keys"; then
            echo "SAME  $name key $k ($(wc -l < "$OUT/a-$name-$k.keys") entries)"
            same=$((same + 1))
        else
            echo "DIFFER $name key $k"
            diff "$OUT/a-$name-$k.keys" "$OUT/b-$name-$k.keys" | head -10 | sed 's/^/    /'
            differ=$((differ + 1))
        fi
        k=$((k + 1))
    done
done

echo "same $same, differ $differ"
[ "$differ" -eq 0 ]
