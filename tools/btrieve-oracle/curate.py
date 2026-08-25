#!/usr/bin/env python3
"""
curate.py -- find the size-changing (page-allocating) operations in a
split_oracle.py recording and produce a dump-v6 diff for each, so the
interesting transitions in a long run are legible without wading through
every snapshot by hand.

USAGE
    python3 curate.py <expdir> <dump-v6-binary>

Reads <expdir>/manifest.tsv, and for every seq whose `size` column differs
from the previous seq's, runs <dump-v6-binary> on both snapshots and writes
a unified diff to <expdir>/events/<seq>.diff, plus a one-line summary to
<expdir>/events/SUMMARY.txt.
"""
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: curate.py <expdir> <dump-v6-binary>", file=sys.stderr)
        return 2
    expdir, dumpbin = sys.argv[1], sys.argv[2]
    rows = []
    with open(os.path.join(expdir, "manifest.tsv")) as f:
        header = f.readline()
        for line in f:
            seq, op, value, tag, status, size = line.rstrip("\n").split("\t")
            rows.append((int(seq), op, value, tag, status, int(size)))

    events_dir = os.path.join(expdir, "events")
    os.makedirs(events_dir, exist_ok=True)
    summary = []

    def dump(seq):
        path = None
        snapdir = os.path.join(expdir, "snapshots")
        for f in os.listdir(snapdir):
            if f.startswith(f"{seq:05d}-"):
                path = os.path.join(snapdir, f)
                break
        if path is None:
            return None
        p = subprocess.run([dumpbin, path], capture_output=True, text=True)
        return p.stdout

    prev_size = None
    for seq, op, value, tag, status, size in rows:
        if prev_size is not None and size != prev_size:
            a = dump(seq - 1)
            b = dump(seq)
            diffpath = os.path.join(events_dir, f"{seq:05d}.diff")
            if a is not None and b is not None:
                import difflib
                d = list(difflib.unified_diff(
                    a.splitlines(keepends=True), b.splitlines(keepends=True),
                    fromfile=f"seq{seq-1}", tofile=f"seq{seq}",
                ))
                with open(diffpath, "w") as out:
                    out.writelines(d)
            line = f"seq {seq}: {op} {value} (status {status}) size {prev_size} -> {size}"
            summary.append(line)
            print(line)
        prev_size = size

    with open(os.path.join(events_dir, "SUMMARY.txt"), "w") as f:
        f.write("\n".join(summary) + "\n")
    print(f"{len(summary)} size-changing events out of {len(rows)} ops")
    return 0


if __name__ == "__main__":
    sys.exit(main())
