#!/usr/bin/env python3
"""
split_oracle.py -- drive crtprobe.exe through a scripted sequence of B-tree
inserts/deletes against genuine Btrieve 6.15, snapshotting the whole file
after every single operation.

Built for docs/2026-08-25-btree-split-oracle.md: crates/btrieve rebuilds a
whole B-tree on every write (Block::update_v6 -> v6_reindex); the replacement
is incremental maintenance, and this records what the real engine does on a
leaf split, an interior/root split, and a delete/underflow, rather than
inferring it from a standard. Every experiment here creates its own,
never-reused file name -- the Microkernel caches pages by path across
processes (sweep.sh's and varfree.c's own warnings), so a name is retired
once used.

USAGE
    python3 split_oracle.py <experiment> <outdir>

Experiments: append512u, middle512u, dup512, append4096u, underflow512u
(see EXPERIMENTS at the bottom). Each writes outdir/<experiment>/snapshots/
NNNNN-<op>.dat, outdir/<experiment>/manifest.tsv (seq, op, value, status,
size), and outdir/<experiment>/geometry.txt.

Every crtprobe invocation opens, does one op, closes -- so every snapshot is
what reached disk, not what the engine was still holding in memory. This
script does not build btrvprobe.exe / crtprobe.exe -- run
tools/btrieve-oracle/build.sh first, then reinstall crtprobe.exe by hand
(build.sh only wires up btrvprobe.exe) if crtprobe.c changed.
"""
import os
import shutil
import subprocess
import sys
import tempfile

PREFIX = os.environ.get("BTRIEVE_WINEPREFIX", os.path.expanduser("~/.btrieve-wine"))
WORK = os.path.join(PREFIX, "drive_c", "btrieve")
CRTPROBE = "crtprobe.exe"

# `wine` forks a background services/wineserver process that inherits
# stdout/stderr and keeps them open past the point `crtprobe.exe` itself
# exits -- `subprocess.run(capture_output=True)` then blocks forever waiting
# for EOF on that pipe, timeout or not (measured: hung the full 30s on the
# very first call this file made). Redirecting to a real file instead of a
# pipe sidesteps it -- the file closes when THIS process is done with it,
# never waiting on wine's grandchildren.
#
# dir=WORK, not the system temp dir: this repo never uses /tmp for scratch.
SCRATCH = tempfile.mkdtemp(prefix="split-oracle-", dir=WORK)


def wine(args, check=True):
    env = dict(os.environ)
    env["WINEPREFIX"] = PREFIX
    env["WINEDEBUG"] = "-all"
    outpath = os.path.join(SCRATCH, "out.txt")
    with open(outpath, "w") as f:
        p = subprocess.run(
            ["wine", CRTPROBE] + args, cwd=WORK, env=env,
            stdout=f, stderr=subprocess.STDOUT, timeout=30,
        )
    out = open(outpath).read().strip()
    if check and p.returncode not in (0, 1):
        raise RuntimeError(f"crtprobe {args} crashed: rc={p.returncode} {out}")
    return p.returncode, out, ""


def dos_path(name):
    return "C:\\btrieve\\" + name


def create(name, reclen, pagesize, dup, overwrite=0):
    flags = 0x100 | (0x001 if dup else 0)
    rc, out, err = wine([
        "create", dos_path(name), str(reclen), str(pagesize), "0", "0",
        str(overwrite), "1", "1", "4", "14", str(flags),
    ])
    if rc != 0:
        raise RuntimeError(f"create {name} failed: {out} {err}")
    return out


def record_hex(reclen, value, tag=0):
    """4-byte little-endian key at record byte 0, then a 4-byte little-endian
    tag (the *order this key value was inserted in*, so a later dump can
    tell insertion order apart from key order), then zero padding to reclen.
    """
    b = value.to_bytes(4, "little") + tag.to_bytes(4, "little")
    b += bytes(reclen - len(b))
    assert len(b) == reclen
    return b.hex()


def insert(name, reclen, value, tag=0):
    rc, out, err = wine(["insert", dos_path(name), record_hex(reclen, value, tag)], check=False)
    status = "OK" if rc == 0 else out.splitlines()[-1] if out else err
    return rc, status


def delete(name, value):
    key_hex = value.to_bytes(4, "little").hex()
    rc, out, err = wine(["delete", dos_path(name), key_hex], check=False)
    status = "OK" if rc == 0 else (out.splitlines()[-1] if out else err)
    return rc, status


def delete_nth(name, value, n):
    """Delete the nth member (0 = head) of `value`'s duplicate chain --
    GET_EQUAL then GET_NEXT n times, then DELETE. `value` need not be
    unique to the chain the way plain `delete` above assumes."""
    key_hex = value.to_bytes(4, "little").hex()
    rc, out, err = wine(["delete_nth", dos_path(name), key_hex, str(n)], check=False)
    status = "OK" if rc == 0 else (out.splitlines()[-1] if out else err)
    return rc, status


def snapshot(name, dest):
    src = os.path.join(WORK, name)
    if not os.path.exists(src):
        # Wine/DOS folded the case; find it case-insensitively.
        for f in os.listdir(WORK):
            if f.lower() == name.lower():
                src = os.path.join(WORK, f)
                break
    shutil.copyfile(src, dest)
    return os.path.getsize(src)


class Recorder:
    def __init__(self, expdir, name, reclen, pagesize, dup):
        self.expdir = expdir
        self.name = name
        self.reclen = reclen
        self.pagesize = pagesize
        self.dup = dup
        self.seq = 0
        os.makedirs(os.path.join(expdir, "snapshots"), exist_ok=True)
        self.manifest = open(os.path.join(expdir, "manifest.tsv"), "w")
        self.manifest.write("seq\top\tvalue\ttag\tstatus\tsize\n")
        with open(os.path.join(expdir, "geometry.txt"), "w") as g:
            g.write(
                f"file={name} reclen={reclen} pagesize={pagesize} dup={dup} "
                f"key: unsigned-binary (type 14), 4 bytes at position 1, "
                f"little-endian, {'DUP|' if dup else ''}EXTTYPE\n"
            )

    def snap(self, op, value, tag, status):
        self.seq += 1
        dest = os.path.join(self.expdir, "snapshots", f"{self.seq:05d}-{op}-{value}.dat")
        size = snapshot(self.name, dest)
        self.manifest.write(f"{self.seq}\t{op}\t{value}\t{tag}\t{status}\t{size}\n")
        self.manifest.flush()
        return size

    def do_create(self, overwrite=0):
        out = create(self.name, self.reclen, self.pagesize, self.dup, overwrite)
        self.snap("create", "-", "-", out.replace("\t", " "))

    def do_insert(self, value, tag=0):
        rc, status = insert(self.name, self.reclen, value, tag)
        self.snap("insert", value, tag, status)
        return rc == 0

    def do_delete(self, value):
        rc, status = delete(self.name, value)
        self.snap("delete", value, "-", status)
        return rc == 0

    def do_delete_nth(self, value, n):
        rc, status = delete_nth(self.name, value, n)
        self.snap(f"delete_nth{n}", value, "-", status)
        return rc == 0

    def close(self):
        self.manifest.close()


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------

def exp_append(outdir, n, pagesize=512, dup=False, name="SPLAPP"):
    """Right-edge append: ascending sequential keys, one record each. Watches
    a single leaf fill, split, and (given enough n) the interior root that
    split creates fill and split in turn -- growing the tree by a level."""
    r = Recorder(outdir, f"{name}.DAT", 12, pagesize, dup)
    r.do_create()
    for i in range(1, n + 1):
        r.do_insert(i, tag=i)
    r.close()


def exp_middle(outdir, spread, gap, name="SPLMID"):
    """Populate a leaf with a sparse ascending sequence (room left to grow),
    then insert one key that falls in the MIDDLE of the existing range --
    the insert that is not at either edge -- and watch how that split (if
    any) distributes entries compared to the append case."""
    r = Recorder(outdir, f"{name}.DAT", 12, 512, False)
    r.do_create()
    values = [gap * i for i in range(1, spread + 1)]
    for i, v in enumerate(values, start=1):
        r.do_insert(v, tag=i)
    # One key landing between the 20th and 21st inserted value.
    mid = values[len(values) // 2] - gap // 2
    r.do_insert(mid, tag=len(values) + 1)
    r.close()


def exp_dup(outdir, n, name="SPLDUP"):
    """A duplicatable key: n distinct ascending values (each its own group of
    1) through at least one split, then a run of several records that all
    SHARE one key value, landing near the split boundary, to see how the
    duplicate chain (head/tail) is handled when its group crosses a split."""
    r = Recorder(outdir, f"{name}.DAT", 12, 512, True)
    r.do_create()
    for i in range(1, n + 1):
        r.do_insert(i, tag=i)
    # Now insert five records that all share the same key value as the LAST
    # value inserted, forcing a duplicate group at the current right edge.
    dup_value = n
    for j in range(5):
        r.do_insert(dup_value, tag=n + 1 + j)
    r.close()


def exp_underflow(outdir, n, name="SPLDEL"):
    """Build a two-(or more)-leaf tree by ascending append, then delete every
    record out of the RIGHTMOST leaf one at a time, oldest-inserted-in-that-
    leaf first, to see whether Btrieve merges/redistributes with the sibling
    or leaves the page sparse, and whether the interior entry pointing at it
    is ever removed."""
    r = Recorder(outdir, f"{name}.DAT", 12, 512, False)
    r.do_create()
    for i in range(1, n + 1):
        r.do_insert(i, tag=i)
    # Delete the top half of the key range, descending from the top (empties
    # the rightmost leaf(s) first without touching the left side at all).
    top_half = list(range(n, n - n // 2, -1))
    for v in top_half:
        r.do_delete(v)
    r.close()


EXPERIMENTS = {
    "append512u": lambda outdir: exp_append(outdir, 1800, pagesize=512, dup=False, name="SPLAPPU"),
    "append4096u": lambda outdir: exp_append(outdir, 360, pagesize=4096, dup=False, name="SPLAPP4"),
    "middle512u": lambda outdir: exp_middle(outdir, 40, 1000, name="SPLMIDU"),
    "dup512": lambda outdir: exp_dup(outdir, 40, name="SPLDUPU"),
    "underflow512u": lambda outdir: exp_underflow(outdir, 120, name="SPLDELU"),
}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in EXPERIMENTS:
        print(f"usage: split_oracle.py <{'|'.join(EXPERIMENTS)}> <outdir>", file=sys.stderr)
        return 2
    name, outdir = sys.argv[1], sys.argv[2]
    expdir = os.path.join(outdir, name)
    os.makedirs(expdir, exist_ok=True)
    EXPERIMENTS[name](expdir)
    print(f"{name}: recorded to {expdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
