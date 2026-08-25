#!/usr/bin/env python3
"""
rawscan.py -- a from-scratch v6 page/FCR/allocation-table reader in Python,
independent of crates/btrieve's own read::file.

WHY THIS EXISTS

crates/btrieve's read::file refuses a whole file outright the moment ANY
claimed page carries a tag it does not recognise (docs/2026-08-25-btree-
split-oracle.md found one such tag, 0x4500, on a leaf a delete-driven merge
emptied). That refusal is the crate reader's own correct, conservative
behaviour -- it must not be loosened just to make an oracle recording
easier to read, since that would mean touching the read path this whole
effort exists to leave alone. This script is the workaround: a second,
independent, TOLERANT decoder that never refuses, used only for analysis
outside the crate, never imported by it and never asserted on by
crates/btrieve/tests/btree_split_oracle.rs except via raw byte reads the
test performs itself.

Only decodes what this oracle's own rig needs: fixed reclen 12, a single
4-byte unsigned-binary key at record position 1, one allocation-table
block. Not a general v6 reader.

USAGE
    rawscan.py <file> fcr                 -- control record + key[0] summary
    rawscan.py <file> alloc               -- every allocation-table entry
    rawscan.py <file> page <physical>     -- one page's header, and its
                                              content decoded AS AN INDEX
                                              PAGE regardless of its tag
                                              (the point: this still works
                                              on a 0x4500 page)
    rawscan.py <file> logical <id>        -- resolve one logical id through
                                              the allocation table, then
                                              print that physical page
"""
import sys

PAGE_SIZE_GUESS = None  # filled in from file length heuristics below


def getu16(data, off):
    return data[off] | (data[off + 1] << 8)


def getlong(data, off):
    # high-word-first long: two little-endian u16 halves, high half first.
    hi = getu16(data, off)
    lo = getu16(data, off + 2)
    return (hi << 16) | lo


def getu32le(data, off):
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)


def guess_page_size(data):
    # v6's FCR page_gen/version fields don't carry page size in a fixed
    # spot this script bothers decoding; instead use the same signal
    # format::generation::identify does -- but the cheap route for this
    # rig's own fixtures (created by split_oracle.py, which always logs its
    # own pagesize in geometry.txt) is: try the legal sizes in order and
    # pick the one where physical page 2 starts with the "PP" magic.
    for candidate in (512, 1024, 1536, 2048, 3584, 4096):
        if len(data) < candidate * 3:
            continue
        off = candidate * 2
        if data[off] == ord('P') and data[off + 1] == ord('P'):
            return candidate
    raise SystemExit("could not guess page size: no 'PP' allocation-table magic found")


def live_fcr_page(data, page_size):
    g0 = getu16(data, 4)
    g1 = getu16(data, page_size + 4)
    return 0 if g0 > g1 else 1


def live_alloc_page(data, page_size):
    g2 = getu16(data, 2 * page_size + 4)
    g3 = getu16(data, 3 * page_size + 4)
    return 2 if g2 > g3 else 3


def fcr_summary(data, page_size):
    live = live_fcr_page(data, page_size)
    base = live * page_size
    generation = getu16(data, base + 4)
    records = getlong(data, base + 0x1a)
    pages = getlong(data, base + 0x26)
    free_v6 = getlong(data, base + 0x9c)
    root_raw = getlong(data, base + 0x110 + 0x00)
    key_records = getlong(data, base + 0x110 + 0x04)
    return {
        "live_fcr_page": live,
        "generation": generation,
        "records": records,
        "pages": pages,
        "free_v6": free_v6,
        "root_raw": root_raw,
        "root_logical": root_raw & 0x00FFFFFF,
        "root_tag": root_raw >> 24,
        "key0_records": key_records,
    }


def alloc_entries(data, page_size):
    live = live_alloc_page(data, page_size)
    entries_per_block = (page_size - 8) // 4
    out = []
    base = live * page_size + 8
    for n in range(entries_per_block):
        off = base + n * 4
        marker = getu16(data, off)
        physical = getu16(data, off + 2)
        logical = n + 1
        out.append((logical, marker, physical))
    return live, out


def physical_of(data, page_size, logical):
    live, entries = alloc_entries(data, page_size)
    for lg, marker, physical in entries:
        if lg == logical:
            return marker, physical
    raise SystemExit(f"logical {logical} has no allocation-table entry")


def page_header(data, page_size, physical):
    off = physical * page_size
    tag = getu16(data, off)
    logical = getu16(data, off + 2)
    stamp = getu16(data, off + 4)
    return tag, logical, stamp


def print_as_index(data, page_size, physical, key_length=4):
    off = physical * page_size
    tag, logical, stamp = page_header(data, page_size, physical)
    count = getu16(data, off + 6)
    rightmost = getlong(data, off + 8)
    leftmost = getlong(data, off + 12)
    print(f"page {physical}: tag={tag:#06x} logical={logical} stamp={stamp} "
          f"count={count} rightmost={rightmost:#010x} leftmost={leftmost:#010x}")
    entry_size = key_length + 8  # unique key; +12 if the key permits duplicates
    entry_off = off + 16
    page_end = off + page_size
    for i in range(count):
        e = entry_off + i * entry_size
        if e + entry_size > page_end and i != count - 1:
            print(f"  entry[{i}] (would run past the page -- stopping)")
            break
        key = int.from_bytes(data[e:e + key_length], "little")
        head = getlong(data, e + key_length)
        child_off = e + key_length + 4
        if i == count - 1 and child_off + 4 > page_end:
            child = None
        else:
            child = getlong(data, child_off)
        child_s = "absent" if child is None else f"{child:#010x} (logical={child & 0xFFFFFF})"
        print(f"  entry[{i}] key={key} head={head:#010x} child={child_s}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, cmd = sys.argv[1], sys.argv[2]
    data = open(path, "rb").read()
    page_size = guess_page_size(data)

    if cmd == "fcr":
        s = fcr_summary(data, page_size)
        print(f"page_size={page_size}")
        for k, v in s.items():
            print(f"  {k} = {v if not isinstance(v, int) else hex(v) if 'raw' in k or 'tag' in k else v}")
    elif cmd == "alloc":
        live, entries = alloc_entries(data, page_size)
        print(f"page_size={page_size} live_alloc_page={live}")
        for logical, marker, physical in entries:
            if marker != 0 or physical != 0:
                print(f"  logical={logical} marker={marker:#06x} physical={physical}")
    elif cmd == "page":
        physical = int(sys.argv[3])
        print_as_index(data, page_size, physical)
    elif cmd == "logical":
        logical = int(sys.argv[3])
        marker, physical = physical_of(data, page_size, logical)
        print(f"logical={logical} -> marker={marker:#06x} physical={physical}")
        if marker != 0:
            print_as_index(data, page_size, physical)
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
