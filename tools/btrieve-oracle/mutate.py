#!/usr/bin/env python3
"""
Damage one index page of a Btrieve file, so the oracle can be shown to notice.

A verification tool that has only ever been pointed at correct input has not
been verified -- it has been used. Before `btrvprobe descend` is allowed to
bless an index this host wrote, it has to go red on an index that is known to
be broken. That is what this produces.

Index pages are identified the way MBBSEmu's reader identifies data pages, by
the complement of its own test: BtrieveFile.LoadBtrieveRecords skips any page
whose byte 5 lacks bit 0x80, so the pages it skips are the index pages. Page 0
is the FCR and is left alone -- corrupting it makes the file fail to OPEN,
which proves nothing about tree traversal.

usage: mutate.py <file> <page-size> [--list | --page N] [--out PATH]
"""
import argparse
import shutil
import sys


def page_kind(page: bytes) -> str:
    """'data' if MBBSEmu's reader would walk this page, else 'index'."""
    return "data" if len(page) > 5 and page[5] & 0x80 else "index"


def pages(blob: bytes, size: int):
    for n in range(len(blob) // size):
        yield n, blob[n * size:(n + 1) * size]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("page_size", type=int)
    ap.add_argument("--list", action="store_true",
                    help="classify every page instead of mutating")
    ap.add_argument("--page", type=int, help="page number to damage")
    ap.add_argument("--out", help="write the damaged copy here")
    args = ap.parse_args()

    blob = open(args.file, "rb").read()
    if len(blob) % args.page_size:
        print(f"warning: {len(blob)} bytes is not a whole number of "
              f"{args.page_size}-byte pages", file=sys.stderr)

    index_pages = [n for n, p in pages(blob, args.page_size)
                   if n and page_kind(p) == "index"]

    if args.list:
        data = sum(1 for n, p in pages(blob, args.page_size) if page_kind(p) == "data")
        print(f"pages       {len(blob) // args.page_size}")
        print(f"data        {data}")
        print(f"index       {len(index_pages)}")
        print(f"index pages {index_pages[:40]}{' ...' if len(index_pages) > 40 else ''}")
        return 0

    if args.page is None:
        if not index_pages:
            print("no index pages found -- nothing to damage", file=sys.stderr)
            return 1
        # The lowest-numbered index page is the one nearest the root, so
        # damaging it invalidates the most descents.
        args.page = index_pages[0]

    if not args.out:
        print("--out is required when mutating", file=sys.stderr)
        return 2

    shutil.copyfile(args.file, args.out)
    with open(args.out, "r+b") as fh:
        off = args.page * args.page_size
        fh.seek(off)
        original = fh.read(args.page_size)
        # Leave the 12-byte page header intact so the page is still *claimed* to
        # be an index page. Scrambling the body is what makes the child pointers
        # and separator keys wrong. Corrupting the header instead would be a
        # weaker test: the engine could reject the page on its type byte without
        # ever attempting a descent.
        body = bytes((b ^ 0x5A) for b in original[12:])
        fh.seek(off + 12)
        fh.write(body)

    print(f"damaged page {args.page} ({page_kind(original)}) of {args.file}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
