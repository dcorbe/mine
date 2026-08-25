B-tree split/underflow oracle recordings, genuine Pervasive/Novell Btrieve
6.15 under Wine. Full findings: docs/2026-08-25-btree-split-oracle.md.

Each experiment directory holds:
  manifest.tsv   every operation of the FULL recorded run, in order: seq,
                 op, value (the record's key), tag (insertion order, so key
                 order and insertion order can be told apart), status, and
                 the whole file's size in bytes after that op. This is the
                 complete "after every single operation" recording; only a
                 few of its snapshots are kept as binary fixtures below.
  geometry.txt   reclen/pagesize/key shape used to create the file.
  <event>/
    before.dat, after.dat   the whole file, before and after the one
                             operation of interest (byte-identical copies
                             of two consecutive manifest.tsv rows' state).
    dump-before.txt,
    dump-after.txt           `cargo run -p btrieve --bin dump-v6 -- <file>`
                             output: every v6 page's decoded content
                             (control record, key descriptor, allocation
                             table, index entries, data slots), in a
                             stable line-oriented form.
    diff.txt                 `diff -u dump-before.txt dump-after.txt` --
                             the actual deliverable: exactly which pages,
                             entries and allocation-table slots changed.

Experiments:
  append512u/leaf-split          -- 41-entry leaf fills and splits, root
                                     moves (depth 1 -> 2). reclen 12,
                                     pagesize 512, unique key.
  append512u/interior-split      -- the interior root that split above
                                     fills to 41 entries and splits again,
                                     root moves a second time (depth 2 -> 3).
  append4096u/leaf-split          -- the same leaf split at pagesize 4096
                                     (max_entries 340, even, vs 512's 41,
                                     odd) -- the geometry that disproved a
                                     half_entries-based guess at the split
                                     point.
  middle512u/leaf-split           -- the record that splits the leaf lands
                                     in the middle of the existing key
                                     range, not at the right edge.
  dup512/leaf-split                -- the same split under a
                                     duplicates-permitted key (wider index
                                     entries: +12 bytes, not +8).
  dup512/duplicate-chain          -- five more records inserted under one
                                     already-split key's LAST value, to see
                                     the head/tail duplicate chain form.
  underflow512u/merge-on-delete   -- deleting the top half of a 4-leaf,
                                     depth-2 tree's keys; before/after
                                     brackets 60 individual deletes, not
                                     one (see the doc for why the exact
                                     triggering delete was not isolated).

Reproduce or extend: tools/btrieve-oracle/split_oracle.py drives
crtprobe.exe (create/insert/delete) and snapshots the file after every
operation; tools/btrieve-oracle/curate.py finds the size-changing ops in a
long run; crates/btrieve/src/bin/dump-v6.rs decodes a snapshot with this
crate's own read::file.

## Round 2 (underflow threshold, merge/redistribute, 0x4500 reclamation)

Added 2026-08-25, closing the three gaps the first round left open (see
docs/2026-08-25-btree-split-oracle.md's "Round 2" section). Same method:
`tools/btrieve-oracle/split_oracle.py`'s `Recorder`, one op per snapshot.
New here: `tools/btrieve-oracle/rawscan.py`, a second, tolerant, from-scratch
decoder used ONLY for files `dump-v6` refuses (an 0x4500-tagged page) --
crates/btrieve's own reader is never loosened to make this easier to read.

  underflow-lifecycle-512/     -- threshold, right-sibling merge, and
                                   0x4500 reclamation, one 4-snapshot run,
                                   odd max_entries (41).
  underflow-lifecycle-4096/    -- the same threshold question at an EVEN
                                   max_entries (340), which crosses on the
                                   first delete instead of the second --
                                   see manifest.txt for why that is NOT a
                                   contradiction.
  underflow-edge-rightmost/    -- the rightmost leaf underflows (no right
                                   sibling): redistributes left, does not
                                   merge.
  underflow-edge-leftmost/     -- the leftmost leaf underflows (no left
                                   sibling): redistributes right.
  underflow-no-room-redistribute/ -- the right sibling is topped up so a
                                   merge would exceed max_entries: Btrieve
                                   redistributes with it anyway rather than
                                   switching to the left sibling.

Each directory's own `manifest.txt` gives the exact op sequence in prose
(this round's fixtures were built by short, one-off scripts rather than
`split_oracle.py`'s CLI experiments, so there is no `manifest.tsv`/
`geometry.txt` pair the way round 1's directories have one). `*.txt` next to
each `.dat` is either `dump-v6`'s output or, when that refuses (an 0x4500
page present), rawscan.py's `fcr`+`alloc` output appended after the refusal
message -- both are in the same file so a reader always sees WHY the
fallback was needed.

## Round 3 (reconciling round 1's merge-into-left with round 2's merge-into-right)

  underflow-right-absent-cascade/ -- the EXACT SAME tree/delete sequence as
                                      round 1's underflow512u/merge-on-delete,
                                      replayed with a snapshot after every
                                      delete instead of one before/after
                                      pair. Shows a leaf that becomes the
                                      rightmost mid-cascade redistributing
                                      with its only (left) neighbour once,
                                      then merging into it once that
                                      neighbour is down to half_entries.
                                      See its own manifest.txt and
                                      docs/2026-08-25-btree-split-oracle.md's
                                      "Round 3" section for the full
                                      predicate tree this settles.

## Round 4 (partial duplicate-chain delete, interior-separator delete, delete-to-empty, multi-candidate reclaim)

Added 2026-08-25, after the concurrent implementer landed real incremental
v6 maintenance and tag 0x4500 support (Task 6) from this doc's own rules.
Every fixture here decodes through plain `read::file` -- `V6Page::retired`
and `pages::fcr::INDEX_FREE_V6` (both new since Round 3) mean rawscan.py's
fallback is not needed for anything recorded from this round on.

  dup-chain-partial-delete/    -- deleting the first/middle/last member of
                                   a 3-member duplicate group, then draining
                                   a separate group to solo and eliminating
                                   it.
  interior-separator-delete/   -- deleting a key that exists only as a
                                   promoted separator in an interior node;
                                   settles predecessor-vs-successor
                                   (predecessor).
  delete-to-empty/             -- deleting a key's last remaining record
                                   (genuine Btrieve allows it; reproduces
                                   the incremental engine's own refusal
                                   bug) and re-inserting afterward.
  retired-page-reclaim-order/  -- two independently-retired (0x4500) pages
                                   queued at once, then two splits: proves
                                   the free list is LIFO (most-recently-
                                   retired reclaimed first), not FIFO or
                                   lowest-logical-id-first.

See each directory's own manifest.txt for the exact op sequence and
`docs/2026-08-25-btree-split-oracle.md`'s "Round 4" section for the full
findings.

## Round 5 (multi-level root collapse)

Added 2026-08-25, the last reachable gap: what happens when an interior
ROOT's own last two children merge into one.

  root-level-collapse/  -- drains the SAME 5-leaf, depth-2 tree rounds 1
                            and 3 built (insert 1..120) all the way to
                            empty (round 3 only drained the top half).
                            Captures the exact operation where the
                            interior root's last entry disappears: the
                            tree drops a level, the surviving child
                            becomes the new root (FCR root pointer moves
                            to the CHILD's own logical id), and BOTH the
                            vacated interior root AND the leaf it just
                            absorbed are retired into the same 0x4500
                            free list, chained together from that one
                            operation. Continues past that to a
                            single-level tree, then to the same virgin
                            shape delete-to-empty recorded (different
                            logical id occupying the root role, same
                            shape).

See its own manifest.txt for the exact op sequence and
`docs/2026-08-25-btree-split-oracle.md`'s "Round 5" section for the full
findings. A second level-shrink (a genuine depth-3 tree draining twice)
was not attempted -- named as the untested extension in both places.
