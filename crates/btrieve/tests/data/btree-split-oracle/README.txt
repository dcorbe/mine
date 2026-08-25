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
