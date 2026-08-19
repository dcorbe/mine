# Mutation log

A green suite proves nothing on its own. Each mutation below was introduced
deliberately and observed to fail the named test. Re-run this list after any
change to the tree, the invariant checker, or the property harness.

**Five of the six mutations were caught by a named test.** The sixth
(Mutation A) was not a coverage hole in the suite — it was a badly chosen
mutation that turned out to be an equivalent mutant, plus a second, real
finding about which invariant-checker branch it was supposed to exercise.
Both are documented in full below rather than papered over.

| # | Mutation | Failing test | Message |
|---|---|---|---|
| A | `overflow`: `<=` becomes `<` | **none — equivalent mutant, see below** | 59/59 unit tests pass, 5/5 smoke tests pass. Not a suite gap: see "Mutation A" below for why no test *could* distinguish this mutation from correct behaviour. |
| B | `with_child_mut`: no `Arc::make_mut` | `insert_api_tests::editing_a_clone_leaves_the_original_alone` (14 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'insert_api_tests::editing_a_clone_leaves_the_original_alone' panicked at crates/bropey/src/tree/children.rs:92:54: aliased` — the `.expect("aliased")` panic. All 14 failures, including the property harness, fail on this identical panic message; none fail on a snapshot-mismatch assertion. |
| C | `with_child_mut`: no size writeback | `tree::children::tests::with_child_mut_refreshes_the_cached_size` (20 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'tree::children::tests::with_child_mut_refreshes_the_cached_size' panicked at crates/bropey/src/tree/children.rs:206:9: assertion `left == right` failed: cached size must follow the mutation / left: 3 / right: 6`. Every other failure (e.g. `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one`) fails one level later, inside `check_invariants`, with the brief's predicted text: `assertion `left == right` failed: cached size 15 disagrees with subtree length 10 at child 2`. |
| D | `append`: no small-piece route | `tree::append::tests::an_underfull_side_is_absorbed_not_left_standing`, `tree::append::tests::repeated_small_appends_do_not_degenerate_the_tree`, `composition_tests::repeated_single_byte_removals_keep_the_tree_legal` (16 tests failed total, including `proptests::rope_matches_the_model`) | All three named tests fail identically, via `check_invariants`: `thread '...' panicked at crates/bropey/src/tree/invariants.rs:23:17: non-root leaf of N bytes is below MIN_BYTES 7` (N was 1, 1, and 6 respectively across the three). All three of the brief's named tests failed — none is weaker than intended. |
| E | `locate_insert`: `<=` becomes `<` | `tree::children::tests::locate_insert_biases_left_at_a_boundary` (18 tests failed total, including `proptests::rope_matches_the_model`) | `thread 'tree::children::tests::locate_insert_biases_left_at_a_boundary' panicked at crates/bropey/src/tree/children.rs:181:9: assertion `left == right` failed / left: (1, 0) / right: (0, 5)`. A named unit test localises the bug directly, as intended — not only the property test. |
| F | `insert`: always take the direct path | `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one` and `proptests::rope_matches_the_model` (2 tests failed) | `thread 'composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one' panicked at crates/bropey/src/tree/mod.rs:64:9: direct insert of 60 bytes exceeds MAX_BYTES 15` — the `debug_assert!` in `Node::insert` fires, confirming it is load-bearing rather than decorative. |

## Notes on individual mutations

### Mutation A is an equivalent mutant, not a suite gap

Flipping `overflow`'s comparison from `children.len() <= MAX_CHILDREN` to
`children.len() < MAX_CHILDREN` changes *when* a node splits, not what the
resulting tree contains. At the test regime's `MAX_CHILDREN = 5`:

- **Original** (`<=`): a node only splits once it holds 6 children (the
  smallest value that fails `<= 5`). `half = 6 / 2 = 3`, so the split
  produces **3/3**.
- **Mutated** (`<`): a node already splits at 5 children (the smallest value
  that fails `< 5`). `half = 5 / 2 = 2`, so the split produces **2/3**.

Both outcomes satisfy `MIN_CHILDREN` (2) and `MAX_CHILDREN` (5) on both
sides, and the rope's byte content is identical either way — only the
packing density of the tree changes, one operation earlier. There is no
observable difference between the mutated and unmutated program for any
test, including the property harness, to catch. **This is a defect in the
mutation itself, not a weakness in the suite or in the tests written across
Tasks 1-11.** A future reader re-deriving this should not treat it as an
open coverage hole to close — it is closed by definition, because there is
nothing to detect.

### The real finding: `MIN_CHILDREN`'s non-root branch is subsumed by an unconditional floor

Mutation A was originally chosen to exercise `check_invariants`'s
non-root `MIN_CHILDREN` assertion (`tree/invariants.rs`, the
`if !is_root { assert!(children.len() >= MIN_CHILDREN, ...) }` branch). It
does not, and not merely because no test tree is deep enough — the
assertion is arithmetically unable to fire independently at test
constants, for a different and more specific reason.

`MIN_CHILDREN = MAX_CHILDREN.div_ceil(2) - 1`. At the test regime's
`MAX_CHILDREN = 5`, that is `5.div_ceil(2) - 1 = 3 - 1 = 2`. But
`check_invariants` also asserts, **unconditionally, for every internal node
regardless of root status**:

```rust
assert!(
    children.len() >= 2,
    "internal node has {} children; nothing in this design removes a child",
    children.len()
);
```

Since `MIN_CHILDREN == 2` exactly equals that hard floor at test constants,
any internal node that would fail the non-root `MIN_CHILDREN` check
(`children.len() < 2`, i.e. `children.len() <= 1`) already fails the
unconditional floor first — the two assertions can never disagree, so the
`MIN_CHILDREN` branch is dead code as far as observable test behaviour goes.
This is defence in depth against a state nothing in the crate can currently
produce anyway: no code path removes a child from an internal node once
placed (`overflow` only splits, never merges down; `append`/`insert` only
add). The assertion exists for whichever future change might add a removal
path, not to catch anything reachable today.

Closing this gap for real — making the `MIN_CHILDREN` branch capable of
firing independently of the unconditional floor — needs `MIN_CHILDREN > 2`
at test constants, which means `MAX_CHILDREN >= 7` under `cfg(test)`
(`min_children(7) = 4 - 1 = 3`). That re-tunes the depth/width of every tree
the existing 64 tests build and would need re-verifying against all of
them, or alternatively exposing `check_invariants` to the integration tests
under `tests/`, which link the crate built *without* `cfg(test)` and were
deliberately kept that way by an earlier ruling (see Task 3's brief). Both
are scope decisions for the plan owner, not something to bolt on inside
this task. No constant was changed and no test was added.

### Mutation B proves detection-by-panic only, not detection-by-snapshot

The corrected mutation replaces `Arc::make_mut` with
`Arc::get_mut(...).expect("aliased")`. Every one of the 14 failures —
`editing_a_clone_leaves_the_original_alone`, the property harness, and 12
others — fails on the identical `"aliased"` panic from the `.expect()`, not
on a later content or snapshot mismatch. That is expected and is as far as
this can be pushed: the crate has zero `unsafe` and no interior mutability,
so a shared `Arc<Node>` cannot be mutated in place at all — silent aliasing
corruption is not expressible in this crate, only a loud panic is. The
aliasing tests exist as a regression guard on that invariant, not as a
demonstrated catch of silent corruption; they cannot fail today because the
type system rules out the case they would need to catch.

## Mutation C: which test localises, which test discovers

The most specific failure is the unit test `with_child_mut_refreshes_the_cached_size`,
which asserts the cached size directly at the point of mutation. Every
other failing test (the 19 others) instead trips `check_invariants`'s
`"cached size N disagrees with subtree length M at child I"` assertion one
level later — including `composition_tests::a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one`,
which is the first alphabetically. Both messages are recorded above.

## Working tree

All six mutations were applied one at a time, run under
`cargo test -p bropey`, and reverted with `git checkout` before the next.
Every `proptest-regressions/` file produced by a deliberately broken
mutation (Mutations B through F all produced one) was deleted before
moving on — those seeds record artificial failures, not real regressions.
The working tree is clean of all six mutations; only this file is new.
